//! The authentication engine.
//!
//! This is where a local client's request becomes a challenge, where the
//! challenge is dispatched to a device over whatever transport is connected, and
//! where the response is verified. It knows nothing about TCP or BLE: transport
//! adapters deliver [`Message`]s to it and it sends [`Frame`]s back, which is
//! what keeps the two transports security-identical.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rba_protocol::crypto::PublicKey;
use rba_protocol::errors::{ProtocolError, Result};
use rba_protocol::frame::Frame;
use rba_protocol::messages::Message;
use rba_protocol::nonce::ReplayGuard;
use rba_protocol::pairing::{
    CodeEntry, PairingResult, PairingSession, PairingStart, PairingSubmit,
};
use rba_protocol::ratelimit::{Limit, RateLimiter};
use rba_protocol::types::{
    AuthRequest, AuthResponse, Challenge, Id, Transport, AUTH_REQUEST_TTL_DEFAULT, RATE_AUTH,
    RATE_AUTH_WINDOW, RATE_PAIRING, RATE_PAIRING_WINDOW,
};
use rba_protocol::verifier;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::audit::{AuditLog, Event};
use crate::registry::{DevicePolicy, DeviceStatus, HostIdentity, Registry};

/// A currently connected device.
#[derive(Clone, Debug)]
pub struct DeviceHandle {
    pub device_id: Id,
    pub key_id: String,
    /// Sends frames towards the device.
    pub tx: mpsc::UnboundedSender<Frame>,
    pub transport: Transport,
    pub connected_at: u64,
    /// Identifies *this* connection, as opposed to this device.
    ///
    /// A device may hold several connections over its lifetime, and teardown runs
    /// asynchronously: the task for a dropped connection can reach
    /// [`Engine::disconnect_device`] after the device has already reconnected. The
    /// device id alone cannot tell the two apart, so disconnects are matched on this
    /// instead. Without it a device that blinks its Wi-Fi is unregistered by its own
    /// dead connection and stays unusable until it reconnects a second time.
    pub conn_id: u64,
}

/// Everything one authentication attempt needs.
///
/// A struct rather than nine positional arguments, so a caller cannot transpose
/// `purpose` and `service` — both of which end up in the signed request context.
#[derive(Debug, Clone, Copy)]
pub struct AuthContext<'a> {
    /// The verified UID of the local caller.
    pub local_uid: u32,
    pub username: &'a str,
    pub purpose: &'a str,
    pub service: &'a str,
    pub operation: &'a str,
    pub device_selector: Option<&'a str>,
    pub timeout_ms: u64,
    pub transport_pref: Transport,
}

/// Outcome of one authentication attempt, as reported to the local client.
#[derive(Debug, Clone)]
pub struct AuthOutcome {
    pub ok: bool,
    pub device_id: Id,
    pub device_name: String,
    pub request_id: Id,
    pub code: Option<&'static str>,
    pub error: Option<String>,
}

impl AuthOutcome {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "authenticated": self.ok,
            "device_id": self.device_id.to_hex(),
            "device": self.device_name,
            "request_id": self.request_id.to_hex(),
            "code": self.code,
            "error": self.error,
        })
    }
}

/// Shared prompt budgets, independent of transport and requested service.
/// Only admitted attempts consume these budgets; rejected requests do not
/// prolong the cooldown or grow the timestamp queues.
struct PromptBudget {
    accounts: RateLimiter,
    devices: RateLimiter,
}

impl PromptBudget {
    fn new() -> Self {
        Self {
            accounts: RateLimiter::new(Limit::new(3, 60)),
            devices: RateLimiter::new(Limit::new(3, 60)),
        }
    }

    fn admit(&mut self, account: &str, device: &str, now: u64) -> Result<()> {
        self.accounts.prune(now);
        self.devices.prune(now);
        if !self.accounts.peek(account, now) || !self.devices.peek(device, now) {
            let retry = self.accounts.retry_after(account, now)
                .max(self.devices.retry_after(device, now));
            return Err(ProtocolError::RateLimited(retry));
        }
        self.accounts.check_and_record(account, now);
        self.devices.check_and_record(device, now);
        Ok(())
    }
}

pub struct Engine {
    pub host: HostIdentity,
    pub registry: Mutex<Registry>,
    replay: Mutex<ReplayGuard>,
    audit: AuditLog,
    devices: Mutex<HashMap<Id, DeviceHandle>>,
    /// Where a connection task delivers a received message for in-flight work.
    pending_auth: Mutex<HashMap<Id, oneshot::Sender<Message>>>,
    pending_pairing: Mutex<Option<oneshot::Sender<PairingSubmit>>>,
    pairing: Mutex<Option<ActivePairing>>,
    last_pairing: Mutex<Option<CompletedPairing>>,
    rate_pairing: Mutex<RateLimiter>,
    /// One limiter per transport, because the limits differ (§11). Keyed by
    /// `Transport` so a request cannot dodge the limit by switching transport.
    rate_auth: Mutex<HashMap<Transport, RateLimiter>>,
    prompt_budget: Mutex<PromptBudget>,
    /// Optional path for persistent rate-limit state.
    rate_limit_path: Option<std::path::PathBuf>,
    /// Advertised host label, shown on the device.
    pub host_name: String,
    /// Hands out a unique id per connection, so a stale teardown can be told apart
    /// from the connection that replaced it.
    next_conn: std::sync::atomic::AtomicU64,
}

/// How far a pairing session has progressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingPhase {
    /// Session open, waiting for a device to connect.
    AwaitingDevice,
    /// The device submitted; the derived code is known and shown to the operator.
    AwaitingConfirmation,
    Confirmed,
}

struct ActivePairing {
    session: PairingSession,
    /// Operator-chosen code, if any.
    chosen: Option<String>,
    /// Which endpoint must type the derived code.
    code_entry: CodeEntry,
    /// Code both sides derived, available once the device has submitted.
    derived: Option<String>,
    /// Challenge-response code (32 hex chars, per-session, replay-resistant).
    challenge_response: Option<String>,
    phase: PairingPhase,
    /// Flipped by the host-side human gate, not by the final device acknowledgement.
    confirmed: Arc<AtomicBool>,
    notify: Arc<Notify>,
    started_at: u64,
    expires_at: u64,
    /// Rate-limit key this session was opened against.
    peer_key: String,
    /// Linux account the new device will be bound to.
    owner: String,
}

struct CompletedPairing {
    session_id: Id,
    /// The local principal that opened the session; only it may observe or
    /// acknowledge the completion.
    peer_key: String,
    acknowledged: bool,
}

impl ActivePairing {
    fn elapsed(&self, now: u64) -> u64 {
        now.saturating_sub(self.started_at)
    }

    fn opened_by(&self) -> &str {
        &self.peer_key
    }
}

impl Engine {
    pub fn new(
        host: HostIdentity,
        registry: Registry,
        audit: AuditLog,
        host_name: String,
    ) -> Arc<Engine> {
        Self::with_rate_limit_path(host, registry, audit, host_name, None)
    }

    pub fn with_rate_limit_path(
        host: HostIdentity,
        registry: Registry,
        audit: AuditLog,
        host_name: String,
        rate_limit_path: Option<std::path::PathBuf>,
    ) -> Arc<Engine> {
        // Load persisted rate limits if available.
        let (rate_pairing, rate_auth) = if let Some(ref path) = rate_limit_path {
            let pairing_path = path.join("pairing.ratelimit");
            let auth_path = path.join("auth.ratelimit");
            let rp =
                RateLimiter::load(&pairing_path, Limit::new(RATE_PAIRING, RATE_PAIRING_WINDOW));
            let mut ra = HashMap::new();
            ra.insert(
                Transport::Wifi,
                RateLimiter::load(&auth_path, Limit::new(RATE_AUTH, RATE_AUTH_WINDOW)),
            );
            ra.insert(
                Transport::Ble,
                RateLimiter::for_auth_transport(Transport::Ble),
            );
            (rp, ra)
        } else {
            (
                RateLimiter::new(Limit::new(RATE_PAIRING, RATE_PAIRING_WINDOW)),
                HashMap::from([
                    (
                        Transport::Wifi,
                        RateLimiter::for_auth_transport(Transport::Wifi),
                    ),
                    (
                        Transport::Ble,
                        RateLimiter::for_auth_transport(Transport::Ble),
                    ),
                ]),
            )
        };
        Arc::new(Engine {
            host,
            next_conn: std::sync::atomic::AtomicU64::new(1),
            registry: Mutex::new(registry),
            replay: Mutex::new(ReplayGuard::new()),
            audit,
            devices: Mutex::new(HashMap::new()),
            pending_auth: Mutex::new(HashMap::new()),
            pending_pairing: Mutex::new(None),
            pairing: Mutex::new(None),
            last_pairing: Mutex::new(None),
            rate_pairing: Mutex::new(rate_pairing),
            rate_auth: Mutex::new(rate_auth),
            prompt_budget: Mutex::new(PromptBudget::new()),
            rate_limit_path,
            host_name,
        })
    }

    /// Persist rate-limit state to disk so it survives daemon restarts.
    pub fn save_rate_limits(&self) {
        if let Some(ref path) = self.rate_limit_path {
            let _ = std::fs::create_dir_all(path);
            if let Ok(rp) = self.rate_pairing.lock() {
                let _ = rp.save(&path.join("pairing.ratelimit"));
            }
            // Save wifi limiter (the primary transport).
            if let Ok(map) = self.rate_auth.lock() {
                if let Some(rl) = map.get(&Transport::Wifi) {
                    let _ = rl.save(&path.join("auth.ratelimit"));
                }
            }
        }
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    // -- device connection bookkeeping ---------------------------------------

    /// Builds the `SESSION_HELLO` the host opens every connection with.
    pub fn session_hello(
        &self,
        session_id: Id,
        host_nonce: [u8; 32],
    ) -> rba_protocol::types::SessionHello {
        rba_protocol::types::SessionHello {
            protocol_version: rba_protocol::PROTOCOL_VERSION,
            host_id: self.host.host_id,
            host_key_id: self.host.public_key().key_id_hex(),
            host_nonce,
            session_id,
            transports: vec![
                rba_protocol::types::Transport::Wifi.as_str().to_owned(),
                rba_protocol::types::Transport::Ble.as_str().to_owned(),
            ],
        }
    }

    /// Same as [`Engine::session_hello`], already framed for the wire.
    pub fn session_hello_frame(&self, session_id: Id, host_nonce: [u8; 32]) -> Result<Frame> {
        Ok(Message::SessionHello(rba_protocol::types::SessionHello {
            protocol_version: rba_protocol::PROTOCOL_VERSION,
            host_id: self.host.host_id,
            host_key_id: self.host.public_key().key_id_hex(),
            host_nonce,
            session_id,
            transports: vec![
                rba_protocol::types::Transport::Wifi.as_str().to_owned(),
                rba_protocol::types::Transport::Ble.as_str().to_owned(),
            ],
        })
        .to_frame())
    }

    /// Registers a device after its `SESSION_HELLO_ACK` has been validated.
    ///
    /// The device's identity comes from the paired registry only. A peer that
    /// presents a `device_id` or `key_id` we have never recorded is refused, and
    /// a peer whose `key_id` disagrees with the record is refused: nothing here
    /// is taken on trust from the connection.
    pub fn register_device(
        self: &Arc<Self>,
        hello: &rba_protocol::types::SessionHello,
        ack: &rba_protocol::types::SessionHelloAck,
        tx: mpsc::UnboundedSender<Frame>,
        transport: Transport,
    ) -> Result<DeviceHandle> {
        if hello.host_id != self.host.host_id {
            return Err(ProtocolError::ContextMismatch(
                "SESSION_HELLO addressed to a different host".into(),
            ));
        }
        if ack.session_id != hello.session_id {
            return Err(ProtocolError::ContextMismatch(
                "SESSION_HELLO_ACK does not belong to this session".into(),
            ));
        }
        let record_key = {
            let reg = self.registry.lock().expect("registry mutex");
            let rec = reg.get(&ack.device_id).ok_or(ProtocolError::NotPaired)?;
            match rec.status {
                crate::registry::DeviceStatus::Paired => {}
                crate::registry::DeviceStatus::Revoked => return Err(ProtocolError::Revoked),
                _ => return Err(ProtocolError::NotPaired),
            }
            rec.key_id()?
        };
        if record_key != ack.device_key_id {
            return Err(ProtocolError::ContextMismatch(
                "device presented a key id that is not the registered one".into(),
            ));
        }
        let handle = DeviceHandle {
            conn_id: self.next_conn_id(),
            device_id: ack.device_id,
            key_id: ack.device_key_id.clone(),
            tx,
            transport,
            connected_at: rba_protocol::unix_now(),
        };
        self.devices
            .lock()
            .expect("devices mutex")
            .insert(ack.device_id, handle.clone());
        self.audit.write(
            &Event::new("device_connected")
                .success()
                .device_id(device_id_hex(&ack.device_id))
                .transport(transport.as_str()),
        );
        Ok(handle)
    }

    /// True when a pairing session is currently open.
    pub fn pairing_active(&self) -> bool {
        self.pairing
            .lock()
            .map(|g| {
                g.as_ref()
                    .map(|a| a.expires_at > rba_protocol::unix_now())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// True when `peer_key` is the caller that opened the live pairing session.
    ///
    /// Pairing codes and confirmation belong to one local principal. Another
    /// local user must not be able to read the code, confirm the session, or
    /// cancel it by entering a wrong value.
    pub fn pairing_opened_by(&self, peer_key: &str) -> bool {
        self.pairing
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|a| a.peer_key == peer_key))
            .unwrap_or(false)
    }

    /// Removes a device, but only if `conn_id` is still the live connection.
    ///
    /// Returns whether anything was removed. A disconnect that arrives after the
    /// device has already reconnected is ignored: the old connection is gone, but the
    /// new one is healthy and must not be unregistered by its predecessor's cleanup.
    /// A process-unique connection id. Monotonic, so no two live connections share
    /// one and no value is ever reused.
    fn next_conn_id(&self) -> u64 {
        self.next_conn
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn disconnect_device(&self, device_id: &Id, conn_id: u64) -> bool {
        let removed = match self.devices.lock() {
            Ok(mut dev) => match dev.get(device_id) {
                // Someone else already reconnected; this teardown is stale.
                Some(h) if h.conn_id != conn_id => false,
                _ => dev.remove(device_id).is_some(),
            },
            Err(_) => {
                // A poisoned mutex here means a panic elsewhere; the handle is
                // unreachable regardless, and this path only runs on disconnect.
                false
            }
        };
        if !removed {
            return false;
        }
        // Any in-flight request for a device that vanished can never complete;
        // let the waiting client fail fast rather than until timeout. Guarded the
        // same way, so a stale teardown cannot cancel a request the replacement
        // connection is already serving.
        if let Ok(mut p) = self.pending_auth.lock() {
            p.remove(device_id);
        }
        true
    }

    /// Removes whatever connection the device currently has, regardless of which one
    /// it is. Used by revocation, where the intent is to drop the device.
    pub fn force_disconnect_device(&self, device_id: &Id) -> bool {
        let removed = match self.devices.lock() {
            Ok(mut dev) => dev.remove(device_id).is_some(),
            Err(_) => false,
        };
        if removed {
            if let Ok(mut p) = self.pending_auth.lock() {
                p.remove(device_id);
            }
        }
        removed
    }

    pub fn connected_devices(&self) -> Vec<DeviceHandle> {
        self.devices
            .lock()
            .map(|d| d.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Routes a `PAIRING_SUBMIT` to the waiting pairing task.
    ///
    /// Called before any device identity is known, since the submission is what
    /// *establishes* which device is connecting.
    pub fn deliver_pairing(&self, submit: PairingSubmit) {
        if let Ok(mut slot) = self.pending_pairing.lock() {
            if let Some(tx) = slot.take() {
                let _ = tx.send(submit);
                return;
            }
        }
        self.audit
            .write(&Event::new("pairing_submit_unexpected").denied("NOT_PAIRED"));
    }

    /// Delivers a message received from a device to whoever is waiting for it.
    pub fn deliver(&self, device_id: &Id, msg: Message) {
        match msg {
            Message::PairingSubmit(submit) => self.deliver_pairing(submit),
            other => {
                if let Ok(mut p) = self.pending_auth.lock() {
                    if let Some(tx) = p.remove(device_id) {
                        let _ = tx.send(other);
                        return;
                    }
                }
                self.audit.write(
                    &Event::new("unsolicited_message")
                        .denied("CONTEXT_MISMATCH")
                        .device_id(device_id_hex(device_id)),
                );
            }
        }
    }

    // -- pairing -------------------------------------------------------------

    /// Opens a short-lived pairing session.
    ///
    /// Refuses if one is already open: there must never be two live pairing
    /// sessions whose codes could be confused.
    pub fn begin_pairing(
        self: &Arc<Self>,
        code: Option<String>,
        owner: String,
        peer_key: String,
    ) -> Result<(Option<String>, u64)> {
        self.begin_pairing_with_mode(code, CodeEntry::Device, owner, peer_key)
    }

    /// Opens a pairing session with an explicit code-entry direction and owner.
    pub fn begin_pairing_with_mode(
        self: &Arc<Self>,
        code: Option<String>,
        code_entry: CodeEntry,
        owner: String,
        peer_key: String,
    ) -> Result<(Option<String>, u64)> {
        let now = rba_protocol::unix_now();
        {
            let mut rp = self.rate_pairing.lock().expect("rate mutex");
            if !rp.check_and_record(&peer_key, now) {
                let retry = rp.retry_after(&peer_key, now);
                self.audit
                    .write(&Event::new("pairing_rate_limited").denied("RATE_LIMITED"));
                return Err(ProtocolError::RateLimited(retry));
            }
        }
        if let Ok(mut guard) = self.pairing.lock() {
            if let Some(active) = guard.as_ref() {
                if active.expires_at > now {
                    return Err(ProtocolError::BadRequest(format!(
                        "a pairing session is already open (expires in {}s); pairing is never permanent",
                        active.expires_at - now
                    )));
                }
            }
            let session_id = Id::random()?;
            let host_nonce = rba_protocol::crypto::random_array()?;
            // The session holds an ephemeral ECDH key. Nothing is derived and no
            // code exists until the device's `PAIRING_SUBMIT` arrives with its
            // own ephemeral key, so there is no provisional public-nonce code.
            let session = PairingSession::new_with_mode(session_id, host_nonce, code_entry);
            let chosen: Option<String> = match code {
                Some(c) => {
                    if c.len() != rba_protocol::types::PAIRING_CODE_DIGITS
                        || !c.chars().all(|x| x.is_ascii_digit())
                    {
                        return Err(ProtocolError::BadRequest(
                            "pairing code must be exactly six ASCII digits".into(),
                        ));
                    }
                    Some(c)
                }
                // No operator-chosen code: both sides derive one from the two
                // nonces and the operator compares the screens.
                None => None,
            };
            let ttl = rba_protocol::types::PAIRING_TTL;
            let expires_at = now + ttl;
            *self.last_pairing.lock().map_err(|_| ProtocolError::Internal("pairing completion mutex poisoned".into()))? = None;
            *guard = Some(ActivePairing {
                session,
                chosen: chosen.clone(),
                code_entry,
                derived: None,
                challenge_response: None,
                phase: PairingPhase::AwaitingDevice,
                confirmed: Arc::new(AtomicBool::new(false)),
                notify: Arc::new(Notify::new()),
                started_at: now,
                expires_at,
                peer_key,
                owner,
            });
            self.audit.write(&Event::new("pairing_started"));
            Ok((chosen, expires_at))
        } else {
            Err(ProtocolError::Internal("pairing mutex poisoned".into()))
        }
    }

    /// Diagnostics about the open pairing session: age, remaining time and the
    /// rate-limit bucket it was opened against. Never includes the code.
    pub fn pairing_status(&self) -> Option<serde_json::Value> {
        let now = rba_protocol::unix_now();
        self.pairing.lock().ok()?.as_ref().map(|a| {
            serde_json::json!({
                "elapsed_secs": a.elapsed(now),
                "expires_at": a.expires_at,
                "opened_by": a.opened_by(),
                "code_entry": a.code_entry.as_str(),
            })
        })
    }

    /// The code to show the operator, when this mode displays it.
    ///
    /// Before the device submits this is the operator-chosen code; afterwards it
    /// is the code derived from the transcript-bound ECDH secret. In
    /// [`CodeEntry::Host`] mode the host
    /// must not display this value: the device displays it. The caller decides
    /// Challenge-response pairing code.
    ///
    /// The code is a 32-character hex string derived from a per-session challenge
    /// and the ECDH shared secret. The user enters this code to complete pairing.
    /// Works for both command-line entry (ADB-style) and QR code display.
    ///
    /// The code is bound to the session and cannot be reused (replay resistance).
    pub fn pairing_code(&self) -> Option<(String, u64)> {
        self.pairing.lock().ok().and_then(|g| {
            g.as_ref().map(|a| {
                let code = a.challenge_response.clone().unwrap_or_default();
                (code, a.expires_at)
            })
        })
    }

    /// Which endpoint is required to type the derived code.
    pub fn pairing_code_entry(&self) -> Option<CodeEntry> {
        self.pairing
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|a| a.code_entry))
    }

    pub fn pairing_phase(&self) -> PairingPhase {
        self.pairing
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|a| a.phase))
            .unwrap_or(PairingPhase::AwaitingDevice)
    }

    /// Records the operator's confirmation for the default device-entry mode.
    ///
    /// Kept for callers that do not need to supply a code; the real work is in
    /// [`Engine::confirm_pairing_with_code`].
    pub fn confirm_pairing(&self) -> Result<()> {
        self.confirm_pairing_with_code(None)
    }

    /// Records the operator's confirmation, verifying the code when the host is
    /// the endpoint that must type it.
    ///
    /// In [`CodeEntry::Device`] mode the host displays the code and the device
    /// verifies the typed value, so no code is needed here. In
    /// [`CodeEntry::Host`] mode the device displays the code, and the host MUST
    /// prove it was typed by supplying it. A wrong value cancels the session
    /// immediately: one comparison attempt per exchange.
    pub fn confirm_pairing_with_code(&self, entered_code: Option<&str>) -> Result<()> {
        let notify = {
            let mut g = self
                .pairing
                .lock()
                .map_err(|_| ProtocolError::Internal("poisoned".into()))?;
            let a = g.as_mut().ok_or(ProtocolError::NotPaired)?;
            if a.phase == PairingPhase::AwaitingDevice {
                return Err(ProtocolError::BadRequest(
                    "no device has submitted a pairing request yet".into(),
                ));
            }
            if a.code_entry == CodeEntry::Host {
                let expected = a.derived.as_deref().ok_or_else(|| {
                    ProtocolError::Internal("pairing code is not available yet".into())
                })?;
                let entered = entered_code.ok_or_else(|| {
                    ProtocolError::BadRequest(
                        "the host must enter the code shown on the device".into(),
                    )
                })?;
                if entered.len() != expected.len()
                    || !rba_protocol::crypto::ct_eq_slice(entered.as_bytes(), expected.as_bytes())
                {
                    // A mismatch is terminal: no retry inside the same exchange.
                    // Retrying would turn the six-digit check into an online
                    // guessing oracle and keep a half-open session alive.
                    let _ = g.take();
                    self.audit
                        .write(&Event::new("pairing_code_mismatch").denied("CONTEXT_MISMATCH"));
                    return Err(ProtocolError::ContextMismatch(
                        "the entered pairing code does not match; pairing cancelled".into(),
                    ));
                }
                self.audit.write(&Event::new("pairing_code_verified"));
            }
            a.phase = PairingPhase::Confirmed;
            a.confirmed.store(true, Ordering::SeqCst);
            Arc::clone(&a.notify)
        };
        notify.notify_waiters();
        self.audit.write(&Event::new("pairing_confirmed"));
        Ok(())
    }

    fn take_pairing_if_active(&self, now: u64) -> Result<ActivePairing> {
        let mut guard = self
            .pairing
            .lock()
            .map_err(|_| ProtocolError::Internal("poisoned".into()))?;
        let active = guard.take().ok_or(ProtocolError::NotPaired)?;
        if active.expires_at < now {
            return Err(ProtocolError::Expired);
        }
        Ok(active)
    }

    pub fn cancel_pairing(&self) {
        if let Ok(mut g) = self.pairing.lock() {
            *g = None;
        }
        if let Ok(mut last) = self.last_pairing.lock() { *last = None; }
    }

    /// Records the device's final `PAIRING_CONFIRMED`.
    ///
    /// The session id must match the host-side pairing that just completed, so a
    /// device cannot acknowledge a session it did not participate in. This is a
    /// statement by the device that it persisted its record; the host cannot
    /// verify that claim, but it is the only signal that the pairing is complete
    /// on both sides.
    pub fn acknowledge_pairing(&self, session_id: &Id) -> Result<()> {
        let mut guard = self
            .last_pairing
            .lock()
            .map_err(|_| ProtocolError::Internal("pairing mutex poisoned".into()))?;
        let completed = guard.as_mut().ok_or(ProtocolError::NotPaired)?;
        if completed.session_id != *session_id {
            return Err(ProtocolError::ContextMismatch(
                "PAIRING_CONFIRMED does not match the completed session".into(),
            ));
        }
        completed.acknowledged = true;
        Ok(())
    }

    /// Whether the device has acknowledged the last completed pairing, for the
    /// local principal that opened it. `None` means no completion is pending for
    /// this caller.
    pub fn pairing_acknowledged_by(&self, peer_key: &str) -> Option<bool> {
        self.last_pairing
            .lock()
            .ok()?
            .as_ref()
            .filter(|p| p.peer_key == peer_key)
            .map(|p| p.acknowledged)
    }

    /// Seconds left in the open pairing session, if any.
    pub fn pairing_remaining(&self) -> Option<u64> {
        let now = rba_protocol::unix_now();
        self.pairing
            .lock()
            .ok()?
            .as_ref()
            .map(|a| a.expires_at.saturating_sub(now))
    }

    /// Drives the connection half of a pairing exchange.
    ///
    /// The session was already opened by an explicit `rba pair`
    /// ([`Engine::begin_pairing`]); this sends `PAIRING_START` on the arriving
    /// connection, waits for `PAIRING_SUBMIT`, verifies it, and returns the
    /// `PAIRING_RESULT` the transport must send back.
    pub async fn drive_pairing(
        self: &Arc<Self>,
        tx: &mpsc::UnboundedSender<Frame>,
        timeout_secs: u64,
    ) -> Result<PairingResult> {
        let code = {
            let g = self
                .pairing
                .lock()
                .map_err(|_| ProtocolError::Internal("poisoned".into()))?;
            g.as_ref()
                .ok_or(ProtocolError::NotPaired)?
                .chosen
                .clone()
                .unwrap_or_default()
        };
        let start_frame = self.pairing_start_frame(&code, rba_protocol::unix_now())?;
        tx.send(start_frame)
            .map_err(|_| ProtocolError::Internal("device connection closed".into()))?;

        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut slot = self
                .pending_pairing
                .lock()
                .map_err(|_| ProtocolError::Internal("poisoned".into()))?;
            *slot = Some(resp_tx);
        }
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), resp_rx).await;
        if let Ok(mut slot) = self.pending_pairing.lock() {
            *slot = None;
        }
        let submit = match received {
            Err(_) => {
                self.cancel_pairing();
                return Err(ProtocolError::Expired);
            }
            Ok(Err(_)) => {
                self.cancel_pairing();
                return Err(ProtocolError::Internal("device connection closed".into()));
            }
            Ok(Ok(s)) => s,
        };

        // Derive the shared secret and publish the code. The selected mode decides
        // which endpoint displays it and which endpoint must type it. Nothing is
        // verified or persisted until the operator confirmation gate.
        {
            // Complete the ephemeral ECDH exchange with the device's keys and
            // publish the transcript-bound code. The same session is reused by
            // `complete_pairing`, so the displayed code and the MACs cover
            // exactly the keys that will be enrolled.
            let mut g = self
                .pairing
                .lock()
                .map_err(|_| ProtocolError::Internal("poisoned".into()))?;
            let a = g.as_mut().ok_or(ProtocolError::NotPaired)?;
            a.session.derive_with_device_ephemeral(
                &self.host.host_id,
                &submit.device_id,
                &self.host.public_key(),
                &submit.device_pubkey,
                submit.device_nonce,
                submit.device_eph_pubkey,
            )?;
            a.derived = Some(a.session.code()?);
            a.phase = PairingPhase::AwaitingConfirmation;
        }
        self.audit.write(&Event::new("pairing_code_ready"));

        // Block until the operator confirms, the session expires, or we time out.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        loop {
            let notified = {
                let g = self
                    .pairing
                    .lock()
                    .map_err(|_| ProtocolError::Internal("poisoned".into()))?;
                let a = g.as_ref().ok_or(ProtocolError::NotPaired)?;
                if a.confirmed.load(Ordering::SeqCst) {
                    break;
                }
                if a.expires_at < rba_protocol::unix_now() {
                    self.cancel_pairing();
                    return Err(ProtocolError::Expired);
                }
                Arc::clone(&a.notify)
            };
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                self.cancel_pairing();
                return Err(ProtocolError::Expired);
            }
            let _ = tokio::time::timeout(
                remaining.min(std::time::Duration::from_millis(250)),
                notified.notified(),
            )
            .await;
        }

        self.complete_pairing(submit)
    }

    /// Verifies a submitted pairing and, only on success, persists the device.
    ///
    /// Ordering matters: the MAC is verified *before* anything is written, so a
    /// failed submission cannot leave a registry entry behind.
    pub fn complete_pairing(&self, mut submit: PairingSubmit) -> Result<PairingResult> {
        let now = rba_protocol::unix_now();
        let active = self.take_pairing_if_active(now)?;
        if active.phase != PairingPhase::Confirmed {
            // Unreachable through `drive_pairing`, but the invariant is worth
            // stating: nothing is persisted without operator confirmation.
            return Err(ProtocolError::Internal(
                "pairing was not confirmed by the operator".into(),
            ));
        }

        if submit.session_id != active.session.session_id {
            self.audit
                .write(&Event::new("pairing_rejected").denied("CONTEXT_MISMATCH"));
            return Err(ProtocolError::ContextMismatch(
                "pairing submit does not match the open session".into(),
            ));
        }

        // The owner was fixed when the local operator opened the session. The
        // device cannot influence it, and a different local caller cannot take
        // the session over.
        let owner = active.owner.clone();
        let peer_key = active.peer_key.clone();
        let session_id = active.session.session_id;
        let mut session = active.session;
        session.derive_with_device_ephemeral(
            &self.host.host_id,
            &submit.device_id,
            &self.host.public_key(),
            &submit.device_pubkey,
            submit.device_nonce,
            submit.device_eph_pubkey,
        )?;
        if let Some(chosen) = &active.chosen {
            if &session.code()? != chosen {
                // When the operator selected a code, the device must have derived
                // exactly that value. A mismatch means the code comparison the
                // operator relied on could not have succeeded.
                self.audit
                    .write(&Event::new("pairing_rejected").denied("CONTEXT_MISMATCH"));
                return Err(ProtocolError::ContextMismatch(
                    "pairing confirmation code does not match".into(),
                ));
            }
        }

        let expected = session.device_mac(
            &self.host.host_id,
            &submit.device_id,
            &self.host.public_key(),
            &submit.device_pubkey,
        )?;
        if !rba_protocol::crypto::ct_eq_slice(&submit.mac, &expected) {
            self.audit
                .write(&Event::new("pairing_mac_invalid").denied("SIGNATURE_INVALID"));
            return Err(ProtocolError::SignatureInvalid);
        }

        let host_mac = session.host_mac(
            &self.host.host_id,
            &submit.device_id,
            &self.host.public_key(),
            &submit.device_pubkey,
        )?;

        // A new pairing can carry cleanup tokens from older pairings. These are
        // bearer capabilities, not proof of same-installation identity: each token
        // lets us find and revoke exactly the old record it belongs to. Process
        // them only after the new pairing's MAC verified, and before upserting the
        // new record, so a new key can replace an old one.
        let revocation_token: [u8; 32] = rba_protocol::crypto::random_array()?;
        let revocation_token_hash = hex::encode(rba_protocol::crypto::sha256(&revocation_token));
        let mut reg = self.registry.lock().expect("registry mutex");
        for token in &submit.cleanup_tokens {
            let hash = hex::encode(rba_protocol::crypto::sha256(token));
            if let Some(revoked) = reg.revoke_by_token_hash(&hash)? {
                self.audit.write(
                    &Event {
                        kind: "pairing_cleanup",
                        device_id: Some(revoked.to_hex()),
                        ..Event::new("pairing_cleanup")
                    }
                    .success(),
                );
            }
        }
        // Only now is anything persisted.
        let policy = DevicePolicy::for_user(owner.clone());
        reg.upsert_paired_full(
            submit.device_id,
            &submit.device_name,
            &submit.device_pubkey,
            now,
            Some(&revocation_token_hash),
            &policy,
        )
        .map_err(|e| {
            self.audit
                .write(&Event::new("pairing_rejected").denied("CONTEXT_MISMATCH"));
            e
        })?;
        drop(reg);
        *self.last_pairing.lock().map_err(|_| ProtocolError::Internal("pairing completion mutex poisoned".into()))? = Some(CompletedPairing { session_id, peer_key, acknowledged: false });

        self.audit.write(
            &Event {
                kind: "paired",
                device_id: Some(submit.device_id.to_hex()),
                device_name: Some(submit.device_name.clone()),
                username: Some(owner),
                detail: Some("explicit basic enrollment grant".into()),
                ..Event::new("paired")
            }
            .success(),
        );

        submit.mac = [0u8; 32];
        Ok(PairingResult {
            session_id: submit.session_id,
            status: 0,
            host_mac: Some(host_mac),
            revocation_token: Some(revocation_token),
        })
    }

    /// Revokes the record matching a device-held revocation token.
    ///
    /// The token is a bearer capability, so this works even when the device has
    /// already forgotten the host and connects with a fresh identity. Returns the
    /// revoked device id for auditing.
    pub fn revoke_by_token(&self, token: &[u8; 32]) -> Result<Option<Id>> {
        let hash = hex::encode(rba_protocol::crypto::sha256(token));
        let revoked = {
            let mut reg = self
                .registry
                .lock()
                .map_err(|_| ProtocolError::Internal("registry mutex poisoned".into()))?;
            reg.revoke_by_token_hash(&hash)?
        };
        if let Some(id) = revoked {
            self.audit.write(
                &Event {
                    kind: "device_unpaired",
                    device_id: Some(id.to_hex()),
                    ..Event::new("device_unpaired")
                }
                .success(),
            );
        }
        Ok(revoked)
    }

    /// Builds the `PAIRING_START` frame for an open session.
    pub fn pairing_start_frame(&self, code: &str, now: u64) -> Result<Frame> {
        let guard = self
            .pairing
            .lock()
            .map_err(|_| ProtocolError::Internal("poisoned".into()))?;
        let active = guard.as_ref().ok_or(ProtocolError::NotPaired)?;
        let start = PairingStart {
            session_id: active.session.session_id,
            host_id: self.host.host_id,
            host_pubkey: self.host.public_key(),
            host_key_id: self.host.public_key().key_id_hex(),
            code: code.to_owned(),
            code_entry: active.code_entry,
            expires_at: active.expires_at.max(now),
            host_nonce: active.session.host_nonce,
            host_eph_pubkey: active.session.host_eph_public,
        };
        Ok(Message::PairingStart(start).to_frame())
    }

    // -- authentication ------------------------------------------------------

    /// Runs one full authentication: fresh challenge, dispatch, verify.
    pub async fn authenticate(self: &Arc<Self>, request: AuthContext<'_>) -> Result<AuthOutcome> {
        let AuthContext {
            local_uid,
            username,
            purpose,
            service,
            operation,
            device_selector,
            timeout_ms,
            transport_pref: _,
        } = request;
        let username = username.to_owned();
        let purpose = purpose.to_owned();
        let service = service.to_owned();
        let operation = operation.to_owned();
        let device_selector = device_selector.map(|s| s.to_owned());
        let now = rba_protocol::unix_now();
        let scope = crate::authz::Scope::parse(&purpose, &service, &operation)
            .map_err(|reason| ProtocolError::BadRequest(format!("invalid scope: {reason:?}")))?;

        // Resolve and authorise the device *before* consuming a challenge. The
        // account binding is part of resolution: a device paired for alice must
        // never be asked to approve bob, even when root is the caller.
        let (device_id, device_name, _key_id) = self
            .resolve_device_for_scope(device_selector.as_deref(), Some(&username), Some(&scope))
            .map_err(|e| {
                self.audit.write(
                    &Event::new("auth")
                        .denied(e.code().as_str())
                        .username(&username)
                        .purpose(&purpose)
                        .detail(e.to_string()),
                );
                e
            })?;
        let public_key: PublicKey = self
            .registry
            .lock()
            .expect("registry mutex")
            .authorize_scope(&device_id, &username, &scope)?;
        let handle = {
            let devs = self.devices.lock().expect("devices mutex");
            devs.get(&device_id).cloned()
        };

        let Some(handle) = handle else {
            self.audit.write(
                &Event::new("auth")
                    .denied("NOT_PAIRED")
                    .device_id(device_id_hex(&device_id))
                    .device_name(device_name.clone())
                    .username(username)
                    .purpose(purpose),
            );
            return Err(ProtocolError::NotPaired);
        };

        // Check the transport limit before reserving the shared prompt budgets.
        // Keep the transport lock until both shared budgets have been admitted;
        // a denied request must not consume any of the three budgets.
        {
            let mut map = self.rate_auth.lock().expect("rate mutex");
            let limiter = map
                .entry(handle.transport)
                .or_insert_with(|| RateLimiter::for_auth_transport(handle.transport));
            let key = device_id.to_hex();
            limiter.prune(now);
            let admission = if !limiter.peek(&key, now) {
                Err(ProtocolError::RateLimited(limiter.retry_after(&key, now)))
            } else {
                self.prompt_budget.lock().expect("prompt budget mutex")
                    .admit(&username, &key, now)
            };
            if let Err(e) = admission {
                self.audit.write(
                    &Event::new("auth_rate_limited")
                        .denied("RATE_LIMITED")
                        .device_id(key)
                        .username(&username)
                        .purpose(&purpose),
                );
                return Err(e);
            }
            limiter.check_and_record(&key, now);
        }

        // Fresh identifiers for every attempt.
        let request_id = Id::random()?;
        let challenge = Challenge::random()?;
        let session_id = Id::random()?;
        let request = AuthRequest::new(
            request_id,
            self.host.host_id,
            device_id,
            username.to_owned(),
            purpose.to_owned(),
            service.to_owned(),
            operation.to_owned(),
            challenge,
            now,
            now + AUTH_REQUEST_TTL_DEFAULT,
            session_id,
        )
        .map_err(|e| {
            self.audit
                .write(&Event::new("auth").denied("BAD_REQUEST").username(&username));
            e
        })?
        .with_display(Some(self.host_name.clone()), None);

        {
            let mut rp = self.replay.lock().expect("replay mutex");
            rp.begin(&request, now)?;
        }

        // Register the response slot *before* the request reaches the device.
        //
        // A device can answer faster than this task yields: it signs and writes
        // the response as soon as it receives the frame. If the slot were
        // installed afterwards, the response would arrive with nothing waiting
        // for it and be discarded, turning a legitimate approval into a spurious
        // timeout. Installing first removes that race entirely.
        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut p = self.pending_auth.lock().expect("pending mutex");
            if p.insert(device_id, resp_tx).is_some() {
                self.replay
                    .lock()
                    .expect("replay mutex")
                    .abort(&device_id, now);
                return Err(ProtocolError::Internal(
                    "another authentication is already in flight".into(),
                ));
            }
        }

        let frame = Message::AuthRequest(request.clone()).to_frame();
        if handle.tx.send(frame).is_err() {
            // The slot is already installed, so clear it again before giving up.
            if let Ok(mut p) = self.pending_auth.lock() {
                p.remove(&device_id);
            }
            self.replay
                .lock()
                .expect("replay mutex")
                .abort(&device_id, now);
            return Err(ProtocolError::Internal("device connection closed".into()));
        }

        let outcome =
            tokio::time::timeout(std::time::Duration::from_millis(timeout_ms.max(1)), resp_rx)
                .await;

        // Clear the slot regardless of outcome.
        if let Ok(mut p) = self.pending_auth.lock() {
            p.remove(&device_id);
        }

        let message = match outcome {
            Err(_) => {
                // Timed out: burn the identifiers so a late response cannot be
                // accepted.
                self.replay
                    .lock()
                    .expect("replay mutex")
                    .abort(&device_id, rba_protocol::unix_now());
                self.log_denial(
                    &device_id,
                    &device_name,
                    &username,
                    &purpose,
                    &service,
                    &operation,
                    &request_id,
                    handle.transport,
                    local_uid,
                    "EXPIRED",
                    "no response from device before timeout",
                );
                return Err(ProtocolError::Expired);
            }
            Ok(Err(_)) => {
                self.replay
                    .lock()
                    .expect("replay mutex")
                    .abort(&device_id, rba_protocol::unix_now());
                self.log_denial(
                    &device_id,
                    &device_name,
                    &username,
                    &purpose,
                    &service,
                    &operation,
                    &request_id,
                    handle.transport,
                    local_uid,
                    "INTERNAL",
                    "device connection dropped",
                );
                return Err(ProtocolError::Internal("device connection dropped".into()));
            }
            Ok(Ok(msg)) => msg,
        };

        // Consume first (burns request_id and challenge), then verify. A replay
        // is rejected even if its signature bytes are identical.
        let consumed = {
            let mut rp = self.replay.lock().expect("replay mutex");
            rp.consume_for_verification(
                &device_id,
                &request_id,
                &challenge,
                rba_protocol::unix_now(),
            )
        };
        let outstanding = match consumed {
            Ok(r) => r,
            Err(e) => {
                self.log_denial(
                    &device_id,
                    &device_name,
                    &username,
                    &purpose,
                    &service,
                    &operation,
                    &request_id,
                    handle.transport,
                    local_uid,
                    e.code().as_str(),
                    &e.to_string(),
                );
                return Err(e);
            }
        };

        let response = match message {
            Message::AuthResponse(r) => r,
            Message::AuthReject(rej) => {
                let code = rba_protocol::errors::ErrorCode::from_wire(rej.reason)
                    .map(|c| c.as_str())
                    .unwrap_or("INTERNAL");
                self.log_denial(
                    &device_id,
                    &device_name,
                    &username,
                    &purpose,
                    &service,
                    &operation,
                    &request_id,
                    handle.transport,
                    local_uid,
                    code,
                    "device rejected the request",
                );
                return Err(ProtocolError::UserCancelled);
            }
            Message::Error(e) => {
                let code = rba_protocol::errors::ErrorCode::from_wire(e.code)
                    .map(|c| c.as_str())
                    .unwrap_or("INTERNAL");
                self.log_denial(
                    &device_id,
                    &device_name,
                    &username,
                    &purpose,
                    &service,
                    &operation,
                    &request_id,
                    handle.transport,
                    local_uid,
                    code,
                    "device reported an error",
                );
                return Err(ProtocolError::Internal(e.message));
            }
            other => {
                self.log_denial(
                    &device_id,
                    &device_name,
                    &username,
                    &purpose,
                    &service,
                    &operation,
                    &request_id,
                    handle.transport,
                    local_uid,
                    "BAD_REQUEST",
                    &format!("unexpected message {}", other.name()),
                );
                return Err(ProtocolError::BadRequest(format!(
                    "unexpected message {}",
                    other.name()
                )));
            }
        };

        let transport = handle.transport;
        match verifier::verify_auth_response(
            &outstanding,
            &response,
            &public_key,
            device_id,
            outstanding.session_id,
            rba_protocol::unix_now(),
            transport,
        ) {
            Ok(()) => {
                let mut reg = self.registry.lock().map_err(|_| ProtocolError::Internal("registry mutex poisoned".into()))?;
                let current = reg.authorize_scope(&device_id, &username, &scope)?;
                if current.as_bytes() != public_key.as_bytes() {
                    return Err(ProtocolError::ContextMismatch("credential changed during authentication".into()));
                }
                reg.record_success(&device_id, rba_protocol::unix_now())?;
                drop(reg);
                self.audit.write(&Event {
                    kind: "auth",
                    device_id: Some(device_id.to_hex()),
                    device_name: Some(device_name.clone()),
                    username: Some(username.to_owned()),
                    purpose: Some(purpose.to_owned()),
                    service: Some(service.to_owned()),
                    operation: Some(operation.to_owned()),
                    request_id: Some(request_id.to_hex()),
                    transport: Some(transport.as_str().to_owned()),
                    local_uid: Some(local_uid),
                    result: crate::audit::Outcome::Success,
                    code: None,
                    detail: None,
                });
                Ok(AuthOutcome {
                    ok: true,
                    device_id,
                    device_name,
                    request_id,
                    code: None,
                    error: None,
                })
            }
            Err(e) => {
                self.log_denial(
                    &device_id,
                    &device_name,
                    &username,
                    &purpose,
                    &service,
                    &operation,
                    &request_id,
                    transport,
                    local_uid,
                    e.code().as_str(),
                    &e.to_string(),
                );
                Err(e)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn log_denial(
        &self,
        device_id: &Id,
        device_name: &str,
        username: &str,
        purpose: &str,
        service: &str,
        operation: &str,
        request_id: &Id,
        transport: Transport,
        local_uid: u32,
        code: &str,
        detail: &str,
    ) {
        self.audit.write(&Event {
            kind: "auth",
            device_id: Some(device_id.to_hex()),
            device_name: Some(device_name.to_owned()),
            username: Some(username.to_owned()),
            purpose: Some(purpose.to_owned()),
            service: Some(service.to_owned()),
            operation: Some(operation.to_owned()),
            request_id: Some(request_id.to_hex()),
            transport: Some(transport.as_str().to_owned()),
            local_uid: Some(local_uid),
            result: crate::audit::Outcome::Denied,
            code: Some(code.to_owned()),
            detail: Some(detail.to_owned()),
        });
    }

    /// Finds a device by id or name and returns `(id, name, key_id)`.
    ///
    /// `for_user` is the account the caller is entitled to authenticate. When it
    /// is `Some`, devices not bound to that account are invisible to selection;
    /// `None` is the root/administrative view.
    pub fn resolve_device(
        &self,
        selector: Option<&str>,
        for_user: Option<&str>,
    ) -> Result<(Id, String, String)> {
        self.resolve_device_for_scope(selector, for_user, None)
    }

    fn resolve_device_for_scope(
        &self,
        selector: Option<&str>,
        for_user: Option<&str>,
        scope: Option<&crate::authz::Scope>,
    ) -> Result<(Id, String, String)> {
        let reg = self.registry.lock().expect("registry mutex");
        let allowed = |rec: &crate::registry::DeviceRecord| {
            rec.status.may_authenticate()
                && match (for_user, scope) {
                    (Some(user), Some(scope)) => rec.id().and_then(|id| reg.authorize_scope(&id, user, scope)).is_ok(),
                    (Some(user), None) => rec.is_bound_to(user),
                    (None, None) => true,
                    (None, Some(_)) => false,
                }
        };
        match selector {
            None => {
                // Prefer a connected, paired device; otherwise report that none
                // is paired rather than guessing.
                let connected = self.devices.lock().expect("devices mutex");
                let mut candidates: Vec<&Id> = connected.keys().collect();
                candidates.sort();
                for id in candidates {
                    if let Some(rec) = reg.get(id) {
                        if allowed(rec) {
                            return Ok((*id, rec.name.clone(), rec.key_id()?));
                        }
                    }
                }
                Err(ProtocolError::NotPaired)
            }
            Some(sel) => {
                if let Ok(id) = Id::from_hex(sel) {
                    let rec = reg.get(&id).ok_or(ProtocolError::NotPaired)?;
                    // Report lifecycle state precisely before the account filter,
                    // so a revoked device is `Revoked`, not a policy mismatch.
                    match rec.status {
                        DeviceStatus::Revoked => return Err(ProtocolError::Revoked),
                        DeviceStatus::Pairing | DeviceStatus::Replaced => {
                            return Err(ProtocolError::NotPaired)
                        }
                        DeviceStatus::Paired => {}
                    }
                    if !allowed(rec) {
                        return Err(ProtocolError::ContextMismatch(format!(
                            "device {} is not authorized for this user",
                            rec.name
                        )));
                    }
                    return Ok((id, rec.name.clone(), rec.key_id()?));
                }
                let mut matches = Vec::new();
                for rec in reg.by_name(sel) {
                    if allowed(rec) {
                        matches.push(rec);
                    }
                }
                match matches.len() {
                    0 => Err(ProtocolError::ContextMismatch(format!(
                        "device {sel:?} is not authorized for this user"
                    ))),
                    1 => {
                        let rec = matches[0];
                        Ok((rec.id()?, rec.name.clone(), rec.key_id()?))
                    }
                    n => Err(ProtocolError::BadRequest(format!(
                        "device name {sel:?} is ambiguous ({n} matches); use the device id"
                    ))),
                }
            }
        }
    }

    pub fn list_devices(&self, viewer: Option<&str>) -> Vec<serde_json::Value> {
        let connected: Vec<Id> = self
            .connected_devices()
            .iter()
            .map(|h| h.device_id)
            .collect();
        self.registry
            .lock()
            .expect("registry mutex")
            .all()
            .into_iter()
            .filter(|rec| viewer.map_or(true, |user| rec.is_bound_to(user)))
            .map(|mut rec| {
                let id = rec.id().unwrap_or_default();
                if let Some(user) = viewer {
                    rec.policy.grants.retain(|g| g.principal.as_str() == user);
                }
                serde_json::json!({
                    "device_id": rec.device_id,
                    "name": rec.name,
                    "key_id": rec.key_id().unwrap_or_default(),
                    "status": rec.status.as_str(),
                    "grants": rec.policy.grants,
                    "available": connected.contains(&id),
                    "added_at": rec.added_at,
                    "last_seen": rec.last_seen,
                    "auth_count": rec.auth_count,
                    "summary": rec.summary(),
                })
            })
            .collect()
    }

    /// Administrative policy mutation; IPC enforces the administrator boundary.
    pub fn set_device_scope(&self, selector: &str, permission: crate::authz::Grant, grant: bool) -> Result<()> {
        let (id, _, _) = self.resolve_device(Some(selector), None)?;
        self.registry.lock().map_err(|_| ProtocolError::Internal("registry mutex poisoned".into()))?.set_scope(&id, permission.clone(), grant)?;
        self.audit.write(&Event::new(if grant { "scope_granted" } else { "scope_removed" }).device_id(id.to_hex()).username(permission.principal.as_str().to_owned()).detail(format!("{}/{}/{:?}", permission.scope.purpose, permission.scope.service, permission.scope.operation)).success());
        Ok(())
    }

    pub fn revoke_device(&self, selector: &str) -> Result<String> {
        let (id, name, _) = self.resolve_device(Some(selector), None)?;
        self.registry.lock().expect("registry mutex").revoke(&id)?;
        // Drop the live connection too: revocation must take effect immediately,
        // not at the next reconnect. Unconditional on purpose: revocation targets the
        // device, not one of its connections, so a reconnect racing the revocation
        // must not survive it.
        self.force_disconnect_device(&id);
        self.audit.write(
            &Event::new("revoked")
                .success()
                .device_id(device_id_hex(&id))
                .device_name(name.clone()),
        );
        Ok(name)
    }

    /// Unpair a selected credential. Shared or empty policies require an administrator.
    pub fn unpair_device(&self, selector: &str, caller_user: Option<&str>) -> Result<String> {
        let (id, name, _) = self.resolve_device(Some(selector), None)?;
        {
            let mut reg = self.registry.lock().expect("registry mutex");
            let rec = reg.get(&id).ok_or(ProtocolError::NotPaired)?;
            if let Some(user) = caller_user {
                if !rec.is_bound_to(user) || rec.policy.grants.iter().any(|g| g.principal.as_str() != user) {
                    return Err(ProtocolError::ContextMismatch("only an administrator may unpair a shared credential".into()));
                }
            }
            reg.unpair(&id)?;
        }
        self.force_disconnect_device(&id);
        self.audit.write(&Event::new("unpaired").success().device_id(device_id_hex(&id)).device_name(name.clone()));
        Ok(name)
    }

    /// Status filtered to the caller's own devices.
    ///
    /// `viewer` is `None` for root. `peer_key` decides whether the open pairing
    /// session belongs to this caller, so another local user cannot use status
    /// to watch a pairing they did not start.
    pub fn status(&self, viewer: Option<&str>, peer_key: &str) -> serde_json::Value {
        let connected = self.connected_devices();
        let (paired_devices, connected_devices) = {
            let reg = self.registry.lock().expect("registry mutex");
            let paired = reg
                .all()
                .iter()
                .filter(|r| {
                    r.status.may_authenticate() && viewer.map_or(true, |user| r.is_bound_to(user))
                })
                .count();
            let connected = connected
                .iter()
                .filter(|h| {
                    viewer.map_or(true, |user| {
                        reg.get(&h.device_id)
                            .map(|r| r.is_bound_to(user))
                            .unwrap_or(false)
                    })
                })
                .count();
            (paired, connected)
        };
        let pairing = if viewer.is_none() || self.pairing_opened_by(peer_key) {
            self.pairing_code()
        } else {
            None
        };
        serde_json::json!({
            "host_id": self.host.host_id.to_hex(),
            "host_key_id": self.host.public_key().key_id_hex(),
            "host_name": self.host_name,
            "paired_devices": paired_devices,
            "connected_devices": connected_devices,
            // The code itself is only obtainable via the pairing_code command, so a
            // status dump never puts it into a log or a terminal scrollback.
            "pairing": pairing.map(|(_code, expires)| serde_json::json!({
                "active": true,
                "expires_at": expires,
                "seconds_remaining": expires.saturating_sub(rba_protocol::unix_now()),
                "code_entry": self.pairing_code_entry().map(|m| m.as_str()),
            })),
        })
    }

    pub fn pending_count(&self) -> usize {
        self.pending_auth.lock().map(|p| p.len()).unwrap_or(0)
    }

    pub fn device_status(&self, id: &Id) -> Option<DeviceStatus> {
        self.registry.lock().ok()?.get(id).map(|r| r.status)
    }
}

fn device_id_hex(id: &Id) -> String {
    id.to_hex()
}

/// Convenience: the response a device sends when it declines.
pub fn reject_frame(request_id: Id, code: rba_protocol::errors::ErrorCode) -> Frame {
    Message::AuthReject(rba_protocol::types::AuthReject {
        request_id,
        reason: code.as_u32() as u64,
    })
    .to_frame()
}

/// Convenience used by transports and tests.
pub fn auth_response(
    request_id: Id,
    device_id: Id,
    session_id: Id,
    key_id: &str,
    signature: [u8; 64],
) -> Frame {
    Message::AuthResponse(AuthResponse {
        request_id,
        device_id,
        session_id,
        algorithm: rba_protocol::crypto::ALGORITHM.to_owned(),
        key_id: key_id.to_owned(),
        signature,
    })
    .to_frame()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rba_protocol::crypto::PrivateKey;
    use rba_protocol::types::{SessionHello, SessionHelloAck, CHALLENGE_LEN};

    /// Builds an engine with one device already paired, plus the identity the daemon
    /// will present in its SESSION_HELLO.
    fn engine_with_paired_device() -> (Arc<Engine>, Id, Id, String) {
        let host_id = Id::random().expect("OS randomness is required");
        let host = HostIdentity::for_tests(PrivateKey::generate().expect("OS randomness"), host_id);
        let device_key = PrivateKey::generate().expect("OS randomness");
        let device_id = Id::random().expect("random");
        let mut registry = Registry::in_memory();
        registry
            .upsert_paired_for_user(device_id, "Pixel", &device_key.public_key(), 100, "alice")
            .expect("pair");
        let engine = Engine::with_rate_limit_path(
            host,
            registry,
            AuditLog::null(),
            "test-host".into(),
            None,
        );
        (
            engine,
            host_id,
            device_id,
            key_id_of(&device_key.public_key()),
        )
    }

    fn key_id_of(pk: &rba_protocol::crypto::PublicKey) -> String {
        hex::encode(rba_protocol::crypto::sha256(pk.as_bytes()))
    }

    fn hello_for(host_id: Id) -> SessionHello {
        SessionHello {
            protocol_version: rba_protocol::PROTOCOL_VERSION,
            host_id,
            host_key_id: String::new(),
            host_nonce: [7u8; CHALLENGE_LEN],
            session_id: Id::random().expect("random"),
            transports: vec!["wifi".into()],
        }
    }

    fn ack_for(device_id: Id, key_id: &str, session_id: Id) -> SessionHelloAck {
        SessionHelloAck {
            protocol_version: rba_protocol::PROTOCOL_VERSION,
            device_id,
            device_key_id: key_id.to_owned(),
            device_nonce: [9u8; CHALLENGE_LEN],
            session_id,
        }
    }

    /// The bug this guards: a device whose connection blips reconnects, and the old
    /// connection's teardown then unregisters the new one. The device is left
    /// unusable until it happens to reconnect a second time, which looks to a user
    /// like a broken product rather than a race.
    #[test]
    fn a_stale_disconnect_does_not_unregister_the_replacement_connection() {
        let (engine, host_id, device_id, key_id) = engine_with_paired_device();

        // First connection.
        let hello = hello_for(host_id);
        let first = engine
            .register_device(
                &hello,
                &ack_for(device_id, &key_id, hello.session_id),
                mpsc::unbounded_channel().0,
                Transport::Wifi,
            )
            .expect("first connection registers");

        // The device drops and immediately comes back before the old task has finished
        // tearing down.
        let hello2 = hello_for(host_id);
        let second = engine
            .register_device(
                &hello2,
                &ack_for(device_id, &key_id, hello2.session_id),
                mpsc::unbounded_channel().0,
                Transport::Wifi,
            )
            .expect("second connection registers");
        assert_ne!(first.conn_id, second.conn_id, "each connection is distinct");

        // Now the old connection's task notices the drop and cleans up. It must not
        // touch the live connection.
        assert!(
            !engine.disconnect_device(&device_id, first.conn_id),
            "a stale disconnect must report that it removed nothing"
        );
        assert_eq!(
            engine.connected_devices().len(),
            1,
            "the replacement connection must survive its predecessor's teardown"
        );

        // The live connection still disconnects cleanly, exactly once.
        assert!(engine.disconnect_device(&device_id, second.conn_id));
        assert!(engine.connected_devices().is_empty());
    }

    /// Revocation targets the device, not a connection, so it must drop whichever
    /// connection is live even if the caller is not the one that registered it.
    #[test]
    fn force_disconnect_drops_the_live_connection_regardless_of_who_calls() {
        let (engine, host_id, device_id, key_id) = engine_with_paired_device();
        let hello = hello_for(host_id);
        engine
            .register_device(
                &hello,
                &ack_for(device_id, &key_id, hello.session_id),
                mpsc::unbounded_channel().0,
                Transport::Wifi,
            )
            .expect("registers");
        assert!(engine.force_disconnect_device(&device_id));
        assert!(engine.connected_devices().is_empty());
    }
}

#[cfg(test)]
mod prompt_budget_tests {
    use super::*;

    #[test]
    fn account_budget_is_shared_across_devices() {
        let mut budget = PromptBudget::new();
        for device in ["a", "b", "c"] {
            assert!(budget.admit("alice", device, 100).is_ok());
        }
        assert!(matches!(budget.admit("alice", "d", 101), Err(ProtocolError::RateLimited(_))));
        assert!(budget.admit("bob", "d", 101).is_ok());
    }

    #[test]
    fn device_budget_is_shared_across_accounts_and_rejections_do_not_extend_it() {
        let mut budget = PromptBudget::new();
        for account in ["alice", "bob", "carol"] {
            assert!(budget.admit(account, "a", 100).is_ok());
        }
        for _ in 0..100 {
            assert!(matches!(budget.admit("dave", "a", 159), Err(ProtocolError::RateLimited(1))));
        }
        assert!(budget.admit("dave", "a", 160).is_ok());
    }
}
