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
    CodeEntry, PairingChallenge, PairingProof, PairingResult, PairingStart, PairingSubmit,
};
use rba_protocol::types::{
    AuthRequest, AuthResponse, Challenge, Id, Transport, AUTH_REQUEST_TTL_DEFAULT,
};
use rba_protocol::verifier;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::admission::Admission;
use crate::audit::{AuditLog, Event};
use crate::registry::{DevicePolicy, DeviceStatus, HostIdentity, Registry};

fn enrollment_error(_: rba_enrollment::Error) -> ProtocolError { ProtocolError::SignatureInvalid }

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

pub struct Engine {
    pub host: HostIdentity,
    pub registry: Mutex<Registry>,
    replay: Mutex<ReplayGuard>,
    audit: AuditLog,
    devices: Mutex<HashMap<Id, DeviceHandle>>,
    /// Where a connection task delivers a received message for in-flight work.
    pending_auth: Mutex<HashMap<Id, oneshot::Sender<Message>>>,
    pairing: Mutex<Option<ActivePairing>>,
    last_pairing: Mutex<Option<CompletedPairing>>,
    /// All rate-limit dimensions share one admission transaction.
    admission: Mutex<Admission>,
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
    session_id: Id,
    /// Locally generated or locally entered password, never sent on the wire.
    code: Option<rba_enrollment::PairingCode>,
    code_entry: CodeEntry,
    phase: PairingPhase,
    connection_claimed: bool,
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

struct PendingEnrollment {
    submit: PairingSubmit,
    cleanup_tokens: Vec<[u8; 32]>,
    token_hash: String,
    owner: String,
}

struct CompletedPairing {
    session_id: Id,
    expires_at: u64,
    pending: Option<PendingEnrollment>,
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
        Self::with_admission(
            host,
            registry,
            audit,
            host_name,
            Admission::open(None).expect("in-memory admission requires no filesystem"),
        )
    }

    pub fn with_rate_limit_path(
        host: HostIdentity,
        registry: Registry,
        audit: AuditLog,
        host_name: String,
        rate_limit_path: &std::path::Path,
    ) -> Result<Arc<Engine>> {
        let admission = Admission::open(Some(rate_limit_path))?;
        Ok(Self::with_admission(host, registry, audit, host_name, admission))
    }

    fn with_admission(
        host: HostIdentity,
        registry: Registry,
        audit: AuditLog,
        host_name: String,
        admission: Admission,
    ) -> Arc<Engine> {
        Arc::new(Engine {
            host,
            next_conn: std::sync::atomic::AtomicU64::new(1),
            registry: Mutex::new(registry),
            replay: Mutex::new(ReplayGuard::new()),
            audit,
            devices: Mutex::new(HashMap::new()),
            pending_auth: Mutex::new(HashMap::new()),
            pairing: Mutex::new(None),
            last_pairing: Mutex::new(None),
            admission: Mutex::new(admission),
            host_name,
        })
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

    /// Assign an open pairing attempt to exactly one transport connection.
    pub fn claim_pairing_connection(&self) -> Option<Id> {
        let mut guard = self.pairing.lock().ok()?;
        let active = guard.as_mut()?;
        if active.connection_claimed || active.expires_at <= rba_protocol::unix_now() {
            return None;
        }
        active.connection_claimed = true;
        Some(active.session_id)
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

    /// Delivers a message received from a device to whoever is waiting for it.
    pub fn deliver(&self, device_id: &Id, msg: Message) {
        if let Ok(mut pending) = self.pending_auth.lock() {
            if let Some(tx) = pending.remove(device_id) {
                let _ = tx.send(msg);
                return;
            }
        }
        self.audit.write(
            &Event::new("unsolicited_message")
                .denied("CONTEXT_MISMATCH")
                .device_id(device_id_hex(device_id)),
        );
    }

    // -- pairing -------------------------------------------------------------

    /// Opens a short-lived pairing session.
    ///
    /// Refuses if one is already open: there must never be two live pairing
    /// sessions whose codes could be confused.
    pub fn begin_pairing(
        self: &Arc<Self>,
        owner: String,
        peer_key: String,
    ) -> Result<(Option<String>, u64)> {
        self.begin_pairing_with_mode(CodeEntry::Device, owner, peer_key)
    }

    /// Opens a pairing session with an explicit code-entry direction and owner.
    pub fn begin_pairing_with_mode(
        self: &Arc<Self>,
        code_entry: CodeEntry,
        owner: String,
        peer_key: String,
    ) -> Result<(Option<String>, u64)> {
        let now = {
            let mut admission = self.admission.lock().map_err(|_| {
                ProtocolError::Internal("admission mutex poisoned".into())
            })?;
            let now = rba_protocol::unix_now();
            if let Err(e) = admission.pairing(&peer_key, now) {
                self.audit.write(
                    &Event::new("pairing_admission_denied").denied(e.code().as_str()),
                );
                return Err(e);
            }
            now
        };
        if let Ok(mut guard) = self.pairing.lock() {
            if let Some(active) = guard.as_ref() {
                if active.expires_at > now {
                    return Err(ProtocolError::BadRequest(format!(
                        "a pairing session is already open (expires in {}s); pairing is never permanent",
                        active.expires_at - now
                    )));
                }
            }
            let mut staged = self.last_pairing.lock()
                .map_err(|_| ProtocolError::Internal("pairing completion mutex poisoned".into()))?;
            if staged.as_ref().is_some_and(|p| p.pending.is_some() && p.expires_at > now) {
                return Err(ProtocolError::BadRequest("a pairing is awaiting device confirmation".into()));
            }
            let session_id = Id::random()?;
            // Only the displaying endpoint generates a fresh random password.
            let password = if code_entry == CodeEntry::Device {
                Some(rba_enrollment::PairingCode::generate().map_err(enrollment_error)?)
            } else { None };
            let display = password.as_ref().map(|c| String::from_utf8_lossy(c.as_ascii()).into_owned());
            let ttl = rba_protocol::types::PAIRING_TTL;
            let expires_at = now + ttl;
            *staged = None;
            *guard = Some(ActivePairing {
                session_id,
                code: password,
                code_entry,
                phase: PairingPhase::AwaitingDevice,
                connection_claimed: false,
                confirmed: Arc::new(AtomicBool::new(false)),
                notify: Arc::new(Notify::new()),
                started_at: now,
                expires_at,
                peer_key,
                owner,
            });
            self.audit.write(&Event::new("pairing_started"));
            Ok((display, expires_at))
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

    /// Return only non-secret metadata for the owner of a pairing attempt.
    pub fn pairing_status_for(&self, peer_key: &str, administrative: bool) -> Result<Option<serde_json::Value>> {
        let g = self.pairing.lock().map_err(|_| ProtocolError::Internal("pairing mutex poisoned".into()))?;
        let Some(a) = g.as_ref() else { return Ok(None); };
        if a.expires_at <= rba_protocol::unix_now() { return Ok(None); }
        if !administrative && a.peer_key != peer_key {
            return Err(ProtocolError::ContextMismatch("pairing belongs to another caller".into()));
        }
        Ok(Some(serde_json::json!({
            "active": true, "expires_at": a.expires_at,
            "phase": format!("{:?}", a.phase).to_lowercase(),
            "code_entry": a.code_entry.as_str(),
            "seconds_remaining": a.expires_at.saturating_sub(rba_protocol::unix_now()),
        })))
    }

    /// In-process fixture helper; never exposed through the control API.
    pub fn pairing_code(&self) -> Option<(String, u64)> {
        let g = self.pairing.lock().ok()?;
        let a = g.as_ref()?;
        if a.expires_at <= rba_protocol::unix_now() { return None; }
        let code = if a.code_entry == CodeEntry::Device {
            a.code.as_ref().map(|c| String::from_utf8_lossy(c.as_ascii()).into_owned()).unwrap_or_default()
        } else { String::new() };
        Some((code, a.expires_at))
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
    pub fn confirm_pairing(&self, peer_key: &str) -> Result<()> {
        self.confirm_pairing_with_code(peer_key, None)
    }

    /// Host-entry mode accepts one local password submission. The PAKE peer
    /// confirmation, not a locally derived comparison, decides whether it is right.
    pub fn confirm_pairing_with_code(&self, peer_key: &str, entered_code: Option<&str>) -> Result<()> {
        let notify = {
            let mut g = self.pairing.lock().map_err(|_| ProtocolError::Internal("poisoned".into()))?;
            let a = g.as_mut().ok_or(ProtocolError::NotPaired)?;
            if a.peer_key != peer_key { return Err(ProtocolError::ContextMismatch("pairing belongs to another caller".into())); }
            if a.expires_at <= rba_protocol::unix_now() || a.confirmed.load(Ordering::SeqCst) {
                return Err(ProtocolError::NotPaired);
            }
            match a.code_entry {
                CodeEntry::Host => {
                    if a.phase != PairingPhase::AwaitingConfirmation { return Err(ProtocolError::NotPaired); }
                    let code = entered_code.ok_or_else(|| ProtocolError::BadRequest("enter the device's code".into()))?;
                    a.code = Some(rba_enrollment::PairingCode::parse(code.as_bytes()).map_err(enrollment_error)?);
                }
                CodeEntry::Device => {
                    if entered_code.is_some() { return Err(ProtocolError::BadRequest("the device enters the code".into())); }
                }
            }
            a.phase = PairingPhase::Confirmed;
            a.confirmed.store(true, Ordering::SeqCst);
            Arc::clone(&a.notify)
        };
        notify.notify_waiters();
        Ok(())
    }

    pub fn cancel_pairing(&self) {
        // Used by in-process tests and administrative shutdown.
        let _ = self.cancel_pairing_for("", true);
    }

    pub fn cancel_pairing_for(&self, peer_key: &str, administrative: bool) -> Result<()> {
        let mut active = self.pairing.lock()
            .map_err(|_| ProtocolError::Internal("pairing mutex poisoned".into()))?;
        let mut staged = self.last_pairing.lock()
            .map_err(|_| ProtocolError::Internal("pairing mutex poisoned".into()))?;
        let owner = active.as_ref().map(|p| p.peer_key.as_str())
            .or_else(|| staged.as_ref().filter(|p| p.pending.is_some()).map(|p| p.peer_key.as_str()));
        if !administrative && owner.is_some_and(|owner| owner != peer_key) {
            return Err(ProtocolError::ContextMismatch("pairing belongs to another caller".into()));
        }
        *active = None;
        if staged.as_ref().is_some_and(|p| !p.acknowledged) {
            *staged = None;
        }
        Ok(())
    }

    /// Discard only the attempt owned by a closing connection, never a newer one.
    pub fn cancel_pairing_attempt(&self, session_id: &Id) {
        if let Ok(mut active) = self.pairing.lock() {
            if active.as_ref().is_some_and(|p| p.session_id == *session_id) {
                *active = None;
            }
            self.discard_pairing_result(session_id);
        }
    }

    /// Commit only after the device has confirmed the exact pairing session.
    pub fn acknowledge_pairing(&self, session_id: &Id) -> Result<()> {
        let mut guard = self.last_pairing.lock()
            .map_err(|_| ProtocolError::Internal("pairing mutex poisoned".into()))?;
        let completed = guard.as_mut().ok_or(ProtocolError::NotPaired)?;
        if completed.session_id != *session_id {
            return Err(ProtocolError::ContextMismatch(
                "PAIRING_CONFIRMED does not match the completed session".into(),
            ));
        }
        let now = rba_protocol::unix_now();
        if completed.expires_at <= now {
            completed.pending = None;
            return Err(ProtocolError::Expired);
        }
        let enrollment = completed.pending.take().ok_or(ProtocolError::NotPaired)?;
        let policy = DevicePolicy::for_user(enrollment.owner.clone());
        let revoked = self.registry.lock()
            .map_err(|_| ProtocolError::Internal("registry mutex poisoned".into()))?
            .commit_enrollment(&enrollment.submit, &enrollment.cleanup_tokens, now, &enrollment.token_hash, &policy)?;
        for id in revoked {
            self.audit.write(&Event {
                kind: "pairing_cleanup",
                device_id: Some(id.to_hex()),
                ..Event::new("pairing_cleanup")
            }.success());
        }
        completed.acknowledged = true;
        self.audit.write(&Event {
            kind: "paired",
            device_id: Some(enrollment.submit.device_id.to_hex()),
            device_name: Some(enrollment.submit.device_name),
            username: Some(enrollment.owner),
            detail: Some("explicit basic enrollment grant".into()),
            ..Event::new("paired")
        }.success());
        Ok(())
    }

    /// Discard an unfinished enrollment if its result connection closes.
    pub fn discard_pairing_result(&self, session_id: &Id) {
        if let Ok(mut guard) = self.last_pairing.lock() {
            if guard.as_ref().is_some_and(|p| p.session_id == *session_id && !p.acknowledged) {
                *guard = None;
            }
        }
    }

    /// Whether the device has acknowledged the last completed pairing, for the
    /// local principal that opened it. `None` means no completion is pending for
    /// this caller.
    pub fn pairing_acknowledged_by(&self, peer_key: &str) -> Option<bool> {
        self.last_pairing
            .lock()
            .ok()?
            .as_ref()
            .filter(|p| p.peer_key == peer_key && (p.acknowledged || (p.pending.is_some() && p.expires_at > rba_protocol::unix_now())))
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

    /// The code is never compared or transmitted. The host waits for the
    /// device share, obtains the local password once, and requires a valid
    /// reciprocal confirmation on this connection before staging trust.
    pub async fn drive_pairing(
        self: &Arc<Self>, session_id: Id, tx: &mpsc::UnboundedSender<Frame>,
        resp_rx: oneshot::Receiver<PairingSubmit>, proof_rx: oneshot::Receiver<PairingProof>,
        certificate_sha256: [u8; 32], timeout_secs: u64,
    ) -> Result<PairingResult> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        tx.send(self.pairing_start_frame(session_id, rba_protocol::unix_now())?)
            .map_err(|_| ProtocolError::NotPaired)?;
        let submit = tokio::time::timeout_at(deadline, resp_rx).await.map_err(|_| ProtocolError::Expired)?
            .map_err(|_| ProtocolError::NotPaired)?;
        if submit.session_id != session_id { return Err(ProtocolError::NotPaired); }
        {
            let mut g = self.pairing.lock().map_err(|_| ProtocolError::Internal("poisoned".into()))?;
            let a = g.as_mut().filter(|a| a.session_id == session_id && a.connection_claimed).ok_or(ProtocolError::NotPaired)?;
            if !a.confirmed.load(Ordering::SeqCst) { a.phase = PairingPhase::AwaitingConfirmation; }
        }
        let (password, context) = loop {
            let notify = {
                let mut g = self.pairing.lock().map_err(|_| ProtocolError::Internal("poisoned".into()))?;
                let a = g.as_mut().filter(|a| a.session_id == session_id).ok_or(ProtocolError::NotPaired)?;
                if a.expires_at <= rba_protocol::unix_now() { return Err(ProtocolError::Expired); }
                if a.confirmed.load(Ordering::SeqCst) {
                    let password = a.code.take().ok_or(ProtocolError::NotPaired)?;
                    let context = rba_enrollment::Context {
                        session_id: session_id.0, host_id: self.host.host_id.0, device_id: submit.device_id.0,
                        host_public_key: *self.host.public_key().as_bytes(), device_public_key: *submit.device_pubkey.as_bytes(),
                        host_certificate_sha256: certificate_sha256, expires_at: a.expires_at,
                        code_entry: match a.code_entry { CodeEntry::Device => rba_enrollment::CodeEntry::DeviceTypes, CodeEntry::Host => rba_enrollment::CodeEntry::HostTypes },
                    };
                    break (password, context);
                }
                Arc::clone(&a.notify)
            };
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() { return Err(ProtocolError::Expired); }
            let _ = tokio::time::timeout(remaining.min(std::time::Duration::from_millis(250)), notify.notified()).await;
        };
        let (host_share, exchange) = {
            let mut rng = rand_core_10::UnwrapErr(getrandom_04::SysRng);
            rba_enrollment::start_host(password, &context, &mut rng).map_err(enrollment_error)?
        };
        let unconfirmed = exchange.finish(&submit.share).map_err(enrollment_error)?;
        let challenge = PairingChallenge { session_id, share: host_share.try_into().map_err(|_| ProtocolError::SignatureInvalid)?,
            confirmation: unconfirmed.confirmation().try_into().map_err(|_| ProtocolError::SignatureInvalid)? };
        tx.send(Message::PairingChallenge(challenge).to_frame()).map_err(|_| ProtocolError::NotPaired)?;
        let proof = tokio::time::timeout_at(deadline, proof_rx).await.map_err(|_| ProtocolError::Expired)?
            .map_err(|_| ProtocolError::NotPaired)?;
        if proof.session_id != session_id { return Err(ProtocolError::NotPaired); }
        let _confirmed = unconfirmed.verify_peer(&proof.confirmation).map_err(enrollment_error)?;
        self.stage_enrollment(submit, proof.cleanup_tokens)
    }

    /// Stage only after the private PAKE path has verified the peer's confirmation.
    fn stage_enrollment(&self, submit: PairingSubmit, cleanup_tokens: Vec<[u8; 32]>) -> Result<PairingResult> {
        let mut pairing = self.pairing.lock().map_err(|_| ProtocolError::Internal("pairing mutex poisoned".into()))?;
        if !pairing.as_ref().is_some_and(|p| p.session_id == submit.session_id && p.connection_claimed) {
            return Err(ProtocolError::NotPaired);
        }
        let active = pairing.take().ok_or(ProtocolError::NotPaired)?;
        if active.expires_at <= rba_protocol::unix_now() || active.phase != PairingPhase::Confirmed { return Err(ProtocolError::Expired); }
        let session_id = active.session_id;
        let revocation_token: [u8; 32] = rba_protocol::crypto::random_array()?;
        let token_hash = hex::encode(rba_protocol::crypto::sha256(&revocation_token));
        *self.last_pairing.lock().map_err(|_| ProtocolError::Internal("pairing completion mutex poisoned".into()))? = Some(CompletedPairing {
            session_id, peer_key: active.peer_key, expires_at: active.expires_at,
            pending: Some(PendingEnrollment { submit, cleanup_tokens, token_hash, owner: active.owner }), acknowledged: false,
        });
        Ok(PairingResult { session_id, status: 0, revocation_token: Some(revocation_token) })
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
    fn pairing_start_frame(&self, session_id: Id, now: u64) -> Result<Frame> {
        let guard = self
            .pairing
            .lock()
            .map_err(|_| ProtocolError::Internal("poisoned".into()))?;
        let active = guard.as_ref().filter(|p| p.session_id == session_id && p.connection_claimed)
            .ok_or(ProtocolError::NotPaired)?;
        if active.expires_at <= now {
            return Err(ProtocolError::Expired);
        }
        let start = PairingStart {
            session_id: active.session_id,
            host_id: self.host.host_id,
            host_pubkey: self.host.public_key(),
            host_key_id: self.host.public_key().key_id_hex(),
            code_entry: active.code_entry,
            expires_at: active.expires_at,
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

        // Persist all admission dimensions together before exposing a challenge.
        // Sample the clock under the lock so concurrently arriving requests
        // cannot appear to roll time backwards.
        let now = {
            let mut admission = self.admission.lock().map_err(|_| {
                ProtocolError::Internal("admission mutex poisoned".into())
            })?;
            let now = rba_protocol::unix_now();
            if let Err(e) =
                admission.authenticate(&username, &device_id.to_hex(), handle.transport, now)
            {
                self.audit.write(
                    &Event::new("auth_admission_denied")
                        .denied(e.code().as_str())
                        .device_id(device_id.to_hex())
                        .username(&username)
                        .purpose(&purpose)
                        .service(&service)
                        .operation(&operation)
                        .transport(handle.transport.as_str())
                        .local_uid(local_uid),
                );
                return Err(e);
            }
            now
        };

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
        let pairing = self.pairing_status_for(peer_key, viewer.is_none()).ok().flatten();
        serde_json::json!({
            "host_id": self.host.host_id.to_hex(),
            "host_key_id": self.host.public_key().key_id_hex(),
            "host_name": self.host_name,
            "paired_devices": paired_devices,
            "connected_devices": connected_devices,
            "pairing": pairing,
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
        let engine = Engine::new(host, registry, AuditLog::null(), "test-host".into());
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
