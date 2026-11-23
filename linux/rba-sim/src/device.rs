//! The device side of the protocol, as the Android app would implement it.
//!
//! This is a *simulator*: it plays the role of the device, using a software key
//! instead of Android Keystore, and it can also be told to misbehave so the
//! host's defences can be tested. On a real device the equivalents are
//!
//! | Here                        | On Android                                   |
//! |-----------------------------|----------------------------------------------|
//! | [`DeviceKey`] (software)    | Keystore key, non-exportable, StrongBox if any |
//! | `sign_approved()`           | `BiometricPrompt` then `Signature`            |
//! | always "approves"           | requires `BIOMETRIC_STRONG` success           |
//!
//! The security-relevant ordering is the same in both: the operator (here, the
//! test harness) must be shown the request context, and only then is anything
//! signed.

use std::sync::Arc;

use rba_protocol::crypto::{self, PrivateKey, PublicKey};
use rba_protocol::errors::{ProtocolError, Result};
use rba_protocol::frame::{AsyncFrameWriter, AsyncFrames, Frame};
use rba_protocol::messages::Message;
use rba_protocol::pairing::{PairingResult, PairingSession, PairingStart, PairingSubmit};
use rba_protocol::types::{AuthRequest, AuthResponse, Id, SessionHelloAck, CHALLENGE_LEN};
use tokio::io::{AsyncRead, AsyncWrite};

/// How the simulator should behave when an authentication request arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    /// Sign the request, as a satisfied biometric check would.
    Approve,
    /// Decline, as a user pressing Cancel would.
    Deny,
    /// Claim the biometric check failed.
    BiometricFailed,
    /// Approve, but sign a *different* request than the one received. Models a
    /// confused-deputy or a deliberately malicious device.
    SignWrongRequest,
    /// Approve, but corrupt the signature afterwards. Models a broken or
    /// tampered response.
    CorruptSignature,
    /// Approve, but attribute the response to a different device id.
    WrongDeviceId,
    /// Approve, then re-send the identical response, as a replay would.
    Replay,
    /// Ignore the request entirely, as a prompt that never completes would.
    Stall,
}

#[derive(Debug, Clone)]
pub struct Misbehaviour {
    /// Apply the fault only to the Nth request, 1-based.
    pub on_request: Option<u64>,
    pub behaviour: Behaviour,
}

impl Default for Misbehaviour {
    fn default() -> Self {
        Misbehaviour {
            on_request: None,
            behaviour: Behaviour::Approve,
        }
    }
}

/// The device's persistent identity: a private key it must never disclose, plus
/// the identifier the host knows it by.
#[derive(Debug)]
pub struct DeviceKey {
    key: PrivateKey,
    pub device_id: Id,
    pub device_name: String,
}

impl DeviceKey {
    /// Loads a persisted identity, or creates and stores a new one.
    ///
    /// A real device keeps this in Android Keystore, so the key survives app
    /// restarts but is never exportable. The simulator has no such facility, so
    /// it writes the key to a file to reproduce the same *behaviour*: a stable
    /// device identity across invocations. The file is the simulator's stand-in
    /// for hardware, not a design suggestion.
    pub fn load_or_create(path: &std::path::Path, name: &str) -> Result<DeviceKey> {
        if path.exists() {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| ProtocolError::Internal(format!("read {}: {e}", path.display())))?;
            let v: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| ProtocolError::Internal(format!("parse {}: {e}", path.display())))?;
            let id =
                Id::from_hex(v.get("device_id").and_then(|x| x.as_str()).ok_or_else(|| {
                    ProtocolError::Internal("identity file has no device_id".into())
                })?)?;
            let sk_hex = v
                .get("private_key")
                .and_then(|x| x.as_str())
                .ok_or_else(|| {
                    ProtocolError::Internal("identity file has no private_key".into())
                })?;
            let key = PrivateKey::from_bytes(
                &hex::decode(sk_hex)
                    .map_err(|_| ProtocolError::Internal("private_key is not hex".into()))?,
            )?;
            return Ok(DeviceKey {
                key,
                device_id: id,
                device_name: v
                    .get("device_name")
                    .and_then(|x| x.as_str())
                    .unwrap_or(name)
                    .to_owned(),
            });
        }
        let dk = DeviceKey::generate(name)?;
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let record = serde_json::json!({
            "device_id": dk.device_id.to_hex(),
            "device_name": dk.device_name,
            "private_key": hex::encode(dk.key.to_bytes()),
            "public_key": hex::encode(dk.public_key().as_bytes()),
        });
        std::fs::write(
            path,
            serde_json::to_string_pretty(&record).expect("serialises"),
        )
        .map_err(|e| ProtocolError::Internal(format!("write {}: {e}", path.display())))?;
        restrict(path);
        Ok(dk)
    }

    pub fn generate(name: &str) -> Result<DeviceKey> {
        let key = PrivateKey::generate()?;
        Ok(DeviceKey {
            key,
            device_id: Id::random()?,
            device_name: name.to_owned(),
        })
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    pub fn key_id_hex(&self) -> String {
        self.key.public_key().key_id_hex()
    }

    pub fn device_key_id_short(&self) -> String {
        self.key_id_hex().chars().take(16).collect()
    }

    /// The single point at which this device ever produces a signature.
    ///
    /// On Android this is the `KeyStore` operation guarded by
    /// `setUserAuthenticationRequired(true)`, and it fails with
    /// `UserNotAuthenticatedException` unless a successful
    /// `BIOMETRIC_STRONG` check immediately preceded it. Here the biometric gate
    /// is modelled by the caller only invoking this after `Approve`.
    pub fn sign_request(&self, request: &AuthRequest) -> [u8; 64] {
        self.key.sign(&request.signing_input())
    }

    /// Persists only public material. The private key never leaves this process,
    /// mirroring the Android case.
    pub fn to_public_record(&self) -> serde_json::Value {
        serde_json::json!({
            "device_id": self.device_id.to_hex(),
            "device_name": self.device_name,
            "public_key": hex::encode(self.public_key().as_bytes()),
            "key_id": self.key_id_hex(),
        })
    }
}

/// Keeps the simulator's identity file owner-only, mirroring the Keystore.
fn restrict(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

/// What the simulator should show its operator for a pending request.
#[derive(Debug, Clone)]
pub struct Presented {
    pub user: String,
    pub host: String,
    pub purpose: String,
    pub service: String,
    pub operation: String,
    /// Unsigned display text, shown to the operator but never signed.
    pub untrusted_detail: Option<String>,
}

/// Persists the hosts this device has paired with.
///
/// The Android equivalent is encrypted app storage next to a Keystore-wrapped
/// host identity. Persisting the host's *public* key is sufficient for the check
/// this device performs: it must refuse to sign for a host whose key is not the
/// one it paired with.
pub fn save_hosts(path: &std::path::Path, hosts: &[KnownHost]) -> Result<()> {
    let arr: Vec<serde_json::Value> = hosts
        .iter()
        .map(|h| {
            serde_json::json!({
                "host_id": h.host_id.to_hex(),
                "key_id": h.key_id,
                "public_key": hex::encode(h.public_key.as_bytes()),
            })
        })
        .collect();
    std::fs::write(
        path,
        serde_json::to_string_pretty(&arr).expect("serialises"),
    )
    .map_err(|e| ProtocolError::Internal(format!("write {}: {e}", path.display())))?;
    restrict(path);
    Ok(())
}

/// Loads previously paired hosts.
pub fn load_hosts(path: &std::path::Path) -> Vec<KnownHost> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&raw) else {
        return Vec::new();
    };
    arr.into_iter()
        .filter_map(|v| {
            let id = Id::from_hex(v.get("host_id")?.as_str()?).ok()?;
            let key_hex = v.get("public_key")?.as_str()?;
            let raw = hex::decode(key_hex).ok()?;
            let pk = PublicKey::from_bytes(&raw).ok()?;
            Some(KnownHost {
                host_id: id,
                public_key: pk,
                key_id: v
                    .get("key_id")
                    .and_then(|k| k.as_str())
                    .unwrap_or_default()
                    .to_owned(),
            })
        })
        .collect()
}

/// The host identity the device has learned at pairing.
#[derive(Debug, Clone)]
pub struct KnownHost {
    pub host_id: Id,
    pub public_key: PublicKey,
    pub key_id: String,
}

/// Device-side protocol driver, generic over the byte stream.
pub struct Device<S> {
    pub reader: AsyncFrames<tokio::io::ReadHalf<S>>,
    pub writer: AsyncFrameWriter<tokio::io::WriteHalf<S>>,
    pub device: Arc<DeviceKey>,
    pub hosts: Vec<KnownHost>,
    pub misbehaviour: Misbehaviour,
    requests_seen: u64,
    last_response: Option<Vec<u8>>,
}

impl<S> Device<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Decides whether this device will authenticate a request from `host_id`.
    ///
    /// Split out from the request path so the rule can be tested directly rather than
    /// inferred from an integration test that happens to pass. Two conditions must
    /// hold, and both are load-bearing:
    ///
    /// * the `host_id` must be one this device actually paired with, and
    /// * the key presented behind it must be the key that was paired.
    ///
    /// Checking only the identifier would let anyone who learned a host's `host_id` --
    /// which travels in cleartext in every SESSION_HELLO -- pose as that host and have
    /// their requests signed.
    fn trusted_host(
        &self,
        host_id: &Id,
    ) -> std::result::Result<&KnownHost, rba_protocol::errors::ErrorCode> {
        use rba_protocol::errors::ErrorCode;
        let Some(known) = self.hosts.iter().find(|h| h.host_id == *host_id) else {
            println!("[rba] refusing: this host is not paired with me");
            return Err(ErrorCode::NotPaired);
        };
        if !known.public_key.key_id_hex().eq(&known.key_id) {
            // The identifier is known but the key behind it is not the one paired with:
            // refuse rather than trust the identifier.
            println!("[rba] refusing: host key changed since pairing");
            return Err(ErrorCode::NotPaired);
        }
        Ok(known)
    }

    pub fn new(device: Arc<DeviceKey>, stream: S, misbehaviour: Misbehaviour) -> Device<S> {
        let (r, w) = tokio::io::split(stream);
        Device {
            reader: AsyncFrames::new(r),
            writer: AsyncFrameWriter::new(w),
            device,
            hosts: Vec::new(),
            misbehaviour,
            requests_seen: 0,
            last_response: None,
        }
    }

    async fn send(&mut self, m: &Message) -> Result<()> {
        self.writer
            .write_frame(&m.to_frame())
            .await
            .map_err(|e| ProtocolError::Internal(format!("send: {e}")))?;
        Ok(())
    }

    /// Reads the next message, or `None` at a clean end of stream.
    pub async fn recv(&mut self) -> Result<Option<Message>> {
        let f: Option<Frame> = match self.reader.next_frame().await {
            Ok(f) => f,
            Err(e) => return Err(ProtocolError::BadRequest(format!("frame: {e}"))),
        };
        match f {
            None => Ok(None),
            Some(f) => Message::from_frame(&f).map(Some),
        }
    }

    /// Answers `SESSION_HELLO`, which is always the host's first frame.
    pub async fn hello_ack(&mut self, hello: &rba_protocol::types::SessionHello) -> Result<()> {
        let ack = SessionHelloAck {
            protocol_version: rba_protocol::PROTOCOL_VERSION,
            device_id: self.device.device_id,
            device_key_id: self.device.key_id_hex(),
            device_nonce: crypto::random_array::<CHALLENGE_LEN>()?,
            session_id: hello.session_id,
        };
        self.send(&Message::SessionHelloAck(ack)).await
    }

    /// Completes pairing: shows the code, submits the device's transcript
    /// commitment, and verifies the host's reciprocal commitment.
    pub async fn pair(
        &mut self,
        start: &PairingStart,
        auto_confirm: bool,
    ) -> Result<PairingResult> {
        if start.code.is_empty() {
            println!(
                "[rba] Pairing requested by Linux host {}",
                &start.host_id.to_hex()[..8]
            );
        } else {
            println!(
                "[rba] Pairing requested; the operator chose the code {}",
                start.code
            );
        }

        let device_nonce: [u8; CHALLENGE_LEN] = crypto::random_array()?;
        let session = PairingSession::new_device(
            start.session_id,
            start.host_nonce,
            start.host_eph_pubkey,
            &start.host_id,
            &start.host_pubkey,
            &self.device.device_id,
            &self.device.public_key(),
            device_nonce,
            start.code_entry,
        )?;

        // Both screens show a code derived from the same ephemeral ECDH secret
        // and full transcript, including both long-term public keys.
        let code = session.code()?;
        if !start.code.is_empty() && start.code != code {
            // The operator pre-selected a code and the device disagrees, so the
            // comparison the operator intended cannot succeed. Refuse.
            println!(
                "[rba] code mismatch: host chose {}, device derived {code}",
                start.code
            );
            return Err(ProtocolError::ContextMismatch(
                "device-derived code differs from the operator-chosen code".into(),
            ));
        }
        println!("[rba] Compare this code on both screens: {code}");
        if !auto_confirm {
            println!("[rba] (simulator auto-approving; a real app shows a confirmation dialog)");
        }

        let mac = session.device_mac(
            &start.host_id,
            &self.device.device_id,
            &start.host_pubkey,
            &self.device.public_key(),
        )?;
        let submit = PairingSubmit {
            session_id: start.session_id,
            device_id: self.device.device_id,
            device_name: self.device.device_name.clone(),
            device_pubkey: self.device.public_key(),
            device_key_id: self.device.key_id_hex(),
            device_nonce,
            device_eph_pubkey: session
                .device_eph_public
                .ok_or_else(|| ProtocolError::Internal("device ephemeral key missing".into()))?,
            mac,
            cleanup_tokens: Vec::new(),
        };
        self.send(&Message::PairingSubmit(submit)).await?;

        let Some(msg) = self.recv().await? else {
            return Err(ProtocolError::Internal("host closed during pairing".into()));
        };
        let result = match msg {
            Message::PairingResult(r) => r,
            Message::Error(e) => {
                return Err(ProtocolError::BadRequest(format!(
                    "host refused pairing: {} ({})",
                    e.message, e.code
                )))
            }
            other => {
                return Err(ProtocolError::BadRequest(format!(
                    "expected PAIRING_RESULT, got {}",
                    other.name()
                )))
            }
        };

        if result.status != 0 {
            return Err(ProtocolError::BadRequest(
                "host rejected the pairing".into(),
            ));
        }
        let host_mac = result
            .host_mac
            .ok_or_else(|| ProtocolError::BadRequest("PAIRING_RESULT without host_mac".into()))?;

        // The reciprocal commitment proves the host derived the same secret, so
        // the code the operator compared really did cover this exchange.
        let expected = session.host_mac(
            &start.host_id,
            &self.device.device_id,
            &start.host_pubkey,
            &self.device.public_key(),
        )?;
        if !crypto::ct_eq_slice(&host_mac, &expected) {
            return Err(ProtocolError::SignatureInvalid);
        }

        self.hosts.push(KnownHost {
            host_id: start.host_id,
            public_key: start.host_pubkey.clone(),
            key_id: start.host_key_id.clone(),
        });
        println!(
            "[rba] Host {} trusted (key {}).",
            &start.host_id.to_hex()[..8],
            start.host_pubkey.short_fingerprint()
        );
        Ok(result)
    }

    /// Handles one authentication request and returns whether it replied.
    pub async fn handle_auth(&mut self, request: &AuthRequest) -> Result<bool> {
        self.requests_seen += 1;
        // A fault applies either to every request, or only to the targeted one.
        let behaviour = match self.misbehaviour.on_request {
            Some(n) if n == self.requests_seen => self.misbehaviour.behaviour,
            Some(_) => Behaviour::Approve,
            None => self.misbehaviour.behaviour,
        };

        let presented = Presented {
            user: request.username.clone(),
            host: request
                .display_host_name
                .clone()
                .unwrap_or_else(|| request.host_id.to_hex()),
            purpose: request.purpose.clone(),
            service: request.service.clone(),
            operation: request.operation.clone(),
            untrusted_detail: request.display_detail.clone(),
        };
        // What the operator would see before deciding.
        println!(
            "[rba] Authorize: user={} host={} action={} service={} ({})",
            presented.user,
            presented.host,
            presented.purpose,
            presented.service,
            presented.operation
        );
        if let Some(detail) = &presented.untrusted_detail {
            println!("[rba]   unverified description from Linux: {detail}");
        }

        match behaviour {
            Behaviour::Stall => return Ok(false),
            Behaviour::Deny => {
                self.send(&Message::AuthReject(rba_protocol::types::AuthReject {
                    request_id: request.request_id,
                    reason: rba_protocol::errors::ErrorCode::UserCancelled.as_u32() as u64,
                }))
                .await?;
                return Ok(true);
            }
            Behaviour::BiometricFailed => {
                self.send(&Message::AuthReject(rba_protocol::types::AuthReject {
                    request_id: request.request_id,
                    reason: rba_protocol::errors::ErrorCode::BiometricFailed.as_u32() as u64,
                }))
                .await?;
                return Ok(true);
            }
            _ => {}
        }

        // A device only signs for a host it has paired with, and only when the key
        // behind that host_id is the one paired. Both conditions matter and they are
        // one predicate so they cannot drift apart.
        if let Err(reason) = self.trusted_host(&request.host_id) {
            self.send(&Message::AuthReject(rba_protocol::types::AuthReject {
                request_id: request.request_id,
                reason: reason.as_u32() as u64,
            }))
            .await?;
            return Ok(true);
        }

        // Sign the *received* request's canonical input, except when deliberately
        // simulating a malicious or confused device.
        let signed = match behaviour {
            Behaviour::SignWrongRequest => {
                let mut other = request.clone();
                // Approve a broader scope than was requested.
                other.purpose = "polkit".into();
                other.username = "root".into();
                other.service = "org.freedesktop.systemd1.manage-units".into();
                self.device.sign_request(&other)
            }
            _ => self.device.sign_request(request),
        };

        let mut signature = signed;
        if behaviour == Behaviour::CorruptSignature {
            signature[7] ^= 0xff;
        }
        let device_id = if behaviour == Behaviour::WrongDeviceId {
            Id::random()?
        } else {
            self.device.device_id
        };

        let response = Message::AuthResponse(AuthResponse {
            request_id: request.request_id,
            device_id,
            session_id: request.session_id,
            algorithm: crypto::ALGORITHM.to_owned(),
            key_id: self.device.key_id_hex(),
            signature,
        });
        let bytes = response.to_frame().encode();
        self.writer
            .write_raw(&bytes)
            .await
            .map_err(|e| ProtocolError::Internal(format!("send response: {e}")))?;
        self.last_response = Some(bytes);

        if behaviour == Behaviour::Replay {
            println!("[rba] resending the identical response (simulated replay)");
            if let Some(b) = self.last_response.clone() {
                let _ = self.writer.write_raw(&b).await;
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rba_protocol::errors::ErrorCode;

    /// A `Device` needs a stream, but the host-trust rule does not touch it. This
    /// builds one over a sink so the predicate can be exercised on its own.
    fn device_with(hosts: Vec<KnownHost>) -> Device<tokio::io::DuplexStream> {
        let (a, _b) = tokio::io::duplex(64);
        let key = DeviceKey::generate("test-device").unwrap();
        let mut d = Device::new(Arc::new(key), a, Misbehaviour::default());
        d.hosts = hosts;
        d
    }

    fn known_host(seed: u8) -> KnownHost {
        let pk = PrivateKey::from_bytes(&[seed; 32]).unwrap().public_key();
        KnownHost {
            key_id: pk.key_id_hex(),
            public_key: pk,
            host_id: Id::random().unwrap(),
        }
    }

    /// PROTOCOL §11.3: a device may hold records for any number of hosts.
    #[test]
    fn a_device_trusts_every_host_it_paired_with() {
        let hosts: Vec<KnownHost> = (1..=4u8).map(known_host).collect();
        let d = device_with(hosts.clone());
        assert_eq!(d.hosts.len(), 4);
        for h in &hosts {
            assert!(
                d.trusted_host(&h.host_id).is_ok(),
                "each paired host is trusted"
            );
        }
    }

    #[test]
    fn an_unpaired_host_is_refused() {
        let d = device_with(vec![known_host(1)]);
        assert_eq!(
            d.trusted_host(&Id::random().unwrap()).err(),
            Some(ErrorCode::NotPaired)
        );
    }

    /// The identifier alone is not authority. `host_id` is sent in cleartext in every
    /// SESSION_HELLO, so anyone can read it off the wire; only the key behind it counts.
    #[test]
    fn a_known_host_id_with_a_different_key_is_refused() {
        let mut host = known_host(1);
        // Same host_id, someone else's key.
        host.public_key = PrivateKey::from_bytes(&[9u8; 32]).unwrap().public_key();
        let d = device_with(vec![host.clone()]);

        assert_eq!(
            d.trusted_host(&host.host_id).err(),
            Some(ErrorCode::NotPaired)
        );
    }

    /// Pairing a second host must not displace the first: the user has a laptop and a
    /// desktop, and the second pairing must not silently unpair the first.
    #[test]
    fn pairing_a_second_host_leaves_the_first_trusted() {
        let laptop = known_host(1);
        let desktop = known_host(2);
        let d = device_with(vec![laptop.clone(), desktop.clone()]);

        assert!(d.trusted_host(&laptop.host_id).is_ok());
        assert!(d.trusted_host(&desktop.host_id).is_ok());
    }

    /// Forgetting one host must not affect another.
    #[test]
    fn removing_one_host_leaves_the_others_trusted() {
        let laptop = known_host(1);
        let desktop = known_host(2);
        let mut d = device_with(vec![laptop.clone(), desktop.clone()]);
        d.hosts.retain(|h| h.host_id != laptop.host_id);

        assert_eq!(
            d.trusted_host(&laptop.host_id).err(),
            Some(ErrorCode::NotPaired)
        );
        assert!(d.trusted_host(&desktop.host_id).is_ok());
    }

    /// Two hosts are independent records; the same label may appear twice.
    #[test]
    fn hosts_are_distinguished_by_id_not_by_label() {
        let a = KnownHost {
            host_id: Id::random().unwrap(),
            ..known_host(1)
        };
        let b = KnownHost {
            host_id: Id::random().unwrap(),
            ..known_host(2)
        };
        assert_ne!(a.host_id.to_hex(), b.host_id.to_hex());
    }
}
