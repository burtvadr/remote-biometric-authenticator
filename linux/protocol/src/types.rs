//! Protocol data types: identifiers, the authentication request, and the
//! signing transcript (`PROTOCOL.md` §2, §8).

use crate::cbor::{self, Value};
use crate::crypto;
use crate::errors::{ProtocolError, Result};

pub const ID_LEN: usize = 16;
pub const CHALLENGE_LEN: usize = 32;
pub const MAX_NAME_LEN: usize = 64;

/// A 16-byte opaque identifier: `host_id`, `device_id`, `request_id` or
/// `session_id`.
///
/// Identifiers are random CSPRNG output. They are never derived from a
/// hostname, IP address, MAC address or service name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Id(pub [u8; ID_LEN]);

impl Id {
    pub fn random() -> Result<Id> {
        Ok(Id(crypto::random_array()?))
    }

    pub fn from_slice(b: &[u8]) -> Result<Id> {
        if b.len() != ID_LEN {
            return Err(ProtocolError::BadRequest(format!(
                "identifier must be {ID_LEN} bytes, got {}",
                b.len()
            )));
        }
        let mut a = [0u8; ID_LEN];
        a.copy_from_slice(b);
        Ok(Id(a))
    }

    pub fn from_hex(s: &str) -> Result<Id> {
        let v = hex::decode(s)
            .map_err(|_| ProtocolError::BadRequest("identifier is not valid hex".into()))?;
        Id::from_slice(&v)
    }

    pub fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Abbreviated form for operator-facing output: first 8 hex characters.
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A 32-byte authentication challenge. Single use (`PROTOCOL.md` §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Challenge(pub [u8; CHALLENGE_LEN]);

impl Challenge {
    pub fn random() -> Result<Challenge> {
        Ok(Challenge(crypto::random_array()?))
    }

    pub fn from_slice(b: &[u8]) -> Result<Challenge> {
        if b.len() != CHALLENGE_LEN {
            return Err(ProtocolError::BadRequest(format!(
                "challenge must be {CHALLENGE_LEN} bytes, got {}",
                b.len()
            )));
        }
        let mut a = [0u8; CHALLENGE_LEN];
        a.copy_from_slice(b);
        Ok(Challenge(a))
    }

    pub fn as_bytes(&self) -> &[u8; CHALLENGE_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

// ---------------------------------------------------------------------------
// Limits (PROTOCOL.md §11)
// ---------------------------------------------------------------------------

pub const PAIRING_TTL: u64 = 120;
pub const AUTH_REQUEST_TTL_DEFAULT: u64 = 60;
pub const AUTH_REQUEST_TTL_MAX: u64 = 300;
pub const MAX_NONCE_AGE: u64 = 600;
pub const CLOCK_SKEW: u64 = 30;
pub const CLOCK_SKEW_STRICT: u64 = 10;
pub const PAIRING_CODE_DIGITS: usize = 6;
pub const RATE_PAIRING: u32 = 5;
pub const RATE_PAIRING_WINDOW: u64 = 300;
pub const RATE_AUTH: u32 = 30;
pub const RATE_AUTH_WINDOW: u64 = 60;
pub const RATE_BLE_AUTH: u32 = 15;
pub const RATE_BLE_AUTH_WINDOW: u64 = 120;
/// Shared prompt reservation ceiling per account and per device, across transports.
/// This is intentionally stricter than the transport ceilings (SEC-003).
pub const RATE_AUTH_PROMPT: u32 = 3;
pub const RATE_AUTH_PROMPT_WINDOW: u64 = 60;

/// Which freshness window applies. BLE is slower, so it is given a tighter
/// window to compensate for reduced transport reliability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Wifi,
    Ble,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Wifi => "wifi",
            Transport::Ble => "ble",
        }
    }

    pub fn rate_limit(self) -> (u32, u64) {
        match self {
            Transport::Wifi => (RATE_AUTH, RATE_AUTH_WINDOW),
            Transport::Ble => (RATE_BLE_AUTH, RATE_BLE_AUTH_WINDOW),
        }
    }
}

// ---------------------------------------------------------------------------
// Authentication request
// ---------------------------------------------------------------------------

/// The exact set of signed field names. This is the authorization scope: a
/// change here changes what the device has actually approved.
pub const SIGNED_FIELDS: [&str; 10] = [
    "challenge",
    "device_id",
    "expires_at",
    "host_id",
    "issued_at",
    "operation",
    "purpose",
    "request_id",
    "service",
    "username",
];

/// What the device is being asked to approve.
///
/// The ten *signed* fields are the authorization scope. `display_*` fields are
/// unsigned prose shown to the operator and MUST NOT influence the signature
/// (`PROTOCOL.md` §8.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub request_id: Id,
    pub host_id: Id,
    pub device_id: Id,
    pub username: String,
    pub purpose: String,
    pub service: String,
    pub operation: String,
    pub challenge: Challenge,
    pub issued_at: u64,
    pub expires_at: u64,
    // Unsigned / transport-scoped.
    pub session_id: Id,
    pub display_host_name: Option<String>,
    pub display_detail: Option<String>,
}

fn check_name(field: &str, v: &str) -> Result<()> {
    if v.is_empty() {
        return Err(ProtocolError::BadRequest(format!(
            "{field} must not be empty"
        )));
    }
    if v.chars().count() > MAX_NAME_LEN {
        return Err(ProtocolError::BadRequest(format!(
            "{field} exceeds {MAX_NAME_LEN} characters"
        )));
    }
    if v.contains('\0') {
        return Err(ProtocolError::BadRequest(format!("{field} contains NUL")));
    }
    Ok(())
}

impl AuthRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: Id,
        host_id: Id,
        device_id: Id,
        username: String,
        purpose: String,
        service: String,
        operation: String,
        challenge: Challenge,
        issued_at: u64,
        expires_at: u64,
        session_id: Id,
    ) -> Result<AuthRequest> {
        check_name("username", &username)?;
        check_name("purpose", &purpose)?;
        check_name("service", &service)?;
        check_name("operation", &operation)?;
        let ttl = expires_at
            .checked_sub(issued_at)
            .ok_or_else(|| ProtocolError::BadRequest("expires_at precedes issued_at".into()))?;
        if ttl > AUTH_REQUEST_TTL_MAX {
            return Err(ProtocolError::BadRequest(format!(
                "ttl {ttl}s exceeds maximum {AUTH_REQUEST_TTL_MAX}s"
            )));
        }
        Ok(AuthRequest {
            request_id,
            host_id,
            device_id,
            username,
            purpose,
            service,
            operation,
            challenge,
            issued_at,
            expires_at,
            session_id,
            display_host_name: None,
            display_detail: None,
        })
    }

    pub fn with_display(mut self, host: Option<String>, detail: Option<String>) -> Self {
        self.display_host_name = host;
        self.display_detail = detail;
        self
    }

    /// The canonical CBOR map of the ten signed fields.
    ///
    /// Exactly these fields are signed. Adding a field here changes the signed
    /// scope and requires a protocol version bump.
    pub fn signed_core(&self) -> Value {
        Value::map([
            ("challenge", Value::Bytes(self.challenge.0.to_vec())),
            ("device_id", Value::Bytes(self.device_id.0.to_vec())),
            ("expires_at", Value::Uint(self.expires_at)),
            ("host_id", Value::Bytes(self.host_id.0.to_vec())),
            ("issued_at", Value::Uint(self.issued_at)),
            ("operation", Value::text(self.operation.clone())),
            ("purpose", Value::text(self.purpose.clone())),
            ("request_id", Value::Bytes(self.request_id.0.to_vec())),
            ("service", Value::text(self.service.clone())),
            ("username", Value::text(self.username.clone())),
        ])
    }

    /// The exact bytes that get signed (`PROTOCOL.md` §8.2):
    ///
    /// ```text
    /// "RBA_AUTH_V1" || 0x00 || 0x01 || canonical_cbor(core_map)
    /// ```
    pub fn signing_input(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(crypto::DOMAIN_SIGNING.len() + 2 + 256);
        v.extend_from_slice(crypto::DOMAIN_SIGNING);
        v.push(0x00);
        v.push(crate::frame::PROTOCOL_VERSION);
        v.extend_from_slice(&cbor::encode(&self.signed_core()));
        v
    }

    /// SHA-256 of the signing input. Recorded in the cross-language test
    /// vectors so both implementations can be compared without reproducing the
    /// ECDSA operation.
    pub fn signing_input_digest(&self) -> [u8; 32] {
        crypto::sha256(&self.signing_input())
    }

    // -- wire format ---------------------------------------------------------

    pub fn to_payload(&self) -> Vec<u8> {
        let mut entries: Vec<(&str, Value)> = vec![
            ("challenge", Value::Bytes(self.challenge.0.to_vec())),
            ("device_id", Value::Bytes(self.device_id.0.to_vec())),
            ("expires_at", Value::Uint(self.expires_at)),
            ("host_id", Value::Bytes(self.host_id.0.to_vec())),
            ("issued_at", Value::Uint(self.issued_at)),
            ("operation", Value::text(self.operation.clone())),
            ("purpose", Value::text(self.purpose.clone())),
            ("request_id", Value::Bytes(self.request_id.0.to_vec())),
            ("service", Value::text(self.service.clone())),
            ("session_id", Value::Bytes(self.session_id.0.to_vec())),
            ("username", Value::text(self.username.clone())),
        ];
        if let Some(h) = &self.display_host_name {
            entries.push(("display_host_name", Value::text(h.clone())));
        }
        if let Some(d) = &self.display_detail {
            entries.push(("display_detail", Value::text(d.clone())));
        }
        cbor::encode(&Value::map(entries))
    }

    pub fn from_payload(payload: &[u8]) -> Result<AuthRequest> {
        let v = cbor::decode_canonical(payload)
            .map_err(|e| ProtocolError::BadRequest(format!("auth_request payload: {e}")))?;

        let req = AuthRequest {
            request_id: req_id(&v, "request_id")?,
            host_id: req_id(&v, "host_id")?,
            device_id: req_id(&v, "device_id")?,
            username: req_text(&v, "username")?,
            purpose: req_text(&v, "purpose")?,
            service: req_text(&v, "service")?,
            operation: req_text(&v, "operation")?,
            challenge: Challenge::from_slice(req_bytes(&v, "challenge")?)?,
            issued_at: req_uint(&v, "issued_at")?,
            expires_at: req_uint(&v, "expires_at")?,
            session_id: req_id(&v, "session_id")?,
            display_host_name: opt_text(&v, "display_host_name")?,
            display_detail: opt_text(&v, "display_detail")?,
        };

        check_name("username", &req.username)?;
        check_name("purpose", &req.purpose)?;
        check_name("service", &req.service)?;
        check_name("operation", &req.operation)?;
        if let Some(d) = &req.display_detail {
            if d.chars().count() > 512 {
                return Err(ProtocolError::BadRequest(
                    "display_detail is too long".into(),
                ));
            }
        }
        // Re-apply the TTL ceiling to decoded values too: a peer could send a
        // long-lived request that this side would never have produced.
        if req.expires_at < req.issued_at {
            return Err(ProtocolError::BadRequest(
                "expires_at precedes issued_at".into(),
            ));
        }
        if req.expires_at - req.issued_at > AUTH_REQUEST_TTL_MAX {
            return Err(ProtocolError::BadRequest(format!(
                "ttl exceeds {AUTH_REQUEST_TTL_MAX}s"
            )));
        }
        // Guard against a decoded request silently dropping a signed field:
        // every key in the signed scope must be present and re-encodable.
        let encoded = req.signed_core();
        for k in SIGNED_FIELDS {
            if encoded.get(k).is_none() {
                return Err(ProtocolError::BadRequest(format!(
                    "signed field {k} missing"
                )));
            }
        }
        Ok(req)
    }
}

pub(crate) fn req_bytes<'a>(v: &'a Value, k: &str) -> Result<&'a [u8]> {
    v.get(k)
        .and_then(|x| x.as_bytes())
        .ok_or_else(|| ProtocolError::BadRequest(format!("missing or non-bytes field {k}")))
}

pub(crate) fn req_text(v: &Value, k: &str) -> Result<String> {
    v.get(k)
        .and_then(|x| x.as_text())
        .map(|s| s.to_owned())
        .ok_or_else(|| ProtocolError::BadRequest(format!("missing or non-text field {k}")))
}

pub(crate) fn opt_text(v: &Value, k: &str) -> Result<Option<String>> {
    match v.get(k) {
        None => Ok(None),
        Some(Value::Text(s)) => Ok(Some(s.clone())),
        Some(_) => Err(ProtocolError::BadRequest(format!("field {k} must be text"))),
    }
}

pub(crate) fn req_uint(v: &Value, k: &str) -> Result<u64> {
    v.get(k)
        .and_then(|x| x.as_uint())
        .ok_or_else(|| ProtocolError::BadRequest(format!("missing or non-uint field {k}")))
}

pub(crate) fn req_id(v: &Value, k: &str) -> Result<Id> {
    Id::from_slice(req_bytes(v, k)?)
}

// ---------------------------------------------------------------------------
// Session hello
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHello {
    pub protocol_version: u64,
    pub host_id: Id,
    pub host_key_id: String,
    pub host_nonce: [u8; CHALLENGE_LEN],
    pub session_id: Id,
    pub transports: Vec<String>,
}

/// The protocol has one supported wire version, not a negotiation range.
fn validate_wire_version(version: u64) -> Result<()> {
    if version != crate::PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(u8::try_from(version).unwrap_or(u8::MAX)));
    }
    Ok(())
}

impl SessionHello {
    pub fn to_payload(&self) -> Vec<u8> {
        cbor::encode(&Value::map([
            ("host_id", Value::Bytes(self.host_id.0.to_vec())),
            ("host_key_id", Value::text(self.host_key_id.clone())),
            ("host_nonce", Value::Bytes(self.host_nonce.to_vec())),
            ("protocol_version", Value::Uint(self.protocol_version)),
            ("session_id", Value::Bytes(self.session_id.0.to_vec())),
            (
                "transports",
                Value::Array(
                    self.transports
                        .iter()
                        .map(|t| Value::text(t.clone()))
                        .collect(),
                ),
            ),
        ]))
    }

    pub fn from_payload(payload: &[u8]) -> Result<SessionHello> {
        let v = cbor::decode_canonical(payload)
            .map_err(|e| ProtocolError::BadRequest(format!("session_hello payload: {e}")))?;
        let transports = match v.get("transports") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|i| i.as_text().map(|s| s.to_owned()))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| ProtocolError::BadRequest("transports must be text array".into()))?,
            _ => return Err(ProtocolError::BadRequest("missing transports array".into())),
        };
        let h = SessionHello {
            protocol_version: req_uint(&v, "protocol_version")?,
            host_id: req_id(&v, "host_id")?,
            host_key_id: req_text(&v, "host_key_id")?,
            host_nonce: {
                let b = req_bytes(&v, "host_nonce")?;
                if b.len() != CHALLENGE_LEN {
                    return Err(ProtocolError::BadRequest(
                        "host_nonce must be 32 bytes".into(),
                    ));
                }
                let mut a = [0u8; CHALLENGE_LEN];
                a.copy_from_slice(b);
                a
            },
            session_id: req_id(&v, "session_id")?,
            transports,
        };
        validate_wire_version(h.protocol_version)?;
        if h.host_key_id.len() != 64
            || !h
                .host_key_id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(ProtocolError::BadRequest(
                "host_key_id must be 64 lowercase hex chars".into(),
            ));
        }
        Ok(h)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHelloAck {
    pub protocol_version: u64,
    pub device_id: Id,
    pub device_key_id: String,
    pub device_nonce: [u8; CHALLENGE_LEN],
    pub session_id: Id,
}

impl SessionHelloAck {
    pub fn to_payload(&self) -> Vec<u8> {
        cbor::encode(&Value::map([
            ("device_id", Value::Bytes(self.device_id.0.to_vec())),
            ("device_key_id", Value::text(self.device_key_id.clone())),
            ("device_nonce", Value::Bytes(self.device_nonce.to_vec())),
            ("protocol_version", Value::Uint(self.protocol_version)),
            ("session_id", Value::Bytes(self.session_id.0.to_vec())),
        ]))
    }

    pub fn from_payload(payload: &[u8]) -> Result<SessionHelloAck> {
        let v = cbor::decode_canonical(payload)
            .map_err(|e| ProtocolError::BadRequest(format!("session_hello_ack payload: {e}")))?;
        let nb = req_bytes(&v, "device_nonce")?;
        if nb.len() != CHALLENGE_LEN {
            return Err(ProtocolError::BadRequest(
                "device_nonce must be 32 bytes".into(),
            ));
        }
        let mut nonce = [0u8; CHALLENGE_LEN];
        nonce.copy_from_slice(nb);
        let protocol_version = req_uint(&v, "protocol_version")?;
        validate_wire_version(protocol_version)?;
        Ok(SessionHelloAck {
            protocol_version,
            device_id: req_id(&v, "device_id")?,
            device_key_id: req_text(&v, "device_key_id")?,
            device_nonce: nonce,
            session_id: req_id(&v, "session_id")?,
        })
    }
}

// ---------------------------------------------------------------------------
// Auth response / reject / error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub request_id: Id,
    pub device_id: Id,
    pub session_id: Id,
    pub algorithm: String,
    pub key_id: String,
    pub signature: [u8; crypto::SIG_LEN],
}

impl AuthResponse {
    pub fn to_payload(&self) -> Vec<u8> {
        cbor::encode(&Value::map([
            ("algorithm", Value::text(self.algorithm.clone())),
            ("device_id", Value::Bytes(self.device_id.0.to_vec())),
            ("key_id", Value::text(self.key_id.clone())),
            ("request_id", Value::Bytes(self.request_id.0.to_vec())),
            ("session_id", Value::Bytes(self.session_id.0.to_vec())),
            ("signature", Value::Bytes(self.signature.to_vec())),
        ]))
    }

    pub fn from_payload(payload: &[u8]) -> Result<AuthResponse> {
        let v = cbor::decode_canonical(payload)
            .map_err(|e| ProtocolError::BadRequest(format!("auth_response payload: {e}")))?;
        let sb = req_bytes(&v, "signature")?;
        if sb.len() != crypto::SIG_LEN {
            return Err(ProtocolError::SignatureInvalid);
        }
        let mut sig = [0u8; crypto::SIG_LEN];
        sig.copy_from_slice(sb);
        let r = AuthResponse {
            request_id: req_id(&v, "request_id")?,
            device_id: req_id(&v, "device_id")?,
            session_id: req_id(&v, "session_id")?,
            algorithm: req_text(&v, "algorithm")?,
            key_id: req_text(&v, "key_id")?,
            signature: sig,
        };
        if r.algorithm != crypto::ALGORITHM {
            return Err(ProtocolError::BadRequest(format!(
                "unsupported algorithm {}",
                r.algorithm
            )));
        }
        Ok(r)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthReject {
    pub request_id: Id,
    pub reason: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMsg {
    pub code: u64,
    pub message: String,
    pub request_id: Option<Id>,
}

impl ErrorMsg {
    pub fn to_payload(&self) -> Vec<u8> {
        let mut e: Vec<(&str, Value)> = vec![
            ("code", Value::Uint(self.code)),
            ("message", Value::text(self.message.clone())),
        ];
        if let Some(r) = &self.request_id {
            e.push(("request_id", Value::Bytes(r.0.to_vec())));
        }
        cbor::encode(&Value::map(e))
    }

    pub fn from_payload(payload: &[u8]) -> Result<ErrorMsg> {
        let v = cbor::decode_canonical(payload)
            .map_err(|e| ProtocolError::BadRequest(format!("error payload: {e}")))?;
        Ok(ErrorMsg {
            code: req_uint(&v, "code")?,
            message: req_text(&v, "message").unwrap_or_default(),
            request_id: match v.get("request_id") {
                Some(Value::Bytes(b)) => Some(Id::from_slice(b)?),
                None => None,
                Some(_) => {
                    return Err(ProtocolError::BadRequest("request_id must be bytes".into()))
                }
            },
        })
    }

    pub fn from_error(e: &ProtocolError, request_id: Option<Id>) -> ErrorMsg {
        ErrorMsg {
            code: e.code().as_u32() as u64,
            message: e.to_string(),
            request_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuthRequest {
        AuthRequest::new(
            Id::from_slice(&[0x11; 16]).unwrap(),
            Id::from_slice(&[0x22; 16]).unwrap(),
            Id::from_slice(&[0x33; 16]).unwrap(),
            "alice".into(),
            "sudo".into(),
            "sudo".into(),
            "authenticate".into(),
            Challenge::from_slice(&[0x44; 32]).unwrap(),
            1_700_000_000,
            1_700_000_060,
            Id::from_slice(&[0x55; 16]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn signing_input_has_the_specified_prefix() {
        let si = sample().signing_input();
        let domain = b"RBA_AUTH_V1";
        assert_eq!(
            domain.len(),
            11,
            "spec documents this as an 11-byte separator"
        );
        assert_eq!(&si[..11], domain);
        assert_eq!(si[11], 0x00, "NUL separator");
        assert_eq!(si[12], 0x01, "protocol version");
        // Body is canonical CBOR for a 10-pair map: 0xA0 + 10 = 0xAA.
        assert_eq!(si[13], 0xaa);
    }

    #[test]
    fn signed_core_excludes_display_and_session_fields() {
        let r = sample().with_display(
            Some("workstation".into()),
            Some("systemctl restart sshd".into()),
        );
        let core = r.signed_core();
        for absent in ["display_host_name", "display_detail", "session_id"] {
            assert!(core.get(absent).is_none(), "{absent} must not be signed");
        }
        // ...and adding display text must not change the signature input.
        assert_eq!(r.signing_input(), sample().signing_input());
    }

    #[test]
    fn any_signed_field_change_changes_the_signing_input() {
        let base = sample();
        let mut variants = Vec::new();
        let mut v = base.clone();
        v.username = "bob".into();
        variants.push(v);
        let mut v = base.clone();
        v.purpose = "polkit".into();
        variants.push(v);
        let mut v = base.clone();
        v.service = "login".into();
        variants.push(v);
        let mut v = base.clone();
        v.operation = "authorize".into();
        variants.push(v);
        let mut v = base.clone();
        v.host_id = Id::from_slice(&[0x99; 16]).unwrap();
        variants.push(v);
        let mut v = base.clone();
        v.device_id = Id::from_slice(&[0x99; 16]).unwrap();
        variants.push(v);
        let mut v = base.clone();
        v.request_id = Id::from_slice(&[0x99; 16]).unwrap();
        variants.push(v);
        let mut v = base.clone();
        v.challenge = Challenge::from_slice(&[0x99; 32]).unwrap();
        variants.push(v);
        let mut v = base.clone();
        v.issued_at = 1_700_000_001;
        variants.push(v);
        let mut v = base.clone();
        v.expires_at = 1_700_000_061;
        variants.push(v);

        for v in variants {
            assert_ne!(
                v.signing_input(),
                base.signing_input(),
                "signing input must change; variant differs only in: {v:?}"
            );
        }
    }

    #[test]
    fn payload_roundtrip_preserves_everything() {
        let r = sample().with_display(Some("workstation".into()), None);
        let bytes = r.to_payload();
        let back = AuthRequest::from_payload(&bytes).unwrap();
        assert_eq!(r, back);
        // The signed transcript survives a wire round-trip unchanged, so a
        // signature made by the device still verifies.
        assert_eq!(r.signing_input(), back.signing_input());
    }

    #[test]
    fn rejects_non_canonical_payload() {
        let mut good = sample().to_payload();
        good.push(0x00); // trailing byte
        assert!(matches!(
            AuthRequest::from_payload(&good),
            Err(ProtocolError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_missing_signed_field() {
        let mut v = cbor::decode(&sample().to_payload()).unwrap();
        // Rebuild without "username".
        if let Value::Map(pairs) = &mut v {
            pairs.retain(|(k, _)| k.as_text() != Some("username"));
        }
        let payload = cbor::encode(&v);
        assert!(matches!(
            AuthRequest::from_payload(&payload),
            Err(ProtocolError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_ttl_beyond_the_maximum() {
        let e = AuthRequest::new(
            Id::random().unwrap(),
            Id::random().unwrap(),
            Id::random().unwrap(),
            "alice".into(),
            "sudo".into(),
            "sudo".into(),
            "authenticate".into(),
            Challenge::random().unwrap(),
            1_000,
            1_000 + AUTH_REQUEST_TTL_MAX + 1,
            Id::random().unwrap(),
        );
        assert!(e.is_err());
    }

    #[test]
    fn hello_and_ack_reject_every_unsupported_version_sample() {
        let mut hello = SessionHello {
            protocol_version: crate::PROTOCOL_VERSION,
            host_id: Id([1; 16]),
            host_key_id: "a".repeat(64),
            host_nonce: [2; CHALLENGE_LEN],
            session_id: Id([3; 16]),
            transports: vec!["wifi".into()],
        };
        let mut ack = SessionHelloAck {
            protocol_version: crate::PROTOCOL_VERSION,
            device_id: Id([4; 16]),
            device_key_id: "b".repeat(64),
            device_nonce: [5; CHALLENGE_LEN],
            session_id: hello.session_id,
        };
        assert_eq!(SessionHello::from_payload(&hello.to_payload()).unwrap(), hello);
        assert_eq!(SessionHelloAck::from_payload(&ack.to_payload()).unwrap(), ack);
        for version in [0, crate::PROTOCOL_VERSION + 1, 255, 256, u64::MAX] {
            hello.protocol_version = version;
            ack.protocol_version = version;
            assert!(matches!(SessionHello::from_payload(&hello.to_payload()), Err(ProtocolError::UnsupportedVersion(_))));
            assert!(matches!(SessionHelloAck::from_payload(&ack.to_payload()), Err(ProtocolError::UnsupportedVersion(_))));
        }
    }

    #[test]
    fn id_length_is_enforced() {
        assert!(Id::from_slice(&[0u8; 15]).is_err());
        assert!(Id::from_slice(&[0u8; 16]).is_ok());
        assert!(Challenge::from_slice(&[0u8; 31]).is_err());
        assert!(Challenge::from_slice(&[0u8; 32]).is_ok());
    }

    #[test]
    fn auth_response_rejects_wrong_signature_length_and_algorithm() {
        let r = AuthResponse {
            request_id: Id::random().unwrap(),
            device_id: Id::random().unwrap(),
            session_id: Id::random().unwrap(),
            algorithm: "ES256".into(),
            key_id: "a".repeat(64),
            signature: [0u8; 64],
        };
        assert!(!r.to_payload().is_empty());
        assert!(AuthResponse::from_payload(&r.to_payload()).is_ok());

        let mut bad = r.clone();
        bad.algorithm = "HS256".into();
        assert!(AuthResponse::from_payload(&bad.to_payload()).is_err());

        let short = cbor::encode(&Value::map([
            ("algorithm", Value::text("ES256")),
            ("device_id", Value::Bytes(r.device_id.0.to_vec())),
            ("key_id", Value::text("a".repeat(64))),
            ("request_id", Value::Bytes(r.request_id.0.to_vec())),
            ("session_id", Value::Bytes(r.session_id.0.to_vec())),
            ("signature", Value::Bytes(vec![0u8; 63])),
        ]));
        assert_eq!(
            AuthResponse::from_payload(&short),
            Err(ProtocolError::SignatureInvalid)
        );
    }
}
