//! SPAKE2 enrollment wire messages. The short code is never a wire field.
use crate::cbor::{self, Value};
use crate::crypto::{PublicKey, PUBKEY_LEN};
use crate::errors::{ProtocolError, Result};
use crate::types::{req_bytes, req_id, req_text, req_uint, Id, PAIRING_TTL};

pub const ENROLLMENT_SUITE: &str = "spake2-p256-sha256-v2";

fn decode(payload: &[u8], fields: usize) -> Result<Value> {
    let v = cbor::decode_canonical(payload).map_err(|e| ProtocolError::BadRequest(format!("enrollment payload: {e}")))?;
    if !matches!(&v, Value::Map(entries) if entries.len() == fields) {
        return Err(ProtocolError::BadRequest("unexpected enrollment fields".into()));
    }
    Ok(v)
}
fn bytes<const N: usize>(v: &Value, field: &str) -> Result<[u8; N]> {
    req_bytes(v, field)?.try_into().map_err(|_| ProtocolError::BadRequest(format!("invalid {field} length")))
}
fn share(v: &Value, field: &str) -> Result<[u8; PUBKEY_LEN]> {
    let s: [u8; PUBKEY_LEN] = bytes(v, field)?;
    PublicKey::from_bytes(&s)?;
    Ok(s)
}
fn suite(v: &Value) -> Result<()> {
    if req_text(v, "suite")? != ENROLLMENT_SUITE {
        return Err(ProtocolError::BadRequest("unsupported enrollment suite".into()));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CodeEntry {
    /// The Linux host displays the code; the device must not display it and must
    /// require the operator to type it.
    #[default]
    Device,
    /// The device displays the code; the Linux host must not display it and must
    /// require the operator to type it.
    Host,
}

impl CodeEntry {
    /// Stable transcript byte. Must not change without a protocol version bump.
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Device => 0,
            Self::Host => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Host => "host",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "device" => Ok(Self::Device),
            "host" => Ok(Self::Host),
            other => Err(ProtocolError::BadRequest(format!(
                "unknown code_entry {other:?}; expected device or host"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingStart {
    pub session_id: Id,
    pub host_id: Id,
    pub host_pubkey: PublicKey,
    pub host_key_id: String,
    pub code_entry: CodeEntry,
    pub expires_at: u64,
}
impl PairingStart {
    pub fn to_payload(&self) -> Vec<u8> {
        cbor::encode(&Value::map([
            ("suite", Value::text(ENROLLMENT_SUITE)),
            ("session_id", Value::bytes(self.session_id.0.to_vec())),
            ("host_id", Value::bytes(self.host_id.0.to_vec())),
            ("host_pubkey", Value::bytes(self.host_pubkey.as_bytes().to_vec())),
            ("host_key_id", Value::text(self.host_key_id.clone())),
            ("code_entry", Value::text(self.code_entry.as_str())),
            ("expires_at", Value::Uint(self.expires_at)),
        ]))
    }
    pub fn from_payload(payload: &[u8]) -> Result<Self> {
        let v = decode(payload, 7)?;
        suite(&v)?;
        let expires_at = req_uint(&v, "expires_at")?;
        let now = crate::unix_now();
        if expires_at <= now || expires_at > now.saturating_add(PAIRING_TTL) { return Err(ProtocolError::Expired); }
        let host_pubkey = PublicKey::from_bytes(req_bytes(&v, "host_pubkey")?)?;
        let host_key_id = req_text(&v, "host_key_id")?;
        if host_key_id != host_pubkey.key_id_hex() { return Err(ProtocolError::ContextMismatch("host key id".into())); }
        Ok(Self { session_id: req_id(&v, "session_id")?, host_id: req_id(&v, "host_id")?, host_pubkey, host_key_id,
            code_entry: CodeEntry::parse(&req_text(&v, "code_entry")?)?, expires_at })
    }
}

/// Initial device identity and SPAKE2 share; no secret or revocation token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingSubmit {
    pub session_id: Id,
    pub device_id: Id,
    pub device_name: String,
    pub device_pubkey: PublicKey,
    pub device_key_id: String,
    pub share: [u8; PUBKEY_LEN],
}
impl PairingSubmit {
    pub fn to_payload(&self) -> Vec<u8> {
        cbor::encode(&Value::map([
            ("suite", Value::text(ENROLLMENT_SUITE)),
            ("session_id", Value::bytes(self.session_id.0.to_vec())),
            ("device_id", Value::bytes(self.device_id.0.to_vec())),
            ("device_name", Value::text(self.device_name.clone())),
            ("device_pubkey", Value::bytes(self.device_pubkey.as_bytes().to_vec())),
            ("device_key_id", Value::text(self.device_key_id.clone())),
            ("share", Value::bytes(self.share.to_vec())),
        ]))
    }
    pub fn from_payload(payload: &[u8]) -> Result<Self> {
        let v = decode(payload, 7)?;
        suite(&v)?;
        let device_pubkey = PublicKey::from_bytes(req_bytes(&v, "device_pubkey")?)?;
        let device_key_id = req_text(&v, "device_key_id")?;
        if device_key_id != device_pubkey.key_id_hex() { return Err(ProtocolError::ContextMismatch("device key id".into())); }
        Ok(Self { session_id: req_id(&v, "session_id")?, device_id: req_id(&v, "device_id")?,
            device_name: req_text(&v, "device_name")?, device_pubkey, device_key_id, share: share(&v, "share")? })
    }
}

/// Host share and RFC 9382 confirmation, before credential activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingChallenge { pub session_id: Id, pub share: [u8; PUBKEY_LEN], pub confirmation: [u8; 32] }
impl PairingChallenge {
    pub fn to_payload(&self) -> Vec<u8> { cbor::encode(&Value::map([
        ("session_id", Value::bytes(self.session_id.0.to_vec())), ("share", Value::bytes(self.share.to_vec())),
        ("confirmation", Value::bytes(self.confirmation.to_vec())),
    ])) }
    pub fn from_payload(payload: &[u8]) -> Result<Self> {
        let v = decode(payload, 3)?;
        Ok(Self { session_id: req_id(&v, "session_id")?, share: share(&v, "share")?, confirmation: bytes(&v, "confirmation")? })
    }
}

/// Device sends this only after confirming the host and satisfying its UI gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingProof { pub session_id: Id, pub confirmation: [u8; 32], pub cleanup_tokens: Vec<[u8; 32]> }
impl PairingProof {
    pub fn to_payload(&self) -> Vec<u8> { cbor::encode(&Value::map([
        ("session_id", Value::bytes(self.session_id.0.to_vec())), ("confirmation", Value::bytes(self.confirmation.to_vec())),
        ("cleanup_tokens", Value::Array(self.cleanup_tokens.iter().map(|t| Value::bytes(t.to_vec())).collect())),
    ])) }
    pub fn from_payload(payload: &[u8]) -> Result<Self> {
        let v = decode(payload, 3)?;
        let cleanup_tokens = match v.get("cleanup_tokens") {
            Some(Value::Array(items)) if items.len() <= 64 => items.iter().map(|item| {
                item.as_bytes().and_then(|b| b.try_into().ok()).ok_or_else(|| ProtocolError::BadRequest("invalid cleanup token".into()))
            }).collect::<Result<Vec<[u8; 32]>>>()?,
            _ => return Err(ProtocolError::BadRequest("invalid cleanup tokens".into())),
        };
        Ok(Self { session_id: req_id(&v, "session_id")?, confirmation: bytes(&v, "confirmation")?, cleanup_tokens })
    }
}

/// Commit offer after mutual PAKE confirmation. A successful offer has a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingResult { pub session_id: Id, pub status: u64, pub revocation_token: Option<[u8; 32]> }
impl PairingResult {
    pub fn to_payload(&self) -> Vec<u8> {
        let mut entries = vec![("session_id", Value::bytes(self.session_id.0.to_vec())), ("status", Value::Uint(self.status))];
        if let Some(t) = self.revocation_token { entries.push(("revocation_token", Value::bytes(t.to_vec()))); }
        cbor::encode(&Value::map(entries))
    }
    pub fn from_payload(payload: &[u8]) -> Result<Self> {
        let v = cbor::decode_canonical(payload).map_err(|e| ProtocolError::BadRequest(format!("pairing_result: {e}")))?;
        let status = req_uint(&v, "status")?;
        let token = match (status, &v) {
            (0, Value::Map(e)) if e.len() == 3 => Some(bytes(&v, "revocation_token")?),
            (1, Value::Map(e)) if e.len() == 2 && v.get("revocation_token").is_none() => None,
            _ => return Err(ProtocolError::BadRequest("invalid pairing result".into())),
        };
        Ok(Self { session_id: req_id(&v, "session_id")?, status, revocation_token: token })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingConfirmed {
    pub session_id: Id,
}

impl PairingConfirmed {
    pub fn to_payload(&self) -> Vec<u8> {
        cbor::encode(&Value::map(vec![(
            "session_id",
            Value::Bytes(self.session_id.0.to_vec()),
        )]))
    }

    pub fn from_payload(payload: &[u8]) -> Result<PairingConfirmed> {
        let v = cbor::decode_canonical(payload)
            .map_err(|e| ProtocolError::BadRequest(format!("pairing_confirmed payload: {e}")))?;
        if !matches!(&v, Value::Map(entries) if entries.len() == 1) {
            return Err(ProtocolError::BadRequest("invalid pairing acknowledgement".into()));
        }
        let session_id = req_bytes(&v, "session_id")?;
        let sid_id = Id::from_slice(session_id)?;
        Ok(PairingConfirmed { session_id: sid_id })
    }
}

#[cfg(test)]
mod pairing_confirmed_tests {
    use super::*;

    #[test]
    fn acknowledgement_roundtrips_a_protocol_id() {
        let expected = Id::from_slice(&[0x42; crate::types::ID_LEN]).unwrap();
        let payload = PairingConfirmed { session_id: expected }.to_payload();
        assert_eq!(PairingConfirmed::from_payload(&payload).unwrap().session_id, expected);
    }

    #[test]
    fn acknowledgement_rejects_wrong_identifier_length() {
        let payload = cbor::encode(&Value::map(vec![(
            "session_id", Value::Bytes(vec![0; 32]),
        )]));
        assert!(PairingConfirmed::from_payload(&payload).is_err());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpair {
    pub token: [u8; 32],
}

impl Unpair {
    pub fn to_payload(&self) -> Vec<u8> {
        cbor::encode(&Value::map([("token", Value::Bytes(self.token.to_vec()))]))
    }

    pub fn from_payload(payload: &[u8]) -> Result<Unpair> {
        let v = cbor::decode_canonical(payload)
            .map_err(|e| ProtocolError::BadRequest(format!("unpair payload: {e}")))?;
        let bytes = req_bytes(&v, "token")?;
        if bytes.len() != 32 {
            return Err(ProtocolError::BadRequest(
                "revocation token must be 32 bytes".into(),
            ));
        }
        let mut token = [0u8; 32];
        token.copy_from_slice(bytes);
        Ok(Unpair { token })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_offer_is_rejected() {
        let v = Value::map([("code", Value::text("123456"))]);
        assert!(PairingStart::from_payload(&cbor::encode(&v)).is_err());
    }
    #[test]
    fn proof_rejects_wrong_confirmation_size() {
        let v = Value::map([("session_id", Value::bytes(vec![0;16])), ("confirmation", Value::bytes(vec![0;31])), ("cleanup_tokens", Value::Array(vec![]))]);
        assert!(PairingProof::from_payload(&cbor::encode(&v)).is_err());
    }
}
