//! The protocol message set and its mapping onto frames (`PROTOCOL.md` §5).

use crate::errors::{ProtocolError, Result};
use crate::frame::Frame;
use crate::pairing::{PairingConfirmed, PairingResult, PairingStart, PairingSubmit, Unpair};
use crate::types::{
    AuthReject, AuthRequest, AuthResponse, ErrorMsg, SessionHello, SessionHelloAck,
};

pub const MSG_PAIRING_START: u16 = 1;
pub const MSG_PAIRING_SUBMIT: u16 = 2;
pub const MSG_PAIRING_RESULT: u16 = 3;
pub const MSG_PAIRING_CONFIRMED: u16 = 4;
pub const MSG_SESSION_HELLO: u16 = 10;
pub const MSG_SESSION_HELLO_ACK: u16 = 11;
pub const MSG_AUTH_REQUEST: u16 = 12;
pub const MSG_AUTH_RESPONSE: u16 = 13;
pub const MSG_AUTH_REJECT: u16 = 14;
pub const MSG_UNPAIR: u16 = 15;
pub const MSG_ERROR: u16 = 20;

pub const MESSAGE_NAMES: [(u16, &str); 11] = [
    (MSG_PAIRING_START, "PAIRING_START"),
    (MSG_PAIRING_SUBMIT, "PAIRING_SUBMIT"),
    (MSG_PAIRING_RESULT, "PAIRING_RESULT"),
    (MSG_PAIRING_CONFIRMED, "PAIRING_CONFIRMED"),
    (MSG_SESSION_HELLO, "SESSION_HELLO"),
    (MSG_SESSION_HELLO_ACK, "SESSION_HELLO_ACK"),
    (MSG_AUTH_REQUEST, "AUTH_REQUEST"),
    (MSG_AUTH_RESPONSE, "AUTH_RESPONSE"),
    (MSG_AUTH_REJECT, "AUTH_REJECT"),
    (MSG_UNPAIR, "UNPAIR"),
    (MSG_ERROR, "ERROR"),
];

pub fn message_name(t: u16) -> &'static str {
    MESSAGE_NAMES
        .iter()
        .find(|(c, _)| *c == t)
        .map(|(_, n)| *n)
        .unwrap_or("UNKNOWN")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    PairingStart(PairingStart),
    PairingSubmit(PairingSubmit),
    PairingResult(PairingResult),
    PairingConfirmed(PairingConfirmed),
    SessionHello(SessionHello),
    SessionHelloAck(SessionHelloAck),
    AuthRequest(AuthRequest),
    AuthResponse(AuthResponse),
    AuthReject(AuthReject),
    Unpair(Unpair),
    Error(ErrorMsg),
}

impl Message {
    pub fn msg_type(&self) -> u16 {
        match self {
            Message::PairingStart(_) => MSG_PAIRING_START,
            Message::PairingSubmit(_) => MSG_PAIRING_SUBMIT,
            Message::PairingResult(_) => MSG_PAIRING_RESULT,
            Message::PairingConfirmed(_) => MSG_PAIRING_CONFIRMED,
            Message::SessionHello(_) => MSG_SESSION_HELLO,
            Message::SessionHelloAck(_) => MSG_SESSION_HELLO_ACK,
            Message::AuthRequest(_) => MSG_AUTH_REQUEST,
            Message::AuthResponse(_) => MSG_AUTH_RESPONSE,
            Message::AuthReject(_) => MSG_AUTH_REJECT,
            Message::Unpair(_) => MSG_UNPAIR,
            Message::Error(_) => MSG_ERROR,
        }
    }

    pub fn name(&self) -> &'static str {
        message_name(self.msg_type())
    }

    pub fn to_payload(&self) -> Vec<u8> {
        match self {
            Message::PairingStart(m) => m.to_payload(),
            Message::PairingSubmit(m) => m.to_payload(),
            Message::PairingResult(m) => m.to_payload(),
            Message::PairingConfirmed(m) => m.to_payload(),
            Message::SessionHello(m) => m.to_payload(),
            Message::SessionHelloAck(m) => m.to_payload(),
            Message::AuthRequest(m) => m.to_payload(),
            Message::AuthResponse(m) => m.to_payload(),
            Message::AuthReject(m) => m.to_payload(),
            Message::Unpair(m) => m.to_payload(),
            Message::Error(m) => m.to_payload(),
        }
    }

    pub fn to_frame(&self) -> Frame {
        Frame::new(self.msg_type(), self.to_payload())
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_frame().encode()
    }

    /// Parses a frame into a message. An unassigned type is an error, never a
    /// silently ignored frame.
    pub fn from_frame(f: &Frame) -> Result<Message> {
        if f.flags != 0 {
            return Err(ProtocolError::UnsupportedVersion(f.version));
        }
        Ok(match f.msg_type {
            MSG_PAIRING_START => Message::PairingStart(PairingStart::from_payload(&f.payload)?),
            MSG_PAIRING_SUBMIT => Message::PairingSubmit(PairingSubmit::from_payload(&f.payload)?),
            MSG_PAIRING_RESULT => Message::PairingResult(PairingResult::from_payload(&f.payload)?),
            MSG_PAIRING_CONFIRMED => {
                Message::PairingConfirmed(PairingConfirmed::from_payload(&f.payload)?)
            }
            MSG_SESSION_HELLO => Message::SessionHello(SessionHello::from_payload(&f.payload)?),
            MSG_SESSION_HELLO_ACK => {
                Message::SessionHelloAck(SessionHelloAck::from_payload(&f.payload)?)
            }
            MSG_AUTH_REQUEST => Message::AuthRequest(AuthRequest::from_payload(&f.payload)?),
            MSG_AUTH_RESPONSE => Message::AuthResponse(AuthResponse::from_payload(&f.payload)?),
            MSG_AUTH_REJECT => {
                let v = crate::cbor::decode_canonical(&f.payload)
                    .map_err(|e| ProtocolError::BadRequest(format!("auth_reject: {e}")))?;
                let request_id =
                    v.get("request_id")
                        .and_then(|x| x.as_bytes())
                        .ok_or_else(|| {
                            ProtocolError::BadRequest("auth_reject: missing request_id".into())
                        })?;
                let reason = v.get("reason").and_then(|x| x.as_uint()).ok_or_else(|| {
                    ProtocolError::BadRequest("auth_reject: missing reason".into())
                })?;
                Message::AuthReject(AuthReject {
                    request_id: crate::types::Id::from_slice(request_id)?,
                    reason,
                })
            }
            MSG_UNPAIR => Message::Unpair(Unpair::from_payload(&f.payload)?),
            MSG_ERROR => Message::Error(ErrorMsg::from_payload(&f.payload)?),
            other => return Err(ProtocolError::UnknownMessage(other)),
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Message> {
        let (f, _) =
            Frame::decode(bytes).map_err(|e| ProtocolError::BadRequest(format!("frame: {e}")))?;
        Message::from_frame(&f)
    }
}

impl AuthReject {
    pub fn to_payload(&self) -> Vec<u8> {
        crate::cbor::encode(&crate::cbor::Value::map([
            ("reason", crate::cbor::Value::Uint(self.reason)),
            (
                "request_id",
                crate::cbor::Value::Bytes(self.request_id.0.to_vec()),
            ),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;
    use crate::types::{Challenge, Id};

    fn auth_request() -> AuthRequest {
        AuthRequest::new(
            Id::from_slice(&[1u8; 16]).unwrap(),
            Id::from_slice(&[2u8; 16]).unwrap(),
            Id::from_slice(&[3u8; 16]).unwrap(),
            "alice".into(),
            "sudo".into(),
            "sudo".into(),
            "authenticate".into(),
            Challenge::from_slice(&[4u8; 32]).unwrap(),
            1_700_000_000,
            1_700_000_060,
            Id::from_slice(&[5u8; 16]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn auth_request_frame_roundtrip() {
        let m = Message::AuthRequest(auth_request());
        let bytes = m.encode();
        let back = Message::from_bytes(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn unknown_message_type_is_rejected() {
        let f = Frame::new(999, vec![]);
        assert!(matches!(
            Message::from_frame(&f),
            Err(ProtocolError::UnknownMessage(999))
        ));
    }

    #[test]
    fn bad_version_is_rejected_at_frame_decode() {
        let mut bytes = Message::Error(ErrorMsg {
            code: 1,
            message: "x".into(),
            request_id: None,
        })
        .encode();
        bytes[4] = 2;
        assert!(Message::from_bytes(&bytes).is_err());
    }

    #[test]
    fn auth_reject_roundtrip() {
        let m = Message::AuthReject(AuthReject {
            request_id: Id::from_slice(&[7u8; 16]).unwrap(),
            reason: 6,
        });
        assert_eq!(Message::from_bytes(&m.encode()).unwrap(), m);
    }

    #[test]
    fn auth_response_roundtrip() {
        let sk = PrivateKey::from_bytes(&[0x42; 32]).unwrap();
        let m = Message::AuthResponse(AuthResponse {
            request_id: Id::random().unwrap(),
            device_id: Id::random().unwrap(),
            session_id: Id::random().unwrap(),
            algorithm: "ES256".into(),
            key_id: sk.public_key().key_id_hex(),
            signature: sk.sign(b"ctx"),
        });
        assert_eq!(Message::from_bytes(&m.encode()).unwrap(), m);
    }

    #[test]
    fn all_message_type_codes_are_unique() {
        let mut codes: Vec<u16> = MESSAGE_NAMES.iter().map(|(c, _)| *c).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(before, codes.len());
    }
}
