//! Protocol error codes (`PROTOCOL.md` §9).
//!
//! Every code maps to a *deny*. There is deliberately no "soft failure" variant:
//! `ProtocolError` has no representation for "proceed anyway".

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ErrorCode {
    BadRequest = 1,
    UnsupportedVersion = 2,
    UnknownMessage = 3,
    NotPaired = 4,
    Revoked = 5,
    UserCancelled = 6,
    BiometricFailed = 7,
    RateLimited = 8,
    Expired = 9,
    Replay = 10,
    SignatureInvalid = 11,
    ContextMismatch = 12,
    Internal = 13,
}

impl ErrorCode {
    /// Decodes a code from its wire representation, which is a CBOR unsigned
    /// integer and therefore 64-bit.
    pub fn from_wire(v: u64) -> Option<ErrorCode> {
        Some(match v {
            1 => ErrorCode::BadRequest,
            2 => ErrorCode::UnsupportedVersion,
            3 => ErrorCode::UnknownMessage,
            4 => ErrorCode::NotPaired,
            5 => ErrorCode::Revoked,
            6 => ErrorCode::UserCancelled,
            7 => ErrorCode::BiometricFailed,
            8 => ErrorCode::RateLimited,
            9 => ErrorCode::Expired,
            10 => ErrorCode::Replay,
            11 => ErrorCode::SignatureInvalid,
            12 => ErrorCode::ContextMismatch,
            13 => ErrorCode::Internal,
            _ => return None,
        })
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "BAD_REQUEST",
            ErrorCode::UnsupportedVersion => "UNSUPPORTED_VERSION",
            ErrorCode::UnknownMessage => "UNKNOWN_MESSAGE",
            ErrorCode::NotPaired => "NOT_PAIRED",
            ErrorCode::Revoked => "REVOKED",
            ErrorCode::UserCancelled => "USER_CANCELLED",
            ErrorCode::BiometricFailed => "BIOMETRIC_FAILED",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::Expired => "EXPIRED",
            ErrorCode::Replay => "REPLAY",
            ErrorCode::SignatureInvalid => "SIGNATURE_INVALID",
            ErrorCode::ContextMismatch => "CONTEXT_MISMATCH",
            ErrorCode::Internal => "INTERNAL",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Structurally invalid message.
    BadRequest(String),
    UnsupportedVersion(u8),
    UnknownMessage(u16),
    NotPaired,
    Revoked,
    UserCancelled,
    BiometricFailed,
    RateLimited(u64),
    Expired,
    Replay(String),
    SignatureInvalid,
    ContextMismatch(String),
    Internal(String),
}

impl ProtocolError {
    pub fn code(&self) -> ErrorCode {
        match self {
            ProtocolError::BadRequest(_) => ErrorCode::BadRequest,
            ProtocolError::UnsupportedVersion(_) => ErrorCode::UnsupportedVersion,
            ProtocolError::UnknownMessage(_) => ErrorCode::UnknownMessage,
            ProtocolError::NotPaired => ErrorCode::NotPaired,
            ProtocolError::Revoked => ErrorCode::Revoked,
            ProtocolError::UserCancelled => ErrorCode::UserCancelled,
            ProtocolError::BiometricFailed => ErrorCode::BiometricFailed,
            ProtocolError::RateLimited(_) => ErrorCode::RateLimited,
            ProtocolError::Expired => ErrorCode::Expired,
            ProtocolError::Replay(_) => ErrorCode::Replay,
            ProtocolError::SignatureInvalid => ErrorCode::SignatureInvalid,
            ProtocolError::ContextMismatch(_) => ErrorCode::ContextMismatch,
            ProtocolError::Internal(_) => ErrorCode::Internal,
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::BadRequest(m) => write!(f, "bad request: {m}"),
            ProtocolError::UnsupportedVersion(v) => write!(f, "unsupported version {v}"),
            ProtocolError::UnknownMessage(t) => write!(f, "unknown message type {t}"),
            ProtocolError::NotPaired => write!(f, "host is not paired"),
            ProtocolError::Revoked => write!(f, "host was revoked"),
            ProtocolError::UserCancelled => write!(f, "user cancelled"),
            ProtocolError::BiometricFailed => write!(f, "biometric authentication failed"),
            ProtocolError::RateLimited(secs) => write!(f, "rate limited; retry in {secs}s"),
            ProtocolError::Expired => write!(f, "request expired"),
            ProtocolError::Replay(m) => write!(f, "replay: {m}"),
            ProtocolError::SignatureInvalid => write!(f, "signature verification failed"),
            ProtocolError::ContextMismatch(m) => write!(f, "context mismatch: {m}"),
            ProtocolError::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

pub type Result<T> = std::result::Result<T, ProtocolError>;
