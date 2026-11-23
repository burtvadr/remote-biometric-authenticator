//! Wire protocol and cryptography for the Remote Biometric Authenticator.
//!
//! This crate is the Linux-side implementation of
//! `protocol/specification/PROTOCOL.md`. The Android application implements the
//! same document independently in Kotlin; the two are validated against the
//! shared vectors in `protocol/test-vectors/`.
//!
//! What lives here:
//!
//! * [`cbor`] — canonical CBOR subset with enforced canonical form
//! * [`frame`] — length-prefixed framing
//! * [`types`] — identifiers, request context, signing transcript
//! * [`messages`] — the message set
//! * [`pairing`] — explicit pairing and its confirmation MACs
//! * [`crypto`] — key handling, ECDSA verification, HMAC/HKDF
//! * [`nonce`] — replay protection
//! * [`ratelimit`] — sliding-window rate limiting
//! * [`verifier`] — the host-side authentication decision
//!
//! No cryptographic primitive is implemented here; all come from RustCrypto.
//! Nothing in this crate performs I/O or holds policy beyond the protocol, so it
//! is straightforward to exercise exhaustively in tests.

pub mod cbor;
pub mod crypto;
pub mod errors;
pub mod frame;
pub mod messages;
pub mod nonce;
pub mod pairing;
pub mod ratelimit;
pub mod types;
pub mod verifier;

use std::time::{SystemTime, UNIX_EPOCH};

/// Protocol version implemented by this crate (`PROTOCOL.md` §5, §17).
pub const PROTOCOL_VERSION: u64 = 1;

/// Hard cap on a frame payload, from `PROTOCOL.md` §11.
pub const MAX_FRAME_PAYLOAD: usize = 65_536;

/// DNS-SD service type (`PROTOCOL.md` §13.1).
pub const SERVICE_TYPE: &str = "_rba._tcp.local.";

/// BLE GATT identifiers (`PROTOCOL.md` §13.2). Project-assigned 128-bit UUIDs in
/// a private range; they are routing data and never identity.
pub mod ble {
    pub const SERVICE_UUID: &str = "8f1c0001-9d2b-4a7e-b0c4-5f6a71c3d801";
    pub const RX_CHARACTERISTIC_UUID: &str = "8f1c0002-9d2b-4a7e-b0c4-5f6a71c3d801";
    pub const TX_CHARACTERISTIC_UUID: &str = "8f1c0003-9d2b-4a7e-b0c4-5f6a71c3d801";

    /// Maximum payload of a single GATT characteristic value.
    pub const SEGMENT_SIZE: usize = 20;
}

/// Seconds since the Unix epoch, saturating at 0 before 1970.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Version string reported by `rba --version` and in logs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_now_is_plausible() {
        // Later than 2020 and earlier than 2100.
        let n = unix_now();
        assert!(n > 1_577_836_800, "clock looks wrong: {n}");
        assert!(n < 4_102_444_800, "clock looks wrong: {n}");
    }

    #[test]
    fn ble_uuids_are_wellformed_and_distinct() {
        for u in [
            ble::SERVICE_UUID,
            ble::RX_CHARACTERISTIC_UUID,
            ble::TX_CHARACTERISTIC_UUID,
        ] {
            assert_eq!(u.len(), 36);
            assert_eq!(u.chars().filter(|c| *c == '-').count(), 4);
            assert_eq!(u, u.to_lowercase());
        }
        assert_ne!(ble::SERVICE_UUID, ble::RX_CHARACTERISTIC_UUID);
        assert_ne!(ble::SERVICE_UUID, ble::TX_CHARACTERISTIC_UUID);
        assert_ne!(ble::RX_CHARACTERISTIC_UUID, ble::TX_CHARACTERISTIC_UUID);
        // A single characteristic value carries at most MTU-3 bytes, 20 for the
        // default MTU of 23. Segmentation must therefore exist.
        assert_eq!(ble::SEGMENT_SIZE, 20);
    }

    #[test]
    fn service_type_matches_the_specification() {
        assert_eq!(SERVICE_TYPE, "_rba._tcp.local.");
    }
}
