//! Host-side verification of an authentication response.
//!
//! This is the single place where "the device approved this exact thing" is
//! decided. It takes the outstanding request that the replay guard has already
//! consumed, and the device's stored public key. It never trusts any value
//! supplied by the peer for the public key, the device id, the username, the
//! host id, or the scope.

use crate::crypto::{self, PublicKey};
use crate::errors::{ProtocolError, Result};
use crate::types::{
    AuthRequest, AuthResponse, Id, Transport, AUTH_REQUEST_TTL_MAX, CLOCK_SKEW, CLOCK_SKEW_STRICT,
};

/// The transport a request arrived over, used only to pick the freshness
/// window. Transport must never change the security decision.
fn skew_for(transport: Transport) -> u64 {
    match transport {
        Transport::Wifi => CLOCK_SKEW,
        Transport::Ble => CLOCK_SKEW_STRICT,
    }
}

/// Freshness check (`PROTOCOL.md` §11.1).
pub fn check_freshness(request: &AuthRequest, now: u64, transport: Transport) -> Result<()> {
    let skew = skew_for(transport);
    if request.issued_at > now.saturating_add(CLOCK_SKEW) {
        return Err(ProtocolError::Expired);
    }
    if now > request.expires_at.saturating_add(skew) {
        return Err(ProtocolError::Expired);
    }
    if request.expires_at < request.issued_at {
        return Err(ProtocolError::Expired);
    }
    if request.expires_at.saturating_sub(request.issued_at) > AUTH_REQUEST_TTL_MAX {
        return Err(ProtocolError::Expired);
    }
    Ok(())
}

/// Full verification of a response against the request it answers.
///
/// `device_pubkey` must come from the trusted device registry, never from the
/// response or the transport.
pub fn verify_auth_response(
    request: &AuthRequest,
    response: &AuthResponse,
    device_pubkey: &PublicKey,
    expected_device_id: Id,
    expected_session_id: Id,
    now: u64,
    transport: Transport,
) -> Result<()> {
    // 1. The response must answer exactly this request.
    if response.request_id != request.request_id {
        return Err(ProtocolError::ContextMismatch(
            "response request_id does not match".into(),
        ));
    }

    // 2. The response must come from the device the request was addressed to.
    //    Guards against a second paired device relaying a third device's
    //    signature.
    if response.device_id != expected_device_id || response.device_id != request.device_id {
        return Err(ProtocolError::ContextMismatch(format!(
            "response device {} does not match expected {}",
            response.device_id.short(),
            expected_device_id.short()
        )));
    }

    // 3. It must belong to the session that carried the request.
    if response.session_id != expected_session_id || response.session_id != request.session_id {
        return Err(ProtocolError::ContextMismatch(
            "response session_id does not match".into(),
        ));
    }

    // 4. Algorithm must be the one we implement. No negotiation, no fallback.
    if response.algorithm != crypto::ALGORITHM {
        return Err(ProtocolError::BadRequest(format!(
            "unsupported algorithm {}",
            response.algorithm
        )));
    }

    // 5. The declared key id must be the key we actually verify with. This is a
    //    consistency check, not the trust decision.
    if response.key_id != device_pubkey.key_id_hex() {
        return Err(ProtocolError::ContextMismatch(
            "response key_id does not match the registered device key".into(),
        ));
    }

    // 6. Freshness, before spending signature verification.
    check_freshness(request, now, transport)?;

    // 7. The cryptographic proof, over the exact canonical context.
    device_pubkey.verify(&request.signing_input(), &response.signature)
}

/// Convenience wrapper that reports success as a boolean, for callers that only
/// need the decision.
pub fn verify_auth_response_ok(
    request: &AuthRequest,
    response: &AuthResponse,
    device_pubkey: &PublicKey,
    expected_device_id: Id,
    expected_session_id: Id,
    now: u64,
    transport: Transport,
) -> bool {
    verify_auth_response(
        request,
        response,
        device_pubkey,
        expected_device_id,
        expected_session_id,
        now,
        transport,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;
    use crate::types::{Challenge, MAX_NAME_LEN};

    const NOW: u64 = 1_700_000_030;

    fn device() -> (PrivateKey, PublicKey, Id) {
        let sk = PrivateKey::from_bytes(&[0x21; 32]).unwrap();
        let pk = sk.public_key();
        let id = Id::from_slice(&[0x33; 16]).unwrap();
        (sk, pk, id)
    }

    /// A second, unrelated paired device.
    fn other_device() -> (PrivateKey, PublicKey, Id) {
        let sk = PrivateKey::from_bytes(&[0x77; 32]).unwrap();
        let pk = sk.public_key();
        let id = Id::from_slice(&[0x88; 16]).unwrap();
        (sk, pk, id)
    }

    fn request(device_id: Id, session_id: Id) -> AuthRequest {
        AuthRequest::new(
            Id::from_slice(&[1u8; 16]).unwrap(),
            Id::from_slice(&[2u8; 16]).unwrap(),
            device_id,
            "alice".into(),
            "sudo".into(),
            "sudo".into(),
            "authenticate".into(),
            Challenge::from_slice(&[4u8; 32]).unwrap(),
            NOW - 10,
            NOW + 20,
            session_id,
        )
        .unwrap()
    }

    fn good_response(sk: &PrivateKey, req: &AuthRequest, pk: &PublicKey) -> AuthResponse {
        AuthResponse {
            request_id: req.request_id,
            device_id: req.device_id,
            session_id: req.session_id,
            algorithm: crypto::ALGORITHM.into(),
            key_id: pk.key_id_hex(),
            signature: sk.sign(&req.signing_input()),
        }
    }

    #[test]
    fn accepts_a_genuine_response() {
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        let resp = good_response(&sk, &req, &pk);
        verify_auth_response(&req, &resp, &pk, did, sid, NOW, Transport::Wifi).unwrap();
    }

    #[test]
    fn ble_transport_accepts_the_same_response_as_wifi() {
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        let resp = good_response(&sk, &req, &pk);
        verify_auth_response(&req, &resp, &pk, did, sid, NOW, Transport::Ble).unwrap();
    }

    #[test]
    fn rejects_signature_for_a_different_user() {
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        // The device signs a request for "bob".
        let mut bob = req.clone();
        bob.username = "bob".into();
        let resp = AuthResponse {
            request_id: req.request_id,
            device_id: req.device_id,
            session_id: req.session_id,
            algorithm: crypto::ALGORITHM.into(),
            key_id: pk.key_id_hex(),
            signature: sk.sign(&bob.signing_input()),
        };
        assert_eq!(
            verify_auth_response(&req, &resp, &pk, did, sid, NOW, Transport::Wifi),
            Err(ProtocolError::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_signature_for_a_different_purpose() {
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        let mut polkit = req.clone();
        polkit.purpose = "polkit".into();
        let resp = AuthResponse {
            request_id: req.request_id,
            device_id: req.device_id,
            session_id: req.session_id,
            algorithm: crypto::ALGORITHM.into(),
            key_id: pk.key_id_hex(),
            signature: sk.sign(&polkit.signing_input()),
        };
        assert!(verify_auth_response(&req, &resp, &pk, did, sid, NOW, Transport::Wifi).is_err());
    }

    #[test]
    fn rejects_signature_from_a_different_host() {
        // Same device key, but the response was produced for another host's
        // host_id. Cross-host replay must fail.
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        let mut other_host = req.clone();
        other_host.host_id = Id::from_slice(&[0xEE; 16]).unwrap();
        let resp = good_response(&sk, &other_host, &pk);
        assert_eq!(
            verify_auth_response(&req, &resp, &pk, did, sid, NOW, Transport::Wifi),
            Err(ProtocolError::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_signature_from_a_different_device_key() {
        let (_, pk_a, did) = device();
        let sk_b = PrivateKey::from_bytes(&[0x22; 32]).unwrap();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        // Signed by a key that is not the registered one for this device.
        let resp = AuthResponse {
            request_id: req.request_id,
            device_id: req.device_id,
            session_id: req.session_id,
            algorithm: crypto::ALGORITHM.into(),
            key_id: pk_a.key_id_hex(),
            signature: sk_b.sign(&req.signing_input()),
        };
        assert_eq!(
            verify_auth_response(&req, &resp, &pk_a, did, sid, NOW, Transport::Wifi),
            Err(ProtocolError::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_a_relay_from_another_paired_device() {
        let (sk, pk, did) = device();
        let (_, _, other_did) = other_device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        let mut resp = good_response(&sk, &req, &pk);
        // A relay rewrites the device_id to itself.
        resp.device_id = other_did;
        assert!(matches!(
            verify_auth_response(&req, &resp, &pk, did, sid, NOW, Transport::Wifi),
            Err(ProtocolError::ContextMismatch(_))
        ));
    }

    #[test]
    fn rejects_wrong_session() {
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        let mut resp = good_response(&sk, &req, &pk);
        resp.session_id = Id::from_slice(&[0x77; 16]).unwrap();
        assert!(matches!(
            verify_auth_response(&req, &resp, &pk, did, sid, NOW, Transport::Wifi),
            Err(ProtocolError::ContextMismatch(_))
        ));
    }

    #[test]
    fn rejects_expired_request() {
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        let resp = good_response(&sk, &req, &pk);
        let late = req.expires_at + CLOCK_SKEW + 1;
        assert_eq!(
            verify_auth_response(&req, &resp, &pk, did, sid, late, Transport::Wifi),
            Err(ProtocolError::Expired)
        );
    }

    #[test]
    fn rejects_request_from_the_future() {
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let mut req = request(did, sid);
        req.issued_at = NOW + 10_000;
        req.expires_at = NOW + 10_030;
        let resp = good_response(&sk, &req, &pk);
        assert_eq!(
            verify_auth_response(&req, &resp, &pk, did, sid, NOW, Transport::Wifi),
            Err(ProtocolError::Expired)
        );
    }

    #[test]
    fn rejects_tampered_signature_bytes() {
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        let mut resp = good_response(&sk, &req, &pk);
        resp.signature[10] ^= 0x01;
        assert_eq!(
            verify_auth_response(&req, &resp, &pk, did, sid, NOW, Transport::Wifi),
            Err(ProtocolError::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_unsupported_algorithm_instead_of_negotiating() {
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        let mut resp = good_response(&sk, &req, &pk);
        resp.algorithm = "HS256".into();
        assert!(matches!(
            verify_auth_response(&req, &resp, &pk, did, sid, NOW, Transport::Wifi),
            Err(ProtocolError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_mismatched_key_id() {
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        let mut resp = good_response(&sk, &req, &pk);
        resp.key_id = PrivateKey::from_bytes(&[0x99; 32])
            .unwrap()
            .public_key()
            .key_id_hex();
        assert!(matches!(
            verify_auth_response(&req, &resp, &pk, did, sid, NOW, Transport::Wifi),
            Err(ProtocolError::ContextMismatch(_))
        ));
    }

    #[test]
    fn freshness_window_is_tighter_on_ble() {
        let (sk, pk, did) = device();
        let sid = Id::from_slice(&[5u8; 16]).unwrap();
        let req = request(did, sid);
        let resp = good_response(&sk, &req, &pk);
        // 20 seconds past expiry: within the Wi-Fi skew (30s), outside the
        // BLE one (10s).
        let t = req.expires_at + 20;
        assert!(verify_auth_response(&req, &resp, &pk, did, sid, t, Transport::Wifi).is_ok());
        assert_eq!(
            verify_auth_response(&req, &resp, &pk, did, sid, t, Transport::Ble),
            Err(ProtocolError::Expired)
        );
    }

    #[test]
    fn name_length_limit_is_enforced_on_construction() {
        let long = "a".repeat(MAX_NAME_LEN + 1);
        assert!(AuthRequest::new(
            Id::random().unwrap(),
            Id::random().unwrap(),
            Id::random().unwrap(),
            long,
            "sudo".into(),
            "sudo".into(),
            "authenticate".into(),
            Challenge::random().unwrap(),
            0,
            30,
            Id::random().unwrap(),
        )
        .is_err());
    }
}
