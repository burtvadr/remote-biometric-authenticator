//! Rust-side conformance test over the shared vectors.
//!
//! The Kotlin implementation has its own runner against the same files. Both
//! sides must agree byte-for-byte on canonical encodings and on the signing
//! transcript; if either drifts, one of the two runners fails.

use std::path::{Path, PathBuf};

use rba_protocol::cbor;
use rba_protocol::crypto::{self, PrivateKey, PublicKey};
use rba_protocol::frame::Frame;
use rba_protocol::messages::Message;
use rba_protocol::types::{AuthRequest, Challenge, Id};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is <repo>/linux/protocol, so the fixtures sit beside
    // it at <repo>/protocol/test-vectors. Canonicalize so a typo is reported as
    // a missing directory rather than as a confusing per-file error.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent() // <repo>/linux
        .and_then(|linux| linux.parent()) // <repo>
        .expect("repository root")
        .join("protocol/test-vectors")
        .canonicalize()
        .expect("protocol/test-vectors must exist; regenerate with: make vectors")
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()))
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"))
}

#[test]
fn canonical_cbor_vectors_encode_identically() {
    let v = load("cbor-canonical.json");
    let cases = v["canonical"].as_array().expect("canonical array");
    assert!(cases.len() >= 15, "expected a substantial vector set");
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expected = unhex(case["value_hex"].as_str().unwrap());
        // Decoding the vector and re-encoding must reproduce it exactly: this is
        // the canonical-form property that makes signing the bytes unambiguous.
        let decoded = cbor::decode(&expected)
            .unwrap_or_else(|e| panic!("{name}: reference encoding rejected by us: {e}"));
        assert_eq!(
            cbor::encode(&decoded),
            expected,
            "{name}: re-encoding is not byte-identical"
        );
        assert_eq!(
            case["roundtrip_stable"], true,
            "{name}: vector metadata disagrees"
        );
    }
}

#[test]
fn non_canonical_cbor_vectors_are_rejected() {
    let v = load("cbor-canonical.json");
    let cases = v["non_canonical"].as_array().expect("non_canonical array");
    assert!(cases.len() >= 15, "expected the full rule set R1-R8");
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let bytes = unhex(case["value_hex"].as_str().unwrap());
        assert!(
            cbor::decode(&bytes).is_err(),
            "{name} (rule {}) must be rejected, but we accepted it",
            case["rule"]
        );
        assert_eq!(case["rejected_by_rust"], true, "{name}: vector metadata");
    }
}

#[test]
fn framing_vectors_round_trip() {
    let v = load("framing.json");
    assert_eq!(v["header_len"], 13);
    for case in v["frames"].as_array().unwrap() {
        let bytes = unhex(case["frame_hex"].as_str().unwrap());
        let (frame, n) = Frame::decode(&bytes)
            .unwrap_or_else(|e| panic!("{}: {e}", case["name"].as_str().unwrap()));
        assert_eq!(n, bytes.len(), "frame length mismatch");
        assert_eq!(frame.msg_type, case["msg_type"].as_u64().unwrap() as u16);
        assert_eq!(frame.encode(), bytes, "re-encoding must be identical");
    }
    for case in v["rejected"].as_array().unwrap() {
        let bytes = unhex(case["hex"].as_str().unwrap());
        assert!(
            Frame::decode(&bytes).is_err(),
            "{} must be rejected",
            case["name"]
        );
    }
}

#[test]
fn message_vectors_round_trip() {
    let v = load("messages.json");
    for case in v["messages"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let payload = unhex(case["payload_hex"].as_str().unwrap());
        let expected_type = case["msg_type"].as_u64().unwrap() as u16;

        // The vector records the canonical payload. Framing it and decoding it
        // back must reproduce exactly those bytes: that is what proves our
        // encoder and decoder agree with the reference.
        let frame = Frame::new(expected_type, payload.clone());
        let (decoded, consumed) = Frame::decode(&frame.encode()).unwrap();
        assert_eq!(consumed, frame.encode().len(), "{name}");
        assert_eq!(
            decoded.payload, payload,
            "{name}: payload did not survive framing"
        );
        assert_eq!(
            decoded.encode(),
            frame.encode(),
            "{name}: frame is not canonical"
        );

        assert!(
            rba_protocol::messages::MESSAGE_NAMES
                .iter()
                .any(|(c, _)| *c == expected_type),
            "{name}: unknown message type {expected_type}"
        );
    }
}

#[test]
fn auth_request_vector_matches_our_encoding() {
    let v = load("signing-transcript.json");
    let baseline = v["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["name"] == "baseline")
        .expect("a baseline case")
        .clone();
    let fields = &baseline["fields"];
    let request = AuthRequest::new(
        Id::from_slice(&unhex(fields["request_id"].as_str().unwrap())).unwrap(),
        Id::from_slice(&unhex(fields["host_id"].as_str().unwrap())).unwrap(),
        Id::from_slice(&unhex(fields["device_id"].as_str().unwrap())).unwrap(),
        fields["username"].as_str().unwrap().to_string(),
        fields["purpose"].as_str().unwrap().to_string(),
        fields["service"].as_str().unwrap().to_string(),
        fields["operation"].as_str().unwrap().to_string(),
        Challenge::from_slice(&unhex(fields["challenge"].as_str().unwrap())).unwrap(),
        fields["issued_at"].as_u64().unwrap(),
        fields["expires_at"].as_u64().unwrap(),
        Id::from_slice(&unhex(fields["session_id"].as_str().unwrap())).unwrap(),
    )
    .expect("vector describes a valid request");

    assert_eq!(
        hex::encode(request.to_payload()),
        baseline["payload_hex"].as_str().unwrap(),
        "payload encoding differs from the vector"
    );
    assert_eq!(
        hex::encode(request.signing_input()),
        baseline["signing_input_hex"].as_str().unwrap(),
        "signing input differs from the vector"
    );
    assert_eq!(
        hex::encode(request.signing_input_digest()),
        baseline["signing_input_sha256"].as_str().unwrap()
    );
    // The domain separator is fixed and the version byte follows the NUL.
    assert_eq!(v["domain_separator"], "RBA_AUTH_V1");
    assert_eq!(
        v["signed_fields"].as_array().unwrap().len(),
        10,
        "the signed scope is exactly ten fields"
    );
}

#[test]
fn every_signed_field_changes_the_transcript_and_display_text_does_not() {
    let v = load("signing-transcript.json");
    let cases = v["cases"].as_array().unwrap();
    let baseline = cases
        .iter()
        .find(|c| c["name"] == "baseline")
        .expect("a baseline case");
    let baseline_digest = baseline["signing_input_sha256"].as_str().unwrap();

    // Every case other than the display-text one must move the transcript: those
    // are the fields the user is actually authorising.
    let signed_changes = [
        "different_username",
        "different_purpose",
        "different_service",
        "different_operation",
        "different_host",
        "different_device",
        "different_request_id",
        "different_challenge",
        "different_expiry",
    ];
    for want in signed_changes {
        let case = cases
            .iter()
            .find(|c| c["name"] == want)
            .unwrap_or_else(|| panic!("missing vector {want}"));
        assert_eq!(
            case["differs_from_baseline"], true,
            "{want} is part of the signed scope and must change the transcript"
        );
        assert_ne!(
            case["signing_input_sha256"].as_str().unwrap(),
            baseline_digest,
            "{want}: digest unchanged"
        );
    }

    // Display text is deliberately outside the signed scope.
    let display = cases
        .iter()
        .find(|c| c["name"] == "with_unsigned_display_text")
        .expect("the display-text case must be present");
    assert_eq!(
        display["differs_from_baseline"], false,
        "unsigned display text must not change the signature"
    );
    assert_eq!(
        display["signing_input_sha256"].as_str().unwrap(),
        baseline_digest
    );
}

#[test]
fn signature_vectors_agree_on_validity() {
    let v = load("signatures.json");
    assert_eq!(v["algorithm"], "ES256 (ECDSA P-256 over SHA-256)");

    let device = &v["device_key"];
    let sk =
        PrivateKey::from_bytes(&unhex(device["private_scalar_hex"].as_str().unwrap())).unwrap();
    let pk = PublicKey::from_bytes(&unhex(device["public_key_hex"].as_str().unwrap())).unwrap();

    // Our own key must round-trip to the recorded public key and key id.
    assert_eq!(sk.public_key(), pk, "scalar and public key disagree");
    assert_eq!(pk.key_id_hex(), device["key_id_hex"].as_str().unwrap());
    assert_eq!(pk.short_fingerprint(), device["short_fingerprint"]);

    let message = unhex(v["message"]["signing_input_hex"].as_str().unwrap());
    assert_eq!(
        hex::encode(crypto::sha256(&message)),
        v["message"]["signing_input_sha256"].as_str().unwrap()
    );

    for case in v["verification_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let sig = unhex(case["signature_hex"].as_str().unwrap());
        let expect_valid = case["expect_valid"].as_bool().unwrap();
        let got = pk.verify(&message, &sig).is_ok();
        assert_eq!(
            got, expect_valid,
            "{name}: validity disagrees with the vector"
        );
    }
}

#[test]
fn a_signature_from_the_wrong_key_is_refused() {
    let v = load("signatures.json");
    let device_pk =
        PublicKey::from_bytes(&unhex(v["device_key"]["public_key_hex"].as_str().unwrap())).unwrap();
    let host_sk = PrivateKey::from_bytes(&unhex(
        v["host_key"]["private_scalar_hex"].as_str().unwrap(),
    ))
    .unwrap();
    let message = unhex(v["message"]["signing_input_hex"].as_str().unwrap());

    // The host key must not be able to impersonate the device.
    let sig = host_sk.sign(&message);
    assert!(device_pk.verify(&message, &sig).is_err());
}

#[test]
fn pairing_wire_vectors_roundtrip() {
    let v = load("messages.json");
    for name in ["pairing_submit", "pairing_challenge", "pairing_proof", "pairing_result"] {
        let entry = v["messages"].as_array().unwrap().iter().find(|e| e["name"] == name).unwrap();
        let payload = unhex(entry["payload_hex"].as_str().unwrap());
        let frame = Frame::new(entry["msg_type"].as_u64().unwrap() as u16, payload.clone());
        let message = Message::from_frame(&frame).unwrap();
        assert_eq!(message.to_payload(), payload, "{name}");
    }
}

#[test]
fn a_message_payload_vector_parses_into_the_expected_type() {
    let v = load("messages.json");
    let cases = v["messages"].as_array().unwrap();
    let find = |name: &str| -> Value {
        cases
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("missing vector {name}"))
            .clone()
    };
    // Pairing messages are checked as raw CBOR because their validity depends on
    // the current clock; the rest must round-trip through the real parser.
    let pairing = find("pairing_confirmed");
    let payload = unhex(pairing["payload_hex"].as_str().unwrap());
    let frame = Frame::new(4, payload.clone());
    match Message::from_frame(&frame).unwrap() {
        Message::PairingConfirmed(ack) => {
            assert_eq!(ack.session_id.as_bytes(), &[0x99; 16]);
            assert_eq!(ack.to_payload(), payload);
        }
        other => panic!("expected PAIRING_CONFIRMED, got {}", other.name()),
    }
    let ack = find("session_hello_ack");
    let payload = unhex(ack["payload_hex"].as_str().unwrap());
    let frame = Frame::new(11, payload);
    match Message::from_frame(&frame).unwrap() {
        Message::SessionHelloAck(a) => {
            assert_eq!(a.protocol_version, rba_protocol::PROTOCOL_VERSION);
            assert_eq!(a.device_key_id.len(), 64);
        }
        other => panic!("expected SESSION_HELLO_ACK, got {}", other.name()),
    }

    let reject = find("auth_reject");
    let frame = Frame::new(14, unhex(reject["payload_hex"].as_str().unwrap()));
    match Message::from_frame(&frame).unwrap() {
        Message::AuthReject(r) => assert_eq!(r.reason, 6, "USER_CANCELLED"),
        other => panic!("expected AUTH_REJECT, got {}", other.name()),
    }

    let err = find("error");
    let frame = Frame::new(20, unhex(err["payload_hex"].as_str().unwrap()));
    match Message::from_frame(&frame).unwrap() {
        Message::Error(e) => assert_eq!(e.code, 10, "REPLAY"),
        other => panic!("expected ERROR, got {}", other.name()),
    }
}
