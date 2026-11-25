//! Generates the cross-language conformance vectors.
//!
//! The Kotlin implementation of `PROTOCOL.md` is written independently, against
//! the specification rather than against this code. These vectors are what prove
//! the two implementations actually agree on the wire and on the signing
//! transcript; without them "two implementations" is only a claim.
//!
//! Run with:
//!
//! ```text
//! cargo run -p rba-protocol --bin vecgen -- ../protocol/test-vectors
//! ```
//!
//! Signatures are *not* compared byte-for-byte. ECDSA is randomised on Android,
//! where the Keystore chooses the per-signature nonce, so a byte comparison would
//! be meaningless. What must match exactly is the canonical encoding and the
//! signing transcript; those are recorded as hex, together with the SHA-256
//! digest of the transcript.

use std::fs;
use std::path::PathBuf;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey as P256SecretKey;
use rba_protocol::cbor;
use rba_protocol::crypto::{self, PrivateKey};
use rba_protocol::frame::{Frame, HEADER_LEN, MAGIC, PROTOCOL_VERSION};
use rba_protocol::messages::Message;
use rba_protocol::pairing::{PairingChallenge, PairingConfirmed, PairingProof, PairingResult, PairingStart, PairingSubmit};
use rba_protocol::types::{
    AuthReject, AuthRequest, AuthResponse, Challenge, ErrorMsg, Id, SessionHello, SessionHelloAck,
    AUTH_REQUEST_TTL_DEFAULT,
};
use serde_json::{json, Value};

fn hexs(b: &[u8]) -> String {
    hex::encode(b)
}

fn det_eph(seed: u8) -> P256SecretKey {
    P256SecretKey::from_slice(&[seed; 32]).expect("valid P-256 scalar")
}

fn eph_public(secret: &P256SecretKey) -> [u8; crypto::PUBKEY_LEN] {
    let point = secret.public_key().to_encoded_point(false);
    let mut bytes = [0u8; crypto::PUBKEY_LEN];
    bytes.copy_from_slice(point.as_bytes());
    bytes
}

/// Builds a complete 13-byte frame header.
///
/// A malformed-input vector must be well formed *as a frame* so that it is
/// rejected only for the property under test, rather than for being truncated.
fn malformed_header(
    magic: &[u8; 4],
    version: u8,
    msg_type: u16,
    flags: u16,
    payload_len: u32,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN);
    v.extend_from_slice(magic);
    v.push(version);
    v.extend_from_slice(&msg_type.to_be_bytes());
    v.extend_from_slice(&flags.to_be_bytes());
    v.extend_from_slice(&payload_len.to_be_bytes());
    assert_eq!(v.len(), HEADER_LEN);
    v
}

/// Deterministic identifiers so regenerating the vectors produces identical
/// files, which keeps the fixtures reviewable in diffs.
fn det_id(byte: u8) -> Id {
    Id([byte; 16])
}

fn det_challenge(byte: u8) -> Challenge {
    Challenge([byte; 32])
}

fn base_request() -> AuthRequest {
    AuthRequest::new(
        det_id(0x11),
        det_id(0x22),
        det_id(0x33),
        "alice".into(),
        "sudo".into(),
        "sudo".into(),
        "authenticate".into(),
        det_challenge(0x44),
        1_700_000_000,
        1_700_000_000 + AUTH_REQUEST_TTL_DEFAULT,
        det_id(0x55),
    )
    .expect("valid request")
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../protocol/test-vectors"));
    fs::create_dir_all(&out_dir).expect("create output directory");

    // ---------------------------------------------------------------------
    // 1. Canonical CBOR encoding vectors
    // ---------------------------------------------------------------------
    let mut cbor_cases: Vec<Value> = Vec::new();
    let mut push_cbor = |name: &str, desc: &str, value: cbor::Value, accepted: bool| {
        let encoded = cbor::encode(&value);
        let roundtrip_ok = match cbor::decode(&encoded) {
            Ok(v) => cbor::encode(&v) == encoded,
            Err(_) => false,
        };
        cbor_cases.push(json!({
            "name": name,
            "description": desc,
            "accepted": accepted,
            "value_hex": hexs(&encoded),
            "roundtrip_stable": roundtrip_ok,
        }));
    };

    push_cbor(
        "uint_zero",
        "smallest unsigned integer",
        cbor::Value::Uint(0),
        true,
    );
    push_cbor(
        "uint_23",
        "largest single-byte integer",
        cbor::Value::Uint(23),
        true,
    );
    push_cbor(
        "uint_24",
        "first two-byte integer",
        cbor::Value::Uint(24),
        true,
    );
    push_cbor(
        "uint_255",
        "largest one-byte argument",
        cbor::Value::Uint(255),
        true,
    );
    push_cbor(
        "uint_256",
        "first three-byte integer",
        cbor::Value::Uint(256),
        true,
    );
    push_cbor(
        "uint_65536",
        "first four-byte integer",
        cbor::Value::Uint(65536),
        true,
    );
    push_cbor(
        "uint_max",
        "largest unsigned integer",
        cbor::Value::Uint(u64::MAX),
        true,
    );
    push_cbor(
        "nint_minus_one",
        "-1 encoded as major type 1, argument 0",
        cbor::Value::Nint(0),
        true,
    );
    push_cbor(
        "nint_minus_24",
        "-24 still fits in one byte",
        cbor::Value::Nint(23),
        true,
    );
    push_cbor(
        "nint_minus_25",
        "-25 needs two bytes",
        cbor::Value::Nint(24),
        true,
    );
    push_cbor(
        "text_empty",
        "empty text string",
        cbor::Value::Text(String::new()),
        true,
    );
    push_cbor(
        "text_ascii",
        "ascii text string",
        cbor::Value::Text("alice".into()),
        true,
    );
    push_cbor(
        "text_unicode",
        "multi-byte UTF-8 text string",
        cbor::Value::Text("Benutzer\u{00e4}".into()),
        true,
    );
    push_cbor(
        "bytes_empty",
        "empty byte string",
        cbor::Value::Bytes(Vec::new()),
        true,
    );
    push_cbor(
        "bytes_16",
        "16-byte identifier",
        cbor::Value::Bytes(vec![0x33; 16]),
        true,
    );
    push_cbor(
        "bytes_32",
        "32-byte challenge",
        cbor::Value::Bytes(vec![0x44; 32]),
        true,
    );
    push_cbor("bool_false", "false", cbor::Value::Bool(false), true);
    push_cbor("bool_true", "true", cbor::Value::Bool(true), true);
    push_cbor(
        "map_canonical_order",
        "map keys sorted by encoded bytes: 'b' (0x6162) before 'aa' (0x626161)",
        cbor::Value::map([("aa", cbor::Value::Uint(2)), ("b", cbor::Value::Uint(1))]),
        true,
    );
    push_cbor(
        "nested_map",
        "map containing an array of maps",
        cbor::Value::map([(
            "inner",
            cbor::Value::Array(vec![
                cbor::Value::map([("x", cbor::Value::Uint(1))]),
                cbor::Value::map([("y", cbor::Value::Uint(2))]),
            ]),
        )]),
        true,
    );

    // Non-canonical forms a decoder MUST reject.
    let mut reject_cbor: Vec<Value> = Vec::new();
    let mut push_reject = |name: &str, desc: &str, bytes: Vec<u8>, rule: &str| {
        let actually_rejected = cbor::decode(&bytes).is_err();
        reject_cbor.push(json!({
            "name": name,
            "description": desc,
            "rule": rule,
            "value_hex": hexs(&bytes),
            "rejected_by_rust": actually_rejected,
        }));
    };
    push_reject(
        "uint_nonminimal_8",
        "0 encoded in two bytes",
        vec![0x18, 0x00],
        "R2",
    );
    push_reject(
        "uint_nonminimal_16",
        "24 encoded in three bytes",
        vec![0x19, 0x00, 0x18],
        "R2",
    );
    push_reject(
        "uint_nonminimal_32",
        "256 encoded in five bytes",
        vec![0x1a, 0x00, 0x00, 0x01, 0x00],
        "R2",
    );
    push_reject(
        "indefinite_bytes",
        "indefinite-length byte string",
        vec![0x5f, 0x41, 0x01, 0xff],
        "R1",
    );
    push_reject(
        "indefinite_array",
        "indefinite-length array",
        vec![0x9f, 0x01, 0xff],
        "R1",
    );
    push_reject(
        "indefinite_map",
        "indefinite-length map",
        vec![0xbf, 0xff],
        "R1",
    );
    push_reject("tag", "tagged item", vec![0xc0, 0x00], "R6");
    push_reject(
        "float64",
        "64-bit float",
        vec![0xfb, 0, 0, 0, 0, 0, 0, 0, 0],
        "R7",
    );
    push_reject("undefined", "undefined simple value", vec![0xf7], "R7");
    push_reject(
        "trailing_bytes",
        "valid value followed by a stray byte",
        vec![0x01, 0x02],
        "R4/R5 frame integrity",
    );
    push_reject(
        "truncated_bytes",
        "byte string shorter than declared",
        vec![0x43, 0x01, 0x02],
        "R1",
    );
    let mut unsorted = vec![0xa2u8];
    unsorted.extend_from_slice(&cbor::encode(&cbor::Value::Text("b".into())));
    unsorted.extend_from_slice(&cbor::encode(&cbor::Value::Uint(1)));
    unsorted.extend_from_slice(&cbor::encode(&cbor::Value::Text("a".into())));
    unsorted.extend_from_slice(&cbor::encode(&cbor::Value::Uint(2)));
    push_reject(
        "map_unsorted",
        "map keys out of canonical order",
        unsorted,
        "R4",
    );
    let mut dup = vec![0xa2u8];
    dup.extend_from_slice(&cbor::encode(&cbor::Value::Text("a".into())));
    dup.extend_from_slice(&cbor::encode(&cbor::Value::Uint(1)));
    dup.extend_from_slice(&cbor::encode(&cbor::Value::Text("a".into())));
    dup.extend_from_slice(&cbor::encode(&cbor::Value::Uint(2)));
    push_reject("map_duplicate_key", "map with a repeated key", dup, "R5");
    push_reject(
        "text_overlong",
        "overlong UTF-8 encoding of '/'",
        vec![0x62, 0xc0, 0xaf],
        "R8/§8.6",
    );
    push_reject(
        "text_surrogate",
        "UTF-8 encoded surrogate U+D800",
        vec![0x63, 0xed, 0xa0, 0x80],
        "R8/§8.6",
    );
    push_reject(
        "text_above_max",
        "code point above U+10FFFF",
        vec![0x64, 0xf4, 0x90, 0x80, 0x80],
        "R8/§8.6",
    );

    write_json(
        &out_dir.join("cbor-canonical.json"),
        &json!({
            "spec": "PROTOCOL.md §8.5",
            "description": "Canonical CBOR encoding vectors. Both implementations MUST encode accepted values identically and reject every value in non_canonical.",
            "canonical": cbor_cases,
            "non_canonical": reject_cbor,
        }),
    );

    // ---------------------------------------------------------------------
    // 2. Framing vectors
    // ---------------------------------------------------------------------
    let framing = json!({
        "spec": "PROTOCOL.md §4",
        "description": "Frame layout: magic 'PAF1', version, type, flags, payload length, payload.",
        "header_len": HEADER_LEN,
        "magic_hex": hexs(&MAGIC),
        "frames": [
            {
                "name": "empty_payload",
                "msg_type": 20,
                "frame_hex": hexs(&Frame::new(20, Vec::new()).encode()),
            },
            {
                "name": "auth_request",
                "msg_type": 12,
                "frame_hex": hexs(&Message::AuthRequest(base_request()).to_frame().encode()),
            },
            {
                "name": "large_payload",
                "msg_type": 12,
                "frame_hex": hexs(&Frame::new(12, vec![0xab; 300]).encode()),
            }
        ],
        "rejected": [
            {"name": "bad_magic", "hex": hexs(&malformed_header(b"\xDE\xAD\xBE\xEF", PROTOCOL_VERSION, 1, 0, 0)), "reason": "magic is not PAF1"},
            {"name": "future_version", "hex": hexs(&malformed_header(&MAGIC, PROTOCOL_VERSION + 1, 1, 0, 0)), "reason": format!("version {} is not implemented", PROTOCOL_VERSION + 1)},
            {"name": "nonzero_flags", "hex": hexs(&malformed_header(&MAGIC, PROTOCOL_VERSION, 1, 1, 0)), "reason": format!("flags must be zero in v{}", PROTOCOL_VERSION)},
            {"name": "oversized_length", "hex": hexs(&malformed_header(&MAGIC, PROTOCOL_VERSION, 1, 0, 70_000)), "reason": "payload length exceeds the cap"}
        ]
    });
    write_json(&out_dir.join("framing.json"), &framing);

    // ---------------------------------------------------------------------
    // 3. Message payload vectors
    // ---------------------------------------------------------------------
    let device_sk = PrivateKey::from_bytes(&[0x5au8; 32]).expect("valid key");
    let device_pk = device_sk.public_key();
    let host_sk = PrivateKey::from_bytes(&[0xa7u8; 32]).expect("valid key");

    let messages: Vec<Value> = vec![
        json!({
            "name": "auth_request_minimal",
            "msg_type": 12,
            "payload_hex": hexs(&base_request().to_payload()),
        }),
        json!({
            "name": "auth_request_with_display",
            "description": "unsigned display fields are present in the payload but absent from the signed core",
            "msg_type": 12,
            "payload_hex": hexs(
                &base_request()
                    .with_display(Some("workstation".into()), Some("systemctl restart sshd".into()))
                    .to_payload()
            ),
            "signing_input_sha256_with_display": hexs(
                &base_request()
                    .with_display(Some("workstation".into()), Some("systemctl restart sshd".into()))
                    .signing_input_digest()
            ),
        }),
        json!({
            "name": "session_hello",
            "msg_type": 10,
            "payload_hex": hexs(
                &Message::SessionHello(SessionHello {
                    protocol_version: rba_protocol::PROTOCOL_VERSION,
                    host_id: det_id(0x22),
                    host_key_id: host_sk.public_key().key_id_hex(),
                    host_nonce: [0x66; 32],
                    session_id: det_id(0x55),
                    transports: vec!["wifi".into(), "ble".into()],
                })
                .to_payload()
            ),
        }),
        json!({
            "name": "session_hello_ack",
            "msg_type": 11,
            "payload_hex": hexs(
                &Message::SessionHelloAck(SessionHelloAck {
                    protocol_version: rba_protocol::PROTOCOL_VERSION,
                    device_id: det_id(0x33),
                    device_key_id: device_pk.key_id_hex(),
                    device_nonce: [0x77; 32],
                    session_id: det_id(0x55),
                })
                .to_payload()
            ),
        }),
        json!({
            "name": "auth_response",
            "msg_type": 13,
            "payload_hex": hexs(
                &Message::AuthResponse(AuthResponse {
                    request_id: det_id(0x11),
                    device_id: det_id(0x33),
                    session_id: det_id(0x55),
                    algorithm: "ES256".into(),
                    key_id: device_pk.key_id_hex(),
                    // Fixed here only so the vector is reproducible; the Kotlin
                    // side is not expected to produce identical ECDSA bytes.
                    signature: [0u8; 64],
                })
                .to_payload()
            ),
        }),
        json!({
            "name": "auth_reject",
            "msg_type": 14,
            "payload_hex": hexs(
                &Message::AuthReject(AuthReject {
                    request_id: det_id(0x11),
                    reason: 6,
                })
                .to_payload()
            ),
        }),
        json!({
            "name": "error",
            "msg_type": 20,
            "payload_hex": hexs(
                &Message::Error(ErrorMsg {
                    code: 10,
                    message: "replay".into(),
                    request_id: Some(det_id(0x11)),
                })
                .to_payload()
            ),
        }),
        json!({
            "name": "pairing_start",
            "msg_type": 1,
            "payload_hex": hexs(
                &Message::PairingStart(PairingStart {
                    session_id: det_id(0x99),
                    host_id: det_id(0x22),
                    host_pubkey: host_sk.public_key(),
                    host_key_id: host_sk.public_key().key_id_hex(),
                    code_entry: rba_protocol::pairing::CodeEntry::Device,
                    // PairingStart::from_payload checks the window against the
                    // current clock, so this vector is checked as raw CBOR only.
                    expires_at: 1_700_000_120,
                })
                .to_payload()
            ),
        }),
        json!({
            "name": "pairing_submit",
            "msg_type": 2,
            "payload_hex": hexs(
                &Message::PairingSubmit(PairingSubmit {
                    session_id: det_id(0x99),
                    device_id: det_id(0x33),
                    device_name: "Pixel 9".into(),
                    device_pubkey: device_pk.clone(),
                    device_key_id: device_pk.key_id_hex(),
                    share: eph_public(&det_eph(0x66)),
                })
                .to_payload()
            ),
        }),
        json!({
            "name": "pairing_result",
            "msg_type": 3,
            "payload_hex": hexs(
                &Message::PairingResult(PairingResult {
                    session_id: det_id(0x99),
                    status: 0,
                    revocation_token: Some([0xAA; 32]),
                })
                .to_payload()
            ),
        }),
        json!({ "name": "pairing_challenge", "msg_type": 5,
            "payload_hex": hexs(&Message::PairingChallenge(PairingChallenge { session_id: det_id(0x99), share: eph_public(&det_eph(0x77)), confirmation: [0x11; 32] }).to_payload()) }),
        json!({ "name": "pairing_proof", "msg_type": 6,
            "payload_hex": hexs(&Message::PairingProof(PairingProof { session_id: det_id(0x99), confirmation: [0x22; 32], cleanup_tokens: vec![[0x33; 32]] }).to_payload()) }),
        json!({
            "name": "pairing_confirmed",
            "msg_type": 4,
            "payload_hex": hexs(&Message::PairingConfirmed(PairingConfirmed {
                session_id: det_id(0x99),
            }).to_payload()),
        }),
    ];
    write_json(
        &out_dir.join("messages.json"),
        &json!({
            "spec": "PROTOCOL.md §5-§8",
            "description": "Canonical payload encodings per message type.",
            "messages": messages,
        }),
    );

    // ---------------------------------------------------------------------
    // 4. Signing transcript vectors
    // ---------------------------------------------------------------------
    let mut transcripts: Vec<Value> = Vec::new();
    let base = base_request();
    let mut variants: Vec<(&str, AuthRequest)> = vec![("baseline", base.clone())];

    let mut with_user = base.clone();
    with_user.username = "bob".into();
    variants.push(("different_username", with_user));
    let mut with_purpose = base.clone();
    with_purpose.purpose = "polkit".into();
    variants.push(("different_purpose", with_purpose));
    let mut with_service = base.clone();
    with_service.service = "login".into();
    variants.push(("different_service", with_service));
    let mut with_operation = base.clone();
    with_operation.operation = "authorize".into();
    variants.push(("different_operation", with_operation));
    let mut with_host = base.clone();
    with_host.host_id = det_id(0xEE);
    variants.push(("different_host", with_host));
    let mut with_device = base.clone();
    with_device.device_id = det_id(0xEE);
    variants.push(("different_device", with_device));
    let mut with_request = base.clone();
    with_request.request_id = det_id(0xEE);
    variants.push(("different_request_id", with_request));
    let mut with_challenge = base.clone();
    with_challenge.challenge = det_challenge(0xEE);
    variants.push(("different_challenge", with_challenge));
    let mut with_expiry = base.clone();
    with_expiry.expires_at += 1;
    variants.push(("different_expiry", with_expiry));
    // Display text must not change the transcript.
    variants.push((
        "with_unsigned_display_text",
        base.clone().with_display(
            Some("workstation".into()),
            Some("systemctl restart sshd".into()),
        ),
    ));

    let baseline_digest = base.signing_input_digest();
    for (name, request) in &variants {
        let digest = request.signing_input_digest();
        transcripts.push(json!({
            "name": name,
            "fields": {
                "request_id": hexs(request.request_id.as_bytes()),
                "host_id": hexs(request.host_id.as_bytes()),
                "device_id": hexs(request.device_id.as_bytes()),
                "username": request.username,
                "purpose": request.purpose,
                "service": request.service,
                "operation": request.operation,
                "challenge": hexs(request.challenge.as_bytes()),
                "issued_at": request.issued_at,
                "expires_at": request.expires_at,
                "session_id": hexs(request.session_id.as_bytes()),
            },
            "payload_hex": hexs(&request.to_payload()),
            "request_id": hexs(request.request_id.as_bytes()),
            "username": request.username,
            "purpose": request.purpose,
            "service": request.service,
            "operation": request.operation,
            "signing_input_hex": hexs(&request.signing_input()),
            "signing_input_sha256": hexs(&digest),
            "differs_from_baseline": digest != baseline_digest,
            "expectation": if *name == "with_unsigned_display_text" {
                "identical to baseline: display text is not signed"
            } else {
                "different from baseline: this field is part of the signed scope"
            },
        }));
    }
    write_json(
        &out_dir.join("signing-transcript.json"),
        &json!({
            "spec": "PROTOCOL.md §8.2",
            "description": "The exact bytes signed for an AUTH_REQUEST: domain separator || 0x00 || version || canonical CBOR of the ten signed fields.",
            "domain_separator": "RBA_AUTH_V1",
            "signed_fields": [
                "challenge", "device_id", "expires_at", "host_id", "issued_at",
                "operation", "purpose", "request_id", "service", "username"
            ],
            "cases": transcripts,
        }),
    );

    // ---------------------------------------------------------------------
    // 5. Public keys and signature verification
    // ---------------------------------------------------------------------
    let signed = base.signing_input();
    let good_sig = device_sk.sign(&signed);
    let mut tampered = good_sig;
    tampered[0] ^= 0x01;
    let verify_cases = vec![
        json!({"name": "valid", "expect_valid": true, "signature_hex": hexs(&good_sig)}),
        json!({"name": "bit_flipped", "expect_valid": false, "signature_hex": hexs(&tampered)}),
        json!({"name": "all_zero", "expect_valid": false, "signature_hex": hexs(&[0u8; 64])}),
        json!({"name": "too_short", "expect_valid": false, "signature_hex": hexs(&good_sig[..63])}),
    ];
    write_json(
        &out_dir.join("signatures.json"),
        &json!({
            "spec": "PROTOCOL.md §3, §8.2",
            "description": "Key encodings and verification outcomes. Implementations MUST agree on validity, not on signature bytes.",
            "algorithm": "ES256 (ECDSA P-256 over SHA-256)",
            "device_key": {
                "private_scalar_hex": hexs(&device_sk.to_bytes()),
                "public_key_hex": hexs(device_pk.as_bytes()),
                "key_id_hex": device_pk.key_id_hex(),
                "short_fingerprint": device_pk.short_fingerprint(),
            },
            "host_key": {
                "private_scalar_hex": hexs(&host_sk.to_bytes()),
                "public_key_hex": hexs(host_sk.public_key().as_bytes()),
                "key_id_hex": host_sk.public_key().key_id_hex(),
            },
            "message": {
                "signing_input_hex": hexs(&signed),
                "signing_input_sha256": hexs(&crypto::sha256(&signed)),
            },
            "verification_cases": verify_cases,
        }),
    );

    println!("wrote vectors to {}", out_dir.display());
}

/// Writes pretty-printed JSON with a trailing newline, sorted for stable diffs.
/// Writes pretty-printed JSON with a trailing newline.
fn write_json(path: &std::path::Path, value: &Value) {
    let mut text = serde_json::to_string_pretty(value).expect("serialise vectors");
    text.push('\n');
    fs::write(path, text).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}
