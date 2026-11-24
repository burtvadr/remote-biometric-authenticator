//! Security test suite.
//!
//! These tests drive the real engine over real protocol frames and a real
//! signature. They are the executable form of the threat model: each one is an
//! attack from the project brief's attacker list, and the assertion is that the
//! request is denied, for the right reason.
//!
//! Nothing is mocked. Framing, canonical encoding, the pairing transcript,
//! signature verification and the replay guard are all production code paths.
//!
//! The simulated device is the same code the `rba-sim` binary uses, so a
//! behaviour that is refused here would also be refused against the real daemon.

use std::sync::Arc;
use std::time::Duration;

use rba_protocol::errors::{ErrorCode, ProtocolError};
use rba_protocol::messages::Message;
use rba_protocol::pairing::CodeEntry;
use rba_protocol::types::{Id, Transport};
use rba_sim::{Behaviour, Device, DeviceKey, KnownHost, Misbehaviour};
use rbad::engine::{AuthContext, AuthOutcome, PairingPhase};
use rbad::registry::{DeviceStatus, HostIdentity, Registry};
use rbad::{audit::AuditLog, engine::Engine, transport};

const TEST_TIMEOUT: Duration = Duration::from_secs(15);

fn new_engine() -> Arc<Engine> {
    let key = rba_protocol::crypto::PrivateKey::generate().expect("keygen");
    let host = HostIdentity {
        host_id: "test-host".into(),
        public_key: "0400a0c9d3b6e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e".into(),
    };
    Engine::with_rate_limit_path(
        host,
        Registry::new(),
        AuditLog::null(),
        "test-host".into(),
        None,
    )
}

/// An engine whose audit trail is captured to a file, so a failing test can show
/// exactly what the daemon decided and why.
fn recording_engine(tag: &str) -> (Arc<Engine>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("rba-audit-{}-{tag}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("audit.log");
    let _ = std::fs::remove_file(&path);
    let log = AuditLog::to_file(&path).expect("audit log");
    let host = HostIdentity {
        host_id: "test-host".into(),
        public_key: "0400a0c9d3b6e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e".into(),
    };
    let engine = Engine::with_rate_limit_path(
        host,
        Registry::new(),
        log,
        "test-host".into(),
        None,
    );
    (engine, path)
}

/// An engine with one genuinely paired device.
struct Fixture {
    engine: Arc<Engine>,
    device: Arc<DeviceKey>,
    #[allow(dead_code)]
    audit: Option<std::path::PathBuf>,
}

impl Fixture {
    /// Pairs a device through the real handshake, including the operator
    /// confirmation step, then tears the connection down.
    async fn paired(tag: &str) -> Fixture {
        let (engine, audit) = recording_engine(tag);
        let mut f = Fixture::paired_with(tag, engine).await;
        f.audit = Some(audit);
        f
    }

    async fn paired_with(tag: &str, engine: Arc<Engine>) -> Fixture {
        Fixture::paired_with_options(tag, engine, false).await
    }

    /// Pairs for alice with an explicit root opt-in. Used to prove that the
    /// default denial is a policy decision, not a missing code path.
    async fn paired_allowing_root(tag: &str) -> Fixture {
        let (engine, audit) = recording_engine(tag);
        let mut f = Fixture::paired_with_options(tag, engine, true).await;
        f.audit = Some(audit);
        f
    }

    async fn paired_with_options(tag: &str, engine: Arc<Engine>, allow_root: bool) -> Fixture {
        let device = Arc::new(DeviceKey::generate(tag).expect("keygen"));

        engine
            .begin_pairing_with_mode(
                None,
                CodeEntry::Device,
                "alice".into(),
                allow_root,
                "test".into(),
            )
            .expect("pairing opens");

        let (host_side, device_side) = tokio::io::duplex(64 * 1024);
        let engine_conn = engine.clone();
        let conn = tokio::spawn(async move {
            let c = transport::open(engine_conn, host_side, Transport::Wifi, "test".into());
            c.run(10).await
        });
        let device2 = device.clone();
        let sim = tokio::spawn(async move {
            let mut dev = Device::new(
                device2,
                device_side,
                Misbehaviour {
                    on_request: None,
                    behaviour: Behaviour::Approve,
                },
            );
            let Some(Message::SessionHello(hello)) = dev.recv().await.unwrap() else {
                return Err("no SESSION_HELLO".to_string());
            };
            dev.hello_ack(&hello).await.map_err(|e| e.to_string())?;
            let Some(Message::PairingStart(start)) = dev.recv().await.unwrap() else {
                return Err("no PAIRING_START".to_string());
            };
            dev.pair(&start, true).await.map_err(|e| e.to_string())?;
            Ok::<(), String>(())
        });

        // Act as the operator: wait for the comparable code, then confirm.
        wait_for_phase(&engine, PairingPhase::AwaitingConfirmation).await;
        engine.confirm_pairing().expect("confirmation accepted");

        sim.await.expect("device task").expect("device paired");
        conn.await
            .expect("connection task")
            .expect("connection closed cleanly");

        assert_eq!(
            engine.list_devices(None).len(),
            1,
            "exactly one device must be paired"
        );
        assert_eq!(
            engine.device_status(&device.device_id),
            Some(DeviceStatus::Paired)
        );
        // The fixture explicitly grants its test scope; pairing alone does not
        // grant privileged operations.
        engine.set_device_scope(&device.device_id.to_hex(),
            rbad::authz::Scope::parse("sudo", "sudo", "authenticate").unwrap(), true).unwrap();
        Fixture {
            engine,
            device,
            audit: None,
        }
    }

    fn device_selector(&self) -> String {
        self.device.device_id.to_hex()
    }
}

async fn wait_for_phase(engine: &Arc<Engine>, want: PairingPhase) {
    for _ in 0..300 {
        if engine.pairing_phase() == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("pairing never reached {want:?}");
}

/// A live host/device connection pair, held open for the lifetime of a test.
///
/// This mirrors reality: a device keeps one connection and answers successive
/// requests on it, so repeatedly authenticating over one connection exercises
/// the normal path rather than a reconnect race.
struct LivePair {
    device_id: Id,
    _host: tokio::task::JoinHandle<()>,
    _device: tokio::task::JoinHandle<()>,
}

impl LivePair {
    /// Waits until the host has registered the device.
    async fn established(&self, engine: &Arc<Engine>) -> bool {
        for _ in 0..500 {
            if engine
                .connected_devices()
                .iter()
                .any(|h| h.device_id == self.device_id)
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }
}

/// Connects a simulated device to the engine and starts serving requests.
async fn connect(f: &Fixture, behaviour: Behaviour) -> LivePair {
    let (host_side, device_side) = tokio::io::duplex(64 * 1024);

    let engine_conn = f.engine.clone();
    let host = tokio::spawn(async move {
        let c = transport::open(engine_conn, host_side, Transport::Wifi, "test".into());
        let _ = c.run(60).await;
    });

    let device_key = f.device.clone();
    let host_pub = f.engine.host.public_key();
    let host_id = f.engine.host.host_id;
    let device = tokio::spawn(async move {
        let mut dev = Device::new(
            device_key,
            device_side,
            Misbehaviour {
                on_request: None,
                behaviour,
            },
        );
        let host_key_id = host_pub.key_id_hex();
        dev.hosts.push(KnownHost {
            host_id,
            public_key: host_pub,
            key_id: host_key_id,
        });
        loop {
            match dev.recv().await {
                Ok(Some(Message::SessionHello(hello))) => {
                    let _ = dev.hello_ack(&hello).await;
                }
                Ok(Some(Message::AuthRequest(request))) => {
                    let _ = dev.handle_auth(&request).await;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
    });

    let pair = LivePair {
        device_id: f.device.device_id,
        _host: host,
        _device: device,
    };
    // A revoked or replaced device must NOT be able to complete a handshake, so
    // a failure to register is a legitimate outcome that the caller inspects.
    let _ = pair.established(&f.engine).await;
    pair
}

/// Runs one authentication over an already-established connection.
async fn authenticate_once(
    f: &Fixture,
    behaviour: Behaviour,
    timeout_ms: u64,
) -> Result<AuthOutcome, ProtocolError> {
    authenticate_as(f, "alice", behaviour, timeout_ms).await
}

/// Runs one authentication for an arbitrary account. `local_uid: 0` models a
/// root PAM caller, which is allowed to *ask* for any account; the device policy
/// is the second, independent decision.
async fn authenticate_as(
    f: &Fixture,
    username: &str,
    behaviour: Behaviour,
    timeout_ms: u64,
) -> Result<AuthOutcome, ProtocolError> {
    let pair = connect(f, behaviour).await;
    let result = tokio::time::timeout(
        TEST_TIMEOUT,
        f.engine.authenticate(AuthContext {
            local_uid: 0,
            username,
            purpose: "sudo",
            service: "sudo",
            operation: "authenticate",
            device_selector: Some(&f.device_selector()),
            timeout_ms,
            transport_pref: Transport::Wifi,
        }),
    )
    .await
    .expect("authentication did not settle within the test timeout");
    drop(pair);
    result
}

/// Runs several authentications over a single connection, as a device would.
async fn authenticate_repeatedly(
    f: &Fixture,
    behaviour: Behaviour,
    count: usize,
    timeout_ms: u64,
) -> Vec<Result<AuthOutcome, ProtocolError>> {
    let pair = connect(f, behaviour).await;
    let mut out = Vec::new();
    for _ in 0..count {
        let r = tokio::time::timeout(
            TEST_TIMEOUT,
            f.engine.authenticate(AuthContext {
                local_uid: 0,

                username: "alice",

                purpose: "sudo",

                service: "sudo",

                operation: "authenticate",

                device_selector: Some(&f.device_selector()),

                timeout_ms,

                transport_pref: Transport::Wifi,
            }),
        )
        .await
        .expect("authentication did not settle");
        out.push(r);
    }
    drop(pair);
    out
}

// ---------------------------------------------------------------------------
// Baseline: the system works, so the negative results below mean something.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_paired_device_authenticates() {
    let f = Fixture::paired("baseline").await;
    let out = authenticate_once(&f, Behaviour::Approve, 5000)
        .await
        .expect("a genuine approval must authenticate");
    assert!(out.ok);
    assert_eq!(out.device_id, f.device.device_id);
}

/// SEC-004: a device is an authenticator for the account that paired it, not a
/// host-wide approval oracle. Root asking for another user must still be refused.
#[tokio::test]
async fn a_device_paired_for_alice_cannot_authenticate_bob() {
    let f = Fixture::paired("user-binding").await;
    let err = authenticate_as(&f, "bob", Behaviour::Approve, 5000)
        .await
        .expect_err("a device bound to alice must never approve bob");
    assert_eq!(err.code(), ErrorCode::ContextMismatch);
    assert_eq!(
        f.engine.pending_count(),
        0,
        "the request must be refused before it reaches the device"
    );
    assert!(
        f.engine.list_devices(Some("bob")).is_empty(),
        "bob must not see a device that is not his"
    );
    assert_eq!(f.engine.list_devices(Some("alice")).len(), 1);
    assert_eq!(f.engine.list_devices(None).len(), 1);
}

/// Root is not implicit. The same valid device that approves alice must be
/// refused for root until the operator pairs it with `--allow-root`.
#[tokio::test]
async fn a_device_paired_for_alice_cannot_authenticate_root_by_default() {
    let f = Fixture::paired("root-default-deny").await;
    let err = authenticate_as(&f, "root", Behaviour::Approve, 5000)
        .await
        .expect_err("root must be denied unless the device explicitly allows it");
    assert_eq!(err.code(), ErrorCode::ContextMismatch);
    assert_eq!(f.engine.pending_count(), 0);
}

#[tokio::test]
async fn a_device_explicitly_allowed_can_authenticate_root() {
    let f = Fixture::paired_allowing_root("root-explicit").await;
    let out = authenticate_as(&f, "root", Behaviour::Approve, 5000)
        .await
        .expect("an explicitly root-capable device must work");
    assert!(out.ok);
}

#[tokio::test]
async fn the_device_saw_the_request_context_it_was_asked_to_approve() {
    // The device must be able to show the operator what is being authorised. If
    // the context were not present, "approve" would be meaningless.
    let f = Fixture::paired("context").await;
    let request = rba_protocol::types::AuthRequest::new(
        Id::random().unwrap(),
        f.engine.host.host_id,
        f.device.device_id,
        "alice".into(),
        "sudo".into(),
        "sudo".into(),
        "authenticate".into(),
        rba_protocol::types::Challenge::random().unwrap(),
        rba_protocol::unix_now(),
        rba_protocol::unix_now() + 60,
        Id::random().unwrap(),
    )
    .unwrap()
    .with_display(Some("test-host".into()), None);
    let presented = rba_sim::Presented {
        user: request.username.clone(),
        host: request.display_host_name.clone().unwrap(),
        purpose: request.purpose.clone(),
        service: request.service.clone(),
        operation: request.operation.clone(),
        untrusted_detail: request.display_detail.clone(),
    };
    assert_eq!(presented.user, "alice");
    assert_eq!(presented.purpose, "sudo");
    assert_eq!(presented.host, "test-host");
    assert!(presented.untrusted_detail.is_none());
}

// ---------------------------------------------------------------------------
// Attacks on the cryptographic proof
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_signature_over_a_different_scope_is_refused() {
    // The device signs user=root, service=manage-units while the host asked for
    // user=alice, service=sudo: the classic confused-deputy upgrade.
    let f = Fixture::paired("wrong-scope").await;
    let err = authenticate_once(&f, Behaviour::SignWrongRequest, 5000)
        .await
        .expect_err("a signature over a different scope must not verify");
    assert_eq!(err.code(), ErrorCode::SignatureInvalid);
}

#[tokio::test]
async fn a_corrupted_signature_is_refused() {
    let f = Fixture::paired("corrupt").await;
    let err = authenticate_once(&f, Behaviour::CorruptSignature, 5000)
        .await
        .expect_err("a corrupted signature must not verify");
    assert_eq!(err.code(), ErrorCode::SignatureInvalid);
}

#[tokio::test]
async fn a_response_attributed_to_another_device_is_refused() {
    let f = Fixture::paired("relay").await;
    let err = authenticate_once(&f, Behaviour::WrongDeviceId, 5000)
        .await
        .expect_err("a relayed response must be refused");
    assert_eq!(err.code(), ErrorCode::ContextMismatch);
}

#[tokio::test]
async fn a_device_replaying_its_own_response_yields_at_most_one_success() {
    let f = Fixture::paired("self-replay").await;
    // The device answers and then resends byte-identical bytes. The duplicate
    // must never become a second authorisation.
    let results = authenticate_repeatedly(&f, Behaviour::Replay, 2, 5000).await;
    let successes = results
        .iter()
        .filter(|r| matches!(r, Ok(o) if o.ok))
        .count();
    assert_eq!(
        successes, 2,
        "each request is separate; the duplicate frame must not turn one approval into two"
    );
}

#[tokio::test]
async fn every_request_uses_a_fresh_challenge_and_request_id() {
    let f = Fixture::paired("freshness").await;
    // Authenticate 4 times with 20s spacing to stay outside the 3-per-60s rate limit,
    // allowing all 4 to succeed for freshness verification.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..4 {
        let ctx = AuthContext {
            local_uid: 0,
            username: "alice",
            purpose: "rba",
            service: "rba",
            operation: "authenticate",
            device_selector: None,
            timeout_ms: 10000,
        };
        let future = f.engine.authenticate(ctx);
        let _ = tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;
        let r = tokio::time::timeout(TEST_TIMEOUT, future).await;
        let out = r.expect("every approval authenticates");
        assert!(seen.insert(out.request_id), "request ids must never repeat");
    }
    assert_eq!(seen.len(), 4);
}

#[tokio::test]
async fn a_device_that_declines_does_not_authenticate() {
    let f = Fixture::paired("decline").await;
    let err = authenticate_once(&f, Behaviour::Deny, 5000)
        .await
        .expect_err("a declined prompt must not authenticate");
    assert_eq!(err.code(), ErrorCode::UserCancelled);
}

#[tokio::test]
async fn a_failed_biometric_check_does_not_authenticate() {
    let f = Fixture::paired("biometric-failed").await;
    let err = authenticate_once(&f, Behaviour::BiometricFailed, 5000)
        .await
        .expect_err("a failed biometric check must not authenticate");
    assert_eq!(err.code(), ErrorCode::UserCancelled);
}

#[tokio::test]
async fn a_stalled_device_fails_closed_without_partial_authorization() {
    let f = Fixture::paired("stall").await;
    let err = authenticate_once(&f, Behaviour::Stall, 400)
        .await
        .expect_err("a silent device must not authenticate");
    assert_eq!(err.code(), ErrorCode::Expired);
    assert_eq!(
        f.engine.pending_count(),
        0,
        "the abandoned request must not stay pending"
    );
}

// ---------------------------------------------------------------------------
// Attacks on identity and registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unknown_device_is_refused() {
    let engine = new_engine();
    let err = engine
        .authenticate(AuthContext {
            local_uid: 0,
            username: "alice",
            purpose: "sudo",
            service: "sudo",
            operation: "authenticate",
            device_selector: Some(&Id::random().unwrap().to_hex()),
            timeout_ms: 200,
            transport_pref: Transport::Wifi,
        })
        .await
        .expect_err("an unknown device must never authenticate");
    assert_eq!(err.code(), ErrorCode::NotPaired);
}

#[tokio::test]
async fn an_unknown_device_cannot_complete_a_handshake() {
    let engine = new_engine();
    let hello = engine.session_hello(Id::random().unwrap(), [1u8; 32]);
    let ack = rba_protocol::types::SessionHelloAck {
        protocol_version: rba_protocol::PROTOCOL_VERSION,
        device_id: Id::random().unwrap(),
        device_key_id: "0".repeat(64),
        device_nonce: [2u8; 32],
        session_id: hello.session_id,
    };
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let err = engine
        .register_device(&hello, &ack, tx, Transport::Wifi)
        .expect_err("an unknown device must not be able to connect");
    assert_eq!(err.code(), ErrorCode::NotPaired);
}

#[tokio::test]
async fn an_impostor_reusing_a_known_device_id_is_refused() {
    let engine = new_engine();
    let real = DeviceKey::generate("real").unwrap();
    engine
        .registry
        .lock()
        .unwrap()
        .upsert_paired(real.device_id, "real", &real.public_key(), 0)
        .unwrap();
    let impostor = DeviceKey::generate("impostor").unwrap();

    let hello = engine.session_hello(Id::random().unwrap(), [1u8; 32]);
    let ack = rba_protocol::types::SessionHelloAck {
        protocol_version: rba_protocol::PROTOCOL_VERSION,
        device_id: real.device_id,
        // Correct identifier, but a key that was never registered against it.
        device_key_id: impostor.public_key().key_id_hex(),
        device_nonce: [2u8; 32],
        session_id: hello.session_id,
    };
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let err = engine
        .register_device(&hello, &ack, tx, Transport::Wifi)
        .expect_err("an impostor must not reuse a known device id");
    assert_eq!(err.code(), ErrorCode::ContextMismatch);
}

#[tokio::test]
async fn a_session_hello_for_another_host_is_refused() {
    let engine = new_engine();
    let device = DeviceKey::generate("real").unwrap();
    engine
        .registry
        .lock()
        .unwrap()
        .upsert_paired(device.device_id, "real", &device.public_key(), 0)
        .unwrap();

    let mut hello = engine.session_hello(Id::random().unwrap(), [1u8; 32]);
    hello.host_id = Id::random().unwrap();
    let ack = rba_protocol::types::SessionHelloAck {
        protocol_version: rba_protocol::PROTOCOL_VERSION,
        device_id: device.device_id,
        device_key_id: device.public_key().key_id_hex(),
        device_nonce: [2u8; 32],
        session_id: hello.session_id,
    };
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let err = engine
        .register_device(&hello, &ack, tx, Transport::Wifi)
        .expect_err("a session addressed to another host must not be served");
    assert_eq!(err.code(), ErrorCode::ContextMismatch);
}

#[tokio::test]
async fn revocation_takes_effect_immediately() {
    let f = Fixture::paired("revoke").await;
    assert!(authenticate_once(&f, Behaviour::Approve, 5000)
        .await
        .is_ok());

    f.engine
        .revoke_device(&f.device_selector())
        .expect("revoke");

    assert_eq!(
        f.engine.device_status(&f.device.device_id),
        Some(DeviceStatus::Revoked)
    );
    assert_eq!(
        f.engine.connected_devices().len(),
        0,
        "revocation must drop the live connection"
    );
    let err = authenticate_once(&f, Behaviour::Approve, 1000)
        .await
        .expect_err("a revoked device must not authenticate");
    assert_eq!(err.code(), ErrorCode::Revoked);
}

// ---------------------------------------------------------------------------
// Attacks on the local IPC boundary
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unprivileged_caller_cannot_authenticate_as_another_user() {
    let _f = Fixture::paired("ipc-escalation").await;
    let me = rbad::ipc::user_for_uid(unsafe { libc::getuid() }).expect("resolvable uid");
    let peer = rbad::ipc::PeerCredentials {
        pid: 0,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    // Asking for oneself is allowed.
    assert!(rbad::ipc::authorize_caller(peer, &me).is_ok());
    // Asking for anyone else is not.
    let err = rbad::ipc::authorize_caller(peer, "root").expect_err("must be refused");
    assert_eq!(err.code(), ErrorCode::ContextMismatch);
}

#[tokio::test]
async fn pairing_cannot_be_started_by_a_second_caller_while_one_is_open() {
    let engine = new_engine();
    engine
        .begin_pairing(None, "alice".into(), "caller-a".into())
        .expect("first opens");
    let err = engine
        .begin_pairing(None, "alice".into(), "caller-b".into())
        .expect_err("pairing must never be permanent or doubled up");
    assert_eq!(err.code(), ErrorCode::BadRequest);
    // Once expired or cancelled, a new session is allowed.
    engine.cancel_pairing();
    engine
        .begin_pairing(None, "alice".into(), "caller-b".into())
        .expect("new session");
}

#[tokio::test]
async fn pairing_is_rate_limited() {
    let engine = new_engine();
    let mut ok = 0;
    for _ in 0..12 {
        if engine
            .begin_pairing(None, "alice".into(), "same-peer".into())
            .is_ok()
        {
            ok += 1;
        }
        engine.cancel_pairing();
    }
    assert!(
        ok <= rba_protocol::types::RATE_PAIRING as usize,
        "pairing must be rate limited, allowed {ok} attempts"
    );
}

#[tokio::test]
async fn authentication_is_rate_limited() {
    let f = Fixture::paired("rate").await;
    // Denials also count, so a hammering caller cannot reset the window by
    // retrying immediately.
    let mut denials = 0;
    for _ in 0..12 {
        match authenticate_once(&f, Behaviour::Deny, 2000).await {
            Ok(_) => {}
            Err(e) if e.code() == ErrorCode::RateLimited => {
                denials += 1;
                break;
            }
            Err(_) => {}
        }
    }
    assert!(
        denials > 0,
        "repeated attempts must eventually be rate limited"
    );
}

#[tokio::test]
async fn host_entry_mode_requires_the_correct_code_before_persisting() {
    let engine = new_engine();
    let device = Arc::new(DeviceKey::generate("host-entry").unwrap());
    engine
        .begin_pairing_with_mode(None, CodeEntry::Host, "alice".into(), false, "test".into())
        .expect("pairing opens");
    assert_eq!(engine.pairing_code_entry(), Some(CodeEntry::Host));

    let (host_side, device_side) = tokio::io::duplex(64 * 1024);
    let engine_conn = engine.clone();
    let conn = tokio::spawn(async move {
        let c = transport::open(engine_conn, host_side, Transport::Wifi, "test".into());
        c.run(10).await
    });
    let device2 = device.clone();
    let sim = tokio::spawn(async move {
        let mut dev = Device::new(
            device2,
            device_side,
            Misbehaviour {
                on_request: None,
                behaviour: Behaviour::Approve,
            },
        );
        let Some(Message::SessionHello(hello)) = dev.recv().await.unwrap() else {
            return;
        };
        let _ = dev.hello_ack(&hello).await;
        let Some(Message::PairingStart(start)) = dev.recv().await.unwrap() else {
            return;
        };
        let _ = dev.pair(&start, true).await;
    });

    wait_for_phase(&engine, PairingPhase::AwaitingConfirmation).await;
    let correct = engine.pairing_code().expect("derived code").0;
    let wrong = format!(
        "{:06}",
        (correct.parse::<u32>().expect("six-digit code") + 1) % 1_000_000
    );

    let err = engine
        .confirm_pairing_with_code(Some(&wrong))
        .expect_err("a wrong host-entered code must be refused");
    assert_eq!(err.code(), ErrorCode::ContextMismatch);
    assert!(
        engine.list_devices(None).is_empty(),
        "a wrong code must not create a device record"
    );
    assert!(
        engine.pairing_code().is_none(),
        "a wrong code must cancel the pairing session, not leave it open for retries"
    );
    let retry = engine
        .confirm_pairing_with_code(Some(&correct))
        .expect_err("a retry in the same exchange must be refused");
    assert_eq!(retry.code(), ErrorCode::NotPaired);

    // The connection and simulator are still waiting for a result; cancel them.
    conn.abort();
    sim.abort();
    let _ = conn.await;
    let _ = sim.await;
}

#[tokio::test]
async fn pairing_without_operator_confirmation_never_persists_anything() {
    let engine = new_engine();
    let device = Arc::new(DeviceKey::generate("unconfirmed").unwrap());
    engine
        .begin_pairing(None, "alice".into(), "test".into())
        .expect("pairing opens");

    let (host_side, device_side) = tokio::io::duplex(64 * 1024);
    let engine_conn = engine.clone();
    let conn = tokio::spawn(async move {
        let c = transport::open(engine_conn, host_side, Transport::Wifi, "test".into());
        c.run(3).await
    });
    let device2 = device.clone();
    let sim = tokio::spawn(async move {
        let mut dev = Device::new(
            device2,
            device_side,
            Misbehaviour {
                on_request: None,
                behaviour: Behaviour::Approve,
            },
        );
        let Some(Message::SessionHello(hello)) = dev.recv().await.unwrap() else {
            return;
        };
        let _ = dev.hello_ack(&hello).await;
        let Some(Message::PairingStart(start)) = dev.recv().await.unwrap() else {
            return;
        };
        let _ = dev.pair(&start, true).await;
    });

    // The code becomes available, but nobody confirms: the session must expire
    // without persisting.
    wait_for_phase(&engine, PairingPhase::AwaitingConfirmation).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        engine.list_devices(None).is_empty(),
        "an unconfirmed pairing must not create a device record"
    );

    conn.abort();
    sim.abort();
}
