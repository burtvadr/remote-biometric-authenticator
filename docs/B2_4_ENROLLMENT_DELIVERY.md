# B.2.4 — V2 enrollment implementation delivery

Source candidate; not a production activation or SEC finding closure. Baseline is the original uploaded `2b8e76d` archive with the previous B.0, B.1, B.2.1 wire/message, B.2.2 store, B.2.3 authority and B.2.4 authentication deliveries applied. Latest operator B.2.0/OpenCode working-tree archive is not available here. No new external dependencies, no portable-core extraction, no legacy V2 fallback. The existing SPAKE2 crate/JNI are extended in place; existing V1 runtime is untouched pending the coordinated cutover.

## Implementation

- Host enrollment is owned by `Authority` and its admitted connection-specific pairing slot. START generates a CSPRNG nonce and (device-types direction only) local secret code. For host-types, accept the locally entered code only for the owning interaction. Both directions use RFC 9382 A=host, B=device. No SAS, raw code in a message, or exported PAKE key.
- Bind the exact normative V2 ENROLL-CONTEXT transcript to actual provisional TLS keys, DER certificate hashes, exporter, session/enrollment identity, attestation nonce, expiry, direction and both fresh long-term keys. The portable primitive consumes the already validated transcript, not untrusted wire bytes. JNI bounds input and retains the existing one-handle slot; finish consumes it before peer verification. The legacy 219-byte context is not used in V2.
- Both endpoint state machines verify PAKE confirmation before releasing proof/offer transitions. Wrong order, code, confirmation, key proof, expiry or cancellation fails terminally; connection/owner checks prevent stale teardown from affecting a new pairing.
- Two exact ECDSA role proofs, two role-specific challenges and mandatory trusted attestation verifier calls precede host offer. No default or allow-all verifier exists. The concrete chain/status/hardware/app identity validator is still B.3; test verifier checks role/challenge plumbing only. Validity intervals are checked and bounded to the earliest key assurance and status expiry. Host UI must display actual key/certificate fingerprints and proposed exact replacement credentials, obtain explicit approval including replacement list and initial CLI self-grant choice. Only matched previous tokens reach commit. No automatic elevated or inherited grants.
- Device requires explicit post-PAKE context consent and independent exact offer consent. Key proof signatures must verify before evidence transmission. The application must supply fresh strong-biometric CryptoObject proof and obtain cleanup tokens exclusively from same-host local records. The initial offer may contain no grant or one CLI self-grant, with revision 1. Device stages the exact immutable canonical record before sending ENROLL_STAGED. Host commit helper is no longer public; credentials, historical keys, revocations, grants, receipt hash, offer hash and audit are committed atomically by the state machine after exact ACK. No receipt on rollback. A late successful commit is recoverable, not a false rollback claim.
- Device activates only after matching authenticated receipt and an atomic store compare-and-set; interrupted/lost receipt leaves pending state. Recovery requires exact authenticated production host pin, host ID, credential ID, local transport key and HELLO session, one request, matching receipt, and bounded wall/monotonic deadline. Host restricts to matching active credential and consumes the recovery channel; wrong/unknown/revoked requests receive generic denial. No recovery creates another credential or grants.
- `V2DeviceStore` supplies concrete Android SQLite staging/activation in an app-private non-backed-up directory. Explicit initialization only; exact schema/version/application ID and integrity checks, rollback journal and synchronous EXTRA, no default corruption deletion, no V1 reader. Key aliases derived from credential ID and role (`rba-v2-<credential hex>-transport` and `...-biometric`); B.3 generator must use these and never overwrite. Exact public key checks against AndroidKeyStore are not remote attestation. Unique pending record per host, unique credential/enrollment IDs, max 64 total records, 24-hour pending recovery window and explicit discard. Other active records never inherit/overwrite policy. Local unpair/revocation/tombstone and full active policy integration remain later runtime work. These storage limits/alias names are engineering decisions for review, not measured resource requirements.
- Actual TLS/exporter/provisional and production transport, concrete Android key generation/biometric/UI/attestation verifier, trusted local IPC and Android lifecycle wiring remain required B.3/B.4 integration. The new V2 state machines and store are not reachable from the installed V1 runtime. Physical hardware, release APK and actual Android durable-store tests are not established by JVM/SQL tests. Common versioned Unicode profile remains open. No SEC finding is closed.

## Verification performed here

- Python fixture generation and `--check` for existing wire/message fixtures and new two independent enrollment contexts (one per entry direction, role-specific challenges and context hash).
- Standalone Kotlin/JVM: 82 wire + 284 message/transcript + 22 policy + 24 authentication + 52 enrollment + 151 baseline checks = 615 checks passed. Includes compiling the Kotlin JNI wrapper; does NOT execute native JNI. Enrollment tests use test-only PAKE/store implementations to exercise transitions and real JVM ECDSA proof verification; they do not establish PAKE interoperability or device persistence.
- Independent SQLite: 8/8 existing host schema tests and 3/3 Android schema tests passed (Python SQLite 3.46.1). The latter extract actual SQL constants and test uniqueness, bounds, rollback and reopen; they do not run Android SQLite bindings or Keystore.
- Six host Rust enrollment regression tests (actual SPAKE2 exchange, both directions, proof/attestation gates, order/offer, rollback/expiry, receipt recovery, independent contexts) and three portable primitive regressions are added, not run here. Existing RFC 9382 KAT remains required. The independent context fixtures are NOT a deterministic full application-profile SPAKE2 KAT; independent profile review and native interoperability remain acceptance requirements.
- Android instrumentation test adds actual SQLite reopen/pending/activation and alias matching using isolated test directory and test keys. Not run or compiled here; it does not test attestation.
- Cargo/rustc/Gradle/Android SDK unavailable here. No Rust compilation, native JNI linkage, Android build or actual platform trust validation claimed. CI updated to run independent enrollment fixtures and Android schema tests; GitHub CI execution pending.

## OpenCode verification

Apply the patch after B.2.4 authentication. Review exact modifications, compile and run:

```sh
python3 protocol/tools/v2_wire_vectors.py --check
python3 protocol/tools/v2_message_vectors.py --check
python3 protocol/tools/v2_enrollment_vectors.py --check
python3 protocol/tools/v2_store_tests.py
python3 protocol/tools/v2_device_store_tests.py
cargo test --manifest-path linux/Cargo.toml -p rbad --locked v2_store::authority::enrollment::tests
cargo test --manifest-path linux/Cargo.toml -p rbad --locked
cargo test --manifest-path linux/Cargo.toml -p rba-protocol --locked
cargo test --manifest-path crates/rba-enrollment/Cargo.toml --locked
cargo check --manifest-path crates/rba-enrollment-jni/Cargo.toml --locked
cargo check --manifest-path linux/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path linux/Cargo.toml -p rbad --all-targets --locked
make vectors-kt
# With the actual Android SDK/NDK/device, from android/:
gradle --no-daemon :app:assembleDebug :app:testDebugUnitTest :app:connectedDebugAndroidTest
```

Inspect Android journal/synchronous configuration, fail-closed corruption handler, alias binding, actual on-device pending/activation transactions, dependency lockfiles and exact release build before platform integration. No changes to existing lockfiles from this delivery. B.2.4 source acceptance depends on Rust and independent review. B.2.5 core acceptance must keep B.3/B.4 physical integration gates open and must not claim production eligibility.
