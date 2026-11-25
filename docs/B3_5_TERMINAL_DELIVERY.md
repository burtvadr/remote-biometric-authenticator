# B.3.4/B.3.5 — ALPN regression and one-shot terminal delivery

Source candidate; not a production cutover or evidence of physical Android interoperability. Base: reconstructed original snapshot plus delivered patches through B.3.4. No new dependencies, database schema, legacy fallback, or portable-core extraction.

## Corrections

1. The missing-ALPN test now constructs `alpn_protocols = Vec::new()` for omitted ALPN. A vector containing a zero-length protocol name is not valid TLS ALPN. The assertion for missing ALPN remains, as do the wrong ALPN and client pin/certificate assertions. Production ALPN policy is unchanged.
2. A terminal frame is encoded and retained only by the successful, consumed authority operation. The original connection remains denied for normal I/O and charged against the live slot cap. The internal terminal entry is tied to the original connection, listener, credential and (where applicable) local owner; it is consumed once. The frame is bounded to 1024 bytes and its write window to five seconds, additionally limited by the original authentication/enrollment deadline. Both clocks and the trust/DB state are checked at claim/write. Administrative invalidation, socket closure, relevant local-owner loss, policy changes, revocation, or trust refresh removes pending/in-flight permission. A TLS writer cannot reopen normal reads or substitute a message. `Channel::finish(self)` consumes the channel and claims its exact frame, flushes and closes it. Drop/cancellation closes the charged socket. Ciphertext writes are capped at 16 KiB in this terminal mode; the authority lock serializes each nonblocking socket poll against revocation. No lock spans an await. This is not a guarantee of delivery to the peer or of retroactively retracting bytes already transmitted.
3. `revoke_peer` now consumes a validated `REVOKE` message, checks exact session and credential, and verifies the token in the existing transaction. It arms the receipt only after commit. Enrollment commit and recovery and successful authentication similarly arm the exact receipt; failed operations do not. The Android client closes after these terminal frames. Other operations cannot write these frames through `Channel::write`. The policy sync state machine is not implemented by this patch.

The new API is for the definitive V2 runtime: adapters use `channel.finish().await` after a successful authority operation that arms a receipt. `AuthAccepted` still reports the owner/interaction for the local adapter; its `result` is informational, not transferable wire authority. The actual IPC owner must independently ensure local success is delivered only once and to the original live caller. A failed terminal write does not roll back durable enrollment/revocation; retry through the specified authenticated recovery path. A committed audit records verification, not guaranteed receipt delivery. No implicit fallback or replay on the closed connection.

## Verification

Added five authority regression tests plus two real rustls loopback tests (synthetic in-memory fixture is compiled only under `cfg(test)`), and extended the enrollment and revocation tests to assert the exact claimed frame. The loopback exercises production `accept`, HELLO, typed revocation, commit, terminal finish and EOF; it also attempts an uncommitted ordinary receipt write. The new tests and missing-ALPN regression must be compiled/run in the review environment. Neither Cargo/rustc nor Android SDK/Gradle/hardware are available in the implementation environment. No new Rust pass count claimed. Independent SQLite tests executed: 8 host and 3 device, all passed. Standalone Kotlin regression suite is independent of the Android client and cannot validate its changes.

```
git apply --check rba-b3.5-terminal.patch
git apply rba-b3.5-terminal.patch
git diff --check
cargo test --manifest-path linux/Cargo.toml -p rbad --locked v2_tls::tests
cargo test --manifest-path linux/Cargo.toml -p rbad --locked terminal_
cargo test --manifest-path linux/Cargo.toml -p rbad --locked v2_store::authority::enrollment::tests
cargo test --manifest-path linux/Cargo.toml -p rbad --locked
cargo check --manifest-path linux/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path linux/Cargo.toml -p rbad --all-targets --locked
python3 protocol/tools/v2_store_tests.py
python3 protocol/tools/v2_device_store_tests.py
make vectors-kt
```

## Open requirements

- Owner approval of the B.3.4 transport-key digest policy `{NONE, SHA-256}` (biometric key remains SHA-256 only). This patch does not change that candidate policy.
- Independent compilation/test results, including rustls missing-ALPN and terminal loopback.
- Real host/Android connection-owner integration, operation deadlines, policy sync, Android revocation-only tombstone path, trusted local IPC delivery and cleanup of provisional/orphan aliases. The new receipt path is not a complete dispatcher.
- Physical Android/Conscrypt, Rust-to-Android exporter interoperability and release signing/attestation. Long fuzzing/coverage analysis remains open. SEC-005/007/008/014 and B.3 acceptance are not closed.
