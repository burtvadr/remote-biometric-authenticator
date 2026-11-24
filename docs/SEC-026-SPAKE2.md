# SEC-026 — SPAKE2 enrollment integration candidate

Status: **open — both endpoints and simulator integrated in source; native
and physical verification pending**. No claim of production readiness.

## Dependency and engineering decision

Use the P-256/SHA-256/HKDF/HMAC suite described in RFC 9382, through the
`pakery-spake2` and `pakery-crypto` 0.6.2 APIs. These releases document RFC
Appendix B conformance and explicit confirmation. Independent security audit
status was not established. The commonly cited RustCrypto `spake2` 0.4.0 crate
has different group support and is not an interchangeable implementation of this
suite. Do not write elliptic-curve or SPAKE2 arithmetic locally.

The workspace now requires Rust 1.88 or newer. Both native host and JNI
builds depend on the shared enrollment crate. Android requires the NDK and
`cargo-ndk` with the configured Android Rust targets. Resolve and review the
Cargo lockfiles on the build host; they were not regenerated here.

References:
- https://www.rfc-editor.org/rfc/rfc9382.html
- https://docs.rs/pakery-spake2/0.6.2/pakery_spake2/
- https://docs.rs/pakery-crypto/0.6.2/pakery_crypto/
- https://github.com/djx-y-z/pakery

## Product constraints and component boundary

Both six-digit entry directions must remain available without a camera. The
displaying endpoint generates the secret with an OS CSPRNG; the other receives
it from local human input. Leading zeros are meaningful. The code is never a
network field, a command-line argument, or an audit event. The code is single-use
and must not be retained or accepted as a reusable password. SPAKE2 role A is
always the host and B always the authenticator, independent of display direction.

The component accepts the code and independently obtained enrollment context.
It uses a domain-separated SHA-512 hash reduced to the P-256 scalar field by the
library. This is an RBA-specific password-input profile for random short-lived
codes, not a general password storage or hashing recommendation. Review this
profile before freezing the wire format. RFC 9382 key confirmation is delegated
to the library. The context is associated data for confirmation, including both
long-term public keys, both IDs, session ID, expiry, direction and actual TLS
certificate hash. The latter must be independently derived by each endpoint.
The raw PAKE key cannot be read through the component until peer confirmation
succeeds. No component API writes grants, trusts a certificate or activates a
credential. Those remain responsibilities of the pairing state machine.

## Integration acceptance criteria (verify before closing SEC-026)

1. Revise the versioned wire flow so both identity/key bindings are known before
   SPAKE2 starts. For host-entry mode, the host must wait for human input before
   emitting its SPAKE2 share; device-entry mode must likewise wait for input on
   the device. Neither side transmits the password. Remove the SAS messages,
   ECDH/SAS derivation, derived-code comparison and any fallback in the completed
   migration. Use the mandatory breaking enrollment suite v2; fresh enrollment is acceptable.
2. Execute one exchange per admitted connection/session, with persistent limits
   on session creation and attempts, expiry, ownership and terminal failure on
   a wrong confirmation. Guard both directions against repeated live guesses.
3. Check both RFC confirmation tags before accepting the peer binding. Bind the
   actual TLS certificate rather than a peer claim; do not send existing
   revocation tokens or persist trust before this verification. Any new secret
   transmitted after confirmation needs an authenticated channel and binding to
   the enrollment result; do not reuse the PAKE key directly as a MAC key.
4. Preserve the authorized human gate, staged enrollment, durable host commit,
   final receipt, cancellation, revocation and explicit principal-scoped grants.
   Verify lost receipts and restart behavior without exposing a second runtime
   trust path. Keep the existing ECDSA authentication protocol separate.
5. Connect the same Rust component to Android via a reviewed native bridge with
   owned, single-use state, cancellation/destruction and bounded arrays. Never
   expose native raw pointers as unvalidated JVM handles. Use the normal Android
   Keystore for long-term signing keys; the PAKE library does not replace it.
6. Test both directions on actual Android hardware, malformed shares, wrong
   codes, transcript substitution, replay, version downgrade, disconnects,
   failed storage and rate-limit persistence. Run Rust and Kotlin/wire tests,
   produce reproducible native builds and review all transitive dependencies.

## Verification

```
cargo test --manifest-path crates/rba-enrollment/Cargo.toml
cargo fmt --manifest-path crates/rba-enrollment/Cargo.toml -- --check
cargo clippy --manifest-path crates/rba-enrollment/Cargo.toml --all-targets -- -D warnings
```

In this authoring environment Cargo and the Android SDK/NDK were unavailable.
Kotlin protocol and standalone JNI declaration compilation ran, and the Kotlin
runner passed 136 checks against shared fixtures. These fixtures are not a
substitute for Rust, RFC known-answer, JNI or physical device execution. The
new enrollment messages are wire fixtures; the cryptographic known-answer test
is in `crates/rba-enrollment/tests/rfc9382.rs`.
