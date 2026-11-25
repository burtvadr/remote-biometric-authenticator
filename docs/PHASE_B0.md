# B.0 — baseline audit and automated verification

Base: uploaded GitHub archive, ZIP comment `2b8e76dea7dc544ba834d6f026b7177820e938d6`. This is not the requested historical `2583bbf` baseline. The archive has no Git history; ancestry and remote branch status were not verified. Apply the patch to matching source, not blindly to an older commit.

## Changes and decisions

- Centralize host admission limits in `linux/protocol/src/types.rs`, with typed `RateLimiter` policy constructors reused by initialization and restoration. Existing numerical ceilings and durable state format are unchanged. Wi-Fi 30/60 s, BLE 15/120 s, account and device each 3/60 s, pairing 5/300 s. These are reservation ceilings, not an independent inbound packet/request limiter. Raising biometric prompt throughput is deliberately deferred until explicit intent and separate admission policies are designed. Do not remove the admission state or loosen PAM recovery policy.
- Frame, signing transcript and hello version derive from one constant per implementation. Both hello and acknowledgement decoders reject unsupported versions; Rust stream readers reject invalid fixed headers before waiting for bodies. No downgrade negotiation. The wire version remains **1** until B.2 changes the actual signed profile. `spake2-p256-sha256-v2` is the independent enrollment suite, not wire V2. No cryptographic algorithm, pairing transcript, credential format, or production PAM configuration is changed by this patch.
- CI covers Linux workspace check/test/Clippy, standalone SPAKE2 tests, Kotlin vectors, Android debug compilation, JNI via the existing Gradle cargo-ndk task, Android unit tests and lint. Formatting is advisory initially because pre-existing files have formatting drift; Clippy warnings are reported without `-D warnings`. Toolchain stable and cargo-ndk are not pinned to exact versions; action tags are not SHA-pinned. The JNI crate has no committed standalone lockfile. CI is a candidate, not a verified green run. Pin dependencies/actions and make formatting mandatory after establishing the baseline. Debug APK CI is not release or hardware assurance. No fuzz target is added yet.
- The normative specification had a stale 5/60 s authentication row and ambiguous pairing scope; reconcile the host reservation ceilings with the implementation. The separate obligation to account for malformed network traffic remains open under SEC-007.

## All 26 finding dispositions

This is a bounded static review of current implementation and the tracker, not a line-by-line independent audit. “Prior fix present/reported” is not a new runtime verification. Original severity is retained in the tracker; the roadmap can prioritize differently.

| ID | B.0 disposition | Evidence / next gate |
|---|---|---|
| SEC-001 | Prior issue superseded by SPAKE2; assurance pending | `protocol/src/pairing.rs`, portable enrollment crate and `rbad/src/engine.rs`; see SEC-026 for profile and physical integration review. |
| SEC-002 | Historical/retracted | Tracker retracts original one-byte HMAC claim; obsolete SAS construction removed from active enrollment. |
| SEC-003 | Open, partly remediated | `rbad/src/admission.rs` reserves durable account/device/transport budgets; no number matching or full trusted transaction context. B.0 centralizes limits, not prompt throughput. |
| SEC-004 | Prior fix present, runtime pending | `rbad/src/authz.rs` and security tests for wrong user and root by default; see SEC-025. |
| SEC-005 | Open, confirmed source gap | `DeviceAuthKey.kt` has local Keystore inspection but no `setAttestationChallenge`; host certificate/attestation validation not implemented. |
| SEC-006 | Prior fix reported; reverify deployment | Tracker documents control-socket server identity checks; run privileged PAM integration with real socket ownership and peer identity. |
| SEC-007 | Open, partially remediated | `rbad/src/tls.rs` uses `no_client_auth`; `transport/wifi.rs` has connection cap and TLS deadline; `config.rs` defaults to loopback. No complete pre-authentication accounting or parser fuzzing. |
| SEC-008 | Open, partial | `android/app/build.gradle.kts` debug application suffix and unsigned release configuration; physical release-signed validation missing. |
| SEC-009 | Prior partial fix present | `pam-rba/src/lib.rs` has `catch_unwind`; release profile uses `panic = "abort"`, so do not treat catch_unwind as protection against release aborts. PAM robustness needs integration review. |
| SEC-010 | Needs runtime measurement | Tracker describes timing distinction; compare outcomes under controlled conditions. |
| SEC-011 | Open | `rba/src/main.rs` pairing interaction lacks verified key/source presentation; human identity binding remains. |
| SEC-012 | Removed from accepted CLI in source | Parser recognizes `--code-entry` and reads from stdin; rejects unknown `--code`. Added dummy-value CLI regression; runtime and secret logging/terminal behavior not fully verified. |
| SEC-013 | Prior documentation fix reported | Tracker records debug as troubleshooting-only; recheck deployed PAM configuration. |
| SEC-014 | Open, confirmed | `protocol/src/types.rs` signed field list excludes session_id; `verifier.rs` compares session fields but does not cryptographically bind the TLS channel. B.2/B.3. |
| SEC-015 | Needs privacy verification | `transport/wifi.rs` advertises host key-id metadata; linkability assessment pending. |
| SEC-016 | Prior documentation fix reported | Tracker reports scoped distro-aware PAM documentation; verify actual target deployment. |
| SEC-017 | Open, confirmed | `docs/threat-model.md` uses `/var/lib/rba/host.key`; spec uses `/etc/rba/host.key`. |
| SEC-018 | Open, confirmed | Spec expiration prose disagrees with formula; `verifier.rs` adds skew. No freshness behavior change in B.0. |
| SEC-019 | Historical documentation fix | Tracker marks obsolete test counts resolved; use current CI evidence, not static README counts. |
| SEC-020 | Prior documentation fix reported | Tracker records rollback-line clarification; validate local password recovery separately. |
| SEC-021 | Prior fix present | `rbad/src/ipc.rs` bounds request bytes while reading; Rust tests pending. |
| SEC-022 | Prior fix present | `rbad/src/server.rs` clamps timeout to `MAX_AUTH_TIMEOUT_MS`; runtime verification pending. |
| SEC-023 | Prior fix reported | Tracker records display changes; signed operation context remains incomplete under SEC-003; inspect actual Android prompts on device. |
| SEC-024 | Prior fix present | `config.rs` default loopback, Wi-Fi connection cap and deadlines; actual service bind, firewall, timeout behavior require deployment verification. |
| SEC-025 | Open, implementation candidate | `authz.rs` explicit grants/default-deny and authorization regression cases; stable principal identity, lifecycle and actual runtime behavior not independently verified. |
| SEC-026 | Open, integration candidate | `crates/rba-enrollment`, JNI crate, daemon and simulator integration; Kotlin wire tests pass but Rust KAT, NDK, dependency review, physical enrollment and fault paths pending here. |

Paths beginning `protocol/src`, `rbad/src`, `pam-rba/src`, `rba/src` refer to the Linux workspace; Android Kotlin paths are under `android/`.

## Verification in this environment

- PASS: standalone Kotlin protocol compilation with Kotlin 1.9.0 targeting JVM 17; execution with OpenJDK 21.0.12. Existing vectors plus 15 new version checks: **151/151**. This checks the existing Rust-produced fixtures, not a fresh Rust vector generation.
- PASS: `git diff --check`; CI YAML parses with PyYAML. YAML parsing is not GitHub Actions execution.
- NOT RUN: Rust compilation, Rust tests (including new regression tests, CLI test and SPAKE2 KAT), Rustfmt/Clippy, Gradle tests, Android/NDK builds, actual GitHub CI, physical biometric and PAM integration. No Rust, Gradle or Android SDK in this environment.

## Local review and verification

From repository root:

```sh
git rev-parse HEAD
git apply --check /path/to/rba-b0.patch
git apply /path/to/rba-b0.patch
git diff --check
(cd linux && cargo check -p rbad --locked)
(cd linux && cargo test -p rbad --locked)
(cd linux && cargo test -p rba-protocol --locked)
(cd linux && cargo test -p rba --locked)
cargo test --manifest-path crates/rba-enrollment/Cargo.toml --locked
(cd linux && cargo clippy -p rbad --locked)
(cd linux && cargo test --workspace --locked)
(cd android && gradle :protocol:test)
```

Review lockfile errors explicitly rather than silently removing `--locked`. Run CI and resolve failures before merging. Use a recovery-safe test host for real PAM changes; B.0 does not require modifying PAM. Do not mark SEC-003/025/026 closed based on this delivery. Next milestone B.1: separate inbound request accounting from potential prompt reservations and define operation-specific policies. B.2: implement the actual breaking V2 signed message profile and update both implementations and all shared fixtures atomically.
