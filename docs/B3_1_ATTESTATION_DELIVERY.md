# B.3.1 — Host Android key attestation verifier (review candidate)

This is a development component, not a production cutover or SEC-005 closure. B.2.5 acceptance remains open independently. The component implements the `AttestationVerifier` interface in `v2_store/authority/enrollment.rs`; the existing V1 runtime is unchanged. There is no alternate success or software-key path. No portable-core extraction.

## Profile and dependency decisions

* `openssl = 0.10.81` (distribution-maintained libssl/libcrypto) for PKIX path and certificate signature validation; `x509-parser = 0.18.1` for structured X.509 extension access. No new cryptographic primitive. Cargo must resolve and review the transitive dependency lock, including advisories and licenses. OpenSSL's actual version and security maintenance remain distribution requirements.
* Google recommends its Kotlin attestation verifier library. This Rust-native candidate avoids an additional host JVM service, using maintained path validation and an RBA-specific bounded DER policy reader. The reader and dependency choice require independent review and differential testing against the official verifier. Do not present it as an already independently validated full implementation.
* Trust roots must be independently provisioned from the official Android roots, including the 2026 rotation, and verified by the operator. No system CA defaults, peer-supplied roots, trust-on-first-use, or test roots in production. The constructor accepts trusted *local* roots; official-root provisioning and the privileged configuration adapter are not yet implemented. Test-only roots are public synthetic keys.
* Strict normal PKIX validity, security level 2, leaf-first ordered path and one leaf attestation extension. This deliberately rejects expired chains rather than adopting Android's legacy attestation expiration exception. Unknown fields and unsupported profiles fail closed. This conservative supported-device profile needs acceptance on the actual target device; it is not an assertion that every Android 9+ device supports it. Any revised profile must be justified before enabling production, not a permissive fallback.
* Require hardware attestation and key security levels (TEE or StrongBox), generated P-256 SHA-256 sign-only keys, exact role-specific key and challenge binding, verified locked boot, hardware OS/vendor/boot patch floors, exactly the intended RBA package, minimum release version and one configured release signing digest. Require biometric auth type 2 in hardware without timeout or device-credential alternative for biometric key; transport key is not biometric-gated. These values describe the attested authorization list. Actual per-use biometric enforcement, invalidation and app release-build assurance require platform tests. Attestation does not prove continuing OS/UI integrity.
* Status input is an explicitly trusted local HTTPS snapshot from https://android.googleapis.com/attestation/status. The constructor does not fetch or authenticate HTTP by itself. The eventual adapter must verify the fixed origin, TLS, bounded response, real retrieval time and authenticated cache lifetime (at most 24h), protect persisted snapshots against rollback and block use if unavailable/stale. All listed serials are denied on the verified path, including the root; duplicate keys and malformed snapshots are rejected. Status refresh cannot renew a cached deadline. The actual check time is `status_checked_at`; expiration stays anchored to the authenticated retrieval. Assurance is bounded to 30 days and certificate validity. Full stored-chain revalidation and revocation-driven session invalidation are still required.

## Evidence

* Synthetic fixture generator `protocol/tools/v2_attestation_fixtures.py` (Python cryptography) produces signed chains and negative KeyDescription cases. Checked-in fixtures are hexadecimal DER and public points; no usable production credentials are provided. The generator uses deliberately public test key constants and randomized certificate signatures.
* Independent OpenSSL CLI path fixture tests: 24 checks pass on this delivery environment. This tests certificate path validation only, not the Rust policy reader or its integration.
* Eight Rust tests cover positive roles, missing/incorrect/untrusted chain, role/key/challenge mismatch, 22 negative policy/chain cases, extension placement, revoked path members, status parsing and configuration. Rust compilation and execution pending because Cargo/rustc unavailable here.
* Rust dependencies are directly version-pinned, but the Linux Cargo.lock has intentionally not been changed or claimed resolved. The existing local rusqlite lockfile changes are absent from the reconstructed baseline. Resolve in the real working tree and review before using --locked.

## Local verification

Apply the patch to the B.2.5 state-fuzzing baseline; use the exact latest working tree and reconcile conflicts. Run:

```
python3 protocol/tools/v2_attestation_fixtures.py
cargo check --manifest-path linux/Cargo.toml -p rbad
# Review Cargo.lock changes and dependencies before locked execution.
cargo test --manifest-path linux/Cargo.toml -p rbad --locked v2_store::attestation
cargo test --manifest-path linux/Cargo.toml -p rbad --locked
cargo check --manifest-path linux/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path linux/Cargo.toml -p rbad --all-targets --locked
```

The independent Python fixture check requires Python `cryptography` and the OpenSSL CLI. CI installs libssl-dev for the Rust bindings; existing Rust CI will execute the new unit tests after lock resolution.

## Next B.3 work

1. Independent review, Rust compilation, policy tests, DER fuzzing, official-root differential fixtures and actual Android attestation chains.
2. Trusted root/revocation configuration and retrieval/refresh, persisted assurance enforcement.
3. Fresh Android Keystore key creation with distinct transport and biometric challenges, non-exportable keys, release-signing identity, native TLS and exporter demonstration.
4. End-to-end hardware tests and coordinated integration. No production deployment until gates pass.

References (reviewed during design):
- https://developer.android.com/privacy-and-security/security-key-attestation
- https://source.android.com/docs/security/features/keystore/attestation
- https://github.com/android/keyattestation
- https://docs.rs/openssl/0.10.81/openssl/x509/
- https://docs.rs/x509-parser/0.18.1/x509_parser/
