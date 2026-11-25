# B.2.1 — exact message schemas and transcript component

## Baseline and scope

This patch is based on the original uploaded ZIP (`2b8e76dea7dc544ba834d6f026b7177820e938d6`) with the earlier B.0, B.1 and B.2.1 wire patches applied. The local working copy was committed solely to construct the incremental patch; this is not an upstream commit. The latest operator/OpenCode B.2.0 archive and feasibility notes were not attached, so this does not assert equivalence to that working tree. Apply only after `git apply --check` and review. No daemon, Android app, SPAKE2 primitive/JNI, PAM, portable-core or active protocol cutover changes are included.

## Implementation

- Closed identifiers for all 24 message types and all eight transcript domains in PROTOCOL.md §§3–5. Message constructors and stream readers enforce exact maps, nested fields, length/type/range requirements, canonical CBOR, mandatory sorted capabilities and canonical sorted unique grants. They reject unknown scopes for the initial four operations. Syntax does not establish adapter provenance or grant authorization.
- Domain-specific transcript construction and SHA-256 hashing: exact domain ASCII, NUL and canonical map. The signature field is excluded by construction of the core schema. ECDSA verification signs/verifies the transcript bytes using SHA-256 once; accepts both valid S variants. Points must be uncompressed P-256 and on-curve; signature scalar encodings must be in range. Kotlin uses the JCA provider and explicitly checks public-coordinate membership because key construction alone does not guarantee validation. It performs no private-key operations or new elliptic-curve primitive implementation.
- Cross-field checks for authorization expiry duration, receipt/state, policy digest, distinct enrollment keys and enrollment-offer credential binding. These are local invariants only; comparisons against the actual connection, original local requester, current database policy, trusted clock, keys and pending state belong to the state machines and transport/attestation components.
- Kotlin validated messages retain canonical bytes privately and return fresh decoded values; Rust owns the validated map and only exposes shared references. No generic caller-defined transcript domains. Low-level wire API still exists for structural tests; future runtime must use the validated message path and close on error.
- Certificates are bounded opaque byte strings at this layer. Parsing DER, verifying chains/attestation and revocation, proving PAKE confirmations, and validating enrollment state are not implemented here.

## Dependencies / design decisions requiring review

Rust uses `unicode-normalization = 0.1.24` and `unicode-general-category = 1.1.0`; Kotlin uses `java.text.Normalizer` and `Character` plus JCA. The Cargo.lock entries (including tinyvec 1.8.0 and tinyvec_macros 0.1.1) were assembled using public registry lock metadata (https://git.nextgraph.org/NextGraph/wasm-pack/src/branch/master/Cargo.lock and https://docs.rs/crate/debugbundle/1.0.0-alpha.1/source/Cargo.lock); Cargo could not resolve or download in this environment. Treat the lockfile as a candidate until Cargo verifies it against the actual registry and workspace. Do not bypass `--locked` silently; if resolution fails, review the regenerated lock diff.

The B.1 text rules are enforced with NFC, UTF-8 lengths and rejection of control/format characters. This implementation additionally rejects unassigned code points and line/paragraph separators and bounds ASCII identifiers to 64 bytes. These conservative restrictions must be reviewed against the latest normative specification. Unicode versions on Android, JDK and Rust may differ; establish a common versioned display-text repertoire/profile and cross-platform tests before runtime cutover. A tested JVM is not evidence for all supported Android versions. Public labels are not unique identities and must never authorize requests. Context source identifiers are syntax-checked here, not validated against a trusted adapter registry. Full Unicode spoofing/UI security remains an integration acceptance concern.

## Evidence

Independent Python fixture generation: 284 rows (26 accept, 234 reject, 8 transcript/hash, 8 valid signatures including alternate S, 8 invalid signatures). Fixtures are explicitly constructed independently of the Rust and Kotlin schema tables. Signatures were generated using Python cryptography/OpenSSL with fixed test-only scalar 1 and deterministic ECDSA; committed fixed signature bytes allow standard-library-only fixture regeneration. The dummy certificate bytes and scalar-only signatures in structural accept cases are not trusted certificates or proof of possession.

Executed: Kotlin standalone JVM compilation, 284/284 new fixtures (with additional immutable-copy, domain-separation and channel-tamper assertions), 82/82 existing V2 wire checks and 151/151 existing fixture agreement checks. The latter use existing Rust-generated fixtures, not a fresh Rust run. Python fixture drift checks and patch integrity checks executed. Rust compilation/tests, Cargo dependency resolution, Android SDK/Gradle/JNI tests, hardware TLS/attestation and GitHub CI remain unverified here. No SEC closure is claimed.

## Local review

From repository root after applying this patch:

```sh
python3 protocol/tools/v2_wire_vectors.py --check
python3 protocol/tools/v2_message_vectors.py --check
cargo test --manifest-path linux/Cargo.toml -p rba-protocol --locked --test v2_message
cargo test --manifest-path linux/Cargo.toml -p rba-protocol --locked
cargo check --manifest-path linux/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path linux/Cargo.toml -p rba-protocol --all-targets --locked
make vectors-kt
```

Verify CI separately and report the actual V2 test counts. This component does not close B.2.1, enable V2, or introduce a production fallback. The next engineering task is the coordinated integration design/implementation of validated messages, state machines and cryptographic binding, with dependencies on persistence, authorization, Android trust and platform feasibility explicitly tracked. No runtime V1 removal until the coordinated V2 cutover is ready; no new legacy compatibility code. Portable core extraction remains Phase D only.
