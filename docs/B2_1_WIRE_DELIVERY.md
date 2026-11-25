# B.2.1 — V2 wire primitives delivery (review candidate)

## Scope and baseline

This is a completed implementation unit for framing and structural deterministic
CBOR, not a completed security finding or full V2 implementation. It is based on
`remote-biometric-authenticator-main.zip` (2b8e76d) plus the supplied B.0 and B.1
patches. The claimed updated B.2.0 archive was not available for inspection.
Apply only after checking your actual working tree and reconciling any changes
made after B.1. This patch does not replace your feasibility documents.

The operator deferred portable core extraction to Phase D. Linux Rust and
Android Kotlin implement this wire profile independently. No new dependency,
shared crate, JNI changes, registry changes or runtime negotiation are introduced.
The V2 modules are not called by existing V1 daemon/application paths. V1
remains the baseline runtime, not an intended V2 fallback: remove V1 at the
coordinated V2 integration cutover; do not deploy this unit as a V2 runtime.

## Contract

The wire layer consumes exactly one PAF2 frame (13-byte header, version 2,
zero flags, defined types 10–24 and 30–38, payload 1–65536 bytes). Header
validation precedes body allocation. It rejects unsupported versions and types
rather than negotiating, scanning or downgrading. It requires an authenticated,
deadline-bounded carrier owned by the calling transport; read helpers do not
implement TLS, timeouts or channel state. All errors are terminal at integration.

Canonical CBOR structural validation allows unsigned integers, byte strings,
strict UTF-8 strings, arrays and maps with text keys only. Shortest encodings,
definite lengths, bytewise encoded key order, no duplicate keys and exact input
consumption are required. Root map depth is zero, maximum depth eight; 1024
items count map keys as well as values and the root; arrays/maps are bounded at
32 entries (all specified V2 wire maps are smaller). Lengths are validated in
unsigned width before conversion. Encoders preflight the size and validate the
result; they reject invalid types and noncanonical order rather than silently
repairing input. Reused V1 `Value` and low-level encoding primitives do not make
V1 encodings acceptable to the V2 boundary. Callers own input/values and must
not mutate them concurrently.

This layer does **not** assert that a structurally valid map is an admissible
message. Exact fields, NFC and label rules, scope identifiers, capability sets,
point and scalar validity, signing domains, transcript hashes, certificate
chains, exporter binding, state, freshness and authorization belong to subsequent
message/session validation. Empty maps in the wire fixtures are structural test
cases only, never valid HELLO/authentication requests. No authentication result
or security finding is closed by this unit.

## Evidence and reproducibility

`protocol/tools/v2_wire_vectors.py` is an independent, standard-library Python
encoding oracle; it writes `protocol/test-vectors/v2-wire.tsv`. The 71 cases
include all 24 message type IDs, canonical integer boundaries, UTF-8, exact
resource boundaries, malformed lengths, duplicate keys, bad versions, unknown
message types and truncation. Rust and Kotlin consume the same file. Additional
local tests check encoding rejection, concatenated frames and semantic uint
boundaries. The fixture is integrated in the existing Gradle and standalone
Kotlin runners and Rust integration tests. CI checks that it is reproducible.

Executed locally in the delivery environment:

- Kotlin 1.9.0 / JDK 21 compilation and standalone run: 82 new V2 wire checks PASS.
- Existing Kotlin vectors: 151 checks PASS against existing fixtures.
- Python fixture regeneration and byte-identical --check: PASS.
- Git diff whitespace and patch application on reconstructed B.1: PASS (packaging).

Not executed: Rust compiler, Cargo tests, rustfmt, Clippy, Gradle, Android SDK,
JNI builds, GitHub CI, physical hardware. No Rust interoperability claim until
Rust tests run. No new dependencies or lockfile updates required for this unit.

From repository root after applying the patch:

```sh
python3 protocol/tools/v2_wire_vectors.py --check
cargo test --manifest-path linux/Cargo.toml -p rba-protocol --locked --test v2_wire
cargo test --manifest-path linux/Cargo.toml -p rba-protocol --locked
cargo check --manifest-path linux/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path linux/Cargo.toml -p rba-protocol --all-targets --locked
make vectors-kt
(cd android && gradle --no-daemon :protocol:test)
```

## Next implementation unit

Implement exact V2 message schemas and typed signed transcripts in both
languages, with independent positive/negative schema and transcript fixtures.
Resolve the Unicode normalization/category policy and crypto dependency and
platform constraints explicitly. Then integrate with the state machine, TLS and
attestation once their prerequisites are met. No production activation, fallback,
partial remediation claim or final specification freeze based on these tests.
