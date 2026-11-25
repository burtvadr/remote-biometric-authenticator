# B.2.5 — Coverage-guided Rust parser harnesses

This is a testing-only delivery. It does not activate V2, modify authentication policy, close a finding, or complete B.2.5. The test package is an isolated Cargo workspace under `linux/fuzz`; it depends on the existing Linux protocol crate and does not enter the production build. No network service is contacted by these targets.

## Targets and invariants

| Target | Entry points and properties |
|---|---|
| `v2_frame` | Raw framed stream; structural and typed reads; exact consumed length, header type, and canonical round-trip of the consumed prefix. Trailing bytes may represent another frame and are not silently included in the first one. |
| `v2_payload` | Direct bounded CBOR decoder, canonical encoder, all 24 typed schemas; exact payload round-trip and full encoded-frame consumption. First input byte selects the schema. |
| `v2_transcript` | All eight domain-specific transcript encoders and digest functions; exact domain prefix, NUL separator, unchanged canonical payload, round-trip digest stability, distinct transcript domains. First input byte selects the domain. |

All inputs are synthetic repository fixtures or generated mutations. The seed tool derives content-addressed binary corpora from the committed TSV files, does not delete existing discoveries and is deterministic on fresh directories. Seed generation was executed twice and the directory trees compared: 351 unique frame, 342 payload, eight transcript seeds (701 total). Cargo manifest syntax and target paths were checked. No fuzzer executions or coverage numbers are claimed: Cargo/rustc are unavailable in the delivery environment.

## Local verification (OpenCode)

Install a reviewed Rust nightly and cargo-fuzz version using the Rust Fuzz Book guidance (https://rust-fuzz.github.io/book/cargo-fuzz.html). `libfuzzer-sys` is pinned at 0.4.13 (https://docs.rs/crate/libfuzzer-sys/0.4.13). A separate fuzz lockfile must be generated and reviewed with Cargo; do not modify the production workspace lockfile merely to run fuzzing. Pin and record the nightly and cargo-fuzz versions when recording evidence. Run only against the local harness, without privilege or production credentials.

From the repository root:

```sh
python3 protocol/tools/v2_fuzz_seeds.py
cd linux
cargo +nightly generate-lockfile --manifest-path fuzz/Cargo.toml
cargo +nightly fuzz build
cargo +nightly fuzz run v2_frame -- -max_total_time=300 -max_len=65549 -timeout=10
cargo +nightly fuzz run v2_payload -- -max_total_time=300 -max_len=65537 -timeout=10
cargo +nightly fuzz run v2_transcript -- -max_total_time=300 -max_len=65537 -timeout=10
```

The five-minute bounds are proposed smoke-test durations, not proof of adequate coverage. Capture full command output, revision, toolchain, dependency lockfile, corpus counts, executed inputs and reported coverage; preserve failure artifacts for local regression reproduction. Do not report a skipped or uncompiled target as passed. Review/pin fuzz dependencies and lockfile before enabling the scheduled CI job. Review target coverage, extend seeds and run longer campaigns before acceptance.

## Remaining B.2.5 gates

- Compile and execute all Rust fuzz targets and collect coverage evidence.
- JVM/Kotlin parser fuzzing and host/device state-machine fuzzing, including enrollment and admission transitions. The present targets do not exercise these state machines or physical hardware.
- Independent review of the SPAKE2 application profile; regression fixes for any findings.
- Reconcile exact working tree and B.2.0 evidence. The patch was checked against the original archive plus prior deliveries, not a newly supplied operator snapshot.
- Native JNI/Android integration and platform assurance remain explicit B.3 gates; trusted OS integration remains B.4.

No source or fixture claims substitute for actual execution. Keep B.2.5 open until the core gates are satisfied or the operator explicitly approves a revised acceptance boundary with documented evidence and rationale.
