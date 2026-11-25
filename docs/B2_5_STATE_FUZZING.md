# B.2.5 — Host and device state-machine fuzz drivers

## Scope

Incremental test-only delivery after `rba-b2.5-parser-fuzz.patch`. The local baseline is a reconstruction of the uploaded archive and prior deliveries, not a newly verified upstream commit. No production V2 cutover, protocol/schema change, runtime policy change, portable-core extraction or SEC closure. The normal `rbad` build excludes the fuzz entry point and the synthetic test verifier (`cfg(fuzzing)` is set by cargo-fuzz); the test driver creates its own in-memory SQLite database and never accepts a production store or credentials. The isolated fuzz workspace now also depends on `rbad`. Its separate Cargo lockfile requires regeneration and review.

## Targets

- Rust `v2_host_state`: reconstructs a valid prefix, selects a fault or a positive control, invokes the real Authority authentication/enrollment methods, and checks the resulting decision, exact success owner, terminality, credential presence and audit counts. Tests exercise real SPAKE2, signatures and in-memory SQLite with a synthetic verifier that checks role-specific inputs; not actual attestation. The 32 host seeds cover two authentication stages with eight cases each and both enrollment directions with eight cases each. A bounded suffix varies duplicate, cancellation and closure calls. Two normal Rust unit tests replay these seeds without instrumentation.
- JVM `V2JvmStateFuzz`: 42 seeds cover four authentication stages with six cases each and both enrollment directions with nine cases each. It uses the real Kotlin state-machine methods, actual JVM signatures and test-only PAKE and pending-store adapters. The oracles reject repeated/invalid transitions and verify that invalid enrollment cannot activate a credential. The regular Kotlin standalone and Gradle test suites replay all 42 traces.
- JVM `V2JvmFrameFuzz` / `V2JvmPayloadFuzz`: raw framing and direct CBOR/schema parsing with canonical round-trip invariants. Only expected input rejection or EOF is caught; other exceptions and assertion failures remain visible. Reuse the 351 frame and 342 payload seed inputs.

This is structured, bounded prefix/fault/suffix fuzzing, not an exhaustive model of arbitrary concurrency, crash/restart, all policy changes or receipt-recovery sequences. Those require further review and targeted tests. Native PAKE interoperability, hardware attestation, real TLS/IPC, Android SQLite and physical biometrics remain separate acceptance gates. No claim of security closure follows from corpus replay.

## Commands (OpenCode, from repository root)

```sh
python3 protocol/tools/v2_fuzz_seeds.py
cargo test --manifest-path linux/Cargo.toml -p rbad --locked state_trace_
make vectors-kt
```

The seed tool retains existing discoveries. The expected number of generated fixture seeds on a fresh output directory is 775 (701 prior + 32 host + 42 JVM).

For Rust coverage-guided execution, use reviewed, recorded versions of Rust nightly and cargo-fuzz (https://rust-fuzz.github.io/book/cargo-fuzz.html). Do not run as root or against real credentials. From `linux`:

```sh
cargo +nightly generate-lockfile --manifest-path fuzz/Cargo.toml
cargo +nightly fuzz build
cargo +nightly fuzz run v2_host_state -- -max_total_time=300 -max_len=35 -timeout=10
```

For JVM execution, use a reviewed, pinned standalone Jazzer release from its official repository (https://github.com/CodeIntelligenceTesting/jazzer). Jazzer accepts static `fuzzerTestOneInput(byte[])` methods and a `--cp` classpath. `make vectors-kt` must first compile the test classes. From repository root (replace the tool paths with the verified local installation; `KTORLIN_HOME` is the existing Makefile variable):

```sh
CP="build/kotlin-protocol:$KTORLIN_HOME/lib/kotlin-stdlib.jar"
java -cp "$CP" io.github.burtvadr.rba.protocol.V2JvmParserReplay linux/fuzz/corpus
jazzer --cp="$CP" --target_class=io.github.burtvadr.rba.protocol.V2JvmFrameFuzz linux/fuzz/corpus/v2_frame -max_total_time=300 -max_len=65549 -timeout=10
jazzer --cp="$CP" --target_class=io.github.burtvadr.rba.protocol.V2JvmPayloadFuzz linux/fuzz/corpus/v2_payload -max_total_time=300 -max_len=65537 -timeout=10
jazzer --cp="$CP" --target_class=io.github.burtvadr.rba.protocol.V2JvmStateFuzz linux/fuzz/corpus/v2_jvm_state -max_total_time=300 -max_len=35 -timeout=10
```

Run only the isolated synthetic test harness. Record the toolchain versions, exact baseline, lockfile, actual run output, execution counts and coverage reports. Preserve failures for local regression replay. Five-minute campaigns are smoke tests; longer campaigns, coverage review and additional targeted tests are mandatory before acceptance. Earlier Rust parser targets remain unexecuted. Do not enable scheduled CI before dependencies, commands and limits are reviewed and actually tested.

## Evidence and remaining gates

- Deterministic seed generation checked on two fresh directories: identical trees, 775 inputs.
- Standalone Kotlin compiled and replayed all 42 state seeds and 637 previous checks on JDK 21 with JVM target 17 (local Kotlin version cannot target 21).
- All 693 JVM parser seed inputs replayed successfully (351 frames + 342 payloads), without coverage instrumentation.
- Rust and Cargo are absent in delivery environment. Host traces and coverage-guided harness must be compiled and run locally. Jazzer is also unavailable. No instrumented fuzzer run or coverage numbers are claimed.
- Independent SPAKE2 application-profile review, cross-component acceptance and actual fuzz campaigns remain open. The unchanged pre-release V1 runtime has not been replaced.
