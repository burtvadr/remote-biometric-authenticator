# B.2.5 — Core security acceptance: text profile and verification integrity

## Scope and baseline

Candidate patch against the original `2b8e76d` ZIP with all eight prior ChatGPT patches applied through B.2.4 enrollment. No latest OpenCode working-tree archive, its Cargo resolution for SQLite, or its B.2.0 evidence files were supplied. Local patch-base commit is synthetic, not upstream history. The operator's reported tests are prior evidence, not rerun here. B.2.5 is open; no SEC closure, runtime cutover, legacy fallback or portable-core extraction.

## Changes

1. Replace runtime-dependent display category checks with **RBA Display Text 1**, a fixed normative table of 656 inclusive ranges (`protocol/text-profile/rba-display-text-1.tsv`). Derive the table from UCD 15.0.0 using the Unicode::UCD APIs: Age <= 10.0, General_Category L/M/N/P/S/Zs, excluding Default_Ignorable_Code_Point. The committed ranges are authoritative; generation does not depend on the runtime OS locale or Unicode category database. The Perl generator requires the exact UCD version and the Python generator emits identical Rust/Kotlin ranges with CI drift verification. No network input at runtime. Unicode data provenance: https://www.unicode.org/ucd/ ; Unicode data terms: https://www.unicode.org/license.txt .
2. Strict UTF-8 and byte bounds remain; validate membership before NFC using existing maintained normalizers. This removes dependence on runtime category versions without writing a normalization algorithm. Unicode 10 was selected because the app minimum is Android API 28 (Android's Unicode support table: https://developer.android.com/guide/topics/resources/internationalization). NFC normalization stability for assigned characters is specified by UAX #15 (https://www.unicode.org/reports/tr15/) and the Unicode stability policy (https://www.unicode.org/policies/stability_policy.html). Real minimum-supported Android NFC conformance is still required. No normalization or silent substitution of signed data. Ordinary multilingual labels remain supported, including precomposed Portuguese, Greek, Arabic, CJK, Hangul and Devanagari. Characters assigned after Unicode 10, default ignorables (including variation selectors), private-use and noncharacters are intentionally rejected. This narrower display repertoire is a proposed protocol design decision for the operator's acceptance. It is not a complete UI anti-spoofing policy or a change to identity authorization.
3. Remove the unused Rust `unicode-general-category` dependency and its entry from the reconstructed lockfile. Do not overwrite the operator's regenerated SQLite lockfile; apply the incremental patch and review any lockfile resolution separately.
4. Add 22 independent display-text message fixtures and exhaustive generated table membership comparisons (Rust test iterates all scalar values; JVM test checks all 1,114,112 code-point positions, including surrogates). The generated table comparison establishes code-generation agreement, not correctness of every normalization sequence on every Android platform.
5. `make vectors-kt` now fails when its JDK or Kotlin compiler is missing, rather than reporting successful execution with no tests. Add configurable `KOTLIN_JVM_TARGET` defaulting to 21 for standalone verification with older compilers. CI still uses the project's Gradle/JDK configuration; no downgrade to the application target. The CI fixture job checks the generated repertoire sources.

## Actual evidence

- `perl protocol/tools/v2_text_repertoire.pl` reproduced the exact normative table using Perl UCD 15.0.0.
- `python3 protocol/tools/v2_text_profile.py --check` passed, 656 ranges.
- Wire/message/enrollment independent fixture generation checks passed.
- Kotlin 1.9.0 with JDK 21, standalone JVM bytecode target **17**: 82 wire + 306 message/transcript + 22 policy + 24 authentication + 52 enrollment + 151 historical conformance = 637 checks passed. Exhaustive table comparison also passed. The default JVM target 21 compilation failed because this local compiler supports at most target 20; target 17 was used only for these standalone tests.
- Host SQLite schema tests 8/8 and device schema tests 3/3 passed. These are Python SQLite tests, not Rust or Android binding tests.
- Missing-toolchain negative test returned nonzero as required.
- No Rust/Cargo/Gradle/Android SDK available; Rust test, lockfile validation, native JNI, Android instrumentation, CI and hardware evidence are not claimed.

## Core acceptance register

| Requirement | Current disposition |
|---|---|
| Strict structural framing and message schemas | Prior component tests reported; fresh JVM fixture execution passed; fresh Rust execution pending |
| Canonical transcript and cryptographic proof | Prior fixtures reported; fresh JVM fixtures passed; independent review of application PAKE profile and native JNI interoperability pending |
| Unicode category consistency | Fixed repertoire implemented and regenerated; JVM comparison and examples passed; Rust and minimum-API Android NFC verification pending |
| Transactional host/device storage | Independent SQL tests pass; Rust bindings, Android instrumentation, disk-full and filesystem/power-loss evidence pending |
| Authorization/admission and state transitions | Component tests reported by operator; review actual cross-component call boundaries, clocks, cancellation and lifecycle on verified baseline |
| Reproducible verification | Missing Kotlin tools now fail closed; exact Rust/Android toolchain and actual GitHub CI evidence still pending |
| Parser/state-machine fuzzing | Coverage-guided fuzz targets and execution evidence still pending; fixed regression fixtures do not substitute for fuzzing |
| Android transport/attestation/biometric enforcement | B.3, not established by a verifier interface or test adapter |
| Trusted local caller/intent and account lifecycle | B.4; storage generation identifiers alone do not establish OS provenance |
| Runtime V1 removal and V2 cutover | Not yet performed; no production eligibility |

The reconstructed B.1 `ARCHITECTURE_V2.md` and `IMPLEMENTATION_V2.md` still contain old shared-portable-core requirements, and the reconstructed roadmap lacks Phase D. OpenCode reports those documents were changed locally, but the current files were not supplied. Do not silently overwrite the operator's newer documents. The binding operator decision is portability only after roadmap features are complete. Reconcile the actual document revisions and B.2.0 evidence before final core acceptance.

## Verification commands (repository root)

```sh
python3 protocol/tools/v2_text_profile.py --check
python3 protocol/tools/v2_wire_vectors.py --check
python3 protocol/tools/v2_message_vectors.py --check
python3 protocol/tools/v2_enrollment_vectors.py --check
python3 protocol/tools/v2_store_tests.py
python3 protocol/tools/v2_device_store_tests.py
cargo test --manifest-path linux/Cargo.toml -p rba-protocol --locked
cargo test --manifest-path linux/Cargo.toml -p rbad --locked
cargo test --manifest-path crates/rba-enrollment/Cargo.toml --locked
cargo check --manifest-path crates/rba-enrollment-jni/Cargo.toml --locked
cargo check --manifest-path linux/Cargo.toml --workspace --all-targets --locked
make vectors-kt
```

Record exact test output and source revision, not only a total test count. If the Cargo lockfile differs locally, review the incremental removal rather than replacing the whole file. No B.2.5 acceptance until pending core tests and independent review have evidence. B.3/B.4 hardware and operating-system gates remain separately open.

Parser harness delivery: [B2_5_PARSER_FUZZING.md](B2_5_PARSER_FUZZING.md). Harness source and deterministic corpus generation are delivered; execution, state-machine fuzzing and independent cryptographic review remain pending.

State and JVM parser harnesses: [B2_5_STATE_FUZZING.md](B2_5_STATE_FUZZING.md). Core acceptance remains open pending actual instrumented runs and independent review.
