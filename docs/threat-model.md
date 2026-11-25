# RBA V2 — Threat model

**B.1 target; not verified runtime behavior.** Baseline review: `2b8e76d` + B.0; historical test names and limitations can be recovered from that version. All proposed controls require evidence before release. See [architecture](ARCHITECTURE_V2.md), [wire profile](../protocol/specification/PROTOCOL.md) and [audit tracker](security-audit.md).

## Assets and trust boundaries

| Asset | Custodian | Required property |
|---|---|---|
| OS authentication decision | OS PAM/service | No wrong-principal, wrong-operation or stale approval; local password route independent |
| Host identity key | `/var/lib/rba/v2/` root-only | Confidentiality, integrity, pinned public key |
| Device transport key | Android hardware Keystore | Non-exportable, verified identity; cannot approve biometrics |
| Device biometric key | Android hardware Keystore | Fresh strong biometric per signature; attested key policy |
| Grants, credentials, budgets | Host SQLite transaction store | Atomicity, integrity, revocation and durable limits |
| Pending request and consent | Core and local interaction adapter | Channel-bound, immutable, single-use, deadlines |
| Enrollment code and revocation token | Owned transient memory / protected storage | Never logged or reused for authentication |
| Audit data | Root-owned logs | Minimal, bounded, honest outcome and context provenance |

Trust only kernel-authenticated local peers and configured platform adapters; TLS authenticates enrolled transport keys; cryptographic proof establishes biometric key possession under its verified policy; policy establishes authorization, separately. Discovery, routing addresses, UI labels and capability claims grant no trust. Android UI and OS are trusted to present context and enforce the native biometric boundary; signatures are not evidence of what a compromised UI showed. Enrollment establishes trust only after PAKE, key proofs, attestation, human consent and durable staging/commit. No simulator or debug trust in production.

## Threats and required evidence

| Adversary/failure | Design control | Acceptance evidence |
|---|---|---|
| Active network adversary, fake discovery, relay/substitution | TLS mutual pins; PAKE binds actual peer certs/exporter; signed channel and challenge | Real two-peer mutation tests; mismatched pins and exporter deny |
| Unpaired client, malformed traffic, resource exhaustion | Separate temporary listener, caps before work, exact bounded parser and deadlines | Load, fragmentation, malformed CBOR/TLS and fuzz reports; no unbounded growth |
| Malicious local ordinary process | Peer credentials; scoped trusted integration; no caller-supplied authority | Cross-UID, wrong service, forged scope and malicious local socket tests |
| Prompt fatigue or social engineering | Local explicit number matching, one live request, durable per-principal/device and elevated limits, clear context | Real UX, wrong/missing code and concurrent/failover/restart tests; number phishing remains possible |
| Replay, confused deputy, expired request | Signed immutable context, exporter, request hash, one-shot transition and monotonic deadlines | Negative signature substitution, duplicated evidence, cancel/deadline race tests |
| Account deletion/rename/reuse, unauthorized delegation | Managed lifecycle, opaque generation, explicit grants | Actual account lifecycle test, reject unmanaged identities; no implied root grant |
| Grant mutation or device revocation during authentication | Final transactional authorization check | Concurrent commit ordering tests, no success after earlier revoke |
| Stolen phone, malicious software key, wrong APK | Separate attested keys, fresh biometric, verified boot/app identity, revocation freshness | Release-signed phone positive/negative attestation and biometric tests |
| Device/UI process compromise | Hardware per-use signing limits, scoped context, local intent | Document limits; no claim that hardware proves display integrity or app uncompromised at runtime |
| Re-enrollment, lost receipt, cancellation, failed storage | Durable staging, atomic host commit, exact authenticated status recovery | Fault injection at each persistence transition and both code directions |
| Restart, clock rollback, corrupt state | Atomic store, fail closed, durable counters, no live request restoration | Power-loss model, injected I/O errors, rollback and corrupt-state tests |
| PAM panic, hang or daemon unavailable | Thin bounded client, audited FFI, independent OS password route | Release-mode panic/timeout and real PAM service tests with recovery |
| Tracking, account enumeration | Opt-in generic discovery, no unauthenticated account oracle; minimum logs | Packet captures and controlled timing distributions; traffic presence still visible |

## Assumptions and residual risks

Trusted Linux kernel/root, administrator-managed account lifecycle, trustworthy clock and randomness, supported local filesystem, maintained TLS/PAKE/Keystore implementations and correctly installed trust anchors. Compromised Linux root can replace PAM and state; no protocol can protect that boundary. A compromised Android OS/TEE, malicious trusted UI or coerced user can defeat assumptions; attestation is point-in-time and does not guarantee continuous integrity. A six-digit PAKE code has finite online guessing risk: one admitted exchange, globally bounded attempts, fresh code and explicit human approval limit exposure, not eliminate it. Number matching can be relayed by a cooperating or deceived human; do not market it as unconditional phishing resistance. Traffic analysis, physical coercion, DoS and rollback by privileged administrators are not eliminated. Stale attestation revocation data, invalid clock or failed verification intentionally reduce availability; normal OS recovery must remain. No support for unmanaged account sources or operations whose trusted context/intent UI cannot be established. Future platform adapters require their own threat review.

## Evidence status

B.0 Kotlin checks against existing V1 fixtures and static source review are historical evidence only. V2 design, Rust implementation, native Android TLS, attestation, physical biometric flow, release signatures and PAM deployment have not been validated. Do not mark any V2 security requirement resolved without the acceptance evidence in the tracker. No blanket claim that each threat already has a passing test.
