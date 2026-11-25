# B.3.7.5 — Security assurance levels and isolated compatibility testing

Status: Level 0 is the existing strict V2 implementation; its physical
Android interoperability is an open acceptance gate. Level 1 is an explicit
lower-assurance compatibility path. This change delivers an isolated Level 1
hardware/transport and biometric-gate instrumentation tests; it does not activate Level 1 enrollment
or CLI authentication in the application. No security milestone is closed.

## Motivation and observed evidence

On the Motorola Edge 30 Ultra running LineageOS, operator-reported
instrumentation tests generated the original biometric key and both V2 role
keys successfully without an attestation challenge. The corresponding P-256
key generation with `setAttestationChallenge` failed with KeyMint -10003
(public `ERROR_KEYMINT_FAILURE`), on StrongBox and TEE. TLS and ENROLLSTART
were reached. This isolates the triggering parameter, not the underlying
firmware/provisioning defect, and is not evidence about all Android devices.

## Level definitions (lower number = stricter assurance)

| Property | Level 0 — strict | Level 1 — compatibility test |
| --- | --- | --- |
| Two distinct P-256 keys | Required | Required |
| Android Keystore, local hardware inspection | Required | Required |
| Per-operation strong biometric signature | Required | Required for runtime auth |
| TLS 1.3, channel binding, SPAKE2, explicit consent | Required | Required for runtime enrollment/auth |
| Exact signer, official attestation chain, challenge, boot policy | Verified remotely | Not verified remotely |
| Google attestation revocation freshness | Required | Not applicable; no fabricated result |
| Privileged/system/PAM authorization | Only after separate future acceptance | Forbidden |

Level 1 does not remotely establish hardware protection, biometric enforcement,
app identity, boot integrity or Android attestation revocation status. The host
can verify key possession and signed protocol transcripts only. Local KeyInfo
checks are defense in depth, not remote evidence. A rooted or compromised client
may misrepresent those facts. A signature is not proof of biometric use without
trusted evidence of the signing key's enforcement policy.

## Immediate runnable test

The Android instrumentation suite has separate Level 1 cases using a fresh,
non-attested Android Keystore transport key. It checks local hardware metadata,
non-exportability, exact digest/role parameters, fresh signature verification
and altered-input rejection. It exercises the same Conscrypt TLS 1.3 loopback
harness used for the strict test: mutual key pinning, opaque EC CertificateVerify,
ALPN and exact exporter equality. A second test checks the unattested biometric
key's local per-use strong biometric authorization metadata and verifies that
signing without an authorized CryptoObject fails. Level 1 uses a test-only ALPN and temporary
aliases which are removed in finally blocks. No production database, trust
configuration, enrollment, authentication success or listener is activated.

Run on the physical test device, using the configured Android SDK:

```sh
cd android
gradle :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=io.github.burtvadr.rba.transport.V2TlsHardwareTest#level1UnattestedOpaqueTransportCompletesMutualTlsAndExporterAgrees
gradle :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=io.github.burtvadr.rba.keystore.V2HardwareKeysTest#level1UnattestedBiometricKeyRejectsUnauthenticatedSigning
```

The separate strict tests retain their security requirements. Level 1
passing does not make the strict test pass. This probe is phone-local; it does
not prove Rust/Android TLS interoperability or actual biometric approval.

## Runtime fallback contract (not yet implemented)

The existing host schema and authority explicitly require genuine attestation
and Google-status freshness fields. Never fill those fields with synthetic
values, empty status lists, placeholder roots or invented successful validation.
Do not modify the strict verifier to accept missing evidence.

Implement Level 1 as a separately selected, standalone debug-only runtime:

- Explicit operator selection via a CLI profile; no automatic downgrade after
  a strict enrollment fails, no extra permanent Android GUI controls.
- Independently isolated host identity, state directory, SQLite schema marker,
  sockets and Android credential namespace. Persist the assurance classification
  and use distinct protocol profile binding; never migrate Level 1 trust to Level 0.
- Represent unattested evidence explicitly (e.g. `Unattested` versus
  `VerifiedAttestation`); store ordinary enrollment time separately from attestation
  time. No invented attestation timestamps or status refresh. Enforce the correct
  evidence class in the host authority and at store open, enrollment, request
  admission and final authorization. Level 1 must reject privileged grants and
  service origins independently of the CLI parser.
- Generate two non-exportable Android Keystore keys using the same role-specific
  parameters and per-use biometric CryptoObject, omitting only the Android
  attestation request. Check actual hardware location locally. If not supported,
  fail; do not fall back to a software key in this profile.
- Keep fresh enrollment and authentication proofs, strict canonical message
  validation, TLS 1.3 exporter binding, SPAKE2, number matching, actual key
  possession, explicit fingerprint/CLI grant approval, cancellation, durable
  receipts, revocation, rate limits and replay protection.
- Keep the original Compose interface and workflow, including automatic discovery
  and existing consent controls. Show the lower assurance as text during pairing
  and in CLI status/results; no engineering dashboard. Discovery is not a source
  of trust or an instruction to downgrade a strict credential.
- A strict host must reject all Level 1 records and exchanges, even if manually
  copied or advertised. A Level 1 host must never yield PAM/sudo/GDM/polkit
  success. The lower assurance cannot be silently promoted; fresh Level 0
  enrollment with successful independent attestation is required.

Acceptance for the eventual runtime: Level 0 still fails closed with unavailable
attestation; Level 1 completes standalone real-phone enrollment and biometric
challenge/response on this device; denial, cancellation, wrong key, replay,
revocation, restart, cross-profile substitution and privileged-origin rejection
are tested. No claim of production compatibility or full assurance until measured.
