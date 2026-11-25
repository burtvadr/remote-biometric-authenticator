# B.3.3 — Android V2 hardware-backed keys

## Scope and boundary

This is the V2-only Android adapter, not a production runtime cutover. Existing
V1 key and prompt code remains unchanged until the coordinated cutover. The
new code never opens a V1 alias or falls back to software keys. The platform's
TLS adapter and actual connection owner are still B.3.4/B.3.5 integration work.
Host remote attestation and release identity verification remain mandatory;
local KeyInfo and challenge checks do not substitute for them.

## Implementation

- V2HardwareKeys generates distinct P-256 signing keys at fresh credential-ID
  aliases, using the two challenges returned by V2Enrollment.acceptStart.
- The transport key is signing-only, SHA-256, and not user-authenticated.
  The biometric key is signing-only, SHA-256, hardware-enforced per-operation
  strong-biometric authentication, with invalidation on new biometric enrollment.
- On API 30+, use setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG).
  On API 28–29, use setUserAuthenticationValidityDurationSeconds(-1), never 0.
  KeyInfo must report the per-operation duration (-1), secure enforcement,
  generated origin, expected role, curve, digest and hardware location.
- Prefer StrongBox when advertised; only StrongBoxUnavailableException permits
  a TEE generation attempt, and only if no alias was left behind. The actual
  generated key is inspected. Neither software nor exportable keys pass.
- Check local X.509 public point, bounded certificate-chain encoding, presence
  of the attestation extension and exact challenge on fresh generation. The
  limited extension reader is not a general ASN.1 or attestation verifier.
- V2BiometricOperation takes an immutable transcript copy and gives the prompt
  one prepared Signature. It checks returned CryptoObject identity, consumes
  its terminal outcome once, rejects stale callbacks after cancellation, and
  returns strict raw ECDSA evidence only when the actual Keystore sign succeeds.
  The caller must serialize operations, cancel on lifecycle/session failure,
  and pass the result into the existing enrollment/authentication state machine.
- V2DeviceStore now rechecks both role keys when staging, activating, reopening
  or retrieving credentials. Explicit pending discard commits removal before
  deleting exactly matched aliases. Unrecorded cleanup refuses pending/active
  IDs. No automatic re-key, automatic reset, or migration.
- No new dependency. Native Android Keystore and existing AndroidX Biometric.

## Decisions and remaining integration risks

- Strict role metadata may reject OEM devices that cannot report the required
  properties. Do not weaken checks to make a device pass. Verify actual
  hardware and API 28/29 support; reject unsupported profiles.
- StrongBox is preferred, not mandatory; attested TEE is acceptable.
- Enrollment cancellation and credential cleanup require one serialized
  owner. SQLite and Android Keystore cannot share a transaction. A process
  crash between generation and staging, or during deletion, can leave unused
  aliases. These cannot authorize V2 without a matching active record. A safe
  orphan reclamation policy under the exclusive session owner is still needed
  before production. Never delete a staged record's keys merely because a
  network attempt timed out.
- There is no generic export API or TLS key adapter in this delivery. B.3.4 must
  demonstrate TLS 1.3 using the transport key without changing its approved
  digest/purpose policy, without using the biometric key, and without exporting
  key material. Some TLS providers use prehashed signing; that compatibility
  must be demonstrated, not assumed.
- Debug APK instrumentation checks local hardware, not host release-signer
  acceptance. Actual remote attestation is B.3.6 release-signed hardware evidence.
- No real-device prompt success, cancellation, biometric invalidation, or TLS
  handshake was observed here. No SEC finding is closed.

## Executed verification in the delivery environment

- Standalone JVM V2KeyEncodingChecks: 66 checks passed using real JCA P-256
  signatures (software JVM test keys only), invalid DER inputs and extension
  parsing fixtures.
- Kotlin conformance: 679 checks passed, plus exhaustive display repertoire
  comparison; JVM target 17 on JDK 21 (installed compiler cannot target 21).
- Python SQLite tests: 8 host + 3 device passed.
- Android SDK, Gradle, device and Cargo unavailable. Android compilation,
  instrumentation, and fresh Rust verification were not run.

## Reviewer commands

From repo root, apply the patch on the B.3.2 baseline. Verify the actual tree
and commit first; earlier local dependency lockfile changes are not included.

```sh
git apply --check ~/Downloads/rba-b3.3-hardware-keys.patch
git apply ~/Downloads/rba-b3.3-hardware-keys.patch
git diff --check
make vectors-kt
python3 protocol/tools/v2_store_tests.py
python3 protocol/tools/v2_device_store_tests.py
cd android
gradle --no-daemon :app:assembleDebug :app:assembleDebugAndroidTest :app:testDebugUnitTest :app:lintDebug
```

On a physical test device with enrolled strong biometrics, run the focused
instrumentation tests. Do not substitute emulator results for hardware results.

```sh
gradle --no-daemon :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=io.github.burtvadr.rba.keystore.V2HardwareKeysTest,io.github.burtvadr.rba.session.V2DeviceStoreTest
```

The hardware test checks two fresh keys, exact challenges, role separation,
point mismatch denial, non-exportable key representation and failure of signing
without biometric authorization. The store test checks actual hardware-key
records and compare-and-set activation across reopen, and rejects cleanup of
recorded keys. They deliberately do not skip if hardware is unavailable.

Before production, exercise a legitimate interactive enrollment and auth:
positive strong-biometric CryptoObject signing and host verification, wrong
number/cancel/expiry/disconnect denial, no device-credential fallback,
biometric-set change invalidating the old key (on a test device only),
re-enrollment with fresh identities, and storage reopen/recovery. Check
StrongBox and TEE profiles independently and minimum-supported Android.
B.3.3 acceptance requires build and local hardware evidence, while remote
trust, full runtime integration and release assurance remain B.3.4–B.3.6.

**B.3.4 candidate update:** see [TLS delivery](B3_4_TLS_DELIVERY.md) for the proposed transport-only NONE + SHA-256 digest set required by Conscrypt. The biometric key policy remains SHA-256 only. This change requires owner review and hardware testing.
