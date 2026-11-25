# B.3.4 — TLS 1.3, key pinning and native Android provider candidate

Status: source delivered for review; not active in either V1 runtime. B.3.4 and B.3.5 acceptance remain open. No legacy fallback, no portable core extraction.

## Design

Linux uses the existing rustls 0.23 / ring provider and tokio-rustls. Android uses an explicit app-local Conscrypt provider, pinned to `org.conscrypt:conscrypt-android:2.9.0`; do not register the provider globally. The public Conscrypt exporter API avoids hidden Android APIs. Source for the selected version: https://github.com/google/conscrypt/tree/2.9.0 ; its `common/src/main/java/org/conscrypt/CryptoUpcalls.java` delegates opaque EC key operations to the platform as `NONEwithECDSA`. Source and release existence were checked; downloading/verifying the AAR, transitive native code, Gradle dependency verification, Android minimum API compatibility, advisory review and physical execution remain required. No network access to Maven Central from the implementation environment.

TLS is 1.3 only. Production and explicitly authorized enrollment listeners select exactly `rba/2` and `rba-enroll/2`. The client requires the negotiated protocol; the host rejects missing or mismatching ALPN even if the TLS library completed its handshake. No tickets/resumption or early data on the host; fresh SSLContext per Android connection and ticket suppression. Both endpoints obtain the RFC 9266 32-byte exporter from the actual completed handshake, using label `EXPORTER-Channel-Binding` and empty context. No application-supplied channel assertions.

Host cert must match the host protocol signing key. The production client cert is a single leaf public-key carrier, checked for current validity, P-256 and exact registered transport key; the original complete attestation chain is validated at enrollment and periodically revalidated separately. TLS CertificateVerify remains mandatory. No public CA, discovery or hostname is substituted for the enrolled pin. Temporary enrollment accepts only a self-signed provisional P-256 certificate with proof of private key possession. Provisional TLS is not a trust decision; its actual key and cert fingerprints must be bound by PAKE before any enrollment trust is created. Host and Android use separate mode-specific message sets. Pending device records may use production TLS for status recovery only. A final runtime owner must enforce all additional state-machine transitions.

The host takes actual TCP source and accounts for accepted sockets before TLS work, snapshots only locally eligible registered pins, bounds preclassification traffic, and rechecks the credential at HELLO_ACK. Handshake and first-frame deadlines are absolute. Subsequent frames have a five-second completion deadline after the first byte and an owned operation deadline (30 seconds idle by default). Failed operations invalidate the channel; a dropped/cancelled operation must not be retried on the same channel. The Android adapter uses a socket-closing watchdog on the underlying carrier to bound blocking handshake and frame I/O. Android's provisional key is a fresh short-lived Keystore alias, never a long-term credential; normal closure deletes it. Crash orphan reclamation must be implemented by the serialized runtime owner before cutover.

## Binding key-policy decision requiring owner review

The B.3.3 transport key previously allowed only SHA-256. Conscrypt's delegated opaque EC CertificateVerify uses the already-hashed digest via `NONEwithECDSA`. The proposed exact transport digest set is therefore `{NONE,SHA-256}`, with P-256, SIGN only, generated hardware key, no biometric gating. Host attestation and Android local KeyInfo checks enforce this exact set. The biometric role remains SHA-256 only, hardware-authenticated per operation, and is never exposed to the TLS key manager. Application enrollment proof still uses SHA256withECDSA on the full domain-separated transcript, not raw digest signing. Existing SHA-256-only V2 development transport keys must be discarded through explicit re-enrollment, not upgraded or accepted via a compatibility branch. This is an explicit policy change, not a software fallback. If target hardware cannot provide this profile, the provider choice must be reconsidered before activation. See https://github.com/google/conscrypt/blob/2.9.0/common/src/main/java/org/conscrypt/CryptoUpcalls.java and https://www.rfc-editor.org/rfc/rfc9266.html .

## Verification evidence

Executed in the implementation environment:

- 13 desktop JVM JSSE identity and TLS 1.3 loopback checks (exact key pin, wrong pin, required client cert, wrong ALPN, invalid curve/chain, identity alias handling). This exercises V2TlsIdentity and V2TlsTrust, **not** V2TlsClient or Conscrypt.
- 679 prior Kotlin protocol checks plus full repertoire comparison. Kotlin target 17 on JDK 21, not the default 21 target.
- 27 independent OpenSSL certificate-path fixture checks (includes three new digest-policy fixtures; OpenSSL alone does not enforce Android policy).
- 2 official Android root checks and 11 existing SQLite tests.

Added but not executed: four Rust TLS tests (real mutual TLS, exporter agreement/freshness, rejection of missing/unknown client certificate and incorrect ALPN, wrong host key); one Rust attestation role/digest test; Android physical instrumentation for non-exportable transport-key prehash signing and native Conscrypt-to-Conscrypt mutual TLS/exporter agreement. Cargo/rustc, Gradle, Android SDK and device absent. No live GitHub worktree or dependency lockfile changes verified. Patch base is reconstructed through B.3.3.

## Verification commands

```
git apply --check rba-b3.4-tls.patch
git apply rba-b3.4-tls.patch
git diff --check
python3 protocol/tools/v2_attestation_fixtures.py
cargo test --manifest-path linux/Cargo.toml -p rbad --locked v2_tls::tests
cargo test --manifest-path linux/Cargo.toml -p rbad --locked v2_store::attestation
cargo test --manifest-path linux/Cargo.toml -p rbad --locked
cargo check --manifest-path linux/Cargo.toml --workspace --all-targets --locked
make vectors-kt
cd android
gradle --no-daemon :app:assembleDebug :app:assembleDebugAndroidTest :app:testDebugUnitTest :app:lintDebug
# Physical Android with strong biometric enrolled; no silent skip:
gradle --no-daemon :app:connectedDebugAndroidTest
```

Standalone desktop JVM identity tests (from repo root):

```
base=android/app/src/main/kotlin/io/github/burtvadr/rba
kotlinc "$base/keystore/V2KeyEncoding.kt" "$base/transport/V2TlsIdentity.kt" \
  android/app/src/test/kotlin/io/github/burtvadr/rba/transport/V2TlsIdentityChecks.kt \
  -jvm-target 17 -include-runtime -d /tmp/rba-tls-checks.jar
java -jar /tmp/rba-tls-checks.jar
```

## Integration and security acceptance still required

1. Verify the actual selected Android native provider against the pinned artifact and supported ABIs/minimum API; test StrongBox and TEE separately with the new transport digest set. No claim of hardware TLS acceptance from desktop JSSE or synthetic paths.
2. Exercise real Linux rustls ↔ physical Android Conscrypt TLS and compare independently obtained exporters; prove fresh exporter on reconnect, wrong pins/ALPN/missing cert rejection, and signed transcript substitution rejection. The physical loopback test is useful but not cross-platform evidence.
3. Integrate a single host identity provisioner (same TLS and protocol key), actual explicitly bound listeners, authoritative connection owner, periodic attestation refresh worker and Android connection owner/UI. Validate socket deadlines, preclassification budget, cancellation and connection lifetimes under real network load. No application-layer bypass of the authority.
4. Resolve the terminal lifecycle boundary: existing authority success/revoke/status paths can mark the connection denied before the adapter sends the exact final informational receipt. Provide a typed one-shot terminal write, tied to the committed operation and no subsequent reads; do not add a general bypass of denied connections. Verify failure/receipt recovery and concurrent revocation. Revocation-only Android tombstone connection mode and orphan provisional alias reclamation require the runtime owner.
5. Complete release signing, platform attestation and hardware acceptance. No V1 removal or production activation in this patch. SEC-005, SEC-007, SEC-008, SEC-014 and B.2.5 outstanding coverage remain open.
