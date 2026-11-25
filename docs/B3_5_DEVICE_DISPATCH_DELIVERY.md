# B.3.5 — Android connection ownership candidate

## Scope

The Android-only `V2ConnectionOwner` drives locally selected authentication, both manual SPAKE2 enrollment directions, and authenticated pending-enrollment receipt recovery through the existing V2 TLS, Keystore, native PAKE and SQLite adapters. The process-wide operation mutex excludes concurrent entry. The owner is not yet wired into the active service or concrete UI; it is not a runtime cutover. No new dependencies or portable-core extraction.

`V2OperationWire` maintains one outstanding blocking read during UI interaction and reuses that read for the next response. It closes on EOF, unexpected messages, deadline, write failure or coroutine cancellation; the UI coroutine is cancelled on disconnect. A separate read/write lock in the real TLS adapter allows monitoring while sending. Terminal receipt closure waits for an in-progress bounded write to finish, avoiding closing the carrier while the last frame is still flushing. The owner uses the original monotonic deadlines from the validated state machines, rather than recomputing durations. All read/write calls remain bounded. The real Android CryptoObject adapter is bound to the exact transcript, and cancellation is posted to the main thread; the UI must cooperate with cancellation and show the supplied immutable-by-ownership facts. Activity stop during UI cancels that interaction. Explicit declines before final evidence send the state machine's bound CANCEL; failures or lifecycle loss close the connection. Host success is never inferred from a phone UI callback.

The initial device policy is derived from the exact durably approved revision-1 offer; empty grants deny all. Auth re-reads the exact active record before each sensitive transition. No new policy is learned from a signed challenge. Durable policy synchronization and local policy changes are still pending; later revisions fail closed, rather than accepting stale or unapproved permissions. Pending recovery is a distinct channel profile that cannot authenticate. Failed enrollment discards newly generated keys only if the database confirms that no pending/active record exists. Uncertain commits retain the keys. The cleanup token list is empty until authenticated revocation recovery is implemented; no automatic replacement or deletion of existing credentials.

## Verification performed here

* `make vectors-kt` using Kotlin JVM target 17 on JDK 21: 687 fixture checks (82 wire, 306 message/transcript, 22 device policy, 25 auth, 59 enrollment, 42 structured state traces, 151 existing conformance); exhaustive display repertoire comparison also passed. Eight added protocol checks cover initial policy digest/deny-all and original deadlines.
* Standalone Kotlin/JVM `V2OperationWireChecks`: 23 assertions, using close-aware blocking test link. Covers reuse of read during multiple UI steps, peer EOF, unexpected messages, no writes after rejection, local cancellation and UI dismissal, no concurrent readers, expired deadline and wrong message kind. This does not test actual Conscrypt, Android lifecycle or Keystore.
* Existing independent SQLite tests: 8 host + 3 Android schema checks passed. No database schema change.
* Git whitespace and patch application checked on reconstructed B.3.5 host-dispatch tree. Latest OpenCode working tree not supplied.

## Local verification

From repository root:

```
git apply --check ~/Downloads/rba-b3.5-device-dispatch.patch
git apply ~/Downloads/rba-b3.5-device-dispatch.patch
git diff --check
make vectors-kt
cd android
gradle --no-daemon :app:assembleDebug :app:testDebugUnitTest :app:lintDebug
# Target coordinator unit test directly:
gradle --no-daemon :app:testDebugUnitTest --tests '*V2OperationWireTest'
```

Android Gradle, SDK, Cargo and physical hardware are unavailable in the delivery environment. Real Android compilation and Conscrypt duplex I/O/cancellation must be verified. In particular test host disconnect during each UI stage, activity stop and late biometric callbacks, both pairing directions with real JNI and hardware, lost receipt recovery, terminal receipt arriving during write flush, and store errors during staging. Verify the UI shows trusted signed context and host fingerprint; do not activate a UI that fabricates consent. Release signing and runtime routing remain required.

## Remaining work

Durable policy synchronization (host and Android offer/decision/receipt and device constraints), authenticated Android revocation tombstones and retry/recovery, exclusive-startup orphan-key reclamation, concrete activity/UI/service and local IPC integration, periodic trust refresh, release signing, physical Android and end-to-end TLS/exporter/attestation verification. B.3.4 transport digest policy candidate remains owner-approval pending. B.2.5 coverage analysis remains open. No security finding closed or V1 runtime changed by this delivery.
