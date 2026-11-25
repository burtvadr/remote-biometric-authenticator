# B.3.5 — Android authenticated revocation and receipt recovery

This delivery connects the existing host-side REVOKE/REVOKE_RECEIPT transaction to the Android V2 operation owner. It does not activate V2 or change the V1 runtime. No new dependencies, no shared-core extraction, no compatibility path.

## Invariants

- Explicit local revoke enters the same process-wide exclusive operation owner as authentication, enrollment and policy synchronization. Local denial is committed before connecting; pending/acknowledged revocations are excluded from active credential and policy queries. There is no operation to undo local denial.
- The revocation channel has its own local mode; after the enrolled mTLS and HELLO exchange it accepts only REVOKE_RECEIPT and sends only REVOKE. It loads the exact hardware transport key independently of the biometric key, pins the stored host key and checks the actual session and credential. It cannot route authentication or policy messages.
- Each V2Revocation instance accepts at most one request and one exact receipt, validates wall/monotonic elapsed time and the stored identities, and consumes its attempt before invoking the acknowledgment callback. Failed storage, transport or validation leaves the durable denial in place. Retry opens a new channel. The token is not logged; the instance's token copy is cleared after request construction or cancellation (the encoded message and protected record necessarily retain the token).
- The authenticated receipt is persisted as a compare-and-set before either key is deleted. After acknowledgment, cleanup needs no network or functioning private key. It checks all extant public certificates against the record before deleting, then deletes the durable record and cascades policy/revocation rows. Interrupted cleanup can be retried using the acknowledged record. Missing or mismatched key identity never authorizes deleting a different key.
- The store schema is exact. Old experimental V2 databases missing the revocation table must be explicitly replaced through the development reset/enrollment process; no automatic reset or migration.

## Scope and remaining work

This is the online enrolled-mTLS revocation/retry and post-receipt cleanup component, not the complete B.3 runtime. A host that cannot be reached or no longer accepts the revoked transport pin cannot be asserted to have acknowledged revocation. Local denial persists until actual evidence; a lost/missing transport key, expired server retry window, same-host PAKE offline cleanup token selection and receipt-bound old-record reclamation need the separate offline recovery flow. Startup reclamation of unrecorded aliases and concrete UI/service routing remain pending. Do not delete the only retry record merely because the host is unreachable. The host's existing revocation-only window remains unchanged. Production cutover must not occur until all these lifecycle requirements and physical acceptance pass.

## Verification

Run `make vectors-kt`, `python3 protocol/tools/v2_device_store_tests.py`, `python3 protocol/tools/v2_store_tests.py`. The JVM state tests use a validated enrollment fixture, exercise request and receipt mismatch, timeout, cancellation, replay, failed acknowledgment and a new-session retry. SQL tests execute the extracted schema, not Android SQLite or Keystore. Run `:app:assembleDebug`, `:app:assembleDebugAndroidTest`, `:app:testDebugUnitTest`, `:app:lintDebug` and the updated V2DeviceStoreTest on a physical device with strong biometrics. Test-only storage acknowledgment simulates the verified receipt boundary; actual cross-platform mTLS revocation and lost-receipt recovery remain mandatory integration tests.
