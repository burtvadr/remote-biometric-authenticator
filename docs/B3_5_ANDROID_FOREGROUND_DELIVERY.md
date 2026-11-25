# B.3.5 — V2 Android foreground routing and consent UI

Status: source candidate, not Android build or device acceptance. This is the
foreground component of the final Android UI, not a parallel production mode.

## Delivered

- `V2ForegroundRuntime` is a process-wide, serialized foreground router. Opens
  only the canonical V2 store, invokes exclusive startup reclamation before
  inventory or network operations, and never initializes implicitly. Explicit
  initialization can create a previously nonexistent state directory only.
- `V2OperatorActivity` offers manual endpoint selection, inventory, enrollment,
  authentication, policy sync, pending recovery, revocation, and explicit
  selection of locally disabled records for same-host cleanup. UI metadata is
  not a statement about hardware key health. All network/DB operations execute
  on IO; one local operation at a time. Local revocation denial is durable
  before resolving the network address. On error, refresh before further use.
- `V2OperatorDialogs` implements all existing connection-owner consent hooks.
  User input is required; dismissals, cancellation and activity stops cannot
  approve an operation. Six-digit entry uses a local keypad, no IME or autofill.
  The activity and consent windows use FLAG_SECURE; obscured touches are
  filtered on approval and keypad buttons. These are defense-in-depth, not
  proof of a trusted display or protection from a compromised OS.
- `V2OperatorText` renders an explicit allowlist of validated facts, including
  exact signed scope and context source, principal identifiers, fingerprints,
  revisions and all proposed grants. It does not render whole CBOR maps,
  enrollment tokens, receipt secrets, channel exporters or nonces. Signed
  label text is isolated for display only; its signed encoding is unchanged.
- `V2DeviceStore.inventory()` exposes only nonsecret metadata and distinguishes
  active, pending, revoking and acknowledged-cleanup states.

## Integration boundary

The new activity is intentionally not registered in the existing V1 manifest.
The old launcher, service, boot receiver and notification entry points remain
unchanged until a coordinated cutover. There is no second active authentication
service, V2-to-V1 fallback or portable-core extraction. The activity is native
Android widgets rather than a redesign of the existing Compose theme; final
appearance integration can preserve the roadmap UI features independently.

Next, connect the final V2 launcher and background service/notification routing
with the actual host listener and trusted local operation scheduler. Establish
how a waiting enrolled device is notified of an admitted host operation without
unsolicited approval prompts, polling storms or remote-controlled intent extras.
Do not register this activity as a concurrent alternative while the old service
is active. Do not claim background authentication is delivered here. Retain
manual host selection as a legitimate feature, not a fallback to V1.

## Evidence and local verification

Executed locally with Kotlin JVM target 17 on JDK 21:
- `make vectors-kt`: 739 existing fixture checks plus exhaustive text repertoire.
- `V2OperatorTextChecks`: 28 presentation assertions against validated shared
  fixtures (run as a standalone JVM entry point).
- `python3 protocol/tools/v2_store_tests.py`: 8/8.
- `python3 protocol/tools/v2_device_store_tests.py`: 8/8.

OpenCode: apply patch, run `make vectors-kt`, the two SQLite scripts, and
`gradle --no-daemon :app:testDebugUnitTest --tests '*V2OperatorTextTest'`,
`:app:assembleDebug`, `:app:assembleDebugAndroidTest` and `:app:lintDebug` from
`android/`. Use the existing locked Rust regressions to confirm no change.
The Android SDK, Gradle and a physical device were not available here. The
presentation test does not validate real Android dialogs, lifecycle,
notification routing, overlay behavior, key hardware, or end-to-end TLS.

Physical acceptance must include exact visible text in long and RTL labels,
all grant entries scrollable, explicit consent, cancellation on peer disconnect,
activity stop/recreation, no automatic approval, and failed-network revocation
remaining locally denied. Exercise initialization errors, pending/active/revoking
inventory, retry, and startup reclamation. The manifest and background integration
must be reviewed before those end-to-end checks; no security finding is closed.

The patch is based on the original upload plus all previously delivered patches,
through B.3.5 offline cleanup. It does not incorporate unprovided local fixes.
