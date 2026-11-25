# B.3.7.5.2 — Original Android product interface (candidate)

Baseline: main at 0ff5bae. This is a cumulative patch replacing the earlier
presentation-preparation patch. Apply once to the clean baseline, not on top of
that preparation patch. Do not install until both builds pass.

## Product path

The launcher targets `V2MainActivity` and the existing `AuthenticatorScreen`
composables. The Overview, paired-host cards, settings, theme, fingerprint badge,
dynamic color and launcher icon variants are reused; the raw operator activity
is deleted and there is no alternate debug launcher. The original V1 activity
and implementation remain unregistered, not a runtime fallback. The retained
review-dialog implementation is security consent, not a management dashboard.

The host is still started using the current standalone or `--hardware-test` CLI.
The hardware-test signer/LAN configuration is still explicitly approved on the
host once. With verified status and a bound private IPv4 listener, RBA advertises
V2 DNS-SD endpoints. Enrollment advertises only for a locally admitted pairing.
Android discovers candidates automatically while open. The operator confirms the
nearby unverified pairing request, then completes the existing PAKE, exact
fingerprint review, biometric and initial grant workflow. The authenticated
receipt remains authoritative. Fresh app state is initialized automatically;
missing/corrupt existing state and orphaned V2 aliases cannot be silently reset.

After pairing, foreground launch plus notification permission starts the V2
service. It uses one connection owner, selects exact enrolled host/key hints,
and rediscovers on reconnect; TLS and the enrolled session independently check
all pins. No address or credential is accepted from an Intent. Opening a live
notification is still required for background review. No overlay, full-screen
intent, boot restart or automatic biometric approval was restored. The original
permission card remains but describes overlay/full-screen as not required.
The original unpair action commits local denial atomically for the host before
network retry. Pending receipt recovery and revocation retries use the enrolled
route while the app is open; same-host cleanup still requires exact approval.

## Limits and review gates

- Source-level restoration of the original Overview/Settings, not a verified
  pixel-perfect screenshot comparison. Existing protected native review dialogs
  still supply V2 number input and exact consent; those differ from V1 prompts.
- DNS-SD is untrusted metadata, not authentication. One explicit private IPv4
  address is advertised; no wildcard/public listener or firewall change. A
  cached or spoofed advert cannot grant trust. Ambiguous pairing adverts and
  ambiguous same-host routes are rejected. Physical LAN discovery must be tested.
- The service still has one live authentication connection at a time and uses
  the existing bounded operation deadlines/reconnect delay. Notification-only
  handoff and process-death behavior remain V2 differences. Multi-host rotation,
  stopping/restarting during pairing, and cancellation need physical validation.
- Policy expansion remains in the existing V2 runtime, but an automatic
  host-driven policy synchronization route is not yet exposed by the CLI. The
  engineering policy button is removed; do not claim complete feature parity.
- Full Rust/Android build and lint are not available in the patch authoring
  environment. The known legacy MissingPermission lint diagnostics remain;
  no additional permissions were added just to satisfy inactive V1 code.

## Verification

From the repo root run static entry checks and both independent SQLite suites.
From linux run `cargo test -p rbad --locked discovery_`, the full rbad/rba tests,
`cargo check --workspace --all-targets --locked`, and release build. From android
run `gradle :app:compileDebugKotlin :app:testDebugUnitTest :app:assembleDebug`
and lint. Verify the APK signer. Test in the existing isolated hardware-test
profile without clearing any app data. Check the original Overview, Settings,
icon variants, both pairing directions, consent/cancellation, correct discovery
identity, background auth, unpair while offline, receipt recovery, persistence,
and separation from normal standalone. Compare against reference screenshots
before accepting GUI parity. Do not mark B.3.7.5 complete on a build alone.
