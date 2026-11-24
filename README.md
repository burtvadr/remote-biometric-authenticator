# Remote Biometric Authenticator `rba` (v0.1.0)



<img src="media/icons/auto/rba-light.svg" width="128" height="128" alt="Light icon" align="right" />



A single or multiple devices can act as remote cryptographic authenticators for one or more host machines.
The device approves with native biometric interface;
The host verifies a signature over a fresh challenge instead of trusting a simple transmitted `YES`.

<p align="center">
  <a href="media/demo/demo-v2.mp4">
    <img src="media/demo/demo-v2.gif" width="720" alt="Demo: pairing and fingerprint approval" />
  </a>
</p>

<p align="center">
  <a href="media/demo/demo-v2.mp4">▶ Watch the full demo video</a>
</p>

<p align="center"><sub>Fingerprint mark adapted from <a href="https://www.svgrepo.com/svg/246819/fingerprint">SVG Repo's Security 15 collection</a> (CC0), heavily modified.</sub></p>

```text
$ rba auth --user alice --purpose sudo

Waiting for authentication on Pixel 9 for alice…

[rba] Authorize: user=alice host=workstation action=sudo
[rba] Confirm with your fingerprint.

Authenticated.
  device    Pixel 9
  user      alice
  purpose   sudo
```

## Status

| Component | State |
|---|---|
| Protocol specification | complete, normative |
| Rust implementation | complete, 200 tests |
| Kotlin implementation | complete, 124 cross-language conformance checks |
| `rbad` | working end to end: pairing, challenge/response, verification, revocation |
| `rba` | working |
| `rba-sim` | working, including deliberate misbehaviour for tests |
| `pam_rba` | scoped GDM and polkit overrides; password fallback preserved (`make verify`) |
| Android app | validated on Android 17 LineageOS : Wi-Fi discovery, both pairing code directions, background auto-prompt, biometric-gated signing, auto-close after the decision |
| polkit agent | **unnecessary** — see below. Kept for headless hosts only |
| BLE transport | framing and segmentation complete and tested; BlueZ/central wiring not done |
| fprintd compatibility | not started, deliberately last |

Verification commands, and what each proves:

```bash
make test         # Rust: protocol, daemon, security suite, PAM, vectors
make vectors-kt   # Kotlin against the shared vectors, no Gradle needed
make e2e          # real daemon + simulator: pair, authenticate, replay, leak checks
make verify       # everything above (Rust + Kotlin vectors + end to end)

make android-all  # Android lint, unit tests, debug APK (needs ANDROID_HOME)
```

Latest run: 200 Rust tests pass with no clippy warnings; the Kotlin runner agrees
with Rust on 124 checks; the end-to-end smoke test passes; the Android app lints
clean, passes 31 unit tests, builds a debug APK, and has been exercised end to end
on a physical device in the foreground and in the background.

## Design commitments

* **The proof is a signature over context.** A response covers the host, device,
  request id, user, purpose, service, operation, challenge and expiry, under a
  domain separator. Changing any one of them changes what the user approved.
* **Canonical encoding, enforced.** Payloads are canonical CBOR and the decoder
  rejects every non-canonical form, so exactly one byte string can represent a
  given message. Signing the bytes is therefore unambiguous.
* **Biometric material never moves.** The app asks Keystore to sign and never
  sees a key. A failure to sign is a denial, never an approval.
* **Explicit pairing.** A short-lived session, a six-digit code shown on one
  endpoint and typed on the other (`--code-entry device|host`), reciprocal MACs,
  and a device-side human gate. No permanent pairing mode, and discovery alone
  authorises nothing.
* **Fail closed.** Every failure mode denies. The PAM *stack* may fall through to a
  password; the module itself never converts a protocol failure into success.
* **Revocation is immediate, then best-effort.** The device forgets a host locally
  first. If the pinned link is up it sends a host-issued bearer `UNPAIR` token, and
  the host marks that record revoked. If the host is offline the token is carried
  in the next pairing submit and the host cleans the old record before committing
  the new one. The token authorises revocation only; it is not authentication, and
  losing it means the host operator revokes manually.
* **Transport is not identity.** Wi-Fi and BLE carry identical frames. Which link
  is used changes at most the freshness window.

The SPAKE2 enrollment integration is a candidate pending full Rust, native
Android and physical device verification. Manual six-digit pairing remains the
default; no QR or camera is required. See [pairing](docs/pairing.md),
[SEC-026](docs/SEC-026-SPAKE2.md) and the [threat model](docs/threat-model.md).
Old enrollments are not retroactively upgraded; re-enroll for the new assurance.

## Repository layout

```text
protocol/
  specification/PROTOCOL.md   normative spec: framing, messages, transcript, pairing
  test-vectors/               shared fixtures both implementations must satisfy

linux/
  protocol/                   Rust: CBOR, framing, crypto, verification, replay guard
  rbad/                       the daemon: pairing, engine, registry, transports, IPC
  rba/                        operator CLI
  rba-sim/                    fake device, can misbehave on demand
  pam-rba/                    thin PAM adapter
  systemd/                    service and socket units

android/
  protocol/                   Kotlin protocol implementation + vector runner
  app/                        Compose UI, BiometricPrompt, Keystore, transports

docs/
  architecture.md
  threat-model.md
  pairing.md

packaging/                    native packaging skeletons per distribution family
tests/
  e2e-smoke.sh                real end-to-end smoke test
```

## Quick start

```bash
# Linux daemon against a private state directory, no root needed
linux/target/debug/rbad \
    --state-dir /tmp/rba/state \
    --socket   /tmp/rba/control.sock \
    --audit-log /tmp/rba/audit.log \
    --port 47123 --bind 127.0.0.1:47123 --no-mdns &

# Pair a simulator
linux/target/debug/rba --socket /tmp/rba/control.sock pair
# in another terminal, when the code is displayed:
linux/target/debug/rba-sim pair --host 127.0.0.1:47123 --name "Pixel 9" \
    --daemon linux/target/debug/rbad \
    --daemon-arg --state-dir --daemon-arg /tmp/rba/state

# Authenticate
linux/target/debug/rba-sim serve --host 127.0.0.1:47123 \
    --ca /tmp/rba/state/host.crt --timeout 120 &
linux/target/debug/rba --socket /tmp/rba/control.sock \
    auth --user "$(id -un)" --purpose sudo
```

`tests/e2e-smoke.sh` does all of this and asserts the security properties.

## Testing the Android app over Wi-Fi

Requirements: a **strong biometric** (fingerprint or strong face) is enrolled on
the device, the device and Linux machine are on the same LAN with multicast
enabled, and the device has been allowed to show notifications. For the app to
open itself over another app, allow **display over other apps** (or the
full-screen-intent fallback) from the app's *Background operation* card. The
service keeps one idle link open; it does not poll while that link is healthy.

```bash
# 1. Build the debug APK
make android-all
adb install -r android/app/build/outputs/apk/debug/app-debug.apk

# 2. Start the daemon so it advertises on the LAN (keep this terminal open)
mkdir -p /tmp/rba
linux/target/debug/rbad \
    --state-dir /tmp/rba/state \
    --socket   /tmp/rba/control.sock \
    --audit-log /tmp/rba/audit.log \
    --port 47123

# 3. Start pairing in another terminal.
#    Default (`--code-entry device`): the terminal displays the code; type it on
#    the device. Add `--code-entry host` to have the device display it and type it
#    in the terminal instead.
linux/target/debug/rba --socket /tmp/rba/control.sock pair

# 4. Complete the code gate on the device: type the code shown in the terminal.
#    There is no host-side prompt; the device's typed code is the confirmation.

# 5. Background the app, then request authentication
linux/target/debug/rba --socket /tmp/rba/control.sock \
    auth --user "$(id -un)" --purpose sudo
```

What the device does:

* **Pairing, default (`--code-entry device`):** names the host and asks you to
  type the six-digit code shown in the Linux terminal. It never displays the code.
  A wrong code is rejected; **Cancel**, back, or a lost connection discards the
  pending host. Only the correct code writes the certificate pin and key.
* **Pairing with `--code-entry host`:** displays the code for you to type in the
  Linux terminal, then still requires an explicit **Allow** on the device.
* **Authentication:** an auto-opened request uses a transparent host activity, so
  only the system `BIOMETRIC_STRONG` prompt appears over the current app. The
  prompt shows the signed host/user/action context. There is no approve button and
  no authenticator result screen. Closing the prompt, pressing back, or leaving is
  a denial and sends `USER_CANCELLED`.
* **After the decision:** an auto-opened authentication finishes immediately and
  reveals the app that was underneath. Pairing returns to the Overview page.
  Terminal results auto-dismiss; there is no Done/OK button. The foreground
  service stays alive in the background, holding one idle connection.

The APK is debug-signed and installs as `io.github.burtvadr.rba.debug`; do not treat it
as a production build. The daemon needs inbound UDP 5353 (mDNS) and TCP 47123
(the data connection), so a firewall or guest-Wi-Fi client isolation will stop
discovery. One live host connection is maintained at a time; pair one host per
test.

The *Background operation* card also reports whether notifications, overlay
permission, the full-screen fallback and battery-optimisation exemption are set.
None of those changes the security decision; they only affect whether the prompt
can reach the screen without the app being opened by hand.

The host label shown on the device is the machine hostname (`archlinux` here). The
systemd unit passes `--host-name %H`, because the service sandbox replaces
`/proc/sys/kernel/hostname` with `linux-host`. The label is display-only and is
never a trust input.

`/tmp/rba` is disposable. For a persistent test installation, keep the state
directory and control socket somewhere under your home directory instead, and
pass the same paths to `rba`.

## Installing PAM integration

Use the scoped installers. They write one override for one PAM service, keep a
rollback record, and leave `system-auth`, `sudo`, `sshd`, `su`, `login` and
`gdm-fingerprint` untouched:

```bash
sudo ./packaging/arch/pam-gdm-rba.sh --dry-run
sudo ./packaging/arch/pam-gdm-rba.sh
sudo ./packaging/arch/pam-polkit-rba.sh --dry-run
sudo ./packaging/arch/pam-polkit-rba.sh
sudo ./packaging/arch/pam-sudo-rba.sh --dry-run
sudo ./packaging/arch/pam-sudo-rba.sh
```

The GDM override covers the GNOME login and lock screen. The polkit override
covers `pkexec` and `systemctl` actions that ask polkit. Both wait 5 seconds by
default; pass `--timeout SECONDS` to change that. Roll back with the same script
and `--rollback`.

Keep a root TTY open while testing. Do not edit `/etc/pam.d/system-auth` or
`/etc/pam.d/gdm-fingerprint`, and do not add the module to `sudo`, `su`, `sshd`
or `login` as part of this integration.

On another distribution, translate the same one-line scoped override to its PAM
layout. The module arguments are whitespace-separated `key=value` pairs:
`purpose`, `service`, `device` and `timeout_ms`. Because libpam splits a
configuration line on whitespace, a value cannot contain a space — write
`device=Pixel-9`, not `device=Pixel 9`.

### `sufficient` means password **or** device

`sufficient` is not MFA. A successful device check satisfies the stack; if the
device is absent, unavailable or declines, `pam_unix` still runs and the password
works. That is deliberate availability, but it also means the device is not a
second factor at that prompt.

If you want password **and** device, use `required` for both (or a required
substack) and keep a root TTY open while testing. A lost device then needs that
recovery path rather than a normal login. Do not add `debug` to an installed
line: it is a troubleshooting flag and can write operational detail to syslog.

### Check it and roll it back

Test the GDM path from the lock screen or a fresh login, and the polkit path with
a `pkexec` or `systemctl` action that normally asks for a password. The password
must still work when the device is off, out of range or declining.

Each installer records the file it replaced. Roll back with:

```bash
sudo ./packaging/arch/pam-gdm-rba.sh --rollback
sudo ./packaging/arch/pam-polkit-rba.sh --rollback
```

`tests/pam-integration.sh` loads the real module into a dedicated PAM service.
`tests/common-auth-integration.sh` is a broader test harness for distributions
that use `common-auth`; it is not part of the recommended integration. Neither is
a substitute for a root shell and a tested rollback on your machine.

### Uninstall

```bash
sudo ./packaging/arch/uninstall-local.sh           # keep state and logs
sudo ./packaging/arch/uninstall-local.sh --purge   # also remove state, logs, account
```

It rolls back the `gdm-password` and `polkit-1` overrides first, then removes the
service, binaries and PAM module. It refuses to remove the module while any PAM
stack still references it. The Android app is separate:
`adb uninstall io.github.burtvadr.rba.debug`.

## Why there is no polkit agent

An earlier version of this had one, and it does not work on a normal desktop. polkit
allows **one authentication agent per subject**, and the desktop's own agent
(gnome-shell, polkit-gnome, KAuth) already holds the registration for the session.
Registering there returns:

```
An authentication agent already exists for the given subject
```

and polkit does not offer challenges to an agent on an inactive session, so it never
works anywhere else either. An agent cannot be injected into the desktop to replace
this, and interposing on the bus or substituting polkitd would compromise the entire
authorization stack.

None of that matters, because **polkitd validates a typed password through PAM** — it
opens a PAM transaction named `polkit-1`. There is no `/etc/pam.d/polkit-1`, so libpam
falls back to `/etc/pam.d/other`, which includes `common-auth`. The polkit dialog
already authenticates through PAM.

So the agent is dropped rather than patched. `linux/polkit-agent` remains only as a
possible answer for a headless host with no desktop agent, and it is not part of the
install path.

## Relationship to prior art

`alp` and `pam-android-fingerprint` both solve Android-to-Linux authentication. The
reuse is conceptual: device as authenticator, PAM integration, Wi-Fi operation.

The departure is the trust model. `alp` is built around a pre-shared key, so
compromise of that one value compromises every host it guards. This implementation
uses per-device asymmetric identity with explicit pairing, so a leaked key affects
one device and is revocable independently.

## Documentation

* [`protocol/specification/PROTOCOL.md`](protocol/specification/PROTOCOL.md) — the
  normative protocol
* [`docs/naming.md`](docs/naming.md) — the `rba` / `rbad` naming rules, borrowed from `adb`
* [`docs/rba-cli.md`](docs/rba-cli.md) — the intended CLI and control-API contract
* [`docs/host-backends.md`](docs/host-backends.md) — portable core, platform backends
* [`docs/adb-transport.md`](docs/adb-transport.md) — ADB as a transport, not a trust anchor
* [`docs/architecture.md`](docs/architecture.md) — layering and component map
* [`docs/threat-model.md`](docs/threat-model.md) — adversaries, defences, limitations
* [`docs/pairing.md`](docs/pairing.md) — the pairing flow and its guarantees
* [`docs/security-audit.md`](docs/security-audit.md) — audit tracker and current findings
* [`docs/roadmap.md`](docs/roadmap.md) — support matrix, capability protocol and platform roadmap
* [`docs/versioning.md`](docs/versioning.md) — version bumps, the 1.0.0 gate and the no-re-pair migration guarantee

## Credits

The fingerprint mark is a heavily modified derivative of the
["Fingerprint" icon from the Security 15 collection](https://www.svgrepo.com/svg/246819/fingerprint)
on SVG Repo. The collection is published under the
[CC0 license](https://www.svgrepo.com/page/licensing/#CC0) and uploaded by SVG
Repo; no individual artist is listed. The icons in `media/icons/` and the Android
launcher assets are derivative works of that mark.

## License

0BSD. Do whatever you want with it; there is no warranty.
