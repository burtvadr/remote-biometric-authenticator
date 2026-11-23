# Roadmap

This is a living roadmap. It records what is supported **today**, what is
explicitly not promised, and the order in which new platform and protocol work
should happen. Security findings from [`security-audit.md`](security-audit.md)
take precedence over feature work.

## Current support

| Area | Today |
|---|---|
| Host OS | **Linux only**. Tested on Arch Linux. Debian/Ubuntu PAM instructions exist; Fedora/BSD/macOS/Windows are not supported. |
| Device | **Android 9+** (`minSdk 28`), debug APK. Tested on a Motorola Edge 30 Ultra, API 37. No iOS app. |
| Transport | **Wi-Fi** end to end. BLE framing/segmentation is tested; BlueZ/central wiring is not. |
| Host integration | Linux-PAM; **sudo works today**. Target: GDM password login plus `pkexec`/`systemctl` through polkit. See [Integration target](#integration-target-gnome-login-pkexec-and-systemctl). |
| Service manager | systemd unit + Unix control socket. |
| Build | Debug-signed APK; no release-signed/non-debuggable build. |
| Protocol | Canonical CBOR, P-256 signatures, pinned TLS, pairing code, revocation tokens. |

The real fingerprint reader works at GDM because `gdm-fingerprint` uses
`pam_fprintd`; it is not using this project. `pkexec` and `systemctl` use
polkit/`system-auth`; they are not using this project either. Any expansion to
those stacks is a deployment decision with a larger prompt-fatigue surface.

### Why the other prompts do not work yet

On the tested Arch machine, the installed device line is only in
`/etc/pam.d/sudo`. The other paths are:

```text
pkexec / systemctl      -> /usr/lib/pam.d/polkit-1
                        -> include system-auth

GDM password login      -> /usr/lib/pam.d/gdm-password
                        -> system-local-login
                        -> system-login
                        -> include system-auth

GDM fingerprint login   -> /usr/lib/pam.d/gdm-fingerprint
                        -> pam_fprintd.so
```

Arch keeps vendor PAM files under `/usr/lib/pam.d`; local overrides belong in
`/etc/pam.d`. Editing the vendor files is not durable. Adding the device module to
`system-auth` would affect many services at once and is deliberately not the
default. Adding it to polkit or GDM must be tested with a root TTY available.

## Integration target: GNOME login, pkexec and systemctl

Current priority: make **GNOME login**, **pkexec** and **systemctl**
authentication work with the device's fingerprint, without turning the rest of the
system into an accidental device-only machine.

“Fingerprint” here means the device's biometric prompt through this app, not a
local `fprintd` sensor. GDM's existing fingerprint path (`gdm-fingerprint` +
`pam_fprintd`) is separate and must keep working.

### First step: screen unlock

GNOME's screen lock uses the same `gdm-password` PAM service as the GDM password
login (confirmed in the journal as `gdm-password`). That makes it the smallest
end-to-end win and avoids touching `system-auth`.

The lock screen UI is part of GNOME Shell, not the GDM greeter, but
authentication is routed through the `gdm-password` PAM service. GDM login has no
active user session; the lock screen has one. Both reach the same PAM file, which
is why one override covers both and why a mistake affects both. Other display
managers/lock screens may use different service names (KDE has `kde` and
`kde-fingerprint`).

```bash
sudo ./packaging/arch/pam-gdm-rba.sh --dry-run
sudo ./packaging/arch/pam-gdm-rba.sh
```

Then lock with `Super+L`, press Enter or submit the password form, and approve
the device prompt. The script keeps a backup and supports:

```bash
sudo ./packaging/arch/pam-gdm-rba.sh --rollback
```

Keep a root TTY open. The existing session keyring is already unlocked when you
started the session with a password, so screen unlock does not need a new keyring
password. A cold GDM login with device-only authentication may still leave the
login keyring locked; that is a separate problem.

### Privilege, immutable systems and GDM

Installing this integration is an **administrator action**, not a user action:

- `/etc/pam.d`, the PAM module, the daemon and the systemd unit are system files.
- PAM is loaded by system processes: `gdm-session-worker`, `sudo`, `polkit-agent-helper-1`.
  A user cannot add a module to those stacks for their own account alone.
- On an immutable/read-only-root distro, `/etc` is still administrator-controlled
  (overlay, package layering, rpm-ostree, transactional update). The mechanism
  changes; the privilege requirement does not.
- An admin can install it once; daily pairing and use do not require root. The
  user only needs access to the control socket (the `rba` group).

At the **GDM login screen there is no active user session**. The greeter runs as
`gdm`; the user selects an account, and the system PAM stack authenticates that
target account. This is why a system-wide integration can work there even though
the user is not logged in — and why a purely per-user setup cannot.

The GNOME **lock screen** is different: it runs inside the logged-in session and
uses the same `gdm-password` PAM service, but the PAM configuration is still
system-wide and admin-owned.

Consequences:

- Without administrator access, stock GNOME cannot be made to unlock this way.
  That is a Linux/GDM architecture boundary, not a missing feature in this app.
- Do not “fix” it with a GNOME Shell extension, `loginctl unlock-session`, or a
  user-level agent that bypasses the lock screen. Those weaken the screen lock
  and are not supported.
- A future fprintd-compatible adapter is also a system service; it does not
  remove the administrator requirement.
- If you have no admin rights, use the password or a local fingerprint sensor.
  `rba` can still authenticate a user-run command if the socket is
  accessible, but it cannot change GDM, the lock screen or PAM.

### Scope

- GDM password login.
- `pkexec` and `systemctl` actions that ask polkit for authentication.
- `sudo` continues to work as it does now.
- Password fallback must remain. If the device is unavailable, cancelled or
  times out, the normal password path continues.
- Do **not** add the device to `/etc/pam.d/system-auth`. That file is included by
  GDM, polkit, login and sshd; editing it would change all of them at once.

### Planned PAM layout

Create local overrides by copying the vendor files and adding one line at the top
of the `auth` stack:

```text
/etc/pam.d/gdm-password
  auth  sufficient  pam_rba.so  purpose=gdm  timeout_ms=5000
  auth  include     system-local-login
  ...

/etc/pam.d/polkit-1
  auth  sufficient  pam_rba.so  purpose=polkit  timeout_ms=5000
  auth  include     system-auth
  ...
```

The rest of each vendor file remains unchanged.

Do not put the device in `gdm-fingerprint` initially. That stack is owned by
`pam_fprintd` and is only entered when GDM selects the local fingerprint method.
The first target is the password form: the user submits the form, PAM reaches the
device module, and the device prompt appears. A separate “device” authentication
method in the GDM UI is a later experiment, not part of this change.

### Process identity is part of the integration

`sudo` works because PAM runs as root. GDM and polkit are different:

- `gdm-session-worker` runs as root, so the existing control-socket access and
  `authorize_caller` behavior should work, but this must be verified on the live
  greeter.
- `polkitd` runs as `polkitd`. PAM may execute inside polkitd, which means:
  - it needs access to `/run/rba/control.sock` (group membership or a
    narrow ACL), and
  - `authorize_caller` currently allows root or the caller's own account only.
    A request from `polkitd` for the target desktop account would be refused.

The fix is not “allow polkitd to ask for anyone”. It is an explicit trusted
integration policy: named service UIDs (`root`, `gdm`, `polkitd`) may request
authentication for the target account only when the configured PAM service and
operation match. This is part of SEC-004, not a separate bypass.

If polkit's PAM runs as root on this Arch version, the immediate work is only
group/socket testing. If it runs as polkitd, the trusted-service policy is a
prerequisite.

### Before polkit: questions to answer first

Do not install the `polkit-1` line until these are answered with evidence from
the live machine:

- [ ] Which process runs PAM for `pkexec`/`systemctl`? Is it
      `polkit-agent-helper-1`, `pkexec`, or polkitd? What UID does it run as?
- [ ] Can that process reach `/run/rba/control.sock` (root, group, ACL)?
- [ ] Does `authorize_caller` accept the caller/target pair? A helper running as
      the desktop user can ask for that user; a helper running as polkitd cannot
      ask for desktop without an explicit trusted-service policy.
- [ ] Is the PAM service actually `polkit-1`, and is there a local
      `/etc/pam.d/polkit-1` override, or only the vendor file under
      `/usr/lib/pam.d`?
- [ ] Which concrete action was tested (`pkexec ...`, `systemctl restart ...`)?
      Some `systemctl` operations do not authenticate at all.
- [ ] Does the device show the target user, `purpose=polkit`, and the operation?
- [ ] Does cancel/timeout fall back to the polkit password dialog?
- [ ] Does `PAM_TEXT_INFO` appear in the polkit dialog, or is it dropped?
- [ ] Is this single-user only? Root-targeting polkit actions require SEC-004
      ownership/`allow_root` before they are safe on a shared machine.
- [ ] Is there a rollback file and a root TTY? Do not edit `system-auth`.

Read-only recon before changing anything:

```bash
cat /usr/lib/pam.d/polkit-1
ls -l /usr/lib/polkit-1/polkit-agent-helper-1
# trigger one pkexec/systemctl authentication, then:
journalctl -b --no-pager | grep -i 'polkit\|pam_unix\|pam_rba'
```

On the tested Arch machine:

- `/usr/lib/pam.d/polkit-1` is the vendor file and includes `system-auth`.
- `polkit-agent-helper-1` is socket-activated through
  `polkit-agent-helper@.service`.
- That unit has `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX` and
  `ProtectSystem=strict`. A Unix-socket connection to
  `/run/rba/control.sock` should still be possible, but the helper's UID
  and group access must be confirmed.
- The journal shows `polkit-agent-helper-1` running `pam_unix(polkit-1:auth)`,
  then polkitd reporting the authorization result. It does not show which UID the
  helper had.

Use:

```bash
sudo ./packaging/arch/pam-polkit-rba.sh --dry-run
```

The installer adds the same `sufficient` device line before
`auth include system-auth`; it does not edit the vendor file. Rollback is:

```bash
sudo ./packaging/arch/pam-polkit-rba.sh --rollback
```

The PAM message added for GDM is best-effort and consumer-specific. It is not a
reason to assume the polkit dialog will display it.

### Prompt quality

The device prompt must show enough to make a correct decision:

- the target Linux account;
- the PAM service/purpose (`gdm`, `polkit`, `sudo`);
- the operation (login, polkit action, sudo);
- the approving device and its owner once SEC-004 exists.

The prompt must not show an unsigned display name as the host identity. Account
and operation come from the signed request context.

### Password field plus a visible device option

The current PAM integration cannot show both at once. GNOME's lock screen is not
a generic PAM UI: it knows a password field and, through fprintd, a local
fingerprint method. It does not render arbitrary PAM modules as buttons.

With the device line first:

```text
auth sufficient pam_rba.so ...
auth include system-local-login
```

PAM tries the device first. If it succeeds, the password stack is skipped. If it
fails or times out, the password path runs. That is an invisible priority order,
not two visible choices.

To show a password field **and** a device biometric option side by side, one of
these is required:

1. **A fprintd-compatible virtual device** — GNOME/KDE show their normal
   biometric UI and keep the password field. This is the clean desktop path, but
   it is a system service, conflicts with a real fprintd unless proxied, and the
   fprintd API does not carry the PAM service/operation context.
2. **A GDM/gnome-shell patch or extension** — add a device button to the lock
   screen. Not portable, security-sensitive, and not recommended as the first
   path.
3. **PAM only** — accept that the device is tried before the password and the
   password appears after the timeout. This is what works today.

Do not try to fake two PAM methods by stacking `optional` and `sufficient`
lines. `optional` does not satisfy authentication, and `sufficient` still
short-circuits the password path; the UI will not gain a second button.

Decision for now: keep the PAM-first behavior with a 5 s fallback. Revisit a
fprintd-compatible adapter only after SEC-004 and a real packaging/security
review.

### Waiting, fallback and the “looks broken” problem

The lock screen test now works, but the host shows no visible “check your device”
message while PAM waits. That is a real UX gap, not an authentication failure.

Current behavior:

- PAM calls the device module first.
- If the device is paired and connected but not answered, the module waits up to
  `timeout_ms` (5 s in the gdm line by default).
- If the daemon has no connected device, it should return quickly and fall
  through to the password.
- The line is `sufficient`, so a timeout/unavailable result must continue to
  `pam_unix`. The user is not permanently stuck.

Ownership of the problem:

- **Ours:** the timeout choice, the lack of a fast “no device connected” path, and
  the fact that the module does not emit a visible PAM message.
- **GNOME/GDM:** the lock-screen UI does not expose a generic “device
  authenticator” method or a clear waiting indicator. A native fprintd adapter
  would show a device, but that is a larger future project.

Required tests:

- [ ] Lock with the device powered off or in airplane mode. Press Enter. Confirm
      the password prompt appears after the timeout, not a dead screen.
- [ ] Lock with the device connected but not approved. Confirm the same fallback.
- [ ] Lock with the daemon stopped. Confirm fallback is immediate.
- [ ] If the password prompt does not return, treat it as a bug in our PAM
      integration, not a GNOME limitation.

The PAM module now sends a best-effort `PAM_TEXT_INFO` message:

```text
Check your device to approve this request.
```

Terminals and some PAM consumers display it. GDM's lock screen may ignore
`PAM_TEXT_INFO`; that part is a GDM conversation behavior. The message is
harmless if dropped and is still visible in the journal. It is not a substitute
for a visible authentication method.

Possible improvements, in order:

1. Keep the lock-screen timeout short (5 s by default) and configurable with
   `--timeout`; test whether 5 s is long enough in practice.
2. Add a fast pre-check so an unpaired/disconnected device returns immediately.
3. Emit a PAM info message asking the user to check the device, if GDM displays it.
4. Document the wait in the UI/README.
5. Only then consider a native fprintd-compatible device or a GNOME UI patch.

### Safety and rollback

- Keep a root TTY open for every PAM experiment.
- Back up each file separately:
  `gdm-password.bak.<timestamp>`, `polkit-1.bak.<timestamp>`.
- Change one stack at a time.
- Test with the device offline, with the device cancelling, and with a wrong
  password typed into the GDM/polkit dialog.
- Keep `sufficient`: password must remain available.
- Remove `debug` from the installed line; it is troubleshooting-only.

### Test matrix

- GDM password login with the device present.
- GDM password login with the device absent → password still works.
- GDM login when the device cancels → password still works.
- Local `fprintd` fingerprint login still works.
- `pkexec` allowed action with device; denied/cancelled action with password.
- `systemctl` action that triggers polkit with device; cancel/timeout.
- `sudo` still works.
- `ssh` password/key login is unchanged.
- `su` is unchanged.
- Reboot after each PAM change to prove the greeter is not broken.

### Security caveat

Until SEC-004 ownership and account policy lands, the device is still host-wide.
That is acceptable for a single-user pilot with an explicit warning, but not for
a multi-user machine. Polkit actions can target root; enabling them makes
`allow_root`/ownership urgent.

### SEC-004 implementation sequence

The corrected plan, in the order it should be built:

1. **Ownership** — add `{ uid, name }` to each device record; non-root pairing
   defaults to the initiator; root pairing requires `--owner`; root owner is
   rejected initially. Legacy paired records become unassigned/deny-all, while
   revoked records stay revoked.
2. **Enforcement** — `self` scope only; target UID must equal owner UID; root is
   always denied; delegation is denied; policy is checked before a challenge is
   generated or sent to the device.
3. **Administration** — `selected` accounts, `allow_root` for target UID 0,
   `allow_elevated`, canonical operation mapping, admin CLI and audit of
   approver + target.
4. **Device and protocol** — advertise policy in `PAIRING_RESULT` or a signed
   policy message; show the target account/operation; test migration.

Two corrections matter:

- Store both UID and name and require the current mapping to match. UIDs can be
  recycled and names can be renamed; UID-only or name-only is not enough.
- Operation policy must use a canonical operation derived from trusted,
  root-owned PAM configuration. Raw `operation` strings from IPC are not a
  security boundary.

## Known network issue: VPN / Tailscale

Observed on the test setup:

- The PC runs Tailscale all the time.
- The device and PC are on the same Wi-Fi; pairing and authentication work with
  Tailscale off on the device.
- Turning Tailscale **on** on the device makes this app stop working.
- Syncthing on the same device continues to work normally.

This is our bug, not a Tailscale bug. The network path is available; the app does
not choose it correctly.

Likely causes in the current code:

- The host binds `0.0.0.0` and mDNS uses `enable_addr_auto()`, so it publishes
  **every** host address, including the Tailscale `100.x` address. The device may
  resolve the service to the Tailscale address, the LAN address, or both.
- Android `NsdServiceInfo` is reduced to a single `host` in
  `WifiTransport.discover()`. The app tries that one address and has no fallback
  to the other A/AAAA records.
- `WifiTransport.connect()` creates an unbound `Socket()`, so Android selects the
  default network/VPN route. The app never requests the Wi-Fi `Network` or binds
  the socket to it.
- There is no `NetworkCallback`. Addresses and connections are not re-resolved
  when Wi-Fi, VPN or the default network changes.
- Syncthing works because it binds/listens on multiple interfaces, retries
  addresses, and reconnects; the fact that it continues does not mean Tailscale
  permits arbitrary LAN traffic.

Required behavior:

- Enumerate every resolved host address and try them in a defined order, with a
  short per-address timeout. The default order should be **LAN first**, then
  Tailscale, unless policy says otherwise.
- Use `ConnectivityManager` to obtain the Wi-Fi and VPN `Network` objects and
  bind the data socket with `Network.bindSocket()` before connecting. Choose the
  network that matches the address being tried.
- Register `NetworkCallback` and re-resolve/reconnect on `onAvailable`,
  `onLost`, `onCapabilitiesChanged` and VPN changes.
- Do not publish the Tailscale interface over mDNS by default for local pairing.
  Add a host option such as `--advertise-address` / `--mdns-interface`, or bind
  the daemon to a specific LAN address when that is the intended deployment.
- Make the path policy explicit, for example `--transport-preference lan`,
  `tailscale` or `auto`. Address selection must never weaken TLS pinning or the
  signed transcript; it only decides where bytes are sent.
- Surface diagnostics: the device should log which address/network it chose and
  why, and `rba status`/`devices` should show the host's listen
  addresses.

Do not make “disable Tailscale” or “allow local network access” the only
documented fix. Those are workarounds; the app should coexist with a VPN.

### What Syncthing does differently

Syncthing has no Tailscale-specific rule. It is robust because it treats the
network as a set of candidates and keeps retrying. The relevant mechanisms in its
source:

- **Enumerate interfaces on every announcement.** `lib/beacon/broadcast.go`
  sends an IPv4 broadcast on each running broadcast interface;
  `lib/beacon/multicast.go` sends IPv6 multicast per interface. Both skip
  Android point-to-point interfaces (cellular) and fall back to the general
  broadcast address when interface enumeration fails.
- **Announce more than one address.** `lib/discover/local.go` broadcasts every
  30 seconds and keeps discovery results for 90 seconds, so addresses can change
  without a restart. `lib/connections/service.go` publishes both LAN and WAN
  addresses (`AnnounceLANAddresses`, default true).
- **Rank paths instead of hardcoding one.** `lib/config/optionsconfiguration.go`
  defaults to LAN TCP 10, LAN QUIC 20, WAN TCP 30, WAN QUIC 40, relay 50.
  `lib/connections/service.go` tries the lowest priority first and only falls
  back to worse paths. A point-to-point VPN is classified as non-LAN by
  `lib/osutil/net.go`, not rejected.
- **Dial candidates in parallel.** Within one priority bucket,
  `lib/connections/service.go::dialParallel` dials up to 8 targets per device
  concurrently, each with a 10 second timeout (`lib/connections/tcp_dial.go`),
  and keeps the first usable connection.
- **Retry forever.** `ReconnectIntervalS` defaults to 20 seconds; discovery is
  re-broadcast every 30 seconds. A failed address is retried later, not treated
  as permanent.
- **Try both routing styles.** `lib/dialer/public.go` dials once reusing the
  listen port and once without it, because route selection can differ. It also
  keeps a relay path as a last resort.

The design lesson is simple: **do not pick one address and stop.** Publish every
candidate, prefer LAN, try the alternatives, and re-learn after a network change.
Our protocol does not need Syncthing's relay: LAN plus Tailscale/`100.x` covers
the same fallback role for this deployment.


Acceptance criteria:

- [ ] Pairing and authentication work with the PC's Tailscale up and the device's
      Tailscale on, over the LAN.
- [ ] Authentication works over Tailscale `100.x` when policy allows it and the
      device has Tailscale on.
- [ ] Toggling Tailscale or switching Wi-Fi reconnects without restarting the app.
- [ ] mDNS does not advertise unintended interfaces by default.
- [ ] All resolved addresses are tried, with a bounded timeout each.
- [ ] Tests cover VPN on/off on the device and Tailscale up on the host; address
      choice remains a routing decision, not an authentication decision.

## Syncthing as reference code

Syncthing is a **reference for behavior, not a dependency and not a source to
vendor**. It is MPL-2.0; this tree is 0BSD. No Syncthing code is copied. The
notes below describe what to reimplement independently, split into what is needed
now, what is an upgrade, and what is ongoing robustness work.

### Minimal — needed to fix VPN/Tailscale

These are the pieces required for the current LAN + Tailscale setup:

- Collect **all** resolved host addresses, not a single `NsdServiceInfo.host`.
- Classify each address as LAN or non-LAN/VPN. Prefer LAN, but keep the VPN
  address as a candidate; do not blacklist Tailscale by name.
- Try candidates with a short per-address timeout instead of one attempt.
- Retry and re-resolve periodically, and reconnect when Wi-Fi/VPN changes.
- Bind the Android data socket to the chosen `Network`; do not rely on the
  default route while a VPN is active.
- Let the host advertise only intended interfaces, or add explicit
  `--advertise-address` / `--mdns-interface` controls.
- Log the chosen address, network and failure reason.
- Keep TLS pinning and the signed protocol transcript unchanged. Path selection
  is routing, not authentication.

### Upgrade — useful, not blocking

These improve resilience but are not required for the first fix:

- Parallel dialing within a priority bucket, first usable connection wins.
- Multiple simultaneous connections with priority upgrade/downgrade.
- QUIC/UDP as a second transport alongside TCP/TLS.
- Dialing with and without a reused local port to work around routing quirks.
- Optional relay or rendezvous fallback, preferably an existing transport
  (Tailscale, WireGuard, SSH) or a minimal protocol-specific relay.
- Richer discovery: multiple A/AAAA records, explicit LAN/WAN metadata,
  IPv6-first or IPv4-first policy.
- User-visible path preference and connection status.

Syncthing's relay, global discovery, NAT traversal and BEP protocol are **not**
being adopted. They solve a different problem and are too large for this project.

### Robustness — ongoing quality bar

These are properties every implementation must keep, even in the minimal version:

- Enumerate interfaces fresh on each cycle; do not cache stale interfaces.
- Expire discovery results and retry failed addresses later.
- Bound every attempt with a timeout and the whole cycle with a budget.
- Handle IPv4/IPv6, link-local, loopback and duplicate addresses.
- On Android, skip cellular point-to-point interfaces for local broadcast and
  never assume cellular is a viable local path.
- Isolate one bad address or interface: it must not stop the retry loop.
- Avoid tight reconnect loops; use backoff and respect Doze/battery limits.
- Log attempts, chosen path and failover reason; expose them in
  `rba status`/`devices`.
- Test VPN on/off, Wi-Fi changes, LAN-only, Tailscale-only, no route, and
  dual-stack hosts.
- Never let an address choice bypass certificate pinning, signature checks or
  policy enforcement.

The minimal set is the next transport task. The upgrade items stay on the
roadmap; the robustness rules apply from the first implementation.

## Native desktop integration via fprintd (future)

GNOME and KDE show a native fingerprint UI only because they talk to `fprintd`,
which talks to `libfprint`. A PAM module alone cannot make that UI appear: it only
runs after the desktop has already chosen an authentication method.

So the question is not “can we pretend to be a USB sensor?” It is “can we expose a
virtual biometric device through the same documented interfaces, honestly?”

### What the OS expects

- `fprintd` implements the `net.reactivated.Fprint` D-Bus API: list devices,
  claim, enroll, verify, list/delete prints.
- `libfprint` supports `FP_DEVICE_TYPE_VIRTUAL`; its virtual drivers
  (`FP_VIRTUAL_DEVICE`, `FP_VIRTUAL_IMAGE`) are test tools. They still perform
  local print matching, not remote signature verification.
- GDM, GNOME Settings, KDE lock screen and `pam_fprintd` all use that pipeline.

### Options

1. **PAM only (current)** — scoped `gdm-password` and `polkit-1` overrides.
   No native fingerprint icon; the device prompt appears after the password form
   is submitted. Smallest, most portable, no fake device.
2. **fprintd-compatible service** — implement the documented D-Bus API with a
   virtual device named “Android device (Pixel 9)”. `VerifyStart` triggers the
   device challenge; a successful signature is reported as a verify result.
   No hardware is faked. Problems: it conflicts with a real `fprintd`; losing the
   local sensor unless proxied; enrollment becomes “pair device”, not “scan
   finger”; the API carries the target user but not the PAM service, so the device
   cannot distinguish GDM from sudo from polkit.
3. **libfprint virtual driver** — add a C driver that verifies via the device.
   Most native, but it is LGPL code in our 0BSD tree, requires a patched or
   separately packaged libfprint, needs synthetic print data, and runs inside a
   root system daemon. Heavy maintenance and a large new trust boundary.
4. **Patch GDM/KDE** — not portable, not a clean integration.

### Where the line is

A virtual device is **not** a lie if it is named as a remote device authenticator,
uses the documented interface correctly, and does not claim a local sensor
captured a fingerprint. It becomes a lie when the UI says “fingerprint sensor”,
when enrollment data pretends to be a fingerprint template, or when the weaker
remote trust model is hidden from the user.

The clean framing is: **the device is a biometric authenticator exposed through
fprintd**, not a fake USB fingerprint reader.

### Security constraints

- The service must verify the D-Bus caller and target user; no user may trigger
  another account's device prompt.
- `fprintd`'s API does not carry PAM service/operation context. Consent quality is
  worse than the direct PAM path unless the protocol is extended.
- Pairing and revocation must map to enrollment and print deletion.
- A real local sensor must keep working; do not silently replace `fprintd`.
- Account binding (SEC-004) must exist before a system-wide biometric adapter is
  safe on a multi-user machine.

Decision: **PAM integration first.** A fprintd-compatible adapter is a later
experiment, after SEC-004 and only if native GNOME/KDE fingerprint UI is worth the
packaging and trust-boundary cost. Do not fake USB hardware or a fingerprint
template.

## What "supported" means

A platform is supported only when it has:

1. a working host adapter for the platform's local authentication substrate;
2. a device app with platform-appropriate secure key storage and biometric
   consent;
3. shared conformance vectors passing on both sides;
4. an end-to-end test on real hardware;
5. a platform-specific threat model and audit entry;
6. a release artifact, not only a debug build.

Anything else is "experimental" or "not supported", regardless of whether the
protocol core compiles there.

## Capability negotiation

### Is a separate protocol valid?

**Yes**, with constraints. It is better to define it as a **new authenticated
message family in the existing session** than as a second socket, port or
unauthenticated discovery channel.

A capability exchange can answer:

- what operations a host can request (`sudo`, `su`, `login`, `polkit`, `gdm`,
  `screen-unlock`, `ssh`, `macos-authorization`, ...);
- what authentication factors a device can provide (`strong-biometric`,
  `device-credential`, `secure-enclave`, `tee`, `strongbox`, ...);
- which transports are available (`wifi`, `ble`);
- which display/consent modes are supported (`transparent-prompt`,
  `device-enters-code`, `host-enters-code`, number matching);
- which protocol features are supported (`revocation`, `unpair`,
  `pending-cleanup`, `attestation`, ...);
- implementation limits (name length, timeout range, concurrent requests).

Capabilities are **not** authorization. They describe what an endpoint can do,
not what it is allowed to do. The effective action is the intersection of:

1. **host capability** — the host can request it;
2. **device capability** — the device can display/approve it;
3. **host policy** — this device is authorised for this Linux user/operation;
4. **device policy** — the user enabled that operation/factor;
5. **user consent** — biometric/approval at the time of the request.

A device toggle can only narrow what the device will accept. It must never grant a
host permission the host policy does not already allow. A host toggle can only
narrow what the host will request. Neither side may silently assume the other's
capability.

### Design requirements

- Capabilities are negotiated only after `SESSION_HELLO`/registration, on the same
  authenticated connection.
- The exchange is bound to the session and endpoint identity (signed transcript
  or TLS exporter). It must not be accepted from an unauthenticated peer.
- The message is versioned. Unknown **required** capabilities fail closed;
  unknown optional capabilities are ignored and not enabled.
- No secrets, private keys, tokens or credentials are included.
- A capability downgrade after authentication is not silently accepted. If the
  session is renegotiated, the host and device must both agree to the new set.
- The host enforces authorization server-side. Capability data from the device is
  advisory input to policy, never the policy itself.
- Capability advertisements are privacy-sensitive: they can reveal OS, hardware
  class and enabled services. Prefer coarse values and keep them off mDNS.

### Suggested shape

This is a design sketch, not a frozen wire format:

```text
CAPABILITIES {
  version: 1,
  endpoint: "host" | "device",
  platform: "linux" | "android" | "macos" | "ios" | "bsd",
  operations: ["sudo", "polkit", "login", ...],
  factors: ["strong-biometric", "tee", "strongbox", ...],
  transports: ["wifi", "ble"],
  ui: ["transparent-prompt", "device-code", "host-code", "number-match"],
  features: ["revocation", "unpair", "cleanup", "attestation"],
  limits: { ... }
}
```

The host and device should exchange this once per session, cache only
non-sensitive summaries, and renegotiate when either side changes policy.

## Security options and policy layers

The proposed Settings → **Security options** section is the right place for
device-side consent, but it must not become the host's authorization policy. Use
three independent layers.

| Layer | Stored where | Who may change it | What it can do |
|---|---|---|---|
| Device consent | Android app-private settings | The device user, gated by biometric/app lock if enabled | Narrow which negotiated operations/factors the device will accept |
| Per-user host policy | Per-UID daemon state or `$XDG_CONFIG_HOME/rba/policy`, line-oriented, mode `0600` | The same Linux user through the local control socket (`SO_PEERCRED`) | Allow/narrow operations for that user's own account |
| Global host policy | `/etc/rba/policy`, line-oriented, root-owned `0600` | root only | Device-to-user binding, root/privileged operations, machine-wide integrations |
| Integration installation | PAM/polkit/GDM files, systemd unit, socket ownership | root only | Makes the mechanism available at all |

### Device-side Security options

Suggested toggles, all of which can only **narrow** host policy:

- **Require biometric to open Settings** (or to open the app manually).
- **Require biometric to change security options / unpair a host.**
- Per-host operation toggles, populated from capability negotiation:
  `sudo`, `su`, `polkit`, `systemctl`/`org.freedesktop.systemd1.manage-units`,
  `login`, `gdm`, `sshd`, `screen-unlock`, future actions.
- Per-transport toggles where meaningful: Wi-Fi, BLE.

The app lock is a local UX/consent gate, not a cryptographic boundary. The real
authentication control remains the `BIOMETRIC_STRONG` signature prompt. An
auto-opened request must **not** require a second app-unlock first: the system
biometric prompt is already the authentication. Use the app lock for manual
launch/settings/unpair, not for the transparent request prompt.

Store these settings in app-private `DataStore`/preferences with backup disabled.
They contain no secrets, but their integrity matters. A Keystore HMAC can detect
casual tampering; it cannot protect against a rooted or compromised OS.

### Host-side settings

The PC does not need `sudo` to change a user's own policy if the daemon enforces
peer identity:

- A local client connects to the root/`rba` control socket.
- The daemon reads `SO_PEERCRED` and only permits that UID to change its own
  policy.
- Per-user policy is stored atomically with mode `0600` and audited.
- root-only settings cover global enablement, device-to-user binding, root
  operations, and integration installation.

Do not use one world-writable policy file. It turns "settings" into a privilege
escalation surface. Do not let an unprivileged user enable a global integration
or bind their device to another Linux account.

### Installation versus runtime policy

Installing a PAM/polkit/GDM line requires root. That is expected and separate
from the toggle:

- **Installed but disabled:** the module is present, returns unavailable/ignore,
  and the normal password path continues.
- **Installed and enabled:** the device may be asked for the operations allowed by
  both host policy and device consent.
- **Not installed:** the device cannot authenticate that service, regardless of
  app toggles.

Use `sufficient`, not `required`, for the device line unless the operator
explicitly wants a device-or-lockout policy. Keep an integration-specific rollback
file and a root TTY while changing PAM.

### Disable, mask, or uninstall?

"Masking" is systemd terminology for units; PAM has no equivalent. Once an
integration is installed, prefer disabling it through policy rather than editing
PAM files again:

| State / action | What it means | Root needed? | Effect |
|---|---|---|---|
| Install integration | Add the PAM/polkit/GDM line, module and service | Yes | Makes the mechanism available |
| Enable integration | Policy allows the action for a user/device | No for your own policy; yes for global/other users | Device may authenticate this action |
| Disable integration | Policy denies the action, or the device masks it | No for your own policy / device mask; yes for global/other users | Module is present but the action is not approved |
| Device mask | This device refuses the action | No | Host may still ask; with `sufficient` it falls through to password |
| Daemon stopped/masked | `rbad` is not running; PAM line remains | Yes for systemd mask/stop | Module cannot reach the daemon; password path continues |
| Uninstall | Remove `/etc/pam.d` override, module and, if desired, package | Yes | The integration no longer exists |

Runtime policy should be the normal switch. It is reversible, auditable, and does
not risk a broken PAM stack. Uninstall is for cleaning the machine, not for daily
toggling.

A **device-side mask** is the narrowest switch of all: no sudo, no PAM edit. It
only means this device will refuse requests for that action. The host may still
invoke the PAM module; with `sufficient`, a refusal or unavailable daemon falls
through to the password. A host per-user policy disable also needs no sudo for
that user's own actions. Removing the line globally, changing another user's
policy, or uninstalling the module/package needs root.

The device can hide or grey out an action it has masked; that is only a UI hint.
The host must still enforce its own policy, and the device must still refuse an
unexpected request for a masked action.

Recommendations for implementation:

- Track `installed` (packaging/manifest) separately from `enabled` (policy).
  Do not infer installation by parsing PAM files at runtime.
- Add a `rba integrations` view showing installed, available, enabled
  and disabled actions.
- Let a user disable their own actions without root; require root for global
  actions or device-to-user binding changes.
- Keep a documented uninstall/rollback procedure that restores the original
  `/etc/pam.d` override from the backup created during installation.

### Multi-user hosts

The host identity is the **machine** (`archlinux`), not a Linux account. The
Linux username is a separate signed field on each request. Pairing should stay
per host and device; re-pairing the same host with the same device key would
currently replace the same host record, not create a useful per-user record.

Recommended model:

- The host registry stores an allow-list of Linux users/UIDs per paired device.
- Pairing defaults to the account that started the host-side pairing; root or a
  host administrator can add another account later.
- The device shows the host as `archlinux` plus **Accounts: desktop, alice** (or
  the configured labels).
- The host enforces the allow-list on every request.
- The device displays the signed username and may keep a per-account consent
  toggle. A device-side deny only narrows; it does not grant another account.
- A user who wants an independent trust relationship should pair their own device
  (a separate device record), not reuse another user's device silently.

Account scope is a policy dimension, not a new host identity. Support all of these
without duplicating `host_id`:

| Scope | Pairing | Who authorises | App shows |
|---|---|---|---|
| `self` (default) | The pairing user only | User + host operator | `archlinux` / `desktop` |
| `selected` | A list of accounts | Host admin/root, device confirms the list | `archlinux` / `desktop, alice` |
| `all` | Every normal account, **excluding root** | root, explicit warning | `archlinux` / all accounts |
| `all+root` | Every account including root | root, separate explicit flag | strong root warning |
| Per-user device | One device/key per user | That user pairs independently | separate device records |

The recommended defaults are `self` and a separate device per user when independent
compromise domains are wanted. `selected` and `all` are convenience modes for a
shared device; they do not change the device key. `all+root` should be treated as a
deliberate, strongly discouraged policy.

If the device must enforce the allow-list locally, the host needs to advertise it:
a `PAIRING_RESULT` account list, a capability/policy message after pairing, or a
signed `SESSION_HELLO` extension. The host policy remains authoritative even if
the device list is stale. A sensible wire shape is:

```text
account_scope: "self" | "selected" | "all"
accounts: ["desktop", "alice"]   // only for selected
allow_root: false                // separate, default false
```

The scope and accounts must be bound to the pairing transcript or a signed policy
message; the device displays the final scope and the host enforces it. Expanding
the scope later should require host authorisation and, ideally, a fresh device
confirmation. Shrinking the scope can be host-side.

A shared device key across accounts means a compromised device can approve any
account in its scope. Per-account toggles are consent filters, not separate
security domains. Users who need independent compromise domains should pair
separate devices/keys.

Do not model this as `host_id = archlinux/alice`. That would duplicate host
identity and TLS pins per account and make the machine look like many hosts.

### Worked multi-user scenarios

**One PC, two users, two devices.** This is the recommended independent-trust
model:

```text
host: archlinux
  device A -> device record A, account_scope=self, accounts=[desktop]
  device B -> device record B, account_scope=self, accounts=[alice]

desktop is in wheel; alice is not.
```

- Device A can authenticate `desktop` for login, unlock, polkit and `sudo`.
  Whether `sudo` actually succeeds is still decided by `sudoers`; the device
  proves *who* desktop is, it does not grant the privilege.
- Device B can authenticate `alice` for login, unlock and user-level polkit
  prompts. It cannot make `sudo` succeed because `alice` is not in `sudoers`.
  The host should also refuse to send `auth.sudo` requests to a device whose
  account scope does not include an account allowed to use it.
- A request for `desktop` from device B must be refused by the host before the
  device is asked. The device is not a second authorization system.
- The two devices have separate device keys; compromise of one does not become
  compromise of the other.

**One device, two users.** Supported through `selected` scope, but it is one
compromise domain:

```text
device A -> account_scope=selected, accounts=[desktop, alice]
```

The device shows both accounts. The host still enforces each account's normal
rights. A device compromise can approve any account in its scope; use separate
devices if that matters.

**One device, all normal accounts.** `account_scope=all`, excluding root. This is
convenience for a shared device and a larger blast radius. It does not make every
account an administrator.

**Root.** `allow_root` is separate and defaults to false. `all+root` is a
deliberate, strongly discouraged policy; root can already change `sudoers`,
polkit and PAM, so treating a device as a root factor deserves its own warning and
audit entry.

### Per-account and per-device policy matrix

A device is not just “allowed” or “not allowed”. The host policy needs four
separate questions:

1. **Device principal** — whose device is it? (`desktop`'s device, `alice`'s device)
2. **Target account** — which Linux user is being authenticated? (`desktop` or
   `alice`)
3. **Operation** — login, unlock, user-level auth, polkit action, `sudo`, root?
4. **Device consent** — does the device user approve this specific request now?

The effective decision is the intersection of all four, plus the account's normal
`sudoers`/polkit rights. A device can never grant a right the account does not
already have.

Example configuration for 1 PC, 2 devices, 2 accounts:

```text
account desktop  (in wheel)
  device A -> principal desktop
  device B -> principal alice

account alice    (not in wheel)
```

| Target account | Operation | Device A (desktop) | Device B (alice) |
|---|---|---|---|
| desktop | login / unlock / user auth | allowed, configurable | **denied by default**; can be enabled as delegated login |
| desktop | `sudo` / elevated polkit | allowed by host policy; still checked by sudoers/polkit | **never** |
| alice | login / unlock / user auth | **denied by default**; can be enabled as delegated login | allowed, configurable |
| alice | `sudo` / elevated polkit | no; alice has no sudo rights | **never** |

This gives every combination you described:

- **Device login for the non-root user can be disabled entirely.** Set
  `device_login=false` for `alice`; PAM ignores the device module for that account
  and the password is required.
- **Device login for the non-root user can be enabled** for alice's own device,
  limited to login/unlock/user-level auth.
- **The sudo user's device can be allowed to log in as alice** as a delegated
  login, or denied. Default: denied.
- **The non-root device can never get elevated rights**, even if its owner asks.
  The host should not send `sudo`/root requests to it; sudoers/polkit still deny
  if one somehow arrives.
- **The non-root device cannot log in as the sudo user** unless the host
  administrator explicitly enables that delegation; default: denied.

Suggested policy fields:

```text
account alice:
  device_login: false | true
  allowed_devices: [device-B]           # or a device-id list
  allow_delegated_login_from: [device-A]  # default empty
  allowed_operations: [login, unlock, user-auth]
  allow_elevated: false               # always false unless root policy says otherwise

account desktop:
  device_login: true
  allowed_devices: [device-A]
  allow_delegated_login_from: []
  allowed_operations: [login, unlock, user-auth, sudo, polkit-admin]
  allow_elevated: true                # still constrained by sudoers/polkit
```

Cross-account authentication is **delegation**, not identity sharing: the device
prompt must show both “who is approving” and “which account is being signed in”.
Audit it as a delegated decision. Default it to off. A shared device or a device
allowed to log in as another account is one compromise domain; separate devices
remain the stronger model.

Do not implement this by reusing an admin session or by silently switching the
signed username. The target account is always in the signed request; the host
policy decides whether that device is permitted to name it.

### Authentication is not authorization

| Layer | Decides | Device role |
|---|---|---|
| Pairing | Is this device/host key trusted? | Consent + code entry |
| Account scope | Which Linux accounts may this device approve? | Displays and may narrow |
| PAM authentication | Is this the claimed user? | Strong-biometric signature |
| `sudoers` | May this user run `sudo`? | None |
| polkit | Is this action allowed for this user? | None; the prompt may use PAM |
| Device consent | Does the human approve this request? | Final accept/deny |

A device for a non-admin user is therefore useful without any root access: it
replaces password entry for login, screen unlock and user-level authentication
prompts. It cannot turn that user into an administrator, and the host must never
present it as if it could.

### Installation and account scope

Installing a PAM/polkit/GDM line is machine-wide and needs root. The account
scope and per-user enable/disable policy are separate:

- a user can enable/disable their own operations without root;
- a device can mask an operation without root;
- adding an account to a device's scope, enabling global actions, or allowing root
  needs host administrator/root authorization;
- uninstalling the integration needs root.


### Capability IDs, not generic labels

A toggle for "systemctl" is too broad. Negotiate the actual action identifiers,
for example:

- `auth.sudo`
- `auth.su`
- `org.freedesktop.policykit.exec`
- `org.freedesktop.systemd1.manage-units`
- `login.gdm`
- `login.console`
- `login.sshd`
- `unlock.screen`

The device displays only actions the host advertises, and the host still enforces
its own policy. A stale toggle for an action the host no longer advertises is
ignored, not treated as consent.

## CLI and pairing UX

The current `rba pair` flow is secure enough to finish a pairing, but
the interaction is awkward and misleading. It should feel like `adb`, not like a
guided wizard.

### What it does today

```text
$ sudo rba pair
Pairing open for 120s.
Start pairing on the device now.

Pairing code (shown only here; enter it on the device):

      ┌────────────────┐
      │  198168  │
      └────────────────┘

Send this pairing to the device? [y/N] y
Confirming pairing…
Host record saved. Enter the code on the device to finish pairing.
Host side pairing finished.
```

Problems:

- The host asks `Send this pairing to the device?` **after** already showing the
  code and receiving the device's submission. The question describes an action
  that already happened.
- `Host record saved` appears before the device has confirmed anything. The host
  has persisted its side; the device may still reject, timeout or lose the link.
  This reads like success when the pairing is not finished.
- The boxed code is noisy, and the important value is buried in prose.
- The command exits as soon as the host side is done, without saying whether the
  device stored the host. A user has to guess from the app.
- `sudo` or a fresh group login is needed for the control socket, and the error
  does not explain the stale-group case. `rba pair` should work as the
  desktop user, and a permission failure should print the exact `newgrp`/re-login
  hint.
- `list` is a prose dump, not a stable table, and there is no single place to see
  `paired / connected / pending / revoked`.
- `--yes` is a footgun that exists only to skip a redundant prompt.

### Target: adb-like behavior

One explicit command opens a short-lived pairing session, prints one code, waits,
and reports one final result:

```text
$ rba pair
Waiting for device... (120s)
Code: 198168  type this on the device

Paired  Pixel 9
  host    archlinux
  device  91620145
```

- No host-side `[y/N]`. Running `pair` is already the operator's decision; the
  device's typed code or Allow is the human gate. If a host confirmation is ever
  wanted, make it an explicit `--confirm`, not the default.
- Print the code as a plain line, not box art. Keep it out of logs.
- Do not print `Paired` until the device has persisted the host and acknowledged
  it. Before that, say `Waiting for device confirmation`.
- On failure, print one line and a non-zero exit:
  `Pairing failed: code mismatch` / `Pairing timed out` / `Pairing cancelled on device`.
- Stable exit codes: `0` paired, `1` failure, `2` usage/cannot connect.
- Ctrl-C cancels the session; the host must delete the pending record.
- Text output and stable exit codes are the contract.
- `--timeout` changes the session lifetime; it does not change the protocol
  maximum.

A device view should be boring and scriptable, like `adb devices`:

```text
$ rba devices
DEVICE                    MODEL                 STATE       LAST SEEN
Pixel 9 (91620145)        motorola edge 30 ultra connected   12:08
```

`rba list` is replaced by `rba devices`; there is no alias.

### Protocol change needed for honest completion

Right now the host persists its device record before it sends `PAIRING_RESULT`,
while the device persists only after its human gate. That is why the CLI can say
`Host record saved` while the device still has not accepted.

To make the CLI truthful, add a final device-to-host acknowledgement after the
device persists, for example `PAIRING_CONFIRMED`:

1. Host verifies `device_mac`, stores the record as **pending**, sends
   `PAIRING_RESULT`.
2. Device verifies `host_mac`, asks the operator, then persists.
3. Device sends `PAIRING_CONFIRMED` (bound to the same session/transcript).
4. Host promotes the record to **paired** and the CLI prints `Paired`.
5. Timeout, rejection, code mismatch or link loss deletes the pending record.

Until that exists, the CLI must not claim the pairing is complete; it should say
`Host side complete; waiting for the device` and leave the final state to
`rba devices`.

### Acceptance criteria

- [ ] `rba pair` is one command, one code line, one final result.
- [ ] No default `[y/N]` and no `--yes` requirement.
- [ ] No `Paired`/`Host record saved` text before the device confirms.
- [ ] Pending records are separate from paired records and are cleaned on
      timeout, rejection, mismatch or disconnect.
- [ ] Device-to-host `PAIRING_CONFIRMED` is specified, implemented in Rust and
      Kotlin, and covered by vectors.
- [ ] `rba devices` prints a stable table.
- [ ] Permission denied explains `newgrp rba` / re-login, and normal
      pairing works without `sudo` for a user in the `rba` group.
- [ ] `rba unpair <device>` is a first-class command, not only a hidden
      daemon operation.
- [ ] README and `docs/pairing.md` use the real command transcript.

## Proposed refactor: centralized `rba` CLI and host backends

Status: **draft, review pending**. This is broader than the existing adb-like CLI
item and is not committed scope yet. The drafts are:

- [`rba-cli.md`](rba-cli.md): one `rba` binary, versioned control API, output and
  exit-code contract.
- [`adb-transport.md`](adb-transport.md): ADB as a transport and the limits of an
  app-less Android authenticator.
- [`host-backends.md`](host-backends.md): portable core plus platform backends
  for Linux, BSD, macOS and Windows.

The important boundary is that the daemon stays platform-neutral. PAM, polkit,
launchd, Windows credential providers and service managers are backends, not
core assumptions. The current Linux implementation remains the reference.

ADB is proposed as an optional transport and provisioning channel, not as the
trust anchor. A headless APK (no launcher icon) is possible; a literal no-APK
authenticator is not, because Android Keystore keys and `BiometricPrompt`
auth tokens are app-scoped. See [`adb-transport.md`](adb-transport.md).

Windows is a feasibility item, not a supported target. The Windows Hello
Companion Device Framework is deprecated; a Windows backend would need a
credential-provider or other supported logon integration and its own security
review.

### State and logs: no JSON

Status: **proposed**. Current runtime JSON: `registry.json`, the audit log, the
simulator identity files, and the local control socket. None of it needs JSON.

Follow the model of the tools this CLI imitates. ADB stores keys as plain files
and authorized keys one per line. scrcpy has no persistent config file and uses
a binary control protocol. Small root-owned state should be inspectable with
`cat`, `grep` and `awk`, not a JSON parser.

Proposed formats:

- **Device registry:** one file per device, `<state>/devices/<id>`, containing
  `key=value` lines (`version`, `name`, `public_key`, `status`, `added_at`,
  `last_seen`, `auth_count`, future policy fields). The filename is the device
  ID, so there are no nested arrays or record delimiters. Mode `0600`, atomic
  replace. Values are UTF-8, split at the first `=`; newlines and backslashes
  are escaped. A version mismatch or unknown key is refused, not guessed.
- **Policy:** line-oriented files, `/etc/rba/policy` and
  `$XDG_CONFIG_HOME/rba/policy`, with the same encoding and permission
  rules.
- **Audit log:** one `key=value` event per line, not JSON Lines. Quote values
  that contain spaces; never write secrets.
- **Local control channel:** length-prefixed canonical CBOR, reusing the
  existing protocol codec. It stays binary like ADB/scrcpy control protocols and
  typed like the current client, without a JSON dependency.
- **Generated conformance vectors:** remain JSON test fixtures. They are
  generated by `vecgen`, are not runtime state, and no product code parses them.

There is no dual-format or migration period. The daemon writes the new formats
from scratch, and operators re-pair. That removes the JSON reader, the old
registry parser and the compatibility branch before they are written.

1. Write the new registry only; do not read `registry.json`.
2. Do not preserve or back up old runtime state; the new state directory starts
   empty.
3. Remove `serde_json` from the daemon, CLI, PAM module, polkit agent and
   simulator runtime code. `vecgen` and conformance tests may keep it as a
   development-only dependency.

Acceptance criteria:

- [ ] No JSON files in `/var/lib/rba`, `/etc/rba` or the audit log.
- [ ] `cat` and `grep` can inspect every state file.
- [ ] A fresh state directory contains no JSON and no legacy records.
- [ ] A corrupt record is dropped or quarantined, never treated as trusted.
- [ ] Local IPC round-trips through the CBOR codec with a versioned envelope.
- [ ] No production daemon, CLI, PAM or polkit code depends on `serde_json`;
      only vector generation and tests do.

## Roadmap phases

### Phase 0 — Security remediation

Do these before expanding the platform surface:

- [x] SEC-001: bind the pairing code to an ephemeral ECDH secret and the full
      transcript; add the MITM regression test. A PAKE remains a future upgrade.
- [ ] Pairing upgrade: replace the six-digit SAS with CPace/SPAKE2 or a
      high-entropy QR/NFC secret. Keep ECDH + SAS until a reviewed implementation
      ships; do not hand-roll a PAKE in Kotlin.
- [ ] SEC-003: stop recommending global `common-auth`; scope PAM integration and
      add number matching for authentication.
- [ ] SEC-004: bind each paired device to allowed Linux users; deny root by
      default.
- [ ] SEC-005: design opt-in Android Key Attestation and downgrade policy.
- [ ] SEC-006: verify the control-socket server from the PAM client.
- [ ] SEC-007: persistent rate limits and parser fuzzing remain; connection
      caps, handshake/frame deadlines and the explicit bind policy are done.
- [ ] SEC-009: panic containment and FFI review in the PAM module.
- [x] SEC-021/022/023/024: bounded IPC reads and deadlines, timeout clamp,
      trusted prompt context, connection caps and frame deadlines.
- [ ] Release-signed Android build and a test matrix beyond one debug device.

### Phase 1 — Linux production integration

- [ ] Ship the GDM/polkit integration described in
      [Integration target](#integration-target-gnome-login-pkexec-and-systemctl):
      scoped `/etc/pam.d/gdm-password` and `/etc/pam.d/polkit-1` overrides,
      verified process identity, prompt context and the full test matrix.
- [ ] Implement the adb-like pairing and device UX described in
      [CLI and pairing UX](#cli-and-pairing-ux): one code line, no default
      confirmation prompt, truthful completion, `devices`, `unpair`.
- [ ] Review and, if accepted, implement the centralized `rba` CLI and versioned
      control API from [`rba-cli.md`](rba-cli.md). Do this as a front-end/API
      refactor, not as aliases piled on `rba`.
- [ ] Remove JSON from runtime state, audit and local IPC as described in
      [State and logs: no JSON](#state-and-logs-no-json). Start with a fresh
      state directory; do not read old `registry.json` or preserve old pairings.
- [ ] After the CLI command names, flags, exit codes and output contract freeze,
      write `rba(1)` and the subcommand man pages. Generate shell completions
      from the same command definitions; do not hand-maintain a second flag
      list.
- [ ] Fix VPN/Tailscale coexistence as described in
      [Known network issue](#known-network-issue-vpn--tailscale): try all resolved
      addresses, bind sockets to the chosen `Network`, reconnect on VPN/Wi-Fi
      changes, and stop advertising unintended interfaces by default.
- [ ] Only if LAN + Tailscale are insufficient, evaluate an optional relay or
      rendezvous path. Prefer an existing transport (Tailscale, WireGuard, SSH)
      or a minimal protocol-specific relay; do not adopt Syncthing's relay stack.
- [ ] Provide distro-specific PAM documentation:
      Debian/Ubuntu `common-auth`; Arch `/etc/pam.d/sudo`, `polkit-1`,
      `gdm-password`; Fedora equivalents.
- [ ] Scope the default integration to `sudo` and `polkit`; make GDM/login
      opt-in and explicitly warn about prompt fatigue.
- [ ] Keep `/etc/pam.d` overrides in `/etc`, never edit vendor files under
      `/usr/lib/pam.d`.
- [ ] After SEC-004, evaluate a fprintd-compatible virtual device for native
      GNOME/KDE fingerprint UI. Do not fake USB hardware or a fingerprint
      template; preserve a real local sensor.
- [ ] Add a root-shell recovery procedure and a PAM rollback test to every
      documented flow.
- [ ] Add device-user binding and per-user rate limits.
- [ ] Store an account allow-list per paired device; default to the pairing user,
      add other accounts through host policy, and show them in the app.
- [ ] Do not require re-pairing the same host for each Linux user; keep host
      identity machine-scoped and user identity per request.
- [ ] Document install/enable/disable/device-mask/uninstall as distinct states.
- [ ] Implement the per-account/per-device matrix: `device_login`,
      `allowed_devices`, `allow_delegated_login_from`, `allowed_operations`, and
      `allow_elevated`.
- [ ] Show both the approving principal and the target account on the device;
      audit delegated login separately.
- [ ] Refuse to send `sudo`/elevated requests to a device whose policy cannot
      approve them, before the device is prompted.

### Phase 2 — Capability protocol v1

- [ ] Specify the capability message family and canonical encoding.
- [ ] Add host/device policy intersection rules and tests.
- [ ] Add toggles in Android and the host CLI for supported operations.
- [ ] Add downgrade/mismatch tests and a "required capability missing" failure.
- [ ] Add shared vectors and a conformance run for the new messages.
- [ ] Keep capabilities separate from authorization; document the distinction.
- [ ] Add `account_scope`/`accounts`/`allow_root` to pairing or policy exchange,
      with scope expansion requiring host authorization and device confirmation.

### Phase 3 — Portability

These are separate adapters, not assumptions that the Linux code is portable.

#### BSD

- [ ] OpenPAM adapter instead of Linux-PAM-specific calls.
- [ ] Peer-credential check using `getpeereid`/`LOCAL_PEERCRED` equivalents.
- [ ] No systemd; use the platform service manager.
- [ ] Avahi/Bonjour discovery; no BlueZ central.
- [ ] Real hardware and PAM-stack tests before claiming support.

#### macOS host

- [ ] PAM/OpenPAM adapter for `sudo` and terminal auth.
- [ ] Authorization Plugin for GUI/login; do not pretend PAM alone covers the
      macOS login window.
- [ ] launchd service, Keychain, Bonjour discovery.
- [ ] Separate local-IPC peer validation.

#### iOS authenticator

- [ ] Swift app implementing the shared protocol vectors.
- [ ] Secure Enclave P-256 signing and LocalAuthentication/Face ID.
- [ ] Network.framework/Bonjour and BLE, with realistic background limits.
- [ ] Platform-specific attestation and storage review.
- [ ] App Store / distribution policy review.

#### Windows

- [ ] Feasibility only, not committed: a Credential Provider or another supported
      logon integration, plus named-pipe peer identity and SCM service management.
- [ ] Do not design around the Windows Hello Companion Device Framework; it is
      deprecated. See [`host-backends.md`](host-backends.md).

### Phase 4 — Release and audit

- [ ] Release-signed, non-debuggable Android APK.
- [ ] Reproducible builds and release checksums.
- [ ] Packaging for the supported Linux distributions.
- [ ] Re-run the full audit after each platform adapter lands.
- [ ] Keep `docs/security-audit.md` updated; duplicate findings are linked, not
      deleted.

## Explicit non-goals

- A permanent pairing mode or "trust anything that connects".
- A device capability that grants a Linux user permission the host policy denies.
- Silent downgrade when attestation, strong biometrics or a required transport
  is unavailable.
- Claiming macOS/BSD/iOS support by compiling the Rust core without a real
  platform adapter and hardware test.
- Global PAM installation as the default without a clear warning about prompt
  fatigue and recovery.

## Decision log

| Date | Decision |
|---|---|
| 2026-11-18 | Linux/Arch is the supported target for now. |
| 2026-11-18 | Capability negotiation is a valid separate authenticated message family, not a second unauthenticated protocol. |
| 2026-11-18 | Polkit/GDM/login integration is opt-in and must be scoped; `sudo` remains the tested integration. |
| 2026-11-18 | macOS/BSD/iOS are separate adapters with their own threat models; Windows is out of scope. |
| 2026-11-18 | Do not vendor or port Syncthing code. Reimplement the multi-path/retry behavior from documented concepts; Syncthing is MPL-2.0 and this tree is 0BSD. |
| 2026-11-18 | A relay/rendezvous fallback is optional. Prefer Tailscale/WireGuard/SSH or a minimal protocol-specific relay over adopting Syncthing's relay stack. |
| 2026-11-18 | Syncthing is reference behavior only. Work is split into minimal V2/VPN fixes, optional upgrades, and ongoing robustness; no code, BEP, global discovery or relay is imported. |
| 2026-11-18 | Current integration priority is GDM password login, `pkexec` and `systemctl` via polkit, using scoped `/etc/pam.d` overrides. Do not edit `system-auth` or `gdm-fingerprint` first. |
| 2026-11-18 | Native GNOME/KDE fingerprint UI is a future fprintd-compatible virtual device, not a fake USB sensor. PAM integration comes first; the fprintd adapter waits for SEC-004 and a real packaging/security review. |
| 2026-11-18 | GDM/lock-screen/PAM integration requires administrator install. There is no supported per-user or no-root path; immutable distros still require an admin transaction. The app cannot bypass the greeter or lock screen. |
| 2026-11-20 | Proposal for review: portable core plus host backends, one `rba` CLI, optional ADB transport and a headless Android helper. Man pages wait for the CLI surface to freeze. Not committed scope yet. |
| 2026-11-20 | Runtime state, audit and local IPC will not use JSON. Device records are line-oriented files, the audit log is one event per line, and local IPC reuses the canonical CBOR codec. Generated conformance vectors remain test fixtures. |
