# Host backends

Status: **draft for review**. Nothing here is implemented.

`rba` must not have a Linux-shaped core. The protocol, registry, policy, pairing
and audit model are portable. PAM, polkit, systemd, launchd, Windows logon and
BSD service management are not.

The rule is simple:

> The core decides whether an authentication is valid. A host backend only
> carries a request to the user and reports the result back. A backend can never
> approve on its own, widen policy, or invent a target account.

## Layers

```text
Device (Android app / future platform)
        |
        | rba protocol (transport-independent)
        v
rbad
  portable: protocol, crypto, registry, policy, pairing, sessions, audit
        |
        +-- local IPC + peer identity
        |     Unix socket / named pipe
        |     SO_PEERCRED / getpeereid / LOCAL_PEERCRED / Windows SID
        |
        +-- host backend
        |     linux-pam, linux-polkit, systemd
        |     bsd-pam, rc.d
        |     macos-pam, authorization-services, launchd
        |     windows-credential-provider, SCM
        |
        +-- transport
              wifi, ble, adb
```

The CLI (`rba`) is another client of the same local API. It is portable; the
backend and service-manager parts are not.

## Backend contract

Every host backend must provide, or explicitly declare unsupported:

| Concern | Contract |
|---|---|
| Local IPC | How a local process reaches the daemon, and how the daemon authenticates the caller |
| Peer identity | A stable local identity: UID on Unix, SID on Windows, plus PID where available |
| Auth trigger | How the platform asks rba to authenticate a target account and operation |
| Result mapping | How success/denial/timeout/unavailable maps back to the platform |
| Policy context | The canonical service/operation for that trigger, not a raw caller string |
| Service manager | Start/stop/status/logs for the daemon |
| Installer | Install, verify, backup and roll back the integration |
| Status | Report installed/enabled/available without changing anything |
| Audit | Record the caller, target, operation, device and result |

The backend is a **trigger and installer**, not a second authentication engine.

## Platform matrix

### Linux

- PAM: `pam_rba.so`; local overrides in `/etc/pam.d`, vendor files in
  `/usr/lib/pam.d` (Arch) or `/usr/lib/x86_64-linux-gnu/security` (Debian family).
- polkit: `polkit-1` PAM service; `polkit-agent-helper-1`.
- Service manager: systemd.
- Peer identity: `SO_PEERCRED` on Unix sockets.
- Current implementation and tests live here. It is the reference backend.

Linux is not the whole product. It is the first backend.

### BSD

- PAM: OpenPAM rather than Linux-PAM. The API is similar but not identical.
- Current module uses Linux-PAM extensions:
  - `pam_prompt` / `PAM_TEXT_INFO`;
  - `pam_syslog`;
  - Linux-specific socket credentials.
- Those need a small portability layer or feature gates. Do not pretend a
  Linux-PAM `.so` is a BSD module.
- Service manager: rc.d, not systemd.
- Peer identity: `getpeereid` or `LOCAL_PEERCRED`, depending on BSD.
- Install paths and PAM service names differ (`login`, `sudo`, `sshd`, `su`).

### macOS

- PAM works for `sudo` and `sshd`; on recent macOS, use `/etc/pam.d/sudo_local`
  rather than editing the SIP-protected `sudo` file.
- The login window and lock screen are not a generic PAM UI. Third-party PAM at
  the lock screen is not reliable across macOS versions. Authorization Services
  or a login-window mechanism is a separate backend and needs its own review.
- Touch ID is `LocalAuthentication`, not PAM. It is the local biometric path and
  cannot simply be repointed at a device.
- Service manager: launchd.
- Peer identity: `getpeereid` / `LOCAL_PEERCRED`.
- Distribution: code signing, notarization, Gatekeeper, and possibly Full Disk
  Access or other TCC prompts. A PAM module may need quarantine removal.
- Do not claim "macOS login" until the login-window path is proven; `sudo` is a
  smaller, honest first target.

### Windows

Windows is the most different backend and needs a feasibility project before any
promise:

- There is no PAM and no Unix UID. The local caller is a Windows token/SID.
- Logon and UAC use credential providers (COM DLLs), not a PAM stack. A custom
  credential provider is signed native code running in a privileged logon path;
  it is a high-risk integration.
- **Windows Hello is not a generic plugin API.** It is the local biometric/PIN
  system. The old **Windows Hello Companion Device Framework is deprecated**
  (Windows 10 2004 and later). Do not design around it.
- Realistic paths:
  1. a custom credential provider that calls the rba daemon;
  2. a FIDO2/WebAuthn-style integration, if the product can accept that model;
  3. a separate companion-device or MDM-supported route, if one exists and is
     still supported.
- Service manager: Service Control Manager.
- Local IPC: named pipe with an ACL, plus `GetNamedPipeClientProcessId` and token
  SID checks. A localhost TCP socket is not an acceptable substitute without
  mutual authentication.
- Code signing and installer/rollback are part of the security boundary.

Windows support should be a separate design document, not a checkbox.

## What is portable

- Protocol specification, canonical CBOR, framing, signatures, pairing,
  verification, replay protection.
- Device registry model, policy model, audit schema.
- CLI and its text output/exit codes.
- Transport abstraction: Wi-Fi, BLE, ADB.
- Pairing UX and prompt semantics.

## What is not portable

- PAM API and module loading.
- Peer credential API.
- Service manager.
- Install paths and package formats.
- Login/lock-screen UI integration.
- Privilege model: Unix UID/GID vs Windows SID/token.

## CLI shape for backends

`rba pam` is too narrow as a top-level concept. Use integrations:

```text
rba integrations
rba integration status [backend]
rba integration verify [backend]
rba integration enable <backend> [--target TARGET] [--dry-run]
rba integration disable <backend> [--target TARGET]
```

Examples:

```text
rba integration enable linux-pam --target gdm-password
rba integration enable linux-pam --target polkit-1
rba integration enable macos-pam --target sudo
rba integration enable windows-credential-provider --target logon
```

`rba pam ...` is not a command; PAM is one Linux backend behind
`rba integration`. `rba service ...` auto-detects systemd/launchd/SCM/rc.d and
returns `unsupported` where there is no implementation.

## Android device side

The protocol is portable; the Android implementation is not:

- Android Keystore + `BiometricPrompt` + `BIOMETRIC_STRONG`;
- non-exportable P-256 key;
- foreground service and transparent activity for background prompts;
- app package and signing key are part of the trust state.

The Android application ID is part of the trust state. This release changes it
to `io.github.burtvadr.rba`; there is no in-place upgrade, so the app is
reinstalled and every device pairs again. Do not change it again without
accepting the same re-pairing cost.

A future iOS implementation would use Secure Enclave and `LocalAuthentication`,
but it is a separate device backend. The protocol should not assume Android.

## Refactor implications

1. Extract platform-neutral modules from `linux/`:
   - protocol (already separate);
   - registry, policy, pairing, session and audit;
   - a `HostBackend`/`PeerIdentity`/`LocalIpc` boundary.
2. Replace direct `SO_PEERCRED` and Linux-PAM calls with abstractions.
3. Define the integration manifest and `rba integration` commands.
4. Keep Linux as the reference backend; port BSD/macOS one target at a time.
5. Treat Windows as a separate feasibility/security project.
6. Keep the portable modules free of Linux paths and Linux-only types. The
   naming break in this release is already done; do not add compatibility
   readers for old names or old trust state. A host that moves to this release
   starts with a fresh identity and every device pairs again.

## Open questions

1. Which host platforms are actually in scope for the first release after Linux?
   BSD, macOS and Windows have very different integration costs.
2. Is macOS login/lock-screen support required, or is `sudo` enough for the first
   macOS backend?
3. Is Windows a supported target or only a future experiment? A credential
   provider is a large security commitment.
4. Should the daemon be a portable Rust binary on all platforms, or a per-platform
   service with a shared protocol library?
5. How will peer identity work on Windows without Unix UIDs, and how will policy
   name accounts there?
6. What is the canonical operation vocabulary across platforms (`login`,
   `unlock`, `sudo`, `polkit`, `uac`, `screen-unlock`)?
