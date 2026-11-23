# ADB transport and the "app-less" question

Status: **feasibility draft for review**. Nothing here is implemented.

Short answer:

- **ADB as a transport: yes.**
- **ADB to install/update a headless helper: yes.**
- **A truly app-less authenticator with no APK installed: no, not without weakening
  the security model.**
- **No launcher icon and no app the user has to open: yes, and that is the
  realistic version of "app-less".**

The confusion is worth separating. scrcpy can push a server and run it with
`app_process` because it does not need a secret tied to an app identity or a
biometric approval. rba does.

## What scrcpy does

scrcpy pushes a small Java server to the device and runs it with Android's
`app_process`. That process runs as the `shell` UID and uses shell-level
permissions for display capture, input injection and media encoding. It is
temporary, version-matched to the client, and does not need an installed app.

That model works because scrcpy is not an authenticator:

- it does not own a non-exportable signing key;
- it does not need a fresh human biometric per action;
- it does not need the key operation to be bound to a user-presence token;
- its authority comes from ADB's shell access, which is already broad.

## What rba needs

`rba`'s security property is not "the device answered". It is:

1. a private key that never leaves Android Keystore;
2. a key generated with `setUserAuthenticationRequired(true)`;
3. a `BiometricPrompt` with a `CryptoObject`, so the signature only becomes
   possible after a fresh strong biometric;
4. a host that verifies the signature over the exact signed context.

Android enforces the important part: a Keystore key is scoped to the app UID and
package that created it, and an operation-based key requires the auth token from
the biometric prompt. A shell process does not get to use another app's key, and
`app_process` has no normal Activity/UI token from which to run the public
`BiometricPrompt` flow.

There is no public, portable `adb shell` command that means "show the system
biometric prompt and release a Keystore auth token for this app's key". A
rooted device could run code as the app UID or bypass Keystore, but that is not a
supported security model and not something to build the product on.

## Options

| Option | No APK? | Biometric/Keystore preserved? | Verdict |
|---|---:|---:|---|
| ADB transport + existing app | no | yes | Best first step |
| ADB-provisioned headless APK (no launcher icon) | no | yes | Best "app-less" UX |
| `app_process` server only | yes | no | Transport/diagnostics only |
| Software key in `/data/local/tmp` | yes | no | Rejected |
| Rooted device, run as app UID | yes | weakened | Rejected |

### 1. ADB transport with the existing app

The device keeps the installed app. ADB replaces Wi-Fi/mDNS as the pipe:

```text
host rba CLI
  -> rbad / rbad
  -> adb reverse tcp:47123 tcp:47123
  -> device app connects to 127.0.0.1:47123
```

The app still performs `BiometricPrompt` and Keystore signing. Pairing still uses
the rba code gate. ADB only carries frames.

This is the lowest-risk implementation and can be tested without changing the
security model. It also works on Linux, macOS, Windows and BSD hosts wherever
the `adb` client runs.

### 2. ADB-provisioned headless APK

This is what most people mean by "app-less":

- no launcher icon;
- the user never opens an app;
- `rba pair`/`rba connect` installs or updates a headless build with `adb install
  -r`, starts the pairing/auth activity with `am start`, and communicates over
  `adb reverse`;
- the user only sees the system biometric prompt.

It is still an APK. It has to be, for Keystore and `BiometricPrompt`. The
difference is UX: it behaves like a scrcpy server that the CLI manages, not like
an app the user launches.

Build constraints:

- same `applicationId` and signing key as the normal app, so `adb install -r`
  preserves app data, the Keystore key and the pairing;
- a build flavor with no `MAIN`/`LAUNCHER` activity, or a disabled launcher
  alias;
- a transparent authentication activity and the existing foreground service;
- no debug build for production; a debuggable app lets an ADB-authorized host
  use `run-as`.

`adb uninstall` removes app data and the Keystore key. The CLI must warn about
that and never do it as part of a normal update.

### 3. `app_process` server only

A pushed JAR/DEX can run as shell and speak the protocol, discover the host, and
carry frames. It cannot produce the biometric-gated signature that gives rba its
meaning. If it signs with a key stored in a file, then anyone with ADB or root can
copy the key and sign without the device's user. That is a different, weaker
product.

It could still be useful for:

- transport diagnostics;
- a pairing/status helper that does not authenticate;
- a test harness that drives a real app on another device.

It should not be described as an authenticator.

## Why "just send the server every time" does not fit

scrcpy can replace its server on every run because the server holds no trust.
`rba`'s trust is in:

- the Keystore key, which is bound to the app UID/package;
- the pairing record on the host, which is bound to the device public key;
- the biometric auth token, which is tied to a live `BiometricPrompt` operation.

Reinstalling or replacing the app can destroy the key. Pushing a fresh JAR does
not create a new trusted identity. The host would have to re-pair, and the device
would have to re-enroll. That is not an "app-less" win; it is a re-pairing loop.

## Proposed ADB integration

Keep ADB behind the transport abstraction. Do not make it the default.

```text
rba devices --transport adb
rba pair --transport adb --serial <adb-serial>
rba connect --transport adb --serial <adb-serial>
rba disconnect --transport adb --serial <adb-serial>
```

`-s` remains the rba device selector (cryptographic identity). `--serial` is the
ADB transport selector. They are not interchangeable:

- an ADB serial can change with wireless debugging, port assignment or USB;
- the rba device ID is derived from the trusted public key;
- using an ADB serial as `-s` would make transport identity equal trust identity,
  which the protocol deliberately avoids.

Flow for `rba pair --transport adb`:

1. Check `adb get-state` and `adb devices`; fail clearly on `unauthorized`,
   `offline`, or multiple devices without `--serial`.
2. Start or verify the daemon's loopback listener.
3. `adb reverse tcp:<port> tcp:<port>` so the device can reach the host without
   opening a LAN port.
4. Install/update the headless APK if needed, with `adb install -r` and the same
   signing key.
5. Start the pairing activity with `am start` and explicit extras (host address,
   code-entry mode).
6. Run the existing rba pairing code gate. Do not use ADB's own pairing code as
   the rba code.
7. On exit, remove the reverse tunnel unless the user asked to keep the link.

TLS and pinning must be tested over loopback. If strict hostname verification
rejects `127.0.0.1`, add a pinned-key path for the ADB transport; do not disable
certificate verification.

## Security notes

- **ADB is a broad trust channel.** An authorized ADB host can install and
  uninstall apps, read logs, start activities and often inspect app data. It is
  not equivalent to "this host may authenticate". Treat it as a debug/provisioning
  channel, not as the trust anchor.
- **Developer options are required.** Wireless debugging is Android 11+ and
  OEM/version dependent; USB debugging needs a cable. Neither is a universal
  default.
- **Wireless debugging pairing is not rba pairing.** ADB's code authenticates the
  ADB transport. rba still needs its own code and its own pinned device key.
- **Production builds must be non-debuggable.** A debuggable app allows `run-as`
  and weakens the boundary.
- **App signing matters.** `adb install -r` only preserves data when the signing
  key matches. Losing the signing key means uninstall/reinstall and re-pairing.
- **ADB access can deny service.** It can uninstall the app or clear data; it
  cannot forge a biometric signature without the key. Say that plainly rather
  than claiming ADB is harmless.
- **Do not log secrets.** Pairing codes, tokens and key material stay out of
  `logcat`, the journal and CLI argv.

## Cross-platform note

ADB is available on Linux, macOS, Windows and BSD. The transport code can be
portable even though the host integration backends are not:

- Linux: PAM/polkit/systemd
- macOS: PAM for `sudo`, Authorization Services/loginwindow where supported
- Windows: credential provider or another supported logon integration; the old
  Windows Hello Companion Device Framework is deprecated
- BSD: OpenPAM and the platform service manager

ADB transport work is independent of those backends.

## Verification plan

- USB and wireless ADB, authorized and unauthorized devices.
- Multiple ADB devices with and without `--serial`.
- Pairing over `adb reverse`; code gate both directions.
- Authentication over `adb reverse`; replay and wrong-device tests.
- `adb install -r` preserves pairing and Keystore key.
- `adb uninstall` is detected and warned about.
- TLS/pinning over loopback.
- Disconnect removes the reverse tunnel and does not unpair.
- Linux, macOS and Windows ADB clients at least for the transport layer.

## Open questions

1. Is the goal **no launcher icon / no app to open**, or **no APK installed at
   all**? Only the first preserves the current security model.
2. Is ADB a supported transport, a provisioning tool, or both? The draft proposes
   both, with transport first.
3. Should the headless build be a flavor of the existing app (same package and
   signing key) or a separate package? Same package is the only way to preserve
   the existing Keystore key and pairing.
4. Is depending on `adb` and developer options acceptable for the target users?
   Some managed devices disable both.
5. Do we ship `adb`/platform-tools, or require the user to install them?
6. Is wireless ADB reliable enough to document, or is USB the supported path?
7. How do we test on Android versions/OEMs where background activity launch and
   `am start` restrictions differ?
