# Naming

Status: **normative** for code, command lines, packaging and documentation.

`Remote Biometric Authenticator` is the product name. `rba` is the command and
the identifier used in code, paths, packages and prose. `RBA` is reserved for
environment variables and protocol constants. Capitalization is not semantic:
do not create a second name by changing case.

This is the model used by Android Debug Bridge:

- the product is `Android Debug Bridge`, abbreviated `ADB` in headings;
- the command, binary and package are `adb`;
- the daemon is `adbd`;
- the environment variables are `ADB_*` and `ANDROID_*`;
- the mDNS services are `_adb._tcp` and `_adb-tls-connect._tcp`;
- the CLI says `adb: ...` on errors;
- the source files are `adb_auth.cpp`, `transport_usb.cpp`, `pairing_connection.cpp`.

The command is never `android-debug-bridge`, and it is never `ADB` when typed.
Apply the same rule here: `rba` is what a user types, `Remote Biometric
Authenticator` is what a person reads, and `RBA` only appears where an uppercase
identifier is structurally required.

## Canonical names

| Purpose | Name |
|---|---|
| Product | `Remote Biometric Authenticator` |
| CLI and binary | `rba` |
| Daemon and binary | `rbad` |
| Simulated device | `rba-sim` |
| PAM module | `pam_rba.so` |
| polkit agent | `rba-polkit-agent` |
| Rust protocol package | `rba-protocol` |
| Rust protocol library | `rba_protocol` |
| Android application ID | `io.github.burtvadr.rba` |
| systemd units | `rbad.service`, `rbad.socket` |
| State directory | `/var/lib/rba` |
| Control socket | `/run/rba/control.sock` |
| Audit log | `/var/log/rba/audit.log` |
| Host policy and configuration | `/etc/rba` |
| System account and group | `rba` |
| Socket override | `RBA_SOCKET` |
| mDNS service | `_rba._tcp.local.` |
| Protocol domain separator | `RBA_AUTH_V1` |
| PEM label | `RBA-EC-P256-KEY` |

`rbad` follows the `adb` / `adbd` pattern: the daemon is the command name with a
`d` suffix. It is not `rba-daemon`, `rba_daemon` or `rba.service`.

`rba-sim` is an auxiliary test tool, not a core binary. Hyphens are acceptable
for auxiliary tools, as with `hprof-conv`; the core pair stays short and
unhyphenated. There is no `rba-cli` binary: the CLI is `rba`.

The GitHub repository slug may stay descriptive
(`remote-biometric-authenticator`). That is a URL, not a command. Do not install
a binary with that name.

## CLI rules borrowed from ADB

```text
rba [global options] <command> [command options]
```

- Commands are lowercase, verb-first and short. The current surface is
  `devices`, `pair`, `auth`, `revoke`, `status`, `version`, `help`; lifecycle
  commands such as `unpair` follow the same rule.
- Multiword commands are hyphenated, not underscored: `start-server`,
  `wait-for-device`. Do not invent a second spelling.
- Global selectors go before the command, like `adb -s SERIAL shell`:
  `rba -s DEVICE auth`. `-s` selects the authenticator identity.
- `--serial` is only the ADB transport selector. It is never the trust
  selector.
- Do not copy ADB's `-d` and `-e` flags. They describe a USB/TCP split that
  `rba` does not have.
- Results go to stdout, progress and diagnostics to stderr.
- User-facing errors start with `rba:` on stderr, for example
  `rba: no authenticator selected`. The daemon prefixes its own messages with
  `rbad:`.
- `rba` with no arguments prints help and exits `1`, like `adb`. `rba help`
  exits `0`. There is no TTY-dependent command behavior; use `rba status` or
  `rba ui` explicitly.
- `rba version` prints the product name, protocol version and installed path.
  Do not print a bare version number as the whole output.
- Help is grouped like ADB's: commands, pairing, options, environment. Add
  integration and service groups only when those commands exist.
- `rba devices` is the ADB-shaped inventory command. States are lowercase:
  `connected`, `paired`, `pairing`, `revoked`, `offline`.
- Exit codes are stable and documented (`0` success through `8` pairing
  failure). ADB mostly returns `0` or `1`; authentication outcomes need to be
  distinguishable without parsing English.

Deliberate difference: `rba` never auto-starts `rbad`. ADB starts its host server
on demand because it is a developer tool. `rbad` is a system service under
systemd, launchd, SCM or rc.d, and starting privilege-bearing services is not a
CLI side effect.

## Environment and configuration

- Environment variables use the `RBA_` prefix, uppercase, like `ADB_TRACE` and
  `ADB_SERVER_SOCKET`: `RBA_SOCKET`, and future `RBA_TRACE`, `RBA_DEVICE`.
- Runtime configuration keys are lowercase, dot-separated and namespaced, like
  Android properties: `service.rba.port`, `persist.rba.mdns`.
- mDNS service types are lowercase and hyphenated:
  `_rba._tcp`, `_rba-tls-pairing._tcp`, `_rba-tls-connect._tcp`.
- Network service names are lowercase and colon-terminated, like ADB's
  `host:`, `shell:`, `exec:`: `pair:`, `auth:`, `devices:`.
- Protocol feature names are lowercase snake case: `biometric_uv`,
  `code_entry_host`, `pairing_confirm`.

## Source and documentation

- Rust package names use hyphens (`rba-protocol`, `pam-rba`); Rust library
  names use underscores (`rba_protocol`, `pam_rba`).
- Binary names are lowercase and unhyphenated for the core pair: `rba`,
  `rbad`.
- Kotlin package names are all lowercase (`io.github.burtvadr.rba.protocol`);
  class names are CamelCase (`RbaApplication`), and Compose theme names follow
  the platform convention (`Theme.Rba`).
- Protocol constants and domain separators are uppercase snake or uppercase
  hyphenated (`RBA_AUTH_V1`, `RBA-PAIR-V1`). They are wire identifiers, not
  branding, and are versioned when they change.
- Source filenames are lowercase snake case: `rba_auth.rs`, `pairing.rs`,
  `transport_wifi.rs`.
- Log tags are lowercase: `rba`, `rba_auth`, `rba_pair`, `rba_transport`; the
  daemon uses `rbad`.
- In documentation, write the product in title case on first mention and use
  `rba` in code font thereafter, including at the start of a sentence. Do not
  write `RBA` as a substitute for the command.
- Man pages are `rba(1)` and `rbad(8)`. Do not create `rba-cli(1)` or
  `rba-daemon(8)`.

## Clean break

This project does not ship aliases for old names. Old binaries, units, paths,
PAM modules, Android packages and protocol separators are not recognized. A host
or device that moves to this release is reinstalled and re-paired; old trust
state is not read.

The cost is deliberate. A second name is a second contract, a second set of
paths, a second set of bugs and a permanent compatibility test. One name is
cheaper.

## Short version

```text
rba pair
rba -s pixel-9 auth
rba devices
RBA_SOCKET=/run/rba/control.sock rba status
rba: no authenticator selected
```

Not:

```text
RBA pair
rba-daemon
rba-cli
rba.service
RemoteBiometricAuthenticator
remote-biometric-authenticator auth
```
