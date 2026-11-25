# `rba` CLI and control API

Status: **target contract with staged V2 implementation**. The active V2
standalone CLI implements `rba` (no arguments), `start-server`, `kill-server`,
`devices`, `status`, `version` and `help`. See
[B.3.7.2 lifecycle delivery](B3_7_2_CLI_LIFECYCLE.md) for the exact supported
surface and limitations. The remaining commands below are the intended product
contract, not claims of V2 runtime support. No V1 fallback is active.

The CLI is one client of a versioned daemon API, and that API is the boundary
everything else uses. Replace the old front end once, cleanly, rather than
putting a new command surface on top of the old one.

## Principles

- **One user-facing binary: `rba`.** No user should need to know about
  `rbad`, sockets, PAM modules or systemd units to use a device with a host.
- **The CLI is a client, never an authority.** It holds no keys and makes no
  authentication decision. The daemon verifies signatures and enforces policy.
- **One command surface.** The CLI, future GUIs and the PAM adapter all speak
  the same versioned local API.
- **Explicit privilege.** No silent `sudo`, no silent policy change, no hidden
  root path.
- **Transport is not identity.** A Wi-Fi address, an ADB serial and a Bluetooth
  address identify a link, not a trusted device. Trust is the device public key.
- **No secrets in argv.** Pairing codes and tokens are never accepted as command
  line arguments where shell history or process listings can capture them.
- **Quiet by default.** Results go to stdout; progress and diagnostics go to
  stderr. Text output and stable exit codes are the first contract.

## Command surface

```text
rba [global options] <command> [subcommand] [options]

rba                              initialize/start server and print status
rba start-server [--foreground]
rba kill-server
rba help [command]
rba version
rba status
rba devices [<device>] [-l|--long]
rba devices rename <device> <name>
rba pair [--transport wifi|adb] [--code-entry device|host] [--owner USER]
         [--timeout SECONDS]
rba connect [<device>] [--transport wifi|adb]
rba disconnect [<device>]
rba unpair <device> [--yes]

rba auth [--user USER] [--purpose PURPOSE] [--service SERVICE] [--timeout SECONDS]

rba service start|stop|restart|status|logs [--follow] [--since TIME]

rba status
rba enable gdm [--dry-run] [--yes]
rba disable gdm
rba enable polkit [--dry-run] [--yes]
rba disable polkit

rba policy show [--device DEVICE]
rba policy set [--device DEVICE] [options]
rba policy allow <purpose> [--device DEVICE]
rba policy deny <purpose> [--device DEVICE]
rba policy reset [--device DEVICE] [--yes]

rba config show|get|set|unset [key] [value]
rba completion bash|zsh|fish
```

`rba` with no arguments initializes/starts the standalone daemon if necessary
and reports its status. `rba devices` also starts the daemon automatically.
`rba help`, `rba version`, `rba status` and `rba kill-server` do not start a
stopped daemon. `rba status` reports stopped when no control socket is listening;
`rba kill-server` is idempotent. No command requires a service manager for
standalone execution.

If an interactive screen is added later, it is `rba ui`, a thin client of the
same API. It must not contain a second implementation of pairing,
authentication or policy.

### Why these commands are not in v1

These names were in the earlier proposal and are deliberately deferred or
dropped:

| Command | Reason |
|---|---|
| `rba auth test` | `rba auth` already is the test. A second name adds no behavior. |
| `rba auth status` | `rba status` and `rba devices` already report this. |
| `rba auth use DEVICE` | This is a user preference, not an authentication operation. Put it under `rba config`. |
| `rba auth cancel` | Only add it when the daemon has request IDs and a real cancel method. Do not ship a dead command. |
| `rba pair --code NNNNNN` | The code is a short-lived secret. Keep it out of argv and shell history. Tests can call the daemon API directly. |
| `-d`, `-e` | There is no USB/network device split in `rba`'s trust model. Do not borrow ADB flags with no meaning. |
| `rba devices forget` | Use `rba unpair`. One name for one operation. |

## Global options

```text
-s, --device <ID>     select one authenticator (immutable ID or unique alias)
-v, --verbose         more diagnostics; repeatable
-q, --quiet           suppress progress and non-essential output
    --no-color        disable color
    --timeout <SEC>   operation timeout, where the command supports one
    --socket <PATH>   advanced/test override for the control socket
-h, --help
-V, --version
```

Transport-specific options belong to the command that uses them:

```text
rba pair --transport adb --serial <adb-serial>
rba connect --transport adb --serial <adb-serial>
```

`--serial` is an **ADB transport selector**, not an `rba` device selector. `-s`
always selects the cryptographic identity. This is explained in
[`adb-transport.md`](adb-transport.md).

## Device selection

- `-s` accepts an exact device ID or a unique alias.
- No substring or fuzzy matching. An ambiguous alias is an error that lists the
  candidates.
- If a command needs exactly one device and exactly one is connected, it may use
  that device.
- If more than one is connected, `rba auth` and other single-device commands
  require `-s`; they do not silently pick one.
- Device names are untrusted display strings. The CLI must escape control
  characters before printing them.

## Device lifecycle

```text
$ rba devices

DEVICE       ID        STATE       TRANSPORT  LAST SEEN
Pixel 8      a1b2c3    connected   wifi       now
Office       d4e5f6    paired      -          2d ago
```

`STATE` is one of:

| State | Meaning |
|---|---|
| `connected` | paired and a live link exists |
| `paired` | trusted but no live link |
| `pairing` | a bounded pairing session is open |
| `revoked` | trust was revoked; kept only for audit, not usable |

`rba devices -l` adds the public-key fingerprint, owner, allowed purposes,
transport address and app/protocol version. Text is the contract for v1; a
machine-readable format is deferred until a real consumer exists.

`rba connect` means "ensure a usable link". It does **not** change trust:

- if the device connects inbound, it waits for the link or reports that it is
  already connected;
- if the selected transport can dial out (ADB, later Tailscale), it may establish
  the link;
- if neither is possible, it fails with `unavailable`, not a fake success.

`rba disconnect` drops the current link. It does not unpair.

`rba unpair` removes trust. It is an admin operation for a device owned by
another user; the owner may unpair their own device. The CLI must say whether the
device also needs to forget the host, because host-side and device-side revocation
are separate until the protocol confirms both.

## Pairing

```text
$ rba pair
Waiting for device... (120s)
Code: 123456  type this on the device
Paired.
```

- One bounded session, one progress line, one code line, one result. No box art
  and no host `[y/N]`: running `pair` is the operator's decision, and the device's
  typed code (or Allow) is the human gate. Ctrl-C cancels the session.
- Default code entry is `device`: the host shows the code, the device types it.
- `--code-entry host` reverses the direction, like `adb pair`: the device shows
  the code and the terminal prompts `Enter pairing code:`.
- The CLI does not print `Paired` until the device has persisted its record and
  sent `PAIRING_CONFIRMED`. A timeout, rejection or Ctrl-C exits non-zero and
  leaves no trusted pairing behind.
- `--transport adb` uses ADB only as a pipe. ADB's own pairing code is never used
  as the rba trust code.
- Confirmed pairing stores an explicit `authenticate/rba/authenticate` grant for the chosen account. An ordinary user may pair only for themselves; an administrator must specify `--owner USER`. Other operations require explicit principal-specific grants.

## Authentication

```text
$ rba auth
Waiting for Pixel 8…
Authenticated.
  device   Pixel 8
  user     desktop
  purpose  cli
```

`rba auth` proves that the device holder approved a fresh challenge for the
current user. It grants nothing by itself: it does not make the caller root, does
not unlock the screen and does not authorize `sudo`.

- Default user is the current user.
- A normal user may only request their own account. Root may request another
  account; the daemon enforces this, not the CLI.
- Independently, the selected credential must have the exact principal and scope grant. There is no implicit root authorization. The default scope is `authenticate/rba/authenticate`.
- `--quiet` suppresses "Waiting" but still prints the result.
- Exit codes distinguish denial, timeout and no-device; scripts should not parse
  the human text.

## Service management

```text
rba service status
rba service logs --follow
rba service restart
```

- `status` and `logs` do not require root; `logs` uses the journal and reports a
  clear error if the user cannot read it.
- `start`, `stop` and `restart` require administrator rights. The CLI prints the
  exact command to run; it does not silently invoke `sudo`.
- On a host without systemd, these commands exit `unsupported` (`7`).

## Host integrations

PAM is a Linux/BSD backend, not a top-level `rba` concept. The generic commands are:

```text
rba status                # what is enabled
rba enable gdm            # scoped gdm-password override (login + lock screen)
rba disable gdm           # rollback
rba enable polkit         # scoped polkit-1 override
rba disable polkit        # rollback
rba enable sudo           # scoped sudo override
rba disable sudo          # rollback
```

- `enable` and `disable` require administrator rights and are scoped to one
  backend at a time.
- `enable` shows the exact diff and asks for confirmation. `--dry-run` is
  available without root.
- `--yes` is allowed only for non-interactive admin use; it never skips the diff.
- Never edit `/etc/pam.d/system-auth` or `gdm-fingerprint` as part of a generic
  enable. `sudo`, `sshd`, `su` and `login` are left untouched.
- `polkit` covers both `pkexec` and `systemctl` actions that ask polkit: they
  share the `polkit-1` PAM stack, so one override enables the device for both.
- The implementation delegates to the audited per-platform installer scripts
  (`packaging/arch/pam-gdm-rba.sh`, `pam-polkit-rba.sh`). The CLI does not
  become a second PAM editor.
- On a platform without a supported backend, exit `unsupported` (`7`) and print
  what is missing. Do not guess a PAM layout.
- `rba pam ...` is not a command. PAM is one Linux backend behind
  `rba integration`, and [`host-backends.md`](host-backends.md) defines the
  backend boundary.

## Policy and configuration

These are different things and must not share a command:

| Concern | Command | Who may change it |
|---|---|---|
| Device ownership, account scope, allowed purposes, root, delegation | `rba policy` | Administrator |
| Preferred device, output format, color, default timeout | `rba config` | The local user |

The implemented SEC-025 policy is a set of exact principal/scope grants. `grant-scope` and `remove-scope` require administrator authority, an explicit `--device`, `--user`, and the requested `--purpose`, `--service`, `--operation` (scope defaults match basic CLI authentication). These commands cannot confer operating-system privileges. See [AUTHORIZATION_MODEL.md](AUTHORIZATION_MODEL.md). The previous independent account and root fields are obsolete; fresh enrollment is required.

## Output and exit codes

Human output is the first contract. Progress goes to stderr; result goes to
stdout. Keep the table boring and stable:

```text
$ rba devices

DEVICE       ID        STATE       TRANSPORT  LAST SEEN
Pixel 8      a1b2c3    connected   wifi       now
Office       d4e5f6    paired      -          2d ago
```

Exit codes are stable from the first release:

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | internal or daemon error |
| `2` | usage error |
| `3` | no device, or not paired |
| `4` | denied by the user |
| `5` | timeout or cancelled |
| `6` | policy/administrator denied |
| `7` | unsupported or unavailable on this host |
| `8` | pairing failed |

`rba auth` must distinguish "denied" from "timed out" from "no device"; scripts
should not parse English text.

## Man pages and completions

Man pages come **after** the CLI surface is solid. "Solid" means the command
names, flags, exit codes and output contract have stopped moving. Writing them
first creates a second specification that immediately drifts.

Sequence:

1. Freeze the command tree, global flags, exit codes and output format.
2. Make `--help` the short reference and `rba(1)` the long reference.
3. Generate shell completions from the same `clap` definitions; never maintain a
   separate flag list by hand.
4. Generate a first-draft man page from the CLI definition, then edit it for
   semantics, examples, security caveats and platform-specific commands.
5. Add a docs test that checks the examples in the man page against `--help` and
   the parser.

One `rba(1)` page is enough initially. Split out `rba-policy(1)` or
`rba-integration(1)` only if those sections become too large. `man` pages should
cover the things `--help` cannot: exit codes, the `unpair` vs `disconnect`
distinction, the no-secrets-in-argv rule, and which commands are Linux/BSD/macOS/
Windows-specific.

## Control API

The local control channel is an internal implementation detail, not the device
protocol and not a user-facing contract. Its exact encoding is not part of the
CLI specification. If the request/response shapes are refactored, do it once
behind a typed client with a versioned envelope. The intended encoding is
length-prefixed canonical CBOR using the existing protocol codec, not JSON; see
[`roadmap.md`](roadmap.md#state-and-logs-no-json).

Methods:

```text
status.get
devices.list        devices.get        devices.rename
devices.revoke
pairing.begin       pairing.code       pairing.confirm   pairing.cancel
auth.request        auth.cancel
policy.get          policy.set         policy.reset
```

- `policy.*` is admin-only and checked by `SO_PEERCRED` in the daemon.
- `auth.request` from a normal caller is limited to that caller's own account.
- The PAM module uses the same API with a trusted integration context; it does
  not bypass it.
- `integration.*` and service-manager commands are local CLI/backend operations,
  not daemon methods.

## Refactor sequence

Do not build the new CLI as a pile of aliases over the current one. Use this
order:

1. **Spec and skeleton.** Replace the current `rba` crate with `clap`, help,
   completions and the command tree. Wire `devices`, `status`, `pair`, `auth`,
   `unpair` and `version` to the daemon through a typed client. Keep behavior
   identical; do not keep the old command names as hidden aliases.
2. **Versioned API.** Introduce the `v:1` envelope and typed methods, and update
   the PAM module and simulator in the same change. Do not keep a dual stack.
   Define the text output and exit codes here, not later.
3. **Host commands.** Add `service` as a wrapper
   around the existing audited backends. No new PAM editing logic in Rust.
4. **Policy.** Implement SEC-004 and the admin API first, then expose `rba
   policy`. Do not ship policy commands that the daemon cannot enforce.
5. **Transports.** Introduce the transport abstraction, then ADB. `rba connect`
   and `rba pair` gain `--transport` only when the backend actually supports it.
6. **Names and paths.** This is one clean break: new daemon name, unit, state
   paths, socket, PAM module, Android application ID and protocol separators.
   Do not read old state, rewrite old PAM lines, or keep old aliases.
7. **TUI, completions, man page.** Finalize these only after the command surface
   and exit codes freeze. `rba ui`, if it exists, is a client of the same API; it
   is not a second implementation.

## Clean break

This is a pre-1.0 rename, not a compatibility release. There are no aliases for
old binary names, units, paths, PAM modules, packages or protocol strings, and no
migration code for old trust state.

- **Android application ID.** It is now `io.github.burtvadr.rba`. Keystore keys
  are scoped to the app UID/package, so the installed app cannot be upgraded in
  place: uninstall it, install the new build, and pair again.
- **Host identity and registry.** The state directory is `/var/lib/rba`. Old
  state is not read; a host that moves to this release starts with a new host
  identity and every device must pair again.
- **PAM module.** The module is `pam_rba.so`. Existing PAM lines that name an old
  module are left untouched and simply do not apply; the operator reinstalls the
  integration.
- **Socket.** The control socket is `/run/rba/control.sock`. Old clients and the
  old PAM module cannot connect to it.

Operators reinstall both sides and re-pair. The old and new installations cannot
share trust state.

## Open decisions

1. **`auth` purpose.** `cli` is cleaner than reusing `authenticate`, but it adds a
   purpose to the policy vocabulary. Confirm.
2. **`connect` semantics.** Is `rba` allowed to dial out, or is it always
   device-initiated? The command must not promise more than the transport can do.
3. **Host platforms.** Is the daemon Linux-only for now, with a portable CLI, or
   is a second host platform in scope? The PAM/service commands are inherently
   platform-specific.
4. **ADB.** Transport only, provisioning only, or both? See
   [`adb-transport.md`](adb-transport.md).
5. **Multi-host/multi-device.** The README now says one or more devices and hosts.
   The current app keeps one host link at a time. Decide the model before the CLI
   grows commands that assume it.

## Isolated hardware-testing profile (B.3.7.4 candidate)

Use `rba --hardware-test configure --signer SHA256 --listen PRIVATE_IPV4`
with the verified debug APK signer and selected LAN address, then prefix
`start-server`, `status`, `pair`, `devices`, `auth` and `kill-server` with
`--hardware-test`. See [hardware-test workflow](B3_7_4_HARDWARE_TEST.md).
Default standalone state and trust are unchanged; actual device operations
require verified Android revocation status, even though startup does not.
