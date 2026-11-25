# B.3.7.1 — Rootless bootstrap and unified lifecycle

The public CLI and lifecycle IPC are updated by [B.3.7.2](B3_7_2_CLI_LIFECYCLE.md). The bootstrap and storage rules below remain in force.

This supersedes the manual first-run provisioning procedure in B3_5_RUNTIME_CANDIDATE.md. The public `rba` executable and internal `rbad` artifact call the same V2 entry. No V1 CLI dispatch, legacy control socket, root escalation, system account creation, PAM changes or service installation occurs.

## Run as a normal user

```sh
cargo build --manifest-path linux/Cargo.toml -p rba --locked
linux/target/debug/rba
linux/target/debug/rba status
linux/target/debug/rba stop
```

`rba` or `rba start` connects to an existing daemon or spawns the current executable in a detached process. A private same-UID lifecycle socket provides status and stop only; it has no authentication/administration operation surface. The caller waits for readiness, not just process creation. The outer `daemon.lock` is held for the daemon lifetime (including bootstrap and shutdown); the inner SQLite `state.lock` still protects the database independently. Neither lock is unlinked on shutdown. The daemon's log is private. `rba stop` waits for the lock to become available. There is no PID-based signal dispatch.

Default path: `$XDG_DATA_HOME/rba/standalone-v2`, or `$HOME/.local/share/rba/standalone-v2`. No `/tmp` or system-state fallback. All path ancestors must be directories owned by root or the current user, with no group/world write; no symlinks. The state root and instance directories are owner-only 0700. Secret files and locks are 0600, single-link regular files. The state API verifies the effective owner's UID rather than requiring UID 0. For UID 0 the root-owned ancestor rule remains unchanged. Future privileged installation must enforce its own protected service identity and storage provenance and never adopt the ordinary user's state.

```
standalone-v2/
  daemon.lock
  daemon.log
  daemon.sock          # only while running; stale socket reclaimed under lock
  instance/
    candidate.json
    host-key.pk8
    host-cert.der
    state/
      state.lock
      state.sqlite3
```

First boot stages all material in `bootstrap.pending/`: CSPRNG 16-byte nonzero host ID, P-256 key and self-signed certificate through existing rcgen/ring dependency, and authoritative SQLite initialized through Store. Files and directories are synced; the complete validated tree is renamed to `instance/` before use. Normal subsequent runs validate the exact identity, certificate, schema, host binding, permissions and locks; no replacement or reset. Complete interrupted staging can be published on retry. Incomplete staging is preserved and requires diagnosis; it is not silently erased. Old explicitly provisioned candidate layouts are not automatically imported into this new layout. Use a separate fresh standalone directory. Existing state must not be deleted to make this test pass.

## Trust boundary and remaining work

Default `candidate.json` has `release_signer: null`, zero policy floors and loopback addresses. This means **unconfigured**, not permissive attestation. The fresh daemon opens only its local lifecycle socket, with no network listener or authority. It starts without DNS, Google status, release signer or production credentials. The strict `Policy::validate` and Android hardware-key verification are unchanged. If a real signer and valid strict floors are configured in the instance, the previous provision/revalidation gate still applies before opening TCP. A randomly generated signer cannot identify an APK. Zero floors and accepting software keys do not establish hardware assurance. An explicit isolated debug hardware-testing trust path (actual debug signer, distinct test state, no PAM authority, no fabricated Google status) remains to be implemented. B.4 trusted local operation IPC is also pending. No enrollment or authentication command is claimed operational in this patch; legacy CLI commands are disabled rather than dispatched to V1. No system installation is enabled.

Internal explicit path commands (`--initialize-candidate`, `--check-candidate`, `--run-candidate`) use the new directory layout; `--check-candidate` takes an existing exclusive lock and does not create state. For service manager integrations, run the internal foreground entry only after implementing the protected system runtime. Source templates and installer packaging are a later milestone.

## Verification

Run as a normal user with a non-symlink, owner-controlled HOME on a local filesystem:

```sh
cargo test --manifest-path linux/Cargo.toml -p rbad --locked candidate::
cargo test --manifest-path linux/Cargo.toml -p rba --locked
cargo test --manifest-path linux/Cargo.toml -p rbad --locked
cargo check --manifest-path linux/Cargo.toml --workspace --all-targets --locked
python3 protocol/tools/v2_candidate_entry_tests.py
python3 protocol/tools/v2_store_tests.py
python3 protocol/tools/v2_device_store_tests.py
```

New tests cover bootstrap persistence, exclusive lock, partial staging rejection, missing published certificate failure, two concurrent public launches, duplicate foreground rejection, status, stop and restart. No test establishes real Android interoperability. Production installation remains blocked. This delivery does not extract a portable core or add dependencies.
