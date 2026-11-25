# B.3.7.2 — ADB-style lifecycle and authoritative inventory

This is the first implementation slice of B.3.7.2. It restores the public
standalone lifecycle and inventory on top of the existing V2 bootstrap. No
privilege elevation, legacy protocol, service manager or new dependency.

## Commands

- `rba`: auto-initialize/start the daemon and report readiness.
- `rba start-server`: start if necessary; `--foreground` runs the same engine
  attached to the terminal for diagnostics.
- `rba devices`: auto-initialize/start, then request the actual V2 SQLite
  inventory. Standard output is the header and exact credential IDs, state
  and policy revision, sorted by credential ID. A new empty database produces
  just the header. No device names are fabricated: the current schema does not
  store a display alias. `paired` denotes a non-revoked stored record, not a
  guarantee of current attestation, authorization or connectivity. `connected`
  means a classified active production link exists at the snapshot instant;
  it is not an authentication result. `revoked` denotes a durable tombstone.
- `rba status`: report readiness or stopped without starting a server.
- `rba kill-server`: request graceful shutdown and wait for the lifetime lock;
  no-op if already stopped. Never uses a PID file or sends arbitrary signals.
- `rba help` / `rba version`: no daemon startup, no files created.
- The B.3.7.1 `start` and `stop` spellings remain equivalent aliases.

The public executable spawns itself. Storage, identity and locks are unchanged.
Existing `daemon.sock` is reused only if the verified same-UID peer speaks the
current lifecycle protocol. Stop the previous development executable using its
own `stop` command before starting this build. An incompatible live socket
fails closed rather than being overwritten or causing a second daemon. Stale
refused sockets are removed only by the daemon holding its lifetime lock.

## IPC boundary

Each same-UID Unix stream accepts exactly one five-byte request: `RBL2` followed
by `S`, `X` or `D`. The client half-closes its write side; the server rejects
unknown or trailing bytes before executing a request. Replies carry `RBL2`, a
big-endian 32-bit payload length and a strictly typed JSON payload (maximum
512 KiB, at most 4096 inventory rows), followed by EOF. Both peers check OS
credentials. Requests cannot assert a UID. The SQL query filters by the
verified peer UID and returns only credential ID, revision and revocation;
the authority adds a live-link snapshot. Keys, certificates, tokens, policy
grants and secrets never appear in this response. The IPC endpoint does not
admit authentication or enrollment, change policy or authorize PAM.

## Verification

```sh
cargo test --manifest-path linux/Cargo.toml -p rbad --locked lifecycle_inventory
cargo test --manifest-path linux/Cargo.toml -p rbad --locked standalone_inventory
cargo test --manifest-path linux/Cargo.toml -p rba --locked
cargo test --manifest-path linux/Cargo.toml -p rbad --locked
cargo check --manifest-path linux/Cargo.toml --workspace --all-targets --locked
python3 protocol/tools/v2_candidate_entry_tests.py
python3 protocol/tools/v2_store_tests.py
python3 protocol/tools/v2_device_store_tests.py
```

Run the CLI integration tests as an ordinary Linux user with a private HOME
and a short enough Unix socket path. Tests include fresh and concurrent starts,
identity preservation, stale socket recovery, invalid live-peer protocol,
non-starting help/version/status/kill, and rejection of malformed stop
requests. Inventory unit tests use actual SQLite records with test-only
fixtures, including revocation and UID isolation; a maximum-sized response,
wrong type, duplicate ID, truncated response and trailing bytes are rejected.
The tests do not establish physical device interoperability.

## Remaining B.3.7.2 work

Interactive `pair`, `auth`, `unpair` and `revoke` need verified principal
binding and the existing connection-owned operation drivers; they are not
implemented by this read-only protocol. Isolated hardware-test trust still
needs to be integrated before phone enrollment can work out of the box. This
change does not alter Google status validation, attestation, hardware key
requirements, installation gates or privileged IPC. No portable-core extraction.
