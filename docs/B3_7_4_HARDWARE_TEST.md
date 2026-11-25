# B.3.7.4 — Isolated debug hardware testing (candidate)

Baseline: main at e17de80 (B.3.7.3). No V1 fallback, dependency changes,
production signing requirement, privileged installation, or portable-core extraction.

## Operator workflow

Normal `rba` remains zero-configuration and does not trust a debug signer.
For physical testing, build the existing debug APK. Use Android SDK's trusted
`apksigner verify --print-certs <path-to-app-debug.apk>` against the actual APK.
Check that verification succeeds and there is exactly one signer. Copy that
signer's certificate SHA-256 digest (64 lowercase hex characters). Do not use a
random digest, the APK file hash, or a fingerprint supplied by the phone.

Find the host's private IPv4 address on the trusted test LAN, e.g. with
`ip -4 addr show`. Use the address actually assigned to the host. Do not expose
these ports on public networks or through port forwarding.

```sh
rba --hardware-test kill-server
rba --hardware-test configure --signer "$APK_SIGNER_SHA256" --listen "$HOST_LAN_IPV4"
rba --hardware-test start-server
rba --hardware-test status
```

`APK_SIGNER_SHA256` and `HOST_LAN_IPV4` above stand for the independently
verified APK signer and selected local interface address; they are not secrets.
The configure operation is atomic and idempotent, requires a stopped test
instance, never opens a TCP listener, and preserves identity and database.
The signer cannot be changed by this command. A changed LAN address can be
configured with the same signer after stopping the test daemon. There is no
implicit trust promotion or signer rotation. No config-file editing is needed.

Once status reports `verified Android status; standalone CLI only`, run
`rba --hardware-test pair`. In the debug APK, select enrollment and enter
that host address and port 8766; follow the existing pairing-code and exact
fingerprint review. Explicitly approve a CLI grant if testing authentication.
After phone confirmation, select the enrolled credential and use the same host
address with port 8765 for the normal connection/background service. Run
`rba --hardware-test devices` and `rba --hardware-test auth` in a terminal.
Stop with `rba --hardware-test kill-server`. All test-profile commands use that
prefix. The plain `rba` commands continue to address their separate instance.

## Boundaries

- Separate owner-private root `$XDG_DATA_HOME/rba/hardware-test-v2`, or the
  corresponding HOME fallback. Independent host ID, key, certificate, database,
  daemon lock and sockets. `hardware_test` is an explicit settings marker;
  ordinary candidate loading rejects it, and test loading rejects ordinary state.
- Test policy pins the exact `io.github.burtvadr.rba.debug` package and digest.
  Debug application version floor 1, OS floor Android 9, patch floors 2018-08
  (vendor/boot 2018-08-01). These are compatibility floors, not production
  patch recommendations. Dates must still be present and valid. Hardware-backed
  keys, role separation, verified boot, locked bootloader, official roots,
  chain and challenge verification, per-operation biometrics remain mandatory.
- Only a selected RFC1918 IPv4 address, ports 8765/8766. No wildcard bind,
  discovery, firewall modification, relay, or automatic public exposure.
- Local lifecycle starts before the fixed-origin Google status fetch and remains
  responsive while fetching/retrying. TCP and operation IPC are not opened
  before initial verified status installation. Trust expiry continues to close
  authority access. No fabricated status or unchecked offline auth.
- The current runtime is standalone only. Test results are explicitly labelled;
  no PAM/system integration is enabled. A future privileged runtime must also
  reject test profiles and debug identities, including any attempted migration;
  do not treat owner-controlled state as a privileged security boundary.

## Verification / open gates

Run `cargo test -p rbad --locked hardware_test`, `cargo test -p rba --locked`,
`cargo test -p rbad --locked`, `cargo check --workspace --all-targets --locked`,
`cargo build -p rba --release --locked`. Run the independent entry-point and
SQLite checks. Then test local startup while DNS/Internet is unavailable;
verify no network/operation listener is active before trust and kill-server
remains responsive. Test the actual debug APK on the trusted LAN after a valid
status retrieval, including both pairing directions, rejection of the wrong
signer, cancellation, auth, restart, and test/normal inventory separation.

This patch does **not** implement offline hardware authentication without a
verified revocation snapshot, nor prove Android/Rust TLS interoperability.
The existing authority and schema encode authenticated status freshness as
an invariant. A genuinely offline proof-only test design needs an explicit
separate assurance model, not a synthetic empty status list. A fresh official
status response is needed for actual pairing/authentication here. No production
release preparation or security closure is implied.
