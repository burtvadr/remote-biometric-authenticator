# Session admission (SEC-003)

This replaces the daemon's independent in-memory prompt budgets and periodic
best-effort persistence. It is an admission control component, not a new
credential policy or a new enrollment protocol.

## Invariants

- A pairing attempt consumes the existing per-local-peer budget (5/300 s).
- A connected authorized device's authentication attempt must satisfy all three
  limits: account (3/60 s), device (3/60 s), and selected transport (the existing
  protocol limits, Wi-Fi 30/60 s and BLE 15/120 s). No configured limit changes.
- One engine mutex serializes admission, including persistence. Denials do not
  consume another budget or extend any cooldown. Successful reservations are
  charged even if a later stage fails or a request cannot be dispatched.
- The admission clock is sampled while holding that mutex. A backwards clock
  jump relative to the last committed timestamp denies admission rather than
  discarding active budgets. A trustworthy system wall clock remains an assumption.
- In persistent deployments, the state is written, file-synced, atomically
  renamed and directory-synced before an admitted attempt can expose a challenge
  or pairing session. A failed write disables further admission in that process.
- The OS advisory lock excludes other updated daemon instances using the same
  admission directory. The state directory must be private and writable only by
  the daemon or trusted administrator; privileged state deletion is outside the
  threat model. The new store is not a distributed lock or multi-host budget.
- All five dimensions are restored on startup. Malformed snapshots, out-of-order
  timestamps, duplicate keys and mismatched configured limits fail closed.
- In-memory admission exists for tests and configuration-only checks, not normal
  persistent daemon bootstrap.

## State and deployment

The state lives at `ratelimits/admission-v1.state`, with an exclusive lock on
`ratelimits/admission.lock`. It contains only counters, encoded identifiers and
timestamps; it contains no challenge, private key, biometric or pairing secret.
The line-oriented format is deterministic and versioned. It does not introduce
another runtime JSON format. The obsolete `pairing.ratelimit` and
`auth.ratelimit` files are not loaded. The first run of this pre-release change
starts with a fresh admission window; stop the old daemon before upgrading.

The store is a Linux filesystem adapter. The budget algorithm and explicit-time
operations remain testable separately from the OS or transport. A future
portable core can move the storage adapter without changing admission semantics.
Synchronous durable writes serialize admitted requests; measure the latency on
supported storage rather than weakening durability to make a benchmark pass.

## Regression checks

- Account and device isolation across transports.
- Repeated denials do not grow the active event queue or delay recovery.
- All five budgets survive reopening the admission store.
- Transport rejection does not charge another budget.
- Concurrent requests share the same limit.
- Concurrent process-store access, corrupt snapshots, clock rollback and
  persistence errors deny admission.

Run from `linux/`: `cargo test -p rba-protocol ratelimit`,
`cargo test -p rbad admission`, `cargo test --workspace`,
`cargo fmt --all -- --check`, and `cargo clippy --workspace --all-targets -- -D warnings`.
The full daemon and phone integration suites must still be exercised.

## Scope boundary

This does not implement authentication number matching, trusted command/action
context, secure enrollment replacement (SEC-026), remote hardware attestation
(SEC-005), or stable OS principal identities and delegated authentication
(SEC-025). The existing principal/scope and cryptographic checks remain in place.
It does not replace network handshake limits or prevent all denial-of-service
scenarios. SEC-003 remains open until the outstanding intent and verification
requirements are met.
