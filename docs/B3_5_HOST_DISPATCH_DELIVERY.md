# B.3.5 — Host connection owner and operation dispatch

Status: isolated V2 host integration component for independent verification; no daemon cutover, no new dependencies, no portable-core extraction. Base is the original archive reconstructed through the delivered B.3.5 terminal patch; not a verified live GitHub HEAD.

## Implemented

- `v2_tls::dispatch` consumes each already authenticated/classified `Channel` for exactly one host-selected operation. The authority matches locally admitted authentication by owner, interaction, request, credential and connection. Routing and start run under one lock, with no await while holding the lock. Pairing routing checks the original local owner, admitted enrollment and classified connection. A second route cannot acquire a cancellation guard for an already-dispatched operation.
- Host authentication checks that its signing key is the actual TLS host key, dispatches only after a local display acknowledgement, reads the expected NUMBER_ENTRY and AUTH_RESPONSE in sequence, and processes bound CANCEL via the authority. It returns the successful local interaction event only after the existing transactional final authorization. The event carries the original wall and monotonic expiry. This is not a transferable authentication token or a wire message. The separate `ReceiptDelivery` enum reports whether the terminal network write completed; it must never be used to authorize an OS request.
- Host enrollment uses only the provisional TLS binding from the Channel, drives both code-entry directions, PAKE confirmation, attestation evidence, explicitly acknowledged context/replacement approval, staged commit and terminal receipt. It processes bound ENROLL_CANCEL and denies unexpected message types. No arbitrary verifier or policy result is accepted from a peer.
- Local UI interactions use a bounded one-slot mailbox, per-event one-shot replies, and the original authority deadline for every asynchronous operation. Disconnect, missing acknowledgement, wrong kind, cancellation, or timeout closes the operation; a drop guard invalidates the exact local owner after it has been routed. No local or remote secret is printed or logged. Unsent/uncertain remote receipt delivery does not roll back a committed operation.
- Peer-initiated dispatch is restricted to the existing authenticated ENROLL_STATUS or REVOKE transactions; it cannot originate an authentication or pairing. The committed revocation loopback now exercises this driver.

## Required B.4 integration contract

`LocalLink` is crate-internal and not IPC authentication. Only the trusted OS adapter may generate its unique owner and interaction IDs, create its dedicated receiver, admit the request, and select the channel. Never reuse an owner ID for another interaction or accept these IDs or verified source/detail from client content. The adapter must acknowledge display only after presentation to the owning interaction, and only return an authentication success event to the exact original still-live local caller, checking the original expiry again immediately before delivery. Drop the receiver and close the authority's local owner on any disconnect, including pre-routing failure. Keep it live until the operation driver has finished whenever the interaction remains live; remote terminal receipts are not guaranteed after socket loss. The adapter must not grant access based on the driver return value or on an audit record. Policy synchronization has its own state transitions and is intentionally not routed through these drivers. The existing active V1 runtime is not changed by this isolated component.

## Evidence

Executed independently: 679 standalone Kotlin fixture checks (JVM target 17 on JDK 21), exhaustive repertoire comparison, 8 host SQLite and 3 device SQLite tests, and two pinned-root checks. These are unchanged regression suites, not verification of the new Rust driver. Cargo/rustc unavailable. Added three mailbox/deadline tests and two real rustls authentication loopback tests (valid signed response and incorrect number, with no successful audit on rejection). Modified the existing committed revocation loopback to exercise the new peer terminal driver. All new Rust tests remain unexecuted. Full host enrollment over actual TLS with real Android hardware remains untested.

```
git apply --check rba-b3.5-host-dispatch.patch
git apply rba-b3.5-host-dispatch.patch
git diff --check
cargo test --manifest-path linux/Cargo.toml -p rbad --locked v2_tls::dispatch::tests
cargo test --manifest-path linux/Cargo.toml -p rbad --locked routed_auth_real_tls
cargo test --manifest-path linux/Cargo.toml -p rbad --locked v2_tls::tests
cargo test --manifest-path linux/Cargo.toml -p rbad --locked
cargo check --manifest-path linux/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path linux/Cargo.toml -p rbad --all-targets --locked
make vectors-kt
python3 protocol/tools/v2_store_tests.py
python3 protocol/tools/v2_device_store_tests.py
```

## Still open

Android connection owner, durable policy synchronization, authenticated Android revocation tombstones and recovery, exclusive-startup orphan alias reclamation, production listener/IPC routing, refresh worker, Android dependency/build and real device TLS/exporter/attestation verification, release signing. B.3.4 transport digest policy `{NONE,SHA-256}` remains a candidate awaiting owner approval; no policy change in this patch. Coverage analysis from B.2.5 remains open. No SEC closures or production cutover claimed.
