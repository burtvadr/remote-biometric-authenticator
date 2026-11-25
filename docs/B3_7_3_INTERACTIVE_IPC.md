# B.3.7.3 — Standalone interactive V2 IPC

Baseline: c8e33a500aba6574f630dd199d021260c17913f4. This change preserves the lifecycle drain fix and does not change Cargo.lock or dependencies. No privileged system configuration or deployment is enabled.

## CLI contract

- `rba pair` or `rba pair --code-entry device`: terminal displays the six-digit code.
- `rba pair --code-entry host`: terminal receives the six digits displayed by the phone.
- `rba auth`: select the sole non-revoked credential owned by the current UID. If there is more than one, use `rba auth --device ID` (full credential ID from `rba devices`). Selection alone never confers authorization; the existing V2 authority validates the exact self-CLI grant.
- Both commands autostart the existing server. If device trust is unconfigured they fail explicitly, while lifecycle and inventory still work. No dummy attestation, simulated result or legacy path is introduced.
- The interactive client requires a terminal. A user can cancel by interrupting the process; the original interaction's socket is closed. The daemon enforces the original deadline even if the operator is still entering text. A blocked terminal input may require Enter or Ctrl-C after expiration; no late decision can be used.
- Enrollment displays the actual bound enrollment address and all seven context/key/certificate SHA-256 values, the enrollment ID and exact replacement IDs. Type `yes` to enroll with the current-user CLI grant, `pair-only` to enroll without it, or anything else to cancel. Host commit is not proof of Android receipt delivery.

## Boundary

The dedicated `operation.sock` is owner-only, separate from the existing lifecycle socket. The daemon checks SO_PEERCRED through Tokio, the client checks SO_PEERCRED through libc, and both require the same effective UID. At most eight interactive tasks run at once. No process-supplied account name, UID, scope, provenance or interaction ID is accepted. Account name is resolved through NSS, using the kernel UID. Existing active principals must match the account name; disabled or renamed records are not reactivated. The store is standalone user-owned state, not a trusted OS account generation service; B.4 must implement system principal lifecycle verification separately. A principal is created only on pairing intent. This boundary must not be accepted by PAM, polkit, sudo or login services.

The local stream starts with `RBO2` followed by a message type and two-byte big-endian length (maximum 1024 bytes). Requests and decisions are bounded; fixed-size codes and context hashes are exact. Only one operation per socket, and no unsolicited client bytes while waiting for an event. The original mailbox is dropped on failure, timeout or disconnect and the local operation is invalidated by an authority-owned cancellation guard. The CLI sends display acknowledgments after flushing the terminal. The adapter receives only internal completion events, not success messages from the client or network, and keeps the mailbox alive until the terminal network write finishes. Local success does not carry a reusable authentication token. All tasks are joined on daemon shutdown.

The interactive socket is bound only once the existing strict attestation verifier has been installed. Device trust onboarding (actual debug signer, isolated hardware-test state and no privileged grants), network endpoint selection, system IPC, management/revocation commands and full physical interoperability remain later work. Default bind is still loopback; a phone cannot connect to that endpoint without a suitable explicit transport/configuration. Do not loosen the production verifier to test the UI.

## Verification

- `cargo test -p rbad --locked interaction_`
- `cargo test -p rba --locked`
- `cargo test -p rbad --locked`
- `cargo check --workspace --all-targets --locked`
- `cargo build -p rba --release --locked`

New adapter tests check framing, bounded review layout, disconnected and unsolicited input, completion only after display acknowledgment, rejection of skipped display, and standalone principal identity handling. New public binary integration test verifies automatic startup and denial with no trust. The tests that feed synthetic mailbox events validate the adapter only; they are not evidence of actual biometric authentication. Real device enrollment/authentication acceptance remains pending.
