# B.2.2 — Host V2 transactional persistence candidate

## Scope and baseline

This delivery is a Linux Rust storage component, not an active V2 authentication implementation. It is based on the original uploaded archive at `2b8e76d` plus the four delivered B.0, B.1, B.2.1 wire and message patches. The reported local B.2.0 archive/working tree was not provided; the delivered patch must be checked against the actual local baseline. No portable-core extraction, legacy state migration, temporary production trust path or JSON fallback is introduced. Existing V1 runtime is not wired to this module; remove V1 during the coordinated cutover. The B.1 docs in this reconstructed baseline still have historical portability requirements; the operator's later decision postpones extraction to Phase D.

## Implementation

`linux/rbad/src/v2_store/schema.sql` is the single schema source; `mod.rs` implements typed transactions via rusqlite. `tests.rs` includes ten Rust regression tests. `protocol/tools/v2_store_tests.py` uses the same SQL schema independently (not a Rust API test).

* One host store (schema/application ID 2/RBA2), STRICT tables, foreign keys, bounded rows, exact schema match and startup integrity/foreign-key/cross-table checks. Explicit offline initialize in an empty root-owned 0700 directory; regular single-link 0600 DB and lock; no symlink/unsafe ancestors, nonblocking exclusive flock; normal open never creates or resets. SQLite DELETE journal, synchronous EXTRA, no WAL or SHM accepted, two-second busy timeout and bounded page count. Initialization must precede placing other files in the state directory. A failed partial initialization is an explicit offline operator recovery case, not a reason to reset automatically.
* Opaque principal and generation IDs; unique active UID/name; explicit disabling with owned-credential revocation and removal of delegated grants. Account generation must be established by the future trusted OS lifecycle adapter; a new name/UID is not sufficient. Principal IDs are supplied by that adapter from a CSPRNG. The credential owner is its approver; explicitly approved delegation changes target, not the credential's represented approver.
* Two distinct valid P-256 public keys; cross-role historical key reuse denied. Atomic enrollment, old-token matched revocation, initial explicitly selected CLI self grant, receipt and offer hashes, and outbox. Certificate chains are bounded opaque evidence, not validated here; store does not claim attestation. Pending enrollments are owned by B.2.4 state machine, not durable active credentials; this table records committed enrollments only.
* Exact grant scope; increasing revision; digest uses existing V2 canonical transcript. Expansion requires an exact accepted digest from the future trusted same-channel consent handler. Removal needs no consent. No implicit scope or wildcard. The store does not verify that a supplied digest was authenticated; runtime must call only after proof validation. No success decision or transferable approval token is returned by storage.
* Revocation invalidates grants and increments revision. Exact key+token match for remote revocation; idempotent limited retry until 30 days, explicit cleanup removes token/pin authority while retaining bounded revoked identity/key history. Receipt recovery only for the active matching credential and receipt. Administrative revocation and principal disabling remain possible on clock rollback using the stored high-water timestamp. A full outbox or storage I/O failure must cause the runtime to fail closed, including disabling authentication if revocation cannot commit. Outbox is bounded and at-least-once; delivery and acknowledgement belong to B.4. Permanent key/identity history is intentionally bounded (4096 each), not automatically evicted; capacity exhaustion requires explicit offline operator decision and fresh enrollment if reset is chosen.
* Attestation evidence retained for revalidation; key assurance capped at 30 days, status snapshot at 24 hours from verified timestamp, status refresh cannot extend key assurance. Actual trust-chain/status validation belongs to B.3. Refresh caller must supply trusted evidence, never remote timestamps.
* Independent durable prompt and pairing reservations, exact rolling boundary, atomic multi-budget debit; persisted wall-clock high-water, no automatic clearing on restart. Limits: global prompts 6/60s, per target/credential 3/60s, elevated target/credential 1/60s, pairing global and per initiator 5/300s. Resource/ingress budgets, live ownership, monotonic deadlines and final transaction authorization remain B.2.3/B.2.4 requirements. Callers must not pass unverified identity or time. At the B.2.3 integration, consolidate budget definitions here rather than duplicating them.

## Dependency / environment decision

Pinned direct dependency `rusqlite = "=0.32.1"` (system SQLite, no extension-loading feature). It provides reviewed bindings including the no-follow open flag; requires maintained distribution SQLite >=3.37 for STRICT schema, and package security updates. CI installs `libsqlite3-dev`. Production must verify local supported filesystem and OS package patch policy. No cargo/rustc in this execution environment: `linux/Cargo.lock` is deliberately **unchanged**, not hand-fabricated. Generate and review the transitive lockfile in the actual Rust environment before `--locked` CI; the patch is not yet a compilable verified delivery until that is done. Run dependency/advisory and license review before acceptance.

## Verification and acceptance

Independent Python SQLite 3.46.1 tests pass (8/8), including atomic rollback, crash/reopen with and without commit, concurrent transaction reservation, audit failure rollback, scope/owner rejection, status freshness and UID uniqueness. These demonstrate the SQL behavior, not Rust bindings, privileged file opens, real power-loss durability, or hardware security. Ten Rust tests added, not run here. No SEC finding is marked resolved. No V2 runtime activation; all outstanding platform feasibility and Unicode profile requirements remain.

Commands at repository root after applying patch:

```sh
python3 protocol/tools/v2_store_tests.py
cd linux
# Resolve the new exact direct dependency using Cargo; review Cargo.lock diff.
cargo check -p rbad
cargo test -p rbad --locked v2_store::tests
cargo test -p rbad --locked
cargo check --workspace --all-targets --locked
cargo clippy -p rbad --all-targets --locked
```

Further acceptance: Rust compile and all tests on actual baseline, filesystem/permission/flock fault tests on target local disk, verify dependency/advisory review, run real power-loss/disk-full and outbox saturation tests, then integrate the verified store with the authenticated V2 state machine. Root/admin revocation must remain available or service must be disabled on persistence failure. SQLite cannot prove safety on arbitrary network filesystems, and no automatic rollback detection of malicious root-controlled database snapshots is claimed. Production initialization path and installation policy will be part of B.4. Preserve independent OS password recovery.
