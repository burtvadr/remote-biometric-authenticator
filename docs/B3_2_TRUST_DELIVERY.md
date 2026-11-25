# B.3.2 — Official Android trust provisioning and revocation refresh

Source candidate, not a deployment or a closed SEC-005 finding. This delivery builds on B.3.1 in the reconstructed repository. B.2.5 acceptance is independent and remains open. No portable-core extraction or V1 runtime activation.

## Decisions and security boundary

- The reviewed official Android root set is embedded as two PEM certificates. The DER SHA-256 pins are `cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc` (2022) and `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0` (2026 signing rollout). Both are from the current root section of the Android developer documentation. Root changes require a reviewed source/release update; never trust peer-supplied or automatically downloaded roots. The verifier retains the strict certificate-validity policy from B.3.1; older Android chains that depend on the official special-case legacy expiration guidance may be rejected. Actual target-device acceptance must establish whether the strict profile works; do not enable a generic expiry exception.
- `AndroidAttestationVerifier::provision` retrieves the status list only from `https://android.googleapis.com/attestation/status`. The HTTPS client uses the host's maintained native TLS trust store, hostname/certificate validation, TLS >= 1.2, no redirects or proxy, no automatic compression, bounded body (16 MiB), 5-second connect and 20-second total timeout. That HTTPS trust store does not serve as attestation roots. It sends no credential IDs, certificates or user data. Trust in the privileged host's CA configuration and clock remains an assumption. No unsigned cached file or caller-supplied timestamps become trusted input.
- Freshness requires HTTP 200, JSON, positive unambiguous `max-age`, a valid `Date`, and optionally `Age`. Cap at 24 hours; subtract age and transfer time conservatively. Missing, malformed, ambiguous, expired or uncacheable responses are denied. This is intentionally a narrow supported HTTP profile; verify the actual Google response headers on the target host. Wall and monotonic deadlines both apply. Do not reset the freshness interval when rereading cached data. Snapshots are memory-only; daemon startup must fetch anew. A fetch failure does not renew an existing snapshot. An already installed fresh snapshot can remain in use until its original deadline if a network fetch fails; after expiration no V2 authentication can succeed. A failed installation suspends V2 until a newer valid installation succeeds.
- The authority owns the concrete verifier. Normal builds start with no valid trust window and cannot process V2 auth/enrollment before installation. The former public `refresh_status(credential, at, until, now)` timestamp-only method is removed. Production enrollment evidence uses only the installed verifier, not a generic caller-provided implementation. Existing isolated synthetic test/fuzz code remains test-only. Snapshot publication cancels live requests, pairings and peer classifications; transport integration must close denied sockets. Check freshness at request processing, final auth transaction, and release of the result.
- Store revalidation uses both enrolled canonical chain records, exact stored keys and role-specific policy, current PKIX validity and status. Reading the original challenge from previously verified immutable signed evidence is **not new attestation**; never change `attested_at` or extend `assurance_until`. A credential with invalid evidence, expired original assurance, revoked chain or obsolete policy is revoked and needs explicit fresh enrollment. Revocation and grant deletion, status updates and audit events are atomic. Expired snapshot or SQL failure rolls back; authority stays suspended. Local administrator revocation and independent OS password recovery remain possible. No persistent status JSON, database migration or alternate verifier.

## Evidence and limitations

- Offline root script: both exact fingerprints match, both self-signatures verify with OpenSSL. This is a local consistency check, not a live authenticated download or proof of hardware compatibility.
- Existing synthetic PKIX fixture checks: 24/24 passed. Existing independent host/device SQLite tests: 11/11 passed. Neither exercises the new Rust refresh implementation.
- Eight new Rust tests: root pins, cache age/deadline, malformed headers, unchanged assurance lifetime, revocation/grant cleanup/no resurrection, SQL failure/suspension, policy and lifetime rejection, duplicate/stale snapshot rejection. All await Cargo execution. Existing synthetic enrollment tests now call a private internal verifier-injection path; production API no longer accepts it.
- Two exact direct dependency versions added: reqwest 0.12.28 (blocking/native-tls, default features disabled) and httpdate 1.0.3. No lockfile modification in this environment because Cargo/rustc are absent. Resolve and review the real Linux workspace lockfile, including advisory/license and MSRV checks. Do not overwrite local dependency changes from B.2.2 and B.3.1.
- Actual Google status endpoint unreachable here (DNS resolution fails). No live HTTP verification or real Android evidence. Real platform root/chain compatibility and revocation data validation remain mandatory. The worker/scheduler that fetches before deadline and publishes serially, trusted administrator configuration loading, runtime TLS integration and release-device testing are later B.3 work. `provision` is a blocking worker API; do not invoke it on Tokio's request loop. The normal authority will not operate before install, even if a previous database has unexpired status timestamps. It uses a single owner, and one worker should fetch at a time. This component is not yet wired into the production daemon.

## Verification

Apply to the actual working tree after B.3.1. Reconcile differences with local changes; no new GitHub commit is claimed. Execute:

```
python3 protocol/tools/v2_attestation_roots.py
python3 protocol/tools/v2_attestation_fixtures.py
python3 protocol/tools/v2_store_tests.py
python3 protocol/tools/v2_device_store_tests.py
cargo check --manifest-path linux/Cargo.toml -p rbad
# review Linux Cargo.lock before continuing
cargo test --manifest-path linux/Cargo.toml -p rbad --locked v2_store::attestation
cargo test --manifest-path linux/Cargo.toml -p rbad --locked
cargo check --manifest-path linux/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path linux/Cargo.toml -p rbad --all-targets --locked
```

Local live-origin test must exercise `AndroidAttestationVerifier::provision` on the actual Linux target with an administrator-selected valid policy, and establish that the authentic response is accepted, that freshness and timeout errors do not allow new authentication, and that no alternative origin or untrusted root is accepted. Do not perform live network requests in normal regression tests. Before release verify the root bundle against the official publication independently.

## References

- https://developer.android.com/privacy-and-security/security-key-attestation
- https://android.googleapis.com/attestation/status
- https://docs.rs/reqwest/0.12.28/reqwest/blocking/struct.ClientBuilder.html
- https://docs.rs/httpdate/1.0.3/httpdate/
