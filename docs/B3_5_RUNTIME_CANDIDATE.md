# B.3.5 — Coordinated V2 source entry-point candidate

Status: source candidate, not production activation. This patch follows the
verified background-routing baseline (145 daemon tests and 745 Kotlin checks
reported by the independent reviewer). No release is installed and no active
OS authentication configuration is changed. `IMPLEMENTATION_V2.md` requires
B.5 acceptance before deployment; do not upgrade a live installation to this
candidate. Keep the independent OS password route available.

## Android composition

The source manifest now exposes only `.V2Launcher` (an alias targeting the
nonexported `V2OperatorActivity`), the nonexported notification-review activity,
and the nonexported V2 foreground listener service. No V1 application,
activity, service, boot receiver or V1 launcher is registered. No overlay,
full-screen intent, battery-optimization bypass, BLE, multicast discovery or
boot-resume permission is requested. No runtime protocol/version selector.
The V2 foreground runtime owns explicit store initialization, exclusive startup
reclamation and local operations. The existing notification handoff remains
one-shot and only connects the live operation to foreground UI. Use a fresh
installation; old icon alias state and V1 records are not migrated. The debug
package still has the `.debug` suffix and must not be trusted by production
attestation policy. Actual merged-manifest/SDK verification is still required.

## Host candidate composition

The `rbad` executable accepts only `--initialize-candidate`, `--check-candidate`
and `--run-candidate` with an absolute directory. Old CLI flags and old JSON
control socket are not started. Legacy library implementations are retained
for regression evidence until B.4 replaces the local adapters; no legacy
runtime fallback is reachable from this entry point. There is no unverified
network principal or simulator trust in normal builds.

The administrator provisions the following in a fresh root-owned 0700 absolute
candidate directory, with root-owned non-writable ancestors (not `/tmp`):

* `candidate.json` (0600): exactly the fields below; no duplicate/unknown
  fields, no zero host ID or signer. `bind` is the production TCP address,
  `enrollment_bind` a separate TCP address/port. Use explicit loopback or an
  isolated test LAN interface; no discovery, BLE or ADB runtime is activated.
* `host-key.pk8` (0600): DER PKCS#8 P-256 private key, generated and retained
  offline by the administrator. `host-cert.der` (0600): current, self-signed
  DER X.509 certificate for that same key. The loader derives the application
  signer from the exact TLS key and checks certificate agreement before startup.
  No automatic identity generation, substitution, or legacy key import.
* `state/` (0700, root-owned): empty for explicit initialization, then the
  existing authoritative SQLite state directory and lock. Missing or corrupt
  state fails closed; normal startup never recreates it.

Required JSON fields (values must be supplied by the administrator; these
are types, not usable default policy):

| Field | Type / format |
|---|---|
| host_id | 16-byte nonzero lowercase hex |
| bind | IP:port |
| enrollment_bind | IP:port, distinct nonzero port |
| release_signer | SHA-256 of actual Android release signer certificate DER, 32-byte lowercase hex |
| minimum_app_version | positive Android version code |
| minimum_os_version | Android attestation version, >= 90000 |
| minimum_os_patch | YYYYMM |
| minimum_vendor_patch | YYYYMMDD |
| minimum_boot_patch | YYYYMMDD |

`--initialize-candidate` creates SQLite only, after identity and policy checks.
`--check-candidate` validates local state and identity without networking; it
is not a release readiness check. `--run-candidate` opens and locks the exact
store, fetches fixed-origin Google status on a blocking worker, installs the
verifier and transactionally revalidates credentials before binding TCP. No
listener exists on initial provisioning failure. Refresh is scheduled before
expiry when possible, no faster than every 30 seconds. Failed retrieval does
not extend the prior window; authority maintenance denies access on expiry.
Failed verifier installation blocks access. A successful later refresh can
restore trust only via the existing verifier/revalidation path. There is no
persisted stale status fallback. The production listener has a bounded task set
of 32 connections; authority source/global quotas still apply. SIGINT/SIGTERM
stop acceptance and abort/join socket tasks. A blocking HTTPS fetch may take
its already bounded request timeout to finish during runtime shutdown.

Production classification routes authentication to the existing scheduler,
policy to a bounded credential-specific one-shot local route, recovery and
revocation to the existing authenticated peer-terminal driver. No other
purpose is accepted. Policy queue teardown removes expired/disconnected
owners; the original local deadline also caps the authority's offer deadline.
The enrollment driver binds its separate temporary socket only after an
explicit local pairing admission, accepts one connection, closes the listener
and uses the exact original pairing/owner. B.4 must supply the verified local
adapter (including identity generation, event delivery, cancellation and
original deadlines) to submit to these internal routes; the candidate binary
has no external local admission interface. Thus a fresh candidate cannot yet
enroll or authorize a new local interaction. A network request cannot fill
this gap. Policy acceptance is a typed local operation result, not auth proof.

## Deployment gates

Arch install, Debian configure, and new PAM enablement are explicitly blocked.
PAM rollback and uninstall paths are retained. Old live integration test scripts
fail explicitly rather than changing a system or falsely passing. `make verify`
now runs code and static checks only. Existing legacy systemd files and local
client sources must be replaced in B.4, not installed. No old protocol fallback
or V1 state migration is offered. Release signer provisioning, Android build,
physical tests and B.5 deployment/acceptance are still mandatory.

## Evidence

This delivery introduces four Rust tests: candidate exact IDs, refresh
scheduling, administrative queue ownership/pruning, and the original policy
deadline. They were not compiled or executed here (Cargo unavailable). Static
manifest/entry-point/install contract: 5 checks. Standalone Kotlin vectors:
745 checks plus exhaustive Unicode repertoire comparison. SQLite: 8 host + 8
device. Both official roots and independent message fixture generation checked.
Shell syntax checked. No Android SDK, Gradle, live Google status retrieval,
actual daemon startup, merged APK manifest, or physical device available here.
The static tests are not evidence that Android's merged manifest or real
service behavior has been verified. No production acceptance claim.

Independent verification: `cargo test -p rbad --locked` (expected 149 tests),
`cargo check --workspace --all-targets --locked`, `cargo clippy --workspace
--all-targets --locked`, `make vectors-kt`, `python3
protocol/tools/v2_candidate_entry_tests.py`, both SQLite scripts and Android
`:app:assembleDebug :app:assembleDebugAndroidTest :app:testDebugUnitTest
:app:lintDebug`. Inspect the merged manifest and candidate binary's rejected
legacy invocations. Do not run legacy live OS tests. B.3.6 release signing and
physical acceptance and B.4 local integration remain separate gates; B.2.5
coverage evidence also remains incomplete.
