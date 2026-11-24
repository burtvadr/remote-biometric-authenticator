# Authorization model — Phase 1

## Boundaries

| Concept | Representation in this phase |
|---|---|
| Identity | Trusted local peer and requested account, resolved by IPC; borrowed principal ID in pure evaluator. Linux names remain the persisted identity namespace. |
| Credential | Registry device ID, status and public key; key is revalidated at completion. |
| Authentication evidence | Existing verifier checks the fresh signed request. No new wire fields. |
| Authorization | `authz::Scope`, `Operation`, `Principal`, and `Result<(), Denial>`; exact scope comparison, no wildcard grants. |
| Assurance | Not independently attested; no hardware assurance claim is inferred from a signature. SEC-005 remains open. |

Rate limits remain in the existing SEC-003 session admission path. The evaluator has no platform I/O and can be extracted when a real second platform requires it. The containing daemon crate is not portable yet.

## Lifecycle

The local adapter checks the caller; device selection filters account and scope; current credential and policy are checked before challenge dispatch. The existing replay and signature verifier remains unchanged. Before returning success, the engine locks the registry, rechecks policy and credential identity, and records success. The final check is the decision linearization point; later revocation cannot retroactively invalidate an already issued result.

## Migration and administration

The new field defaults to an empty list, preserving registered keys and existing account bindings, not implicit elevated permissions. Ordinary non-root `authenticate/rba/authenticate` remains available. Every other exact scope requires a grant; root also needs the existing `allow_root` opt-in. An existing PAM deployment must be reviewed and explicitly provisioned before switching to this version. Pairing does not grant privileged scopes. Re-pairing resets grants. The local control API adds a root-only scope mutation command, exposed by `grant-scope` and `remove-scope` with the existing device, purpose, service and operation flags. Scope grants are device-wide across its bound accounts. The ordinary CLI scope is intrinsic to a non-root account binding and cannot be removed through scope removal; revoke the credential instead. These commands do not grant OS-level privileges. The OS still owns its final authorization decision.

## Remaining requirements

SEC-025 stays open: platform identity normalization (including UID aliases and account reuse), trustworthy operation context from platform integrations rather than caller-supplied labels, delegated login and per-principal grants, integration compatibility and concurrency tests remain to be established. Do not use this candidate as a production PAM upgrade before verification. SEC-026 and SEC-005 are unchanged. SEC-003 persistence and unified admission remain outside this change.

## Verification

Static inspection only. Cargo metadata, tests, fmt and clippy were attempted but cargo is absent. No runtime or cross-platform build claims. Security test fixtures explicitly grant their existing test scope; production defaults are not widened to preserve fixtures. Existing shell integration tests need provisioning review.
