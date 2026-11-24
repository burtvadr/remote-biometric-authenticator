# Authorization model — principal-scoped grants

The credential registry is host-local. Each registered credential has a set of exact `(principal, scope)` grants. A scope is `(purpose, service, operation)` with a typed operation. There is no independent user list, root flag, wildcard, deny record or automatic basic permission. An empty grant set denies every authentication request. This is a small allow-list policy, not a general-purpose ABAC/RBAC engine.

## Boundaries

| Concept | Representation |
|---|---|
| Principal | `PrincipalId`, a host-local canonical account identifier supplied by the trusted platform adapter. Linux currently uses NSS canonical account names; the local IPC boundary checks peer UID and target account. |
| Credential | Registry device ID, lifecycle status and public key. |
| Evidence | The existing signed request, verified for freshness, signature and exact context. |
| Authorization | `Grant`, `Scope`, `Operation`, `Denial` and pure `authz::evaluate`. Exact set membership decides whether a credential may authenticate that principal for that operation. |
| Assurance | Not independently attested. No assurance level is inferred from a valid signature (SEC-005 remains open). |

The Linux adapter establishes administrator authority using peer UID 0, not a username comparison inside the evaluator. A root-account grant is simply an exact grant to that account; it cannot authorize another account or another operation. RBA authenticates a principal for an operation; the OS makes the final access decision. The SEC-003 prompt budgets remain in session admission, not policy storage.

## Enrollment and policy management

Successful local, explicitly confirmed pairing writes exactly one initial grant for the selected canonical account, scope `authenticate/rba/authenticate`. Non-administrative callers may pair only for themselves. Administrators must explicitly name the target account. There is no `--allow-root` flag. To change grants, the privileged local control API requires a device, explicit target account and exact scope; ordinary callers cannot add or remove grants. `rba devices` displays relevant grants, filtered to the viewer's account for non-administrators. Unpairing shared credentials is administrator-only (the device's own revocation mechanism is independent).

Every authentication is checked before prompting and again before returning success, including a check of the currently registered key and lifecycle state. Removing a grant does not revoke unrelated grants. A change before the final registry check prevents success; the check is the linearization point. No new wire fields, cryptographic primitives, or external dependencies are introduced.

## Breaking change

Old policy objects are not accepted. No migration or fallback is provided. An incompatible registry fails to load rather than silently broadening trust. For development testing use fresh isolated state and re-pair both endpoints; do not reset a live authentication installation. The current host protocol is unchanged but the local administrative IPC and policy representation are deliberately incompatible.

## Remaining work

Canonical account names are not immutable across deletion/recreation or rename. Stable platform-specific account identifiers, trustworthy operation context, delegated authentication, pairing/replacement policy lifecycle, integration fixtures and concurrent in-flight mutation tests still require review. The containing daemon crate is not yet cross-platform. SEC-025 remains open until these concerns and compilation/runtime verification are addressed. SEC-026 and SEC-005 are out of scope.

References: [NIST SP 800-162](https://csrc.nist.gov/pubs/sp/800/162/upd2/final), [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html). These are principles, not prescriptions for Rust container types.
