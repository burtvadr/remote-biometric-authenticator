# Versioning

Status: **policy**. This is how `rba` versions are assigned and what each bump is
allowed to break. It follows [SemVer](https://semver.org) with one product rule:
**from 1.0.0, upgrading never forces a re-pair** — any change that would
invalidate existing pairings ships with a migration.

Current state: product `0.1.0`, protocol `1`.

## Two numbers, not one

| Number | Where | What it versions |
|---|---|---|
| Product version | workspace `Cargo.toml`, Android `versionName`, `rba version` | the host + app release |
| Protocol version | `PROTOCOL_VERSION`, printed by `rba version` | the wire format and pairing transcript |

Authentication compatibility is a property of the **protocol version and the
trust-state format**, not the product MAJOR. A product release may bump MAJOR
while the protocol stays the same, or bump the protocol together with a
migration. Do not use the product MAJOR as the signal for a protocol break.

## Bump rules

| Bump | Meaning | May break pairing / auth? |
|---|---|---|
| `0.x.y` (current) | development | yes — re-pair / reinstall is expected |
| patch `0.1.1` | host-only fix; no protocol or trust-state change | no |
| minor `0.x.0` | feature or breaking change while `0.x` | yes |
| `1.0.0` | stable and security-audited | no; migration guaranteed from here |
| post-1.0 MAJOR | breaking CLI/API/platform, or a protocol generation | auth preserved via migration |

While `0.x`, anything may change — that is SemVer's initial-development rule, and
it is where the project is now. The rename and the per-device account binding
landed here and deliberately required a re-pair.

### Patch vs minor, concretely

- **Patch** (`0.1.1`): a host bug fix, CLI wording, docs, or a new non-breaking
  flag. The client APK does not need reinstalling and existing pairings keep
  working.
- **Minor** (`0.x.0`): anything that changes the wire protocol, the pairing
  transcript, the trust-state format, the Android application ID / signing key,
  or the PAM / control-socket integration such that the other side must be
  reinstalled or re-paired.

## The 1.0.0 gate

`1.0.0` means "safe to recommend for company and security-sensitive machines",
not merely "feature-complete". It requires:

- the security audit closed, with no open critical/high findings;
- a stable protocol and trust-state format;
- the migration guarantee below in force.

Until then the project stays `0.x` and says so.

## The migration guarantee (post-1.0)

From `1.0.0`, a release that would invalidate existing pairings must ship a
conversion path, so an operator upgrades without re-pairing. The version number
may still be MAJOR; the guarantee is that a migration exists, not that the number
stays small. This is a *migration* guarantee, not a promise that MAJOR never
changes — in SemVer, MAJOR is precisely the bump that may break compatibility.

Backwards compatibility means **migrating trust state forward**, not keeping an
old, weaker protocol alive forever. Prefer: migrate the data, require both sides
to move to the supported protocol within a stated window, and keep failing closed
on unsupported versions (`UNSUPPORTED_VERSION`).

## Compatibility surfaces

Every change is checked against what it actually breaks:

| Surface | Breaks when… | Consequence |
|---|---|---|
| Wire protocol / signing & pairing transcript | message format or transcript changes | old app cannot authenticate with new daemon |
| Trust-state format (registry, host key) | record layout changes | re-pair unless migrated |
| Android application ID / signing key | ID or key changes | reinstall + re-pair (Keystore is per-app) |
| PAM module / control-socket path | name or path changes | reinstall the integration |

A change that touches none of these is a patch. A change that touches one is at
least a minor while `0.x`, and needs a migration from `1.0.0`.
