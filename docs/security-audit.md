# Security audit tracker — V2 acceptance register

**B.1 design only.** The following is the authoritative target acceptance register. Historical severity and findings are preserved below, unchanged except for this prefatory status boundary. A design decision is not remediation; prior fixes are not automatically inherited by a rewrite. B.0 evidence is in [PHASE_B0.md](PHASE_B0.md). Source baseline `2b8e76d` plus delivered B.0 patch. No new code, tests or device execution in B.1.

Close an item only with root cause, complete implementation, removal of obsolete paths, positive/negative regression tests, updated specification/threat model, exact revision/build evidence and physical/deployment evidence where required. Record reviewed residual risk separately; do not label it fixed. SEC-002 was a retracted claim, not a new vulnerability. Documentation-only corrections still require consistency and deployment evidence as applicable. All B.1 statuses below refer to target V2, not an assertion that every prior V1 fix failed.

| ID | Original finding | Status | Owner milestone | Required acceptance evidence |
|---|---|---|---|---|
| SEC-001 | Pairing code is not bound to the public keys | Superseded in V1 candidate; V2 open | B.2/B.3 | PAKE confirmation binds both keys, actual TLS certs/exporter; substitution and independent review. |
| SEC-002 | Pairing code was truncated to one HMAC byte | Historical retraction; prevent regression | B.2 | No SAS or one-byte comparison remains; six-digit random code, PAKE KAT and wrong-code rejection. |
| SEC-003 | Broad `common-auth` deployment creates an MFA-fatigue surface | Open | B.2/B.4/B.5 | Verified local intent, manual number matching, independent persistent prompt/ingress limits, scoped PAM; concurrent and physical tests. |
| SEC-004 | No device-to-Linux-user binding | V1 fix candidate; V2 open | B.2/B.4 | Cross-account and root-by-default denials, managed principal generation and trusted service mapping; live OS tests. |
| SEC-005 | No Android Key Attestation | Open | B.3 | Both keys remotely attested; path, challenge, security level, key auth, boot, app, patch, revocation and freshness negative tests on release device. |
| SEC-006 | PAM client does not verify the control-socket server | V1 fix candidate; V2 open | B.4 | Mutual local peer identity, protected socket path, reject fake daemon and production override; deployment tests. |
| SEC-007 | Network-exposed daemon hardening | Open | B.2/B.3/B.5 | mTLS, pre-auth caps, bind restrictions, deadlines, parser fuzz and resource load tests; no permanent permissive enrollment listener. |
| SEC-008 | Android assurance and release build | Open | B.3/B.5 | Verified non-debuggable release APK, signing digest, hardware and negative tests on supported phone; record device/OS/build. |
| SEC-009 | PAM module robustness | Open | B.4 | Release panic containment actually effective (no abort reliance), FFI safety, bounded I/O, actual PAM recovery and panic tests. |
| SEC-010 | Timing can reveal whether an account has a paired device | Needs measurement | B.3/B.5 | No pre-auth account oracle; compare authorized/unauthorized paths, characterize residual traffic and timing exposure. |
| SEC-011 | Pairing race and display identity | Open | B.3 | Actual peer fingerprints and explicit consent in both directions, substitution/race and wrong peer UI tests. |
| SEC-012 | `--code` is visible in process arguments | Removed in V1 source; V2 verify | B.3/B.4 | No argv code, secret logs or clipboard exposure; CLI rejection, process listing and log capture using dummy data. |
| SEC-013 | Recommended PAM line includes `debug` | Historical docs fix; deploy verify | B.4 | No debug in production examples or installed PAM; configuration and log inspection. |
| SEC-014 | Auth response is not bound to the TLS session | Open | B.2/B.3 | RFC 9266 exporter, session/request IDs and context in signatures; cross-channel replay/substitution rejection. |
| SEC-015 | mDNS metadata and tracking | Needs measurement | B.3/B.5 | Generic opt-in discovery, no stable key/account IDs; packet capture across restarts; residual address linkability documented. |
| SEC-016 | PAM integration docs assume Debian-style `common-auth` | Historical docs fix; deploy verify | B.4 | Distro-specific scoped overrides; no broad common-auth/system-auth edits; installation review. |
| SEC-017 | Host key path differs between documents | Design reconciled; runtime open | B.4 | Single root-only host key path /var/lib/rba/v2/; actual permissions and path tests; no legacy fallback. |
| SEC-018 | `expires_at` skew wording contradicts the formula | Design reconciled; runtime open | B.2 | Exact expiry formula, no post-expiry skew; equality, overflow, rollback and monotonic deadlines tested. |
| SEC-019 | Test counts in the review are outdated | Historical docs correction | B.5 | CI-generated counts with revision and evidence; no stale fixed success counts. |
| SEC-020 | Confusing PAM rollback lines | Historical docs fix; deploy verify | B.4 | One documented rollback path per integration; independent password/root recovery tested. |
| SEC-021 | Control-socket request limit was checked after a full read | V1 fix candidate; V2 open | B.2/B.4 | Bound IPC header before body read, frame and queue limits, malformed/oversize tests and fuzz. |
| SEC-022 | Authentication timeout was caller-controlled and unbounded | V1 fix candidate; V2 open | B.2/B.4 | Bound caller timeout, absolute monotonic deadline across all stages; stalled peer and overflow tests. |
| SEC-023 | Biometric approval showed an unsigned host name | V1 fix candidate; V2 open | B.2/B.3 | Immutable signed host/principal/operation and proven context source; physical UI and mutation tests. |
| SEC-024 | Wi-Fi listener had no connection or handshake deadline | V1 fix candidate; V2 open | B.3 | Bound connection count, handshake/frame/idle deadlines and explicit interface bind; live resource and fault tests. |
| SEC-025 | Operation-specific authorization (Phase 1 candidate) | Open; V1 implementation candidate | B.2/B.4 | Exact grants, delegated approval, managed identity lifecycle, policy intersection, revision races, commit-time recheck and runtime tests. |
| SEC-026 | portable SPAKE2 candidate (not integrated) | Open; V1 integration candidate | B.2/B.3 | RFC 9382 KAT + reviewed application profile, both directions, fresh attestation, atomic staging/commit/status, cancellation/replay/fault and physical tests. |

## Additional design risks (not numbered reproduced findings)

- V2-D1: NSS has no universal immutable account generation. Require managed lifecycle integration and test it before enabling OS authentication.
- V2-D2: Android TLS exporter and unattended hardware Keystore transport signing need a real native bridge feasibility test; no unauthenticated substitute.
- V2-D3: PAM may not expose authenticated exact action context or a usable local number display. Disable unsupported scopes, retain roadmap objective and design a supported integration.
- V2-D4: distributed enrollment receipt loss is not atomic across devices. Verify status recovery and no pending-device authentication.
- V2-D5: Android attestation proves creation-time properties, not continuous OS/UI integrity. Verify freshness/revocation policy and document residual risk.
- V2-D6: SQLite durability, host state permissions and release-mode PAM panic policy require deployment and fault tests.

## Historical tracker (V1 and B.0)

Everything below is retained as original review history, including old “Resolved” labels and superseded paths/algorithms. It is not normative for V2. Use the acceptance register above for decisions.

# Security audit tracker

This is a living tracker for design, protocol and implementation findings. It is
**not** a substitute for a line-by-line code audit. Statuses marked *Needs
verification* depend on code paths or deployment details that were not exercised
when the finding was first written.

- Current tree when this tracker was created: `8e58acb`
- Review provenance: external design/spec review, 2026-11-18; second source
  review, 2026-11-18 (SEC-001 remediation and SEC-021–SEC-024)
- Runtime context: one physical Android device (Motorola Edge 30 Ultra), debug
  APK, Arch Linux host
- New findings are welcome. Use the template at the end and continue the `SEC-`
  numbering. If a finding is a duplicate, keep it and mark `Duplicate of
  SEC-xxx`; do not delete it.

## Status and severity

| Status | Meaning |
|---|---|
| `Confirmed` | Reproduced in the current design or source tree. |
| `Partly confirmed` | The core issue is evidenced, but one or more sub-claims or deployment details remain unverified. |
| `Resolved` | Fixed in the current tree; evidence is recorded below. |
| `Needs verification` | Plausible, but depends on a code path, platform behaviour, or deployment detail not yet checked. |
| `Accepted risk` | Known and deliberately accepted; rationale recorded. |
| `Duplicate` | Same issue as another finding. |

| Severity | Meaning |
|---|---|
| `High` | Can defeat authentication, grant the wrong principal, or break the trust model. |
| `Medium` | Meaningfully weakens a security property, or needs defence in depth. |
| `Low` | Hardening, privacy, usability or documentation issue. |

## Summary

B.0 source review: see [B.0 audit and verification](PHASE_B0.md) for the actual
snapshot identity, all 26 finding dispositions, verification boundaries, and
remaining release gates. Historical observations below are retained as review
history; they are not all descriptions of the current tree.

### High

| ID | Finding | Status |
|---|---|---|
| SEC-001 | Pairing code is not bound to the public keys; an on-path attacker can substitute keys | Resolved |
| SEC-002 | Pairing code was truncated to one HMAC byte, leaving only 256 values | Resolved (review retracted) |
| SEC-003 | Broad `common-auth` deployment plus no per-request context creates an MFA-fatigue surface | Confirmed — partially remediated |
| SEC-004 | No device-to-Linux-user binding; a paired device can approve another account's PAM request | Resolved |

### Medium

| ID | Finding | Status |
|---|---|---|
| SEC-005 | No Android Key Attestation; the host cannot distinguish hardware-backed from software keys | Confirmed |
| SEC-006 | PAM client does not verify the control-socket server; socket path can be overridden | Resolved |
| SEC-007 | Network-exposed daemon: no mTLS, no parser fuzzing; connection/deadline/bind gaps now fixed | Partly resolved (persistent rate limits) |
| SEC-008 | Android assurance gaps: no release-signed build; validation is one debug device | Partly confirmed |
| SEC-009 | PAM module robustness: no `catch_unwind`, FFI `unsafe`, blocking I/O | Resolved (catch_unwind) |
| SEC-021 | Control-socket size limit is checked after an unbounded `read_line` | Resolved |
| SEC-022 | Caller-controlled authentication timeout is unbounded | Resolved |
| SEC-023 | Biometric prompt shows unsigned host name and hides signed operation context | Resolved |
| SEC-024 | Network listener lacks connection/handshake/frame deadlines and wide default bind | Resolved in tree |
| SEC-025 | Operation-specific authorization | Open — implementation candidate |
| SEC-026 | SPAKE2 enrollment | Open — integration candidate |

### Low

| ID | Finding | Status |
|---|---|---|
| SEC-010 | Timing can reveal whether an account has a paired device | Needs verification |
| SEC-011 | Pairing race: operator sees only a device name, not key fingerprint/source | Confirmed |
| SEC-012 | `rba --code` is visible in `argv` | Removed in source; runtime regression pending |
| SEC-013 | Recommended PAM sample includes `debug` | Resolved |
| SEC-014 | Authentication signature is not bound to the TLS session | Confirmed |
| SEC-015 | mDNS exposes stable host metadata; linkability/privacy | Needs verification |
| SEC-016 | PAM integration docs assume Debian-style `common-auth` | Resolved |

### Documentation and consistency

| ID | Finding | Status |
|---|---|---|
| SEC-017 | Host key path differs between threat model and specification | Confirmed |
| SEC-018 | Spec says `expires_at` is not extended by skew, then the formula extends it | Confirmed |
| SEC-019 | Test counts in the review's README excerpt are outdated | Resolved |
| SEC-020 | Two different rollback lines in the PAM section are confusing | Resolved |

---

## High

### SEC-001 — Pairing code is not bound to the public keys

**Severity:** High  
**Status:** Resolved  
**Resolved in:** `d357f26`  
**Source:** external review, 2026-11-18  
**Aliases:** pairing MITM, key substitution, code-vs-key binding  
**Affected:** `protocol/specification/PROTOCOL.md` §6.0/§6.4,
`linux/protocol/src/pairing.rs`, `linux/rbad/src/engine.rs`

**Observation.** The displayed code is derived from `session_id` and the two
nonces only. It does not include either public key. Both nonces are visible to an
on-path attacker during the two-round exchange. The confirmation MACs are HMACs
keyed by the same derived secret, but that secret is known to the attacker once it
has seen both nonces.

The attacker can therefore relay the exchange while substituting its own host key
to the device and its own device key to the host. It can compute
`device_mac`/`host_mac` for the substituted transcript, while the code on both
screens still matches. If the operator confirms, the device stores the attacker's
host key and the host stores the attacker's device key. The attacker can then
authenticate as the requested user.

The review's "choose a nonce until the host code matches" variant is one way to
describe the same weakness. The stronger description is that the attacker does
not need to brute-force anything: it can derive the MAC key directly from the two
observed nonces.

A pre-selected `--code` is not a complete fix as currently designed. It is sent
in `PAIRING_START`, and an on-path attacker can read it and still substitute keys
with valid MACs. Treating `--code` as the only mode would not close the issue by
itself.

**Impact.** Complete pairing MITM: an attacker can become the trusted host and be
trusted as the device, defeating the authentication model.

**Recommendation.**

1. Bind the public keys and the mode into the value that produces the displayed
   code: for example derive `p` from a transcript containing
   `host_id`, `device_id`, `host_pubkey`, `device_pubkey`, `session_id`, the
   nonces and `code_entry`.
2. Prefer **commit-then-reveal** for the nonces, so neither side can choose its
   nonce after seeing the other's; or use a real PAKE (SPAKE2/CPace).
3. Keep the reciprocal MACs, but make the displayed code cover the same
   key-bearing transcript as the MACs.
4. Update the vectors and add a regression test where a middle party substitutes
   both keys and the resulting codes/MACs must not verify.

**Evidence (pre-fix).** The old code derived `p` from `confirmation_key()` over
`session_id`, then `code_from_material(&p)`. The key-bearing transcript was used
only for the MACs, not the code. The specification's old §6.4 construction
matched this.

**Remediation.** The pairing secret is now an ephemeral P-256 ECDH shared secret.
`PAIRING_START` carries `host_eph_pubkey`, `PAIRING_SUBMIT` carries
`device_eph_pubkey`, and both endpoints derive:

```text
transcript = session_id || host_id || device_id || host_pubkey || device_pubkey
          || host_nonce || device_nonce || host_eph_pubkey || device_eph_pubkey
          || code_entry_byte
pairing_secret = HKDF(ECDH_X, "RBA-PAIR-SALT-V1",
                      "RBA-PAIR-TRANSCRIPT-V2" || transcript)
p = HMAC(pairing_secret, "RBA-PAIR-V1" || 0x00 || transcript)
```

The transcript also includes the `code_entry` mode byte (`0` = device types,
`1` = host types). The code, `device_mac` and `host_mac` all cover that transcript. Substituting
either endpoint's long-term or ephemeral key changes the ECDH result and the
transcript, so the two endpoints derive different codes and MACs. Both ephemeral
private keys are zeroized after derivation. `PairingSession::checked_transcript`
refuses to MAC a transcript other than the one the secret was bound to.

**Regression tests.**

- `linux/protocol/src/pairing.rs::man_in_the_middle_cannot_make_both_codes_match`
  terminates the exchange on both sides with substituted keys and asserts the
  host and device codes differ.
- `::code_is_bound_to_the_public_keys` changes only the device key and asserts the
  code changes.
- `::host_ephemeral_key_is_fresh_per_session` asserts a new ECDH key per attempt.
- `::code_is_bound_to_the_code_entry_mode` asserts flipping who types the code
  changes the verification value.
- `::code_changes_with_the_device_nonce`, `::macs_verify_and_detect_substitution`.
- `host_entry_mode_requires_the_correct_code_before_persisting` now asserts a
  wrong code cancels the session and a retry is refused.
- The Kotlin device side reproduces the Rust code and MACs through the shared
  vectors (`make vectors-kt`), including the new ephemeral keys.

**Residual risk.** The six-digit code is a short SAS, so an active attacker can
try to find two ephemeral keys whose codes collide (about `2^20` work per live
session). Pairing is single-use, time-limited and rate-limited; a reviewed PAKE
would remove the grinding bound and remains the stronger long-term option.

---

### SEC-002 — Pairing code was truncated to one HMAC byte

**Severity:** High  
**Status:** Resolved  
**Source:** external review, 2026-11-18  
**Aliases:** 256-code bug, `000040` sample  
**Affected:** `linux/protocol/src/pairing.rs`,
`android/protocol/src/main/kotlin/com/rba/protocol/Messages.kt`,
`protocol/specification/PROTOCOL.md` §6.4

**Observation.** The old implementation reduced `p[0]` (one byte) modulo
`1_000_000`, so only `000000`–`000255` were possible. `000040` in the README was
not evidence of a real six-digit distribution.

**Impact.** The pairing code had 8 bits of entropy instead of ~20; an attacker
needed at most 256 guesses, not 1,000,000.

**Current state.** The code now uses rejection sampling over 32-bit words from the
HMAC, with a deterministic HMAC expansion if every word is rejected. The
specification and both implementations use the same algorithm. The same reviewer
retracted this preliminary finding after checking current `main`: the `p[0]`
excerpt described an older tree. It is retained here as resubmission history, not
as an open vulnerability.

The code is now also bound to the keys via SEC-001, so uniformity and key binding
are both addressed.

**Evidence.** `code_from_material` in `linux/protocol/src/pairing.rs`; the
Kotlin `PairingSession.code()` mirrors it; vectors were regenerated.

---

### SEC-003 — Broad `common-auth` deployment creates an MFA-fatigue surface

**Current implementation candidate (snapshot `2583bbf`):** A single admission
transaction checks account, device and transport budgets before dispatch. All
five counters (including pairing, Wi-Fi and BLE) are persisted together before
an admitted request can create a session or expose a challenge. The old
periodic/shutdown save paths are removed. Corrupt state prevents daemon startup;
write failures prevent further admission, and a second daemon cannot share the
admission store concurrently. Limits are unchanged. See
[`SESSION_ADMISSION.md`](SESSION_ADMISSION.md) for guarantees and tests. Number
matching, trusted transaction context and Rust/runtime verification remain open.
SEC-003 must not be closed on this change alone.

**Severity:** High  
**Status:** Confirmed  
**Source:** external review, 2026-11-18  
**Aliases:** MFA fatigue, PAM scope, `sufficient` weakness  
**Affected:** `README.md` PAM section, `linux/pam-rba/src/lib.rs`,
`linux/rbad/src/engine.rs`, `protocol/specification/PROTOCOL.md` §8.1

**Observation.** The recommended line is `auth sufficient
pam_rba.so purpose=auth debug` in `common-auth`. That file is included by
`sudo`, `sudo-i`, `login`, `su`, `sshd`, `gdm-password` and the `other` fallback
on Debian-style systems. Any service that can trigger PAM can therefore trigger a
device prompt.

The signed request context contains `username`, `purpose`, `service` and
`operation`, but no TTY, PID, command line, or requesting executable.
`display_detail` is explicitly unsigned. The system prompt can therefore look
identical for a benign `sudo` and a malicious trigger.

There is no number matching for authentication (the code-entry gate is pairing
only). The rate limiter is shared per transport, not per target user, and resets
on daemon restart. An attacker with a way to trigger PAM can produce repeated
prompts without a per-user budget.

`sufficient` means the device path can bypass the password. The effective
authentication strength is therefore the weaker of the password and device
factors, not a strict combination.

**Impact.** Prompt fatigue/social engineering can turn one accidental approval into
root or another account. Remote `sshd` attempts and local `su victim` are both
prompt-triggering surfaces.

**Recommendation.**

- Do not recommend a global `common-auth` line by default. Scope the module to
  `polkit-1` and screen unlock; leave `sudo`, `sshd`, `su`, `login` and
  `gdm-fingerprint` unchanged.
- Add number matching for authentication requests, not only pairing.
- Include service, TTY and, where safe, command/operation context in the signed
  scope or at least in the prompt.
- Rate-limit per target user and per device; keep the limiter across restarts.
- For root/high-risk operations, consider `required` password plus device rather
  than `sufficient` device-or-password.

**Evidence.** README PAM sample; `AuthRequest::signedCore()` and §8.1 field table;
`Engine::rate_auth` is keyed by transport and is in-memory.

**Partial remediation (docs).** The README no longer recommends a global
`common-auth` or `sudo` line: it uses scoped `gdm-password` and `polkit-1`
overrides, explains that `sufficient` is password **or** device rather than MFA,
and warns about prompt scope. Number matching, per-user/device rate limits and more signed
context are still open; this remains a real fatigue surface wherever a broad
stack is enabled.

---

### SEC-004 — No device-to-Linux-user binding

**Severity:** High  
**Status:** Resolved  
**Source:** external review, 2026-11-18  
**Aliases:** authorization scope, `su root`, per-user policy  
**Affected:** `linux/rbad/src/registry.rs`,
`linux/rbad/src/engine.rs`, `linux/rbad/src/ipc.rs`,
`protocol/specification/PROTOCOL.md` §11.3

**Observation.** Pairing stores a device identity and public key. It does not store
which Linux account(s) that device may authenticate. The daemon accepts an
`authenticate` request for any `username`; the control-socket rule allows root
(PAM) to ask on behalf of any user. The device itself is only checked for a valid
signature over the requested context.

A paired device is therefore a host-wide authenticator, not a per-account one. If a
user can cause a PAM request for another account (for example `su victim`), their
paired device can approve it. Root is not denied by default.

**Impact.** On a multi-user host, one device can become an approval oracle for
accounts it was never paired to. The signed `username` protects against a relay
changing the name, not against the device being authorised for the wrong account.

**Recommendation.**

- Bind each device record to an allow-list of Linux usernames or UIDs at pairing
  time; default to the pairing user only.
- Deny `root` by default unless the host operator explicitly opts in.
- Expose the binding in `rba devices` and the device's host details.
- Add a test where device A is paired for user alice and a request for bob is
  refused, even though the signature is valid.
- If a host-wide device is intentional, document it as a deliberate policy and
  make it an explicit option.

**Evidence.** `DeviceRecord` has `device_id`, `name`, `public_key`, timestamps and
status; no username/UID field. `authorize_caller` allows peer UID 0 to request any
username. The engine dispatches the requested username after signature
verification, without a per-device policy check.

**Remediation.** Every `DeviceRecord` now carries a `DevicePolicy`: an allow-list
of Linux usernames plus an explicit `allow_root` flag. Pairing binds the device to
the local principal that opened the session (`rba pair` defaults to the invoking
user; root must pass `--owner USER`, and root authentication additionally requires
`--allow-root`). `Engine::resolve_device` and `resolve_authenticating_for` enforce
the binding before any challenge is issued, so a device paired for alice is
refused for bob or root even when root is the caller and the signature would be
valid. A record written before the policy existed deserialises to deny-all, so an
upgrade forces a re-pair rather than silently widening trust. The binding is shown
by `rba devices` (`users:` / `root:`). Tests:
`a_device_paired_for_alice_cannot_authenticate_bob`,
`a_device_paired_for_alice_cannot_authenticate_root_by_default`,
`a_device_explicitly_allowed_can_authenticate_root`, and the registry policy tests.

---

## Medium

### SEC-005 — No Android Key Attestation

**Severity:** Medium  
**Status:** Confirmed  
**Source:** external review, 2026-11-18  
**Aliases:** attestation, hardware-backed key, emulator  
**Affected:** `linux/rbad/src/engine.rs` pairing,
`android/app/src/main/kotlin/com/rba/keystore/DeviceAuthKey.kt`,
`protocol/specification/PROTOCOL.md` §6.2

**Observation.** The host accepts `device_pubkey` after the pairing MAC verifies.
There is no Android Key Attestation certificate chain, no verified boot state, no
verified security level, and no proof that the key is hardware-backed or
biometric-gated. The app inspects its own key location and refuses software keys
for policy, but that is a local claim.

**Impact.** A rooted device, a rogue app, an emulator, or a software Keystore can
present a key that the host treats the same as a StrongBox/TEE key. The
"biometric-gated" guarantee is only as strong as the device's software.

**Recommendation.** Add optional attestation during pairing: a fresh host nonce
inside the attestation challenge, verify the chain to the expected root, record
the security level and verified-boot state, and publish the policy. If attestation
is unavailable, make the downgrade explicit rather than silent.

---

### SEC-006 — PAM client does not verify the control-socket server

**Severity:** Medium  
**Status:** Resolved  
**Source:** external review, 2026-11-18  
**Aliases:** IPC trust, socket impersonation, `RBA_SOCKET`  
**Affected:** `linux/rbad/src/ipc.rs`,
`linux/pam-rba/src/lib.rs`, `linux/systemd/rbad.service`

**Observation.** The server checks `SO_PEERCRED` for incoming clients. The **client**
side (`ipc::call`) simply connects to a Unix socket and trusts the JSON reply. It
does not verify the server's UID/GID or that the socket is the expected root-owned
path. `default_socket()` honours `RBA_SOCKET`, so the PAM stack's
environment can redirect the module. The quick start uses `/tmp/...` paths.

The control socket is mode `0666` (any local user may connect; each request is
authorised from `SO_PEERCRED` and the device policy). Impersonation is limited by
the runtime directory `/run/rba`, which systemd creates owned by the `rba` service
account, so an unprivileged process cannot replace the socket file. That does not
make the client's trust explicit or protect against an `RBA_SOCKET` override.

**Impact.** A process able to place a socket at the configured path (or influence
the PAM environment) could answer "authenticated" and bypass the real daemon.
This is defence in depth, not the primary authentication check, but it is part of
the trust boundary.

**Recommendation.** On the client, check `SO_PEERCRED` of the connected server and
require the expected daemon UID (root or `rba`). Prefer a fixed compiled
path for production; keep `RBA_SOCKET` strictly for tests. Verify the
socket file owner/mode before connecting, and add a test with a fake socket.

**Remediation.** `ipc::call` now calls `verify_server_peer` after connecting,
which checks `SO_PEERCRED` against root, the `rba` service account, or the
current user (for dev/test). The PAM module uses `production_socket()`, which
ignores `RBA_SOCKET` entirely and always returns the compiled default path.
`rba` CLI and polkit-agent still honour `RBA_SOCKET` for testing.

---

### SEC-007 — Network-exposed daemon hardening

**Severity:** Medium  
**Status:** Partly confirmed  
**Source:** external review, 2026-11-18  
**Aliases:** mTLS, fuzzing, bind, rate limiter  
**Affected:** `linux/rbad/src/tls.rs`,
`linux/rbad/src/server.rs`, `linux/rbad/src/transport/wifi.rs`,
`linux/rbad/src/engine.rs`, `linux/rbad/src/config.rs`,
`linux/systemd/rbad.service`

**Confirmed observations.**

- The TLS server uses `WebPkiClientVerifier::no_client_auth()`. There is no mTLS;
  the device authenticates the host certificate by pinning, but the host does not
  authenticate the device at TLS. Protocol frames are parsed before any
  device-level signature check; the session/hello and pairing frames are expected
  to arrive first.
- **Fixed:** the default `Config` now binds `127.0.0.1:47123`. The systemd unit
  passes `--bind 0.0.0.0:47123` explicitly because a device on the LAN needs it;
  that is an operator/deployment choice, not a library default.
- The auth rate limiter is an in-memory `RateLimiter` per transport, not per
  source address, target user, or device; it resets on restart. The review's
  "per source address" description is inaccurate for the current code, but the
  reset and shared-scope concerns are real.
- **Fixed:** the Wi-Fi listener now has a 64-connection semaphore, a 10 s TLS
  handshake deadline, a 15 s session-setup deadline and a 180 s idle frame
  deadline. The control socket has a 32-connection cap and 10 s read/write
  deadlines (SEC-021).
- No fuzz target for the frame/CBOR parser was found. The parser has extensive
  conformance/rejection tests, but that is not fuzzing.

**Impact.** An unauthenticated network peer can consume connections/handshake
resources; a production bind exposes the port on every interface; a restart
clears rate-limit state. Protocol authentication still fails closed, but
availability and defence in depth are weaker than the design claims.

**Remediation (partial).** The admission candidate replaces periodic saves with
one durable snapshot before every admitted pairing/authentication attempt.
See `SESSION_ADMISSION.md`. Network-level pre-authentication resource limits and
parser fuzzing remain separate; the new admission store does not implement them.

**Recommendation.**

- Keep the default bind on loopback or a specific interface; require an explicit
  opt-in for LAN-wide binding. **Done in the tree:** loopback default and an
  explicit unit flag.
- Add a connection cap, handshake timeout, and slowloris-style read budget.
  **Done in the tree:** see SEC-024.
- Add a persistent/global limiter keyed by peer address, target user and device.
- Add a fuzz target for `Frame`/`Message`/CBOR decoding.
- Document that TLS is server-authenticated only and protocol signatures are the
  device authentication; do not call it mTLS. **Done:** the transport module and
  specification say server-authenticated TLS, not mTLS.

---

### SEC-008 — Android assurance and release build

**Severity:** Medium  
**Status:** Partly confirmed  
**Source:** external review, 2026-11-18  
**Aliases:** debug build, attestation, exported components  
**Affected:** `android/app/src/main/kotlin/com/rba/keystore/DeviceAuthKey.kt`,
`android/app/src/main/kotlin/com/rba/session/AuthenticatorSession.kt`,
`android/app/src/main/AndroidManifest.xml`,
`android/app/build.gradle.kts`

**Confirmed observations.**

- `DeviceAuthKey` uses `setUserAuthenticationRequired(true)` and, on API 30+,
  `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`; API 28–29 uses a
  zero validity window and a separate strong-biometric availability check.
- The signing `Signature` is prepared before the prompt and is the object exposed
  through `BiometricPrompt.CryptoObject`; the session refuses to sign if the
  prompt/CryptoObject path is not the one that succeeded.
- `allowBackup="false"` and `fullBackupContent="false"` are set.
- The base activity, transparent prompt activity, service and boot receiver are
  not exported. The launcher aliases are exported with only `MAIN`/`LAUNCHER`
  filters; they are launcher entries, not an IPC trigger.
- The only artifact built and installed is a debug APK with the debug application
  id; there is no release-signed, non-debuggable build or release checklist yet.
- The app has been exercised on one physical Motorola Edge 30 Ultra, including
  background prompts, pairing, and unpair. The review's "never run on a device"
  statement is outdated, but one device is not broad validation.

**Impact.** The Keystore/CryptoObject mechanism is sound in the reviewed code, but
the release/debug gap and the lack of attestation mean the assurance story is not
complete.

**Recommendation.** Produce a release-signed build, document the signing key
custody, run a device matrix (API 28–35, StrongBox and TEE, no biometric, lock
screen), add a reproducible-build check, and add the attestation policy from
SEC-005.

---

### SEC-009 — PAM module robustness

**Severity:** Medium  
**Status:** Resolved (catch_unwind)  
**Source:** external review, 2026-11-18  
**Aliases:** panic across FFI, unwind, unsafe, blocking  
**Affected:** `linux/pam-rba/src/lib.rs`,
`linux/pam-rba/Cargo.toml`

**Observation.** The PAM module is a Rust `cdylib` loaded into `sudo`, `login`,
`sshd` and greeters. It has several `unsafe` FFI blocks around `pam_get_user`,
`pam_get_item`, `pam_syslog`, and the exported `pam_sm_*` functions. No
`catch_unwind` guard was found around the exported entry points. The module uses
blocking `std::os::unix::net::UnixStream` I/O, not a thread pool.

A panic unwinding across an `extern "C"` boundary is undefined behaviour and can
abort the host process. A daemon timeout can block the PAM stack for the configured
timeout; `sshd` forking means this affects one connection, but login/greeter
processes still wait.

**Impact.** A bug or malformed input could crash the authenticating process rather
than falling through to the password. The intended failure mode is "skip this
module", not "kill sudo/login/sshd".

**Recommendation.** Catch panics at every exported entry point and return
`PAM_AUTHINFO_UNAVAIL`/`PAM_IGNORE` as appropriate. Ensure the workspace's panic
strategy is explicit and compatible with the PAM module. Audit every `unsafe`
block for null pointers, non-UTF-8 input, and lifetimes. Add a test that drives the
module with invalid PAM handles/arguments. Keep the timeout bounded and document
the blocking behaviour.

**Remediation.** `pam_sm_authenticate` now wraps its body in
`std::panic::catch_unwind(AssertUnwindSafe(...))` and returns
`PAM_AUTHINFO_UNAVAIL` on panic, so a bug or malformed input fails closed
instead of unwinding into the host process. The blocking I/O timeout remains
bounded by the module's `timeout_ms` argument.

---

## Low

### SEC-010 — Timing can reveal whether an account has a paired device

**Severity:** Low  
**Status:** Needs verification  
**Source:** external review, 2026-11-18  
**Affected:** `linux/pam-rba/src/lib.rs`, daemon timeout path

A user with a paired device waits for the device/daemon timeout; a user without one
falls through immediately. An attacker able to measure PAM response time may
learn which accounts use the device. Recommend a uniform minimum decision delay or
an immediate "unavailable" response that is indistinguishable, and document the
trade-off.

### SEC-011 — Pairing race and display identity

**Severity:** Low  
**Status:** Confirmed  
**Source:** external review, 2026-11-18  
**Affected:** `linux/rba/src/main.rs`, pairing display

The host CLI shows the submitted `device_name`; it does not show the device key
fingerprint or source address before the operator confirms. If two devices race
the pairing session, the operator cannot distinguish them by name. Recommend
showing the key id/fingerprint and connection source, and refusing a second
submission after the first.

### SEC-012 — `--code` is visible in process arguments

**Severity:** Low  
**Status:** Confirmed  
**Source:** external review, 2026-11-18  
**Affected:** `linux/rba/src/main.rs`

`rba pair --code 123456` places the code in `argv`, visible to local
users via `ps`/proc where permitted. Prefer stdin or a prompt, or treat the code
as low-value because it is only a pairing confirmation; do not log it.

### SEC-013 — Recommended PAM line includes `debug`

**Severity:** Low  
**Status:** Resolved  
**Source:** external review, 2026-11-18  
**Affected:** `README.md` PAM section

The sample line was `purpose=auth debug`. Debug output can leak operational detail
to syslog. **Resolved:** the recommended line no longer includes `debug`, and the
README documents it as troubleshooting-only.

### SEC-014 — Auth response is not bound to the TLS session

**Severity:** Low  
**Status:** Confirmed  
**Source:** external review, 2026-11-18  
**Affected:** `protocol/specification/PROTOCOL.md` §8.1/§8.2,
`android/app/src/main/kotlin/com/rba/session/AuthenticatorSession.kt`

The signed core contains the request fields, but not `session_id`. `session_id` is
unsigned, and there is no TLS exporter binding. A valid signature is bound to the
request context, not to the specific TLS connection. This is mitigated by the
one-outstanding-request rule and the replay guard, but a TLS-exporter value in the
signed transcript would be cheap hardening.

### SEC-015 — mDNS metadata and tracking

**Severity:** Low  
**Status:** Needs verification  
**Source:** external review, 2026-11-18  
**Affected:** `linux/rbad/src/transport/wifi.rs`,
`android/app/src/main/kotlin/com/rba/transport/WifiTransport.kt`

The host advertises a stable host label and key-id metadata over DNS-SD. The
review's claim that the **device** advertises a stable `device_id`, key fingerprint
and name was not reproduced in the current code: the current host advertisement
contains host metadata, and the Android side discovers hosts rather than
advertising. The stable host label/key id is still linkable on every network where
the daemon advertises. Recommend documenting this, offering `--no-mdns`, and
considering an ephemeral display label or rotating advertisement where practical.

### SEC-016 — PAM integration docs assume Debian-style `common-auth`

**Severity:** Low  
**Status:** Resolved  
**Source:** external review, 2026-11-18  
**Affected:** `README.md` PAM section, `tests/common-auth-integration.sh`,
`packaging/arch/install-local.sh`

The recommended `common-auth` change is Debian/Ubuntu-specific. Arch uses
`system-auth` and `sudo` includes it. **Resolved:** the README now documents the
scoped `gdm-password` and `polkit-1` installers, leaves `sudo`, `system-auth`,
`sshd`, `su`, `login` and `gdm-fingerprint` untouched, and explains that
`sufficient` is password **or** device.

---

## Documentation and consistency

### SEC-017 — Host key path differs between documents

**Severity:** Low  
**Status:** Confirmed  
**Affected:** `docs/threat-model.md` §table, `PROTOCOL.md` §3 / §29

The threat model lists `/var/lib/rba/host.key`; the specification says
`/etc/rba/host.key`. The implementation default is
`/var/lib/rba` (`Config::DEFAULT_STATE_DIR`). Pick the implementation path
as canonical and update the specification, or explicitly document a deployment
override.

### SEC-018 — `expires_at` skew wording contradicts the formula

**Severity:** Low  
**Status:** Confirmed  
**Affected:** `PROTOCOL.md` §11 / §11.1

The limits table says `expires_at` is **not** extended by skew. The validation
formula adds `CLOCK_SKEW_STRICT` to `expires_at`:
`now <= expires_at + CLOCK_SKEW_STRICT`. Decide whether the formula is the
normative behaviour or the table is; update the other.

### SEC-019 — Test counts in the review are outdated

**Severity:** Low  
**Status:** Resolved  
**Affected:** `README.md`

The review mentioned 188/168 tests. The current tree reports 200 Rust tests and
31 Android unit tests; lint, vectors and the end-to-end smoke test pass. The
review was working from an older snippet. Keep the counts in the README updated
when the suite changes.

### SEC-020 — Confusing PAM rollback lines

**Severity:** Low  
**Status:** Resolved  
**Affected:** `README.md` PAM section

The PAM section created `common-auth.bak`, then later said rollback was from
`sudo.bak` without explaining that it belonged to a different test. A reader could
restore the wrong file. **Resolved:** rollback instructions now refer only to the
backup created by the same procedure.

---

## Findings from the second source review

### SEC-021 — Control-socket request limit was checked after a full read

**Severity:** Medium  
**Status:** Resolved  
**Resolved in:** `d357f26`  
**Source:** second source review, 2026-11-18  
**Aliases:** IPC memory exhaustion, `read_line`, slowloris on the Unix socket  
**Affected:** `linux/rbad/src/ipc.rs`, `linux/rbad/src/server.rs`

**Observation.** `read_request` called `BufReader::read_line`, which grows a
`String` until a newline arrives, and only then compared the length with 64 KiB.
A client with access to the control socket could stream without a newline and
make the daemon buffer unboundedly before the check ran. The server also spawned
one task per accepted connection with no cap or deadline.

**Impact.** Local denial of service by any local process (the socket is
world-connectable) or root. The socket is not network-reachable, so this is not an
unauthenticated remote attack.

**Remediation.** `read_request` now uses `fill_buf`/`consume`, rejects as soon as
`MAX_REQUEST_BYTES` would be exceeded, and never allocates the complete body
before checking. The server caps concurrent control connections at 32 and applies
a 10 s read and write deadline per request/reply. A connection that cannot get a
slot is dropped rather than queued.

**Evidence.** `ipc::MAX_REQUEST_BYTES`, `ipc::read_request`,
`server::MAX_CONTROL_CONNECTIONS`, `server::CONTROL_IO_TIMEOUT`.

---

### SEC-022 — Authentication timeout was caller-controlled and unbounded

**Severity:** Low–Medium  
**Status:** Resolved  
**Resolved in:** `d357f26`  
**Source:** second source review, 2026-11-18  
**Aliases:** pending-slot exhaustion, authenticated local DoS  
**Affected:** `linux/rbad/src/server.rs`, `linux/rbad/src/engine.rs`

**Observation.** The control API accepted `timeout_ms` without a maximum. The
engine holds one pending authentication slot per device, so a caller could keep
that slot occupied far beyond any valid request lifetime.

**Impact.** An authorised local caller could deny authentication for a device by
holding the slot. It cannot authenticate as another user or bypass the signature.

**Remediation.** The IPC boundary clamps the timeout to
`1..AUTH_REQUEST_TTL_MAX * 1000` (currently 300 s). The engine still clears the
slot on expiry, and protocol requests carry their own `expires_at`, so a late
response is rejected independently of the caller's timeout.

**Evidence.** `server::MAX_AUTH_TIMEOUT_MS`; the clamp in `dispatch`.

---

### SEC-023 — Biometric approval showed an unsigned host name

**Severity:** Medium  
**Status:** Resolved  
**Resolved in:** `d357f26`  
**Source:** second source review, 2026-11-18  
**Aliases:** consent context, display name spoofing, omitted operation  
**Affected:** `android/app/src/main/kotlin/com/rba/session/AuthenticatorSession.kt`,
`android/app/src/main/kotlin/com/rba/ui/AuthenticatorScreen.kt`

**Observation.** The prompt used `AuthRequest.displayHostName`, which the protocol
defines as unsigned advisory text, as if it were the host's identity. It also
omitted the signed `operation` in some summaries. A compromised paired host could
therefore present a different name while making a valid signed request.

**Impact.** Consent integrity: the operator could approve a request believing it
came from another machine. It does not forge the device's signature.

**Remediation.** The prompt now displays the **locally stored paired-host name**
plus the signed `host_id` (the authenticated identity), and always shows the
signed `service` and `operation`. `display_host_name` is no longer used as the
host identity; `display_detail` remains in a separately marked "unverified
detail" card. The biometric prompt summary uses the same trusted label and signed
operation. The success screen repeats the stored name and key id.

**Evidence.** `SessionState.AwaitingApproval/AwaitingBiometric/Approved` carry
`hostName` and `hostKeyId` from `trustedHostName()`; `RequestPanel` and
`ApprovedPanel` render those fields.

---

### SEC-024 — Wi-Fi listener had no connection or handshake deadline

**Severity:** Medium  
**Status:** Resolved in tree  
**Resolved in:** `d357f26`  
**Source:** second source review, 2026-11-18  
**Aliases:** connection flood, TLS slowloris, stalled frames, wildcard bind  
**Affected:** `linux/rbad/src/transport/wifi.rs`,
`linux/rbad/src/transport/mod.rs`, `linux/rbad/src/config.rs`,
`linux/systemd/rbad.service`

**Observation.** The listener spawned a task for every accepted TCP connection,
ran the TLS handshake without a deadline, and waited for frames without an idle
deadline. The default bind was `0.0.0.0:47123`, although a source comment claimed
loopback.

**Impact.** A reachable peer could exhaust descriptors, memory or tasks by opening
and stalling connections. The wide bind exposed the listener on every interface.

**Remediation.**

- Default `Config::bind_addr` is `127.0.0.1:47123`. The systemd unit passes
  `--bind 0.0.0.0:47123` explicitly for LAN use and documents the firewall
  requirement.
- At most 64 simultaneous Wi-Fi connections (including handshakes); excess
  accepted sockets are dropped immediately.
- 10 s TLS handshake deadline, 15 s session-setup deadline and 180 s idle
  frame-read deadline.
- TLS remains server-authenticated only; the device is authenticated by the
  protocol signature, not by a client certificate.

**Residual risk.** Parser fuzzing and pre-authentication network-resource
rate limiting remain open under SEC-007. The systemd unit still needs a firewall or a
specific interface address in deployments where the LAN is untrusted.

**Evidence.** `wifi::MAX_WIFI_CONNECTIONS`, `wifi::TLS_HANDSHAKE_TIMEOUT`,
`transport::SESSION_SETUP_TIMEOUT`, `transport::FRAME_READ_TIMEOUT`,
`Config::default`, `linux/systemd/rbad.service`.

---

## New findings

Add new findings below using the next `SEC-` number. If a finding is a duplicate,
keep it and add `Duplicate of SEC-xxx` plus any aliases; do not delete it. If a
finding is later fixed, set `Status: Resolved` and add the commit/test evidence.

```markdown
### SEC-0NN — Short title

**Severity:** High | Medium | Low  
**Status:** Confirmed | Needs verification | Resolved | Accepted risk | Duplicate  
**Source:**  
**Aliases:**  
**Duplicate of:**  
**Affected:**  

**Observation.**  

**Impact.**  

**Recommendation.**  

**Evidence.**  
```

## Verification commands

```bash
make test          # Rust protocol, daemon, security, PAM and vectors
make vectors-kt    # Kotlin conformance
make android-all   # Android lint, unit tests and debug APK
make e2e           # real daemon + simulator end-to-end
make lint          # rustfmt + clippy, warnings denied
```

For PAM changes, keep a root shell open and use the rollback file created by the
same procedure. The daemon's control socket is the only path an unprivileged
frontend uses; do not weaken its peer checks while addressing SEC-006.

### SEC-025 — Operation-specific authorization (Phase 1 candidate)

**Severity:** High. **Status:** Open; implementation candidate, runtime verification pending.

The current candidate replaces separate account, root and operation fields with explicit principal/scope grants. Empty policies deny all operations; confirmed enrollment stores one explicit basic grant. Administrative changes require the exact principal and scope. The existing engine checks current grants and credential identity before prompting and before returning success. No legacy policy loader or automatic migration is provided. See `AUTHORIZATION_MODEL.md` for the breaking change and remaining identity, context, lifecycle and runtime verification requirements. SEC-003 is preserved; PAKE and remote attestation are unchanged.

Repair candidate for snapshot `b23cafaf`: restore typed registry lifecycle, key validation, explicit principal/scope administration and SEC-003 prompt budgets removed by the incomplete rewrite. Keep the ordered grant set (all contained types derive `Ord`). Compilation, formatting, Clippy and runtime verification are still required.

The repaired host confirmation query now reads the acknowledgement flag, checks that the acknowledgement matches the result sent on the same connection, and bounds the final CLI polling loop. The uploaded Android client does not yet implement wire `PAIRING_CONFIRMED`; its human-confirmation UI state is not a wire acknowledgement. Phone pairing end-to-end remains unverified and must be addressed before release.


### Pairing lifecycle follow-up — snapshot `9e6ac805`

Implementation candidate: the host stages enrollment and cleanup revocations until
the same connection delivers a matching `PAIRING_CONFIRMED`; registry changes are
published only after a successful write. The host returns a matching receipt.
Android now encodes/decodes message type 4, checks its local store write and waits
for the host receipt before displaying completion. A connection owns its own
submission channel; cancellation before acknowledgement does not publish a new
credential. Lost final receipts remain an unavoidable ambiguous outcome across
independent stores. This does not replace the SAS pairing construction or close
SEC-026/SEC-005.

Freshness tests inspect actual wire request IDs and challenges without sleeping; a
separate test checks three prompts and rejection of the fourth. The existing
30/minute Wi-Fi transport budget and three-per-minute account/device budgets are
unchanged. The JVM Kotlin vector runner passed 132 checks against the updated
fixtures. Rust compilation, Rust tests, Android app build and physical phone
pairing remain to be verified.


### Phase A follow-up — pairing lifecycle regression in snapshot `2583bbf`

The snapshot's engine reverted connection-owned pairing and staged enrollment,
while its transport, registry, and tests retained the newer interfaces. It also
introduced a `challenge_response` field that was initialized to `None` and never
populated. The actual Rust and Kotlin pairing codecs still implement the
six-digit SAS construction; a commit title or an unused field is not evidence of
SEC-026 remediation.

Repair candidate: restore the previously implemented connection-owned submission,
session-scoped cancellation, derived-code display, and registry commit only
following device acknowledgement. Keep the new durable admission implementation
and its limits. Remove the unused challenge-response field and shared submission
slot. Add a stale-connection cancellation regression test alongside the existing
pending-enrollment and wrong-receipt tests. Rust compilation and all runtime
verification remain pending. SEC-026 is open; this is lifecycle restoration,
not a new enrollment protocol. SEC-005 remains open as well.

### SEC-026 — portable SPAKE2 candidate (not integrated)

A standalone P-256 SPAKE2 component with explicit confirmation and regression
fixtures is available in `crates/rba-enrollment/`. See
[`SEC-026-SPAKE2.md`](SEC-026-SPAKE2.md) for the dependency evaluation and
integration gates. The active daemon and Android pairing protocol are unchanged;
SEC-026 remains open. Compilation, dependency review, RFC known-answer tests,
end-to-end integration and physical Android verification remain pending.


### SEC-026 — SPAKE2 integration follow-up

**Status:** Open; integration candidate. The Rust daemon, simulator and Android
client now route enrollment through the shared RFC 9382 P-256 component and
mandatory v2 enrollment suite. The former SAS wire flow and crypto are removed
from active sources. The Android native bridge owns single-use state; the host
checks the actual TLS certificate binding and stages the registry until the
matching final acknowledgement. Both manual code directions remain supported.
Kotlin wire checks passed (136); Rust/NDK builds and physical device tests
remain unverified here. Independent dependency and application-profile review,
lockfile resolution and fault-path testing remain release gates. Existing
credentials must be re-enrolled to gain SPAKE2 enrollment assurance.
