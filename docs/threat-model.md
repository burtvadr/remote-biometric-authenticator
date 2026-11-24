# Threat model

Scope: an Android device acting as a remote authenticator for a Linux machine.

Each entry below is covered by a test. The test name is given so the mapping from
claim to evidence is checkable.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Ability to authenticate as a Linux user | daemon + PAM | the whole point |
| Device private key | Android Keystore | non-exportable; signing is the approval |
| Host private key | `/var/lib/rba/host.key` | identifies the host to the device |
| Paired-device registry | `/var/lib/rba/registry.json` | defines who is trusted |
| Request context | in flight | determines what was approved |
| Audit log | `/var/log/rba/audit.log` | accountability |

## Adversaries, and what stops each

| # | Adversary | Defence | Test |
|---|---|---|---|
| 1 | On the same Wi-Fi | TLS 1.3 with a pinned host certificate; the decision is a signature regardless | `a_pinned_client_connects_but_an_unpinned_one_cannot` |
| 2 | Spoofs mDNS | Discovery is not trust; identity is the paired key, verified per request | `an_impostor_reusing_a_known_device_id_is_refused` |
| 3 | Spoofs BLE | Same: address, name and service UUID are routing data only | `a_session_hello_for_another_host_is_refused` |
| 4 | Malicious local process | Control socket uses `SO_PEERCRED`; requested user must match the peer UID | `an_unprivileged_caller_cannot_authenticate_as_another_user` |
| 5 | Impersonates the device | Needs the private key, which is non-exportable and biometric-gated | `a_signature_over_a_different_scope_is_refused` |
| 6 | Replays a captured response | `request_id` and `challenge` are consumed before verification | `challenge_cannot_be_reused_after_consumption` |
| 7 | Confused deputy | All ten scope fields are signed and cross-checked | `rejects_signature_for_a_different_user`, `…different_purpose` |
| 8 | Intermittent network access | Requests expire; a partial exchange grants nothing | `a_stalled_device_fails_closed_without_partial_authorization` |
| 9 | Reads app storage | Private key is not in storage at all | Keystore property, `DeviceAuthKey` |
| 10 | Compromises the app process | Gets no more than the user would approve, one request at a time | design property |
| 11 | Rooted device | Out of scope — see limitations | documented |
| 12 | Steals the device | Requires the user's biometric on the stolen device | design property |
| 13 | Re-enrolls biometrics | Keystore key is invalidated; device must re-pair | `setInvalidatedByBiometricEnrollment(true)` |
| 14 | Tricks the user | Signed context is displayed before the prompt; display text is marked unverified | `with_unsigned_display_text` vector |
| 15 | Malicious local service claiming to be the authenticator | Registry decides; nothing self-asserts | `an_unknown_device_is_refused` |
| 16 | Malicious Android claiming to be Linux | The host presents its own identity and the device verifies the reciprocal MAC | `pairing_vectors_reproduce_the_code_and_macs` |

## Explicitly out of scope

* A compromised Linux kernel or root environment. If root is owned, the PAM stack
  and the daemon can be modified; local authentication boundaries are no longer
  trustworthy.
* A compromised Android OS, a rooted device, or a replaced APK.
* Coercion of the user into approving a request. The system shows exactly what is
  being approved, but it cannot prevent a determined social engineer.
* Traffic analysis and endpoint location. The protocol hides content, not the fact
  that a host exists on the network.

## Assumptions

1. Android Keystore correctly gates signing on a fresh strong biometric.
2. The OS randomness source (`getrandom`, `SecureRandom`) is sound.
3. The distro's PAM, systemd and TLS libraries are correct.
4. The operator compares the pairing codes honestly.
5. Clocks are roughly correct; the freshness window accommodates ±30 s.

## Known limitations

Stated rather than hidden:

* **Short pairing passwords and integration assurance.** The candidate uses
  RFC 9382 SPAKE2 with an independently obtained TLS certificate binding and
  durable admission. Six digits still permit online guesses; protect the code
  and limit attempts. Old enrollments retain their original assurance until
  re-enrolled. Full integration and independent review remain pending.
* **ECDSA malleability.** `(r, s)` and `(r, n-s)` both verify. Signature bytes are
  therefore never used as identifiers, and replay defence rests on `request_id`
  and `challenge`.
* **Unsigned display text.** `display_host_name` and `display_detail` are outside
  the signed scope, so they cannot carry authority. The app marks them as unverified
  to the operator.
* **mDNS availability.** Discovery may be blocked by guest networks or multicast
  filtering. A fixed endpoint can be configured; it is never a trust anchor.
* **BLE freshness window.** BLE uses a tighter 10 s skew than Wi-Fi's 30 s, because
  the link is slower. This is a liveness trade-off, not a security difference.
* **Admission persistence candidate.** Pairing, account, device and both transport
  budgets are committed before dispatch; restart and failure tests are supplied
  but require Rust verification. A trustworthy host clock and protected state
  directory are assumed. Authentication intent and pre-auth network flood controls
  remain separate concerns. See `SESSION_ADMISSION.md`.

## Verification status

| Area | State | Where |
|---|---|---|
| Protocol canonicalisation | enforced, tested against shared vectors | `cbor.rs`, `Cbor.kt` |
| Cross-language agreement | 124 checks, Rust and Kotlin | `protocol/tests/vectors.rs`, `VectorRunner.kt` |
| Signature and scope binding | tested per field | `verifier.rs` |
| Replay, expiry, consumption order | tested | `nonce.rs`, `security.rs` |
| Pairing transcript | tested, including substituted keys | `pairing.rs`, `security.rs` |
| Local IPC authorisation | tested | `ipc.rs` |
| TLS pinning | tested with a real handshake | `tls.rs` |
| BLE segmentation | tested, including truncation and poisoning | `BleFraming.kt`, `BleSegmentationTest` |
| Android app compiles and lints clean | verified | `make android-all` |
| PAM failure behaviour | **tested against a live libpam stack**, including real denial, timeout, tamper and misconfiguration paths | `pam-rba`, `tests/pam-integration.sh` |
| Every password prompt on the system | **verified through each service's own stack** — polkit-1, gdm-password, sudo, login, su — from one line in `common-auth` | `tests/common-auth-integration.sh` |
| Rate limiting under a flood | verified: a rate-limited request never reaches the device | same |
| Recovery path | verified: a decline falls through to the password, never a lockout | same |
| Android Keystore and BiometricPrompt | **not** executed — needs a device | `DeviceAuthKey.kt` |
| polkit agent | **registers with a live polkitd**; challenge routing fails, see below | `polkit-agent`, `tests/polkit-integration.sh` |
| fprintd/libfprint compatibility | not implemented | — |

Three gaps remain.

**A real device** is needed for Keystore and `BiometricPrompt`. Nothing here can close
that: it is the one part of this system that cannot be tested without the hardware.

**polkit challenge routing** is blocked by polkit's own design, not by a defect we can
patch around. Establishing this took reverse-engineering the live daemon, and the result
is a product finding rather than a bug:

- polkit 127 has **no `BeginAuthentication` signal**. The agent exports
  `org.freedesktop.PolicyKit1.AuthenticationAgent` and polkitd calls `Authenticate` on
  it; registration is `RegisterAuthenticationAgent(subject, locale, object_path)`, and
  `UnregisterAuthenticationAgent` takes `(subject, object_path)`. **Confirmed working** --
  polkitd accepts the registration with no error.
- A subject is named by **kind only** (`("unix-process", {pid, start-time, uid})` or
  `("unix-session", {session-id})`). The older `unix-process:<pid>` spelling is rejected
  with "Unknown subject of kind", which reads like a permissions problem and is not one.
- polkit **refuses an agent registering a session other than its own**: "Passed session
  and the session the caller is in differs. They must be equal for now." So an agent
  must be *running* inside the session it serves. The agent now detects its own session
  from `/proc/self/cgroup`, registers the session subject, and re-registers on SIGHUP
  when moved.
- polkit permits **one authentication agent per subject**. gnome-shell already holds
  the registration for the active seat session, so a third-party agent cannot displace
  it: registering there returns "An authentication agent already exists for the given
  subject".
- polkit does not offer challenges to an agent on an **inactive** session. The
  integration test's session is inactive, so our agent registers correctly and is never
  called; polkitd logs `Operator of unix-session:2 FAILED to authenticate` with no
  `Authenticate` ever delivered.

The consequence is that a third-party polkit authentication agent is **unusable on any
desktop that already ships one**, which is every mainstream desktop. It can only serve a
session that has no agent of its own: a headless server, a minimal session manager, a
container. That is a narrower and less useful product than the plan assumed, and it
should be an explicit decision rather than a footnote. Options, none of them free:
drop polkit integration; keep it for headless hosts only and say so plainly; or
integrate as a *participant* alongside the desktop agent rather than competing with it,
which polkit does not offer a clean way to do.

**No authorization through the polkit agent has been demonstrated.** Until routing is
resolved the agent must not be installed anywhere that relies on it.

**The one thing that did work** on the polkit path is the negative: an action is refused
once the agent is gone, so an authorization does not outlive the agent that granted it.