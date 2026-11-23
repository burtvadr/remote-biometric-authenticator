# Architecture

```
                            ANDROID
                ┌───────────────────────────┐
                │ BiometricPrompt           │
                │ BIOMETRIC_STRONG only     │
                │                           │
                │           ↓               │
                │ Android Keystore          │
                │ non-exportable EC P-256   │
                └────────────┬──────────────┘
                             │
                      Auth Protocol
                             │
             ┌───────────────┴───────────────┐
             │                               │
          Wi-Fi                             BLE
       mDNS + TLS                         GATT
             │                               │
             └───────────────┬───────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  rbad     │
                    │                  │
                    │ pairing          │
                    │ verification     │
                    │ replay guard     │
                    │ policy           │
                    └───┬────┬─────┬───┘
                        │    │     │
                       PAM  ctl  (audit)
                        │    │
                        ▼    ▼
                     sudo  operator
```

## The one idea

Linux trusts a **cryptographic proof tied to a fresh challenge and the exact
authorization request** — never a `YES`.

```text
Linux                         Android
  │
  │  AUTH_REQUEST { challenge, host, device, user,
  │                 purpose, service, operation,
  │                 issued_at, expires_at }
  ├──────────────────────────────►  BiometricPrompt (BIOMETRIC_STRONG)
  │                                     │
  │                                     ▼
  │                              Keystore signs the
  │                              canonical transcript
  │  AUTH_RESPONSE { signature } ◄─────┤
  ◄─────────────────────────────────────┤
  │
  │  verify signature, scope, freshness,
  │  device identity, replay state
  ▼
success or deny
```

The biometric itself never crosses the protocol. Neither does any long-lived
shared secret after pairing.

## Trust roots

| Party | Long-term key | Storage |
|---|---|---|
| Android device | `device_auth` (ECDSA P-256) | Android Keystore, non-exportable, biometric-gated |
| Linux host | `host_identity` (ECDSA P-256) | `/var/lib/rba/host.key`, root-only |

Linux stores the device's **public** key. A shared pre-shared key is not a trust
anchor here, only a possible bootstrap convenience — pairing authenticates keys
directly instead.

## Layer map

| Layer | Component | Responsibility |
|---|---|---|
| Spec | `protocol/specification/PROTOCOL.md` | Normative wire format and transcript |
| Protocol | `linux/protocol` | Canonical CBOR, framing, crypto, verification |
| Protocol | `android/protocol` | Independent Kotlin implementation |
| Vectors | `protocol/test-vectors/` | Proof the two implementations agree |
| Engine | `linux/rbad` | Challenges, dispatch, verification, pairing |
| Registry | `linux/rbad` | Which device keys are trusted |
| Transport | `linux/rbad/transport` | Wi-Fi (TLS/mDNS) and BLE adapters |
| IPC | `linux/rbad` | `SO_PEERCRED`-authorised control socket |
| Integration | `linux/pam-rba` | Thin PAM adapter |
| UI | `android/app` | Compose screens, biometric, keystore, transports |
| Test | `linux/rba-sim` | Fake device, including misbehaving ones |

## Why the protocol is transport-independent

`PROTOCOL.md` §13 defines one message set. `rba-protocol` has no
transport code at all; the adapters in `transport/` move frames without inspecting
payloads to make security decisions.

This is why BLE's slower link changes only the *freshness window*
(`CLOCK_SKEW_STRICT` instead of `CLOCK_SKEW`). It does not change identity, the
signature algorithm, replay protection, the signed scope, or what "approved" means.

The BLE adapter's only protocol-adjacent job is segmentation: GATT carries 20
bytes per characteristic value, so frames are split and reassembled verbatim.

## What is not claimed

* **Not a defence against a compromised Linux host.** If root is owned, the PAM
  stack and the daemon can be altered. This provides authentication *to* a healthy
  system.
* **Not a defence against a compromised Android device.** A rooted device can use
  the key. The model assumes the OS, Keystore and app package are intact.
* **Not forward-secret against a later key compromise.** The pairing code is a
  keyed integrity check over the transcript, not a PAKE. Documented in
  `PROTOCOL.md` §6.4 rather than papered over.
* **Not a FIDO2 implementation.** The protocol shape resembles a CTAP2
  authenticator, but the integration target is PAM and polkit, so it does not
  adopt FIDO2 for its own sake.

## Failure posture

Every failure is a denial: unknown device, invalid signature, expired request,
replay, transport interruption, ambiguous user, unknown protocol version, malformed
input, pairing mismatch. `PROTOCOL.md` §44 lists them; the security test suite in
`linux/rbad/tests/security.rs` asserts each one.

Whether the *PAM stack* then falls through to a password is the stack's
`sufficient`/`required` ordering, not the module's decision.