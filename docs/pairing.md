# Pairing

Pairing is the one moment where a stranger's key becomes trusted. Everything else
in the protocol can be replayed, refused or revoked; getting this wrong is how a
system like this is subverted.

## The flow

```text
host                                   device
 │  PAIRING_START { session_id,         │
 │                  host_id, host_pubkey,│
 │                  code?, code_entry,   │
 │                  expires_at,          │
 │                  host_nonce,          │
 │                  host_eph_pubkey }    │
 ├──────────────────────────────────────►│
 │                                       │  generate device ECDH key
 │                                       │  derive ECDH secret + transcript
 │                                       │  device: never show the code
 │                                       │  host: show the code
 │  PAIRING_SUBMIT { session_id,         │
 │                   device_id,          │
 │                   device_name,        │
 │                   device_pubkey,      │
 │                   device_nonce,       │
 │                   device_eph_pubkey,  │
 │                   mac }               │
 │◄──────────────────────────────────────┤
 │  derive the same p and code           │
 │  device: display the code             │
 │  host: prompt for the device's code    │
 │  verify mac                           │
 │  persist the device                   │
 │  PAIRING_RESULT { status, host_mac }  │
 ├──────────────────────────────────────►│  verify host_mac
 │                                       │  device: type the host code
 │                                       │  host: show code, require Allow
 │                                       │  persist only after the human gate
```

`code_entry` chooses which endpoint types the code. In `device` mode the Linux
host displays it and the device never does. In `host` mode the device displays it
and the Linux host never does. The endpoint that displays the code must not accept
a bare confirmation in place of the other endpoint's typed value.

**Upgrade note.** `host_eph_pubkey` and `device_eph_pubkey` are required. A device
or host built before this change cannot complete a new pairing with an updated
peer; re-pair after upgrading both sides. Already-paired authentication sessions
are not affected by the pairing-message change, but re-pairing is what enrolls a
key under the new transcript binding.

Three properties are worth calling out.

**The code is derived, not transported.** It is a function of an ephemeral ECDH
secret over the full transcript: both ids, both long-term keys, both nonces,
both ephemeral keys and the code-entry mode. The host cannot compute it before the device contributes
its ephemeral public key, and the device must not reveal its nonce before it knows
an operator is deliberately pairing. So the exchange is necessarily two rounds,
and both sides compute the code independently.

**The MACs are reciprocal.** Each side proves it derived the same secret. The
operator's code entry is therefore not just a human ritual: if the MACs verify,
the code the operator typed really did cover this exchange.

## Device-side consent

A valid `host_mac` proves that the host derived the same transcript. It does not
prove that a human was involved. The Android app's gate depends on `code_entry`:

* **`device` mode (default):** the device never displays the code. It parks the
  verified pairing in `PairingAwaitingConfirmation` and asks the operator to type
  the six-digit code shown on the Linux screen. A wrong value cancels the pairing;
  start a new session rather than retrying against the same exchange. Typing the
  correct code is the consent; there is no separate Allow tap.
* **`host` mode:** the device displays the code for the Linux operator to type.
  After the host proves it derived the same transcript, the device still requires
  an explicit **Allow**. The code entry is a host-side check, not a substitute
  for the device's consent.

Only the human gate writes the host key and certificate pin. **Cancel**, the back
gesture, or losing the connection discards the pending record. The host has
already persisted its own side when it sends `PAIRING_RESULT`; the two records are
independent. A host record alone cannot authenticate anything: the device refuses
requests from a host it has not stored. The device's typed code or Allow is what
makes future authentication possible.

Pairing can be started while the app is in the background. The foreground service
holds an idle discovery/connection loop, and the state that needs the operator
brings the screen forward (subject to Android's overlay or full-screen-intent
permission).

## Operator-chosen codes

`rba pair --code 123456` puts the code in `PAIRING_START`. The device
checks its own derived value against it and refuses immediately on a mismatch;
the host verifies the same equality before persisting.

This turns the human check into a pre-shared code, but the selected `code_entry`
still applies: type it on the endpoint that did not choose it. It is the safer
option where it is practical.

## What the operator is protected against

| Attack | Outcome |
|---|---|
| A different device is substituted in transit | The host derives a different ECDH secret, so its code differs from the one the device would derive for the substituted transcript. The MACs also differ. |
| A different host is substituted | The device derives a different ECDH secret, so its code differs and `host_mac` does not verify. |
| Passive capture of the exchange | The ephemeral ECDH secret is never transmitted, and both ephemeral private keys are destroyed after use. Only public keys are retained. |
| Replay of an earlier pairing | Both nonces and both ephemeral keys are fresh per attempt, so the derived code and MACs differ. |
| A relay that preserves the code but swaps keys | It must make two different ECDH secrets produce the same six-digit value (~2^20 work per live, single-use session). |
| An attacker who races the real device | Only one pairing session can be open at a time, and it expires. The second attempt is refused. |

## What the operator is *not* protected against

Stated plainly, because the limitation is inherent to the design rather than a
bug:

* **The six-digit code is a short SAS, not a PAKE.** An active attacker gets
  roughly one success in `10^6` per pairing attempt, because it must find two
  ephemeral keys whose codes collide. Pairing is single-use, time-limited and
  rate-limited, which bounds online attempts, but a determined attacker with a
  live session still has that `2^20` window. A reviewed PAKE would remove the
  offline-grinding component; this design uses ephemeral ECDH plus a
  transcript-bound SAS instead.
* **No protection from a dishonest operator.** Someone with physical access to both
  screens can approve anything. That is inherent: the person approving is the trust
  anchor.
* **No protection against a compromised device.** A rooted device can lie about its
  biometric and sign whatever it likes during pairing.

## Why there is no unattended path

There is no mode in which a device that merely *appears* on the network becomes
trusted. `rba pair` must be run, it expires, a second attempt is refused
while one is open, the host persists only after its own human gate, and the device
persists only after typing the host's code (or, in `host` mode, after typing the
device's code on the host plus an explicit Allow). Neither side's record is usable
without the other's.

## Device-initiated unpair

The device can remove a host without root on the Linux side. It deletes the host
record and certificate pin immediately, then sends `UNPAIR {token}` on the pinned
link if the host is reachable. The host stores only `SHA-256(token)` and marks the
matching record revoked.

If the host is offline, the local unpair still stands. The device keeps the token
and includes it in the next pairing submit for that host. After the new pairing's
MAC verifies, the host revokes the old record matching the token and then commits
the new one. This is a cleanup capability, not proof of same-installation
identity: a lost token means the host operator must revoke the stale record
manually.

## Revocation

```bash
sudo rba revoke --device "Pixel 9"
```

Revocation takes effect immediately: the registry entry is marked revoked, the live
connection is dropped, and the next attempt is refused with `REVOKED`. Replacing a
device requires a new pairing with a new key, and the registry refuses to
re-register a `device_id` against a different key without an explicit revocation
first, so a stale identifier cannot be silently taken over. A valid
`cleanup_token` in a new pairing submit is an explicit revocation of the old
record; without one, the operator still has to run this command.

## Rate limiting

Pairing is limited to 5 attempts per peer address per 5 minutes, and a live session
cannot be re-opened while another is active. Together these mean a network attacker
cannot use pairing as a way to make a device display a stream of prompts.