# Remote Biometric Authenticator — Protocol Specification v1

Status: **Normative** for `PROTOCOL_VERSION = 1`.

This document defines the wire protocol and the cryptographic transcript for the
Remote Biometric Authenticator. It is deliberately **language-independent**:
the Linux daemon (Rust) and the Android application (Kotlin) implement it twice,
independently, and are validated against the shared test vectors in
`protocol/test-vectors/`.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as
described in RFC 2119.

---

## 1. Scope and security model in one paragraph

The protocol carries a **user-presence proof**: "the holder of Android device
identity *D* satisfied a strong-biometric check for the Linux host *H*, for Linux
user *U*, for authorization *P/S/O*, exactly once, for challenge *C*". The proof is
an ECDSA signature over a canonical encoding of that claim. Biometric material
never crosses the protocol; neither does any long-lived shared secret after
pairing completes. Transport (TCP/TLS or BLE/GATT) is a carrier, never identity.

Trust roots:

| Party | Long-term key | Storage |
|---|---|---|
| Android device | `device_auth` key (ECDSA P-256) | Android Keystore, non-exportable, biometric-gated |
| Linux host | `host_identity` key (ECDSA P-256) | `/etc/rba/host.key`, root-only |

After pairing, the only secrets exchanged over the wire are ephemeral session
nonces and the authentication signature itself.

---

## 2. Conventions

* All integers are unsigned big-endian unless stated otherwise.
* `uint(n)` denotes an unsigned integer of exactly `n` bytes.
* Byte strings are written as `<len> bytes` with a fixed length unless stated.
* Text strings MUST be valid UTF-8 with no overlong encodings (Rust/Kotlin
  decoders reject invalid sequences).
* Timestamps are **unsigned integer seconds since the Unix epoch (UTC)**.
* Hex strings are lowercase, two characters per byte.
* Identifiers are opaque byte strings and MUST NOT be derived from hostnames,
  IP addresses, MAC addresses, device names, or mDNS/BLE identifiers.

---

## 3. Cryptographic algorithms

| Purpose | Algorithm | Identifier |
|---|---|---|
| Identity signatures | ECDSA over NIST P-256, SHA-256 | `ES256` |
| Transcript binding | HMAC-SHA-256 | `HMAC-SHA-256` |
| Session key derivation | HKDF-SHA-256 | — |
| Randomness | OS CSPRNG | — |

### 3.1 Public key encoding (normative)

A P-256 public key MUST be encoded on the wire as the **raw uncompressed EC
point**, exactly 65 bytes:

```text
0x04 || X (32 bytes, big-endian) || Y (32 bytes, big-endian)
```

The first byte MUST be `0x04` and `X`,`Y` MUST lie on the curve
(`y^2 = x^3 - 3x + b mod p`, NIST P-256 / secp256r1). Encoders MUST reject any
other length or prefix. Decoders MUST validate the point is on the curve.

Note: implementations MUST NOT accept SEC1 compressed points (`0x02`/`0x03`) in
v1. This keeps encoding canonical and avoids an entire class of parser ambiguity.

### 3.2 `key_id` (normative)

```text
key_id = SHA-256(raw_public_key_bytes)          // 32 bytes
```

Rendered as 64 lowercase hex characters. `key_id` is a convenience identifier for
logs and operator-facing listings. **It is never an authentication decision**: the
host always verifies the signature against the full stored public key.

### 3.3 Signature encoding (normative)

Signatures are transmitted as the raw fixed-width concatenation `r || s`:

```text
signature = r (32 bytes, big-endian) || s (32 bytes, big-endian)
```

exactly 64 bytes. DER/PEM encodings are not part of this protocol.

ECDSA is malleable: `(r, s)` and `(r, n-s)` are both valid signatures over the
same message. Implementations MUST NOT treat a signature value as a unique
identifier, as a session binding, or as an anti-replay token. Replay defence is
provided solely by §10 (single-use `request_id` and `challenge`).

### 3.4 Rejection rules (MUST)

Implementations MUST reject, without attempting verification, when:

* the signature is not exactly 64 bytes;
* `r` is not in `[1, n-1]`, or `s` is not in `[1, n-1]`;
* the public key encoding is not a valid on-curve uncompressed point.

---

## 4. Frame format

Every protocol message is one **frame**. A frame is transported verbatim and in
order over the transport's byte stream (TCP) or as the concatenation of GATT
characteristic values (BLE).

```text
 0        4        5          7           9              13
 +--------+--------+---------+-----------+---------------+
 | 'P'    | ver    | type     | flags     | payload_len   |
 | 'A'    | u8     | u16 BE   | u16 BE    | u32 BE        |
 | 'F'    |        |          |           |               |
 | '1'    |        |          |           |               |
 +--------+--------+---------+-----------+---------------+
 | payload (payload_len bytes, canonical CBOR)           |
 +-------------------------------------------------------+
```

Header is exactly **13 bytes**.

| Field | Type | Value |
|---|---|---|
| magic | 4 bytes | ASCII `PAF1` (`0x50 0x41 0x46 0x31`) |
| version | u8 | `0x01` |
| type | u16 BE | message type from §5 |
| flags | u16 BE | MUST be `0x0000` in v1; any other value MUST be rejected with `UNSUPPORTED_VERSION`/`BAD_REQUEST` |
| payload_len | u32 BE | `<= 65536`; larger MUST be rejected |

A receiver MUST reject a frame whose total length is inconsistent with
`payload_len`, whose `magic` differs, or whose `version` it does not implement.
Receivers MUST NOT read beyond the declared payload length and MUST discard any
trailing bytes belonging to the next frame rather than treating them as part of
the payload.

### 4.1 Framing discipline (normative)

The first frame a peer sends in either direction MUST be `SESSION_HELLO` (§5).
No other message may be sent before it.

A receiver consumes **exactly** `13 + payload_len` bytes per frame and MUST NOT
scan the byte stream for the magic value in order to resynchronise. The 4-byte
magic is a *framing aid and a version/tag check*, not a resynchronisation anchor:
`PAF1` can legitimately occur inside a CBOR payload, so a scan-based
resynchroniser would let an attacker choose where frames appear on the wire and
thereby inject a forged frame boundary.

Consequently, a stream that loses frame alignment (truncation, a spliced
connection, a desynchronising proxy) MUST be treated as a fatal error: the
receiver fails closed and closes the connection. It MUST NOT attempt recovery.
Because both transports in this protocol are message-oriented (TCP after TLS, or
whole characteristic-value frames on BLE), alignment loss indicates an attack or
a broken peer rather than a normal condition.

---

## 5. Message types

| Code | Name | Direction | Payload |
|---|---|---|---|
| 1 | `PAIRING_START` | host → device | §6.1 |
| 2 | `PAIRING_SUBMIT` | device → host | §6.2 |
| 3 | `PAIRING_RESULT` | host → device | §6.3 |
| 4 | `PAIRING_CONFIRMED` | device → host, then host → device | §6.3.1 |
| 10 | `SESSION_HELLO` | host → device | §7.1 |
| 11 | `SESSION_HELLO_ACK` | device → host | §7.2 |
| 12 | `AUTH_REQUEST` | host → device | §8.1 |
| 13 | `AUTH_RESPONSE` | device → host | §8.2 |
| 14 | `AUTH_REJECT` | device → host | §8.4 |
| 15 | `UNPAIR` | device → host | §6.5 |
| 20 | `ERROR` | either | §9 |

Unassigned codes MUST be answered with `ERROR` / `UNSUPPORTED_VERSION`.

---

## 6. Pairing

Pairing establishes mutual, authenticated knowledge of both public keys and is
gated on an out-of-band six-digit code: one endpoint displays it, and the operator
types it on the other. Discovery alone never authorises anything.

A pairing session selects the entry direction with `code_entry`:

* `device` (the default): the Linux host displays the code and the device requires
  the operator to type it. The device never displays it.
* `host`: the device displays the code and the Linux host requires the operator to
  type it. The host never displays it. The device still requires an explicit Allow
  before it stores the host.

A pairing session is single-use and expires (`PAIRING_TTL`, §11). The host MUST
refuse to begin pairing unless an operator has explicitly started a pairing
session (`rba pair`). There MUST NOT be a permanent pairing mode.

```text
host                                   device
 │  PAIRING_START  {session_id,          │
 │                  host_id, host_pubkey,│
 │                  code?, code_entry,   │
 │                  expires_at,           │
 │                  host_nonce,           │
 │                  host_eph_pubkey}      │
 ├──────────────────────────────────────►│  generate device ECDH key
 │                                       │  derive ECDH secret + transcript
 │                                       │  device: never display the code
 │                                       │  host: display the code
 │  PAIRING_SUBMIT {session_id,          │
 │                   device_id,           │
 │                   device_name,         │
 │                   device_pubkey,       │
 │                   device_key_id,       │
 │                   device_nonce,        │
 │                   device_eph_pubkey,   │
 │                   mac}                 │
 │◄──────────────────────────────────────┤
 │  derive the same p, derive the code   │
 │  device: display the code             │
 │  host: ask the operator for the       │
 │  device's code and verify it            │
 │  verify mac against the session secret│
 │  persist device                       │
 │  PAIRING_RESULT {session_id,           │
 │                   status, host_mac}    │
 ├──────────────────────────────────────►│  verify host_mac
 │                                       │  device: type the host's code
 │                                       │  host: show code, require Allow
 │                                       │  persist only after the human gate
```

### 6.0 Why the code is derived, not transported

The six-digit code is a function of an ephemeral ECDH secret bound to the whole
transcript. The host cannot derive it before the device contributes its ephemeral
public key, and the device must not reveal its nonce before it knows the operator
is pairing deliberately. So the exchange is necessarily two rounds, and the code
is computed on both sides rather than sent.

Because the host's ephemeral private key is generated fresh for each session and
discarded after derivation, an on-path attacker who records the messages cannot
compute the secret, and cannot make a substituted key produce the same code on
both endpoints without finding a collision in the six-digit value.

An operator may pre-select a code with `rba pair --code 123456`. In that
case the host sends it in `PAIRING_START`, the device checks its own derived code
against it and fails immediately on a mismatch, and the host verifies the same
equality before persisting. This turns the human check into one code, entered on
the endpoint that did not choose it.

When no code is pre-selected, the endpoint named by `code_entry` MUST display the
derived code and the other endpoint MUST require the operator to type it. The
displaying endpoint MUST NOT accept a bare confirmation tap in place of the other
endpoint's typed code. There is no unattended pairing path.

### 6.1 `PAIRING_START`

| Key | Type | Constraint |
|---|---|---|
| `session_id` | bstr | 16 bytes |
| `host_id` | bstr | 16 bytes |
| `host_pubkey` | bstr | 65 bytes, §3.1 |
| `host_key_id` | tstr | 64 lowercase hex chars |
| `code` | tstr | six ASCII digits, or empty when the operator chose none |
| `code_entry` | tstr | `device` (default when absent) or `host`; which endpoint types the code |
| `expires_at` | uint | Unix seconds |
| `host_nonce` | bstr | 32 bytes |
| `host_eph_pubkey` | bstr | 65 bytes; ephemeral P-256 public key for this pairing |

### 6.2 `PAIRING_SUBMIT`

| Key | Type | Constraint |
|---|---|---|
| `session_id` | bstr | 16 bytes, MUST equal the `PAIRING_START` value |
| `device_id` | bstr | 16 bytes |
| `device_name` | tstr | 1–64 chars, operator-visible label |
| `device_pubkey` | bstr | 65 bytes |
| `device_key_id` | tstr | 64 hex chars |
| `device_nonce` | bstr | 32 bytes |
| `device_eph_pubkey` | bstr | 65 bytes; ephemeral P-256 public key for this pairing |
| `mac` | bstr | 32 bytes, §6.4 |
| `cleanup_tokens` | array of bstr | Optional; each 32 bytes. Older pairings this device asks the host to revoke, §6.6 |

### 6.3 `PAIRING_RESULT`

| Key | Type | Constraint |
|---|---|---|
| `session_id` | bstr | 16 bytes |
| `status` | uint | `0` = accepted for confirmation, `1` = rejected |
| `host_mac` | bstr | 32 bytes, present only when `status == 0` |
| `revocation_token` | bstr | 32 bytes, present when `status == 0`; bearer capability for §6.5 |

### 6.3.1 `PAIRING_CONFIRMED`

| Key | Type | Constraint |
|---|---|---|
| `session_id` | bstr | 16 bytes, exact pairing session identifier |

The device MUST send this single-field canonical map only after the reciprocal
MAC and the human gate have succeeded and the host record has been durably
stored. It MUST be sent on the connection that delivered the successful
`PAIRING_RESULT`, before closing that connection for a pinned reconnect. The
host MUST reject acknowledgements for a different session or connection, and
MUST NOT report pairing complete to its CLI until the acknowledgement arrives.
The host MUST stage the enrollment until the device acknowledgement, then commit
its registry and echo the same message as a receipt on the same connection.
Only the receipt completes the device UI. The device acknowledgement is not
itself authentication proof. A lost final receipt can leave completion
uncertain; the operator may re-pair. This is not a distributed atomic commit.

### 6.4 Pairing confirmation (normative)

The purpose of this construction is to bind the *whole pairing transcript* to the
code the operator entered. Without it, an off-path attacker could relay a
substitute device key to a device and a substitute host key to the host, and the
operator would have entered a code that authenticates neither.

```text
transcript = session_id || host_id || device_id
           || host_pubkey || device_pubkey
           || host_nonce || device_nonce
           || host_eph_pubkey || device_eph_pubkey
           || code_entry_byte

code_entry_byte = 0x00 for `code_entry = device`
                = 0x01 for `code_entry = host`

ecdh_secret = X-coordinate of (host_eph_private * device_eph_pubkey)
            = X-coordinate of (device_eph_private * host_eph_pubkey)

pairing_secret = HKDF-SHA-256(
        ikm  = ecdh_secret,
        salt = "RBA-PAIR-SALT-V1",
        info = "RBA-PAIR-TRANSCRIPT-V2" || transcript,
        len  = 32)

p = HMAC-SHA-256(key = pairing_secret, msg =
          "RBA-PAIR-V1" || 0x00 || transcript)

code   = decimal, zero-padded to 6 digits, from rejection sampling:
         for each 32-bit big-endian word v in p:
             if v < 4_294_000_000: code = v mod 1_000_000; stop
         if no word qualifies:
             p_1 = HMAC-SHA-256(key = p,
                     msg = "RBA-PAIR-CODE-V1" || 0x00 || u64_be(1))
             repeat with p_1, p_2, ...
mac_d  = HMAC-SHA-256(key = p, msg =
          "RBA-DEVICE-CONFIRM-V1" || 0x00 || transcript)
mac_h  = HMAC-SHA-256(key = p, msg =
          "RBA-HOST-CONFIRM-V1" || 0x00 || transcript)
```

Both endpoints MUST reject an ephemeral public key that is not a valid P-256
point. The ephemeral private key MUST be generated by a CSPRNG for every pairing
session, MUST NOT be reused, and MUST be zeroized after `pairing_secret` is
derived.

The code MUST use rejection sampling as above. A one-byte truncation would
reduce the space to `000000`–`000255`; a bare modulo reduction over a non-multiple
of `1_000_000` would be biased. Rejection sampling makes every six-digit value
exactly equally likely. The probability of a code in `000xxx` is therefore 0.1%.
The expansion is reached with probability about `6e-30`.

Requirements:

* The host MUST verify `mac_d` before persisting anything (§11.4 ordering).
  When `code_entry = device`, it MUST display the derived code and MUST obtain
  explicit positive confirmation from its operator before persisting. When
  `code_entry = host`, it MUST NOT display the code, MUST require its operator to
  type the code shown on the device, and MUST verify that entry before persisting;
  a wrong entry MUST be rejected, MUST NOT be converted into a default or a
  successful pairing, and MUST cancel the session. There is no retry within the
  same exchange.
* The device MUST verify `host_mac` before persisting the host key. When
  `code_entry = device`, it MUST NOT display the code, MUST require the operator
  to type the code displayed by the host, and MUST persist only on an exact match.
  A wrong entry MUST be rejected without persisting and MUST discard the pending
  result; the operator must start a new pairing session. When `code_entry = host`,
  the device MAY display the code for the host
  operator to type, but it MUST still require an explicit **Allow** before
  persisting.
* **Cancel**, the back gesture, expiry, timeout, or loss of the pairing link MUST
  discard the pending result. There MUST NOT be a default-allow, silent, or
  unattended confirmation path.
* The host stages its record when it sends `PAIRING_RESULT` with `status = 0`.
  The new credential MUST NOT authenticate until the device confirms that its
  human gate and local persistence succeeded. The host then commits its
  registry and sends the receipt in §6.3.1. The two sides persist independently.
* The host MUST generate a fresh 32-byte `revocation_token` for every successful
  pairing, return it only over the pinned TLS channel, and store only its SHA-256
  hash with the device record. The token MUST NOT be logged. The device MUST store
  it with the host record and MUST NOT treat it as an authentication credential.
* Pending `cleanup_tokens` in `PAIRING_SUBMIT` MUST be processed only after
  `mac_d` verifies and before the new record is persisted. Each token revokes
  exactly the record whose token hash matches. A token MUST NOT be treated as
  evidence that the new installation is the same device; it only authorises the
  old pairing's cleanup.
* `code`, `mac`, `mac_d`, `host_mac` and `revocation_token` MUST NOT be written
  to logs.
* Both `host_nonce` and `device_nonce` MUST be fresh CSPRNG output for every
  pairing attempt. Reuse breaks the transcript binding.
* Pairing carries **no long-term key material**; only long-lived public keys are
  retained after success.
* There is no code path that pairs a device without an operator having started a
  pairing session. A host MUST refuse `PAIRING_START`-equivalent operations while
  no session is open, and MUST NOT fall back to "trust whatever connected".

**Limitations, stated honestly.** The six-digit code is a short authentication
string (SAS), not a PAKE. An active attacker who terminates the exchange on both
sides derives a different ECDH secret on each side, so the codes differ; to make
them match it must find two ephemeral keys whose six-digit values collide. That
costs about `2^20` work per live session, and pairing sessions are single-use,
time-limited and rate-limited. This is the standard SAS trade-off, not a hidden
weakness.

The construction provides forward secrecy for the pairing transcript: both
ephemeral private keys are zeroized, so recording the exchange and later
obtaining either long-term private key does not reveal `pairing_secret`. It does
not protect against an operator who approves a code they did not actually
compare, or against a compromised endpoint that lies about what it displays. Use
an authenticating transport (TLS, as on Wi-Fi) where available; for BLE, pairing
SHOULD be performed over Wi-Fi.

---

### 6.5 `UNPAIR` (device → host)

| Key | Type | Constraint |
|---|---|---|
| `token` | bstr | 32 bytes, the `revocation_token` from §6.3 |

A device may revoke its own pairing by sending `UNPAIR`. The host MUST compute
`SHA-256(token)`, find the record whose stored revocation-token hash matches, mark
that record revoked, audit the event, and close the connection. The token is a
bearer capability: it authorises revocation only, never authentication, and MUST
NOT be logged.

A device MUST remove its local host record even when the host is unreachable or
does not answer. The local decision is final; `UNPAIR` is the best-effort
notification that lets the host clean its side.

### 6.6 Pending cleanup on re-pair

A device that could not deliver `UNPAIR` MAY retain the token and send it in
`cleanup_tokens` on the next `PAIRING_SUBMIT` for the same host. The host MUST
process those tokens only after the new submit's `mac` verifies and before it
persists the new record. Each valid token revokes exactly the old record it
belongs to; invalid tokens are ignored and audited, not used as a reason to
break an otherwise valid pairing.

`cleanup_tokens` are bearer capabilities, not proof of same-installation
identity. A new key may replace an old record after its token revokes the old
record; without a token, an id already paired with a different key remains
refused (§11.3). A lost token means the host operator must revoke the stale
record manually.

---

## 7. Session establishment

The same session messages precede every logical authentication exchange on every
transport. Transport security (TLS) and protocol identity verification are
**independent**: a successful TLS handshake MUST NOT be treated as authentication,
and the signature in §8 is always required.

### 7.1 `SESSION_HELLO` (host → device, first frame in both directions)

| Key | Type | Constraint |
|---|---|---|
| `protocol_version` | uint | `1` |
| `host_id` | bstr | 16 bytes |
| `host_key_id` | tstr | 64 hex chars |
| `host_nonce` | bstr | 32 bytes |
| `session_id` | bstr | 16 bytes |
| `transports` | array | array of tstr, e.g. `["wifi","ble"]`; advisory |

### 7.2 `SESSION_HELLO_ACK` (device → host)

| Key | Type | Constraint |
|---|---|---|
| `protocol_version` | uint | `1` |
| `device_id` | bstr | 16 bytes |
| `device_key_id` | tstr | 64 hex chars |
| `device_nonce` | bstr | 32 bytes |
| `session_id` | bstr | 16 bytes, MUST equal the `SESSION_HELLO` value |

`session_id` MUST be unique per session and MUST NOT be reused. The host MUST
reject an `AUTH_REQUEST` whose `session_id` it did not open.

---

## 8. Authentication exchange

### 8.1 `AUTH_REQUEST` (host → device)

| Key | Type | Signed | Constraint |
|---|---|---|---|
| `request_id` | bstr | yes | 16 bytes, single use |
| `host_id` | bstr | yes | 16 bytes |
| `device_id` | bstr | yes | 16 bytes, selects the target device |
| `username` | tstr | yes | 1–64 chars |
| `purpose` | tstr | yes | e.g. `sudo`, `login`, `polkit`, `unlock` |
| `service` | tstr | yes | PAM service / polkit action id |
| `operation` | tstr | yes | e.g. `authenticate`, `authorize` |
| `challenge` | bstr | yes | 32 bytes, single use |
| `issued_at` | uint | yes | Unix seconds |
| `expires_at` | uint | yes | Unix seconds |
| `session_id` | bstr | no | 16 bytes, links to §7 |
| `display_host_name` | tstr | **no** | unsigned, advisory display only |
| `display_detail` | tstr | **no** | unsigned, advisory display only |

**Signed vs unsigned.** Exactly the ten fields marked `yes` form the signed
scope. Fields prefixed `display_` are deliberately **not** signed: they are
operator-facing prose ("systemctl restart sshd"), and signing attacker-supplied
prose would give it authority it must not have (§34 of the project brief). The
device MUST render them as unverified descriptive text, MUST NOT let them
influence what is signed, and MUST refuse any request whose *signed* fields are
absent or malformed even if `display_*` fields are well-formed.

A device MUST also reject an `AUTH_REQUEST` whose signed fields do not match the
session it negotiated: `host_id`, `device_id` and `session_id` MUST equal the
values established in §7. This is what makes cross-host and cross-device
confused-deputy attempts fail.

### 8.2 Signature input (normative)

```text
sig_input = "RBA_AUTH_V1"        // 11 ASCII bytes, no NUL terminator
          || 0x00                          // single NUL separator
          || 0x01                          // protocol version, u8
          || core_map                      // canonical CBOR map, below
```

`core_map` contains **exactly** the ten signed fields of §8.1, keyed by their
names, encoded as canonical CBOR (§8.5). Canonical CBOR sorts map keys, so the
field order in this document is presentation order only and carries no meaning.

The device signs `SHA-256(sig_input)` with ECDSA P-256. The host recomputes
`sig_input` from its own outstanding request and verifies against the stored
`device_pubkey`. **The host MUST NOT verify against a public key supplied by the
transport, the peer, or the request itself.**

### 8.3 `AUTH_RESPONSE` (device → host)

| Key | Type | Constraint |
|---|---|---|
| `request_id` | bstr | 16 bytes, MUST equal the request |
| `device_id` | bstr | 16 bytes |
| `session_id` | bstr | 16 bytes |
| `algorithm` | tstr | MUST be `ES256` |
| `key_id` | tstr | 64 hex chars, `key_id` of the signing key |
| `signature` | bstr | 64 bytes, §3.3 |

### 8.4 `AUTH_REJECT` (device → host)

Sent when the user declines, the biometric check fails, or the device refuses on
policy grounds (unknown host, rate limit, unsupported protocol).

| Key | Type | Constraint |
|---|---|---|
| `request_id` | bstr | 16 bytes |
| `reason` | uint | §9 error code |

Rejection MUST be the default on any device-side error. A device MUST NOT sign a
request it has not presented to the user, and MUST NOT sign requests that arrive
while another prompt for the same user is already open (§ rate limiting).

### 8.5 Canonical CBOR encoding (normative)

The encoding is **CTAP2 canonical CBOR**, restricted to a safe subset:

Allowed major types: 0 (unsigned int), 1 (negative int), 2 (byte string),
3 (text string), 4 (array), 5 (map), plus the simple values `false` (0xF4) and
`true` (0xF5).

| Rule | Requirement |
|---|---|
| R1 Definite lengths | Indefinite-length strings, arrays and maps are FORBIDDEN. |
| R2 Shortest integers | Integers MUST use the shortest encoding. `0` is one byte; `23` is one byte; `24` is `0x18 0x18`. |
| R3 Negative integers | Encoded as `-1 - n`, shortest form. |
| R4 Map key order | Keys MUST be sorted by their **encoded key bytes**, bytewise lexicographic, shorter-is-smaller on a prefix. For text keys this means shorter keys first, then bytewise. |
| R5 Unique keys | Duplicate keys are FORBIDDEN. |
| R6 No tags | Tags (major type 6) are FORBIDDEN. |
| R7 No floats/indefinite | Floating point (major type 7, except bool) and `undefined` are FORBIDDEN. |
| R8 Nested sort | Nested maps follow R1–R7 recursively. |

A decoder MUST reject any input violating R1–R8. This is a security requirement,
not a strictness preference: it guarantees **exactly one byte string** can
represent a given logical message, which is what makes "sign the encoding"
equivalent to "sign the request".

### 8.6 Canonical text

Text strings MUST be the shortest form of themselves: a UTF-8 string MUST NOT
start with a byte sequence that is an overlong encoding of a shorter sequence,
MUST NOT contain surrogate code points (`U+D800`–`U+DFFF`), and MUST NOT encode
a code point above `U+10FFFF`. Decoders MUST reject violations. This prevents two
distinct byte strings from denoting the same `username`.

---

## 9. Errors

`ERROR` payload:

| Key | Type | Constraint |
|---|---|---|
| `code` | uint | code below |
| `message` | tstr | 0–256 chars, diagnostic only, never localised policy |
| `request_id` | bstr | 16 bytes, when the error answers a known request |

| Code | Name | Meaning |
|---|---|---|
| 1 | `BAD_REQUEST` | Malformed frame or payload |
| 2 | `UNSUPPORTED_VERSION` | Unknown `protocol_version`, or nonzero `flags` |
| 3 | `UNKNOWN_MESSAGE` | Unassigned message type |
| 4 | `NOT_PAIRED` | Host is not a paired device |
| 5 | `REVOKED` | Host was revoked by the operator |
| 6 | `USER_CANCELLED` | User declined the prompt |
| 7 | `BIOMETRIC_FAILED` | Biometric check failed or unavailable |
| 8 | `RATE_LIMITED` | Too many attempts (§12) |
| 9 | `EXPIRED` | Request past `expires_at` |
| 10 | `REPLAY` | `request_id` or `challenge` already used |
| 11 | `SIGNATURE_INVALID` | Signature verification failed |
| 12 | `CONTEXT_MISMATCH` | Signed context disagrees with the request |
| 13 | `INTERNAL` | Unexpected internal error |

Every failure mode fails **closed**: `NOT_PAIRED`, `REVOKED`, `EXPIRED`,
`REPLAY`, `SIGNATURE_INVALID` and `CONTEXT_MISMATCH` MUST deny. The protocol layer
MUST NOT convert a protocol failure into a success under any circumstance, and
MUST NOT emit a "retry" that would reuse the same `challenge`.

---

## 10. Replay protection

The host MUST maintain, per device, a record of consumed values and MUST reject a
response whose `request_id` **or** `challenge` was already consumed:

* one outstanding request per `device_id` at a time;
* `request_id`: 16 random bytes, never reused for the lifetime of the device;
* `challenge`: 32 random bytes, never reused for the lifetime of the device;
* consumed values are retained for at least `MAX_NONCE_AGE` (§11) and pruned
  only after that window;
* a `challenge` is consumed **before** the signature is verified, so that a
  replay is rejected even when the replayed signature is byte-identical;
* a rejected or timed-out request also consumes its `challenge`.

A signature is valid only for the exact outstanding `AUTH_REQUEST` it answers.
There is no mechanism by which a valid response can authorise a later, different
request, a different user, a different host, a different purpose, a different
service, or a different operation.

---

## 11. Limits

| Constant | Value | Rationale |
|---|---|---|
| `MAX_FRAME_PAYLOAD` | 65536 bytes | one authentication message, bounded memory |
| `CHALLENGE_LEN` | 32 bytes | 256-bit freshness |
| `REQUEST_ID_LEN` | 16 bytes | 128-bit uniqueness |
| `HOST_ID_LEN` / `DEVICE_ID_LEN` | 16 bytes | 128-bit identity |
| `PAIRING_CODE_DIGITS` | 6 | transcribable by a human under time pressure |
| `PAIRING_TTL` | 120 s | pairing session lifetime |
| `AUTH_REQUEST_TTL_DEFAULT` | 60 s | time for a human to complete a fingerprint check |
| `AUTH_REQUEST_TTL_MAX` | 300 s | hard ceiling |
| `MAX_NONCE_AGE` | 600 s | how long consumed ids/challenges are retained |
| `CLOCK_SKEW` | 30 s | tolerance on `issued_at`; `expires_at` is **not** extended by skew |
| `CLOCK_SKEW_STRICT` | 10 s | BLE transport is slower and less reliable |
| `RATE_PAIRING` | 5 / 5 min | per host address |
| `RATE_AUTH` | 5 / 60 s | per device per user |
| `RATE_DEVICE_PROMPT` | 1 open prompt | per device, queue depth 1 |
| `MIN_PAIRED_DEVICES_PER_HOST` | 8 | several devices; §11.3 |
| `MIN_PAIRED_HOSTS_PER_DEVICE` | 8 | a laptop, a desktop and a VM; §11.3 |

### 11.1 Freshness window

A request is acceptable when:

```text
issued_at - CLOCK_SKEW        <= now
now                         <= expires_at + CLOCK_SKEW_STRICT
```

`expires_at` MUST be within `AUTH_REQUEST_TTL_DEFAULT` of `issued_at` and MUST
NOT exceed `AUTH_REQUEST_TTL_MAX`.

### 11.2 Key ids

`host_id` and `device_id` are random; they are **not** derived from the key. When
a device key is replaced, the device generates a new `device_id` and MUST re-pair.

### 11.3 Multiplicity and identity scope

This section states what one id identifies, because "how many devices and how many
PCs" is otherwise left to each implementation and the two sides drift apart.

**Cardinality.** A host MAY hold records for any number of devices, and a device
MAY hold records for any number of hosts. Neither side imposes a limit of one.
Both MUST support at least 8 simultaneously, and MUST NOT assume the peer holds
only one record: a host with four paired devices and a device paired to three PCs are
ordinary configurations, not errors.

**What `device_id` identifies.** One *device*, for the lifetime of its device key.
It is **not** scoped per host. A device presents the same `device_id` to every host
it pairs with, because `device_id` is what discovery advertises (§13.1); an id that
changed per host could not be advertised at all. Consequently `device_id` is a
stable correlation identifier across the hosts a device talks to, and MUST be
treated as such: implementations MUST NOT treat seeing a known `device_id` on a
second host as evidence that the second host is trusted.

**What `host_id` identifies.** One *host*, for the lifetime of its host key. A
device MUST hold one record per host: `host_id`, the host's public key, and that
host's pinned TLS material. A host MUST NOT be able to overwrite another host's
record on the device; pairing a second host MUST leave the first intact.

**Consequence for trust.** Each side trusts only the records it holds. A device
that trusts host A gains nothing about host B: possession of host A's key MUST NOT
authenticate a session claiming to be host B, and the pairing transcript is bound
to `host_id`, so a transcript captured from one pairing MUST NOT validate another.

**Revocation scope.** Revocation removes exactly one `(host, device)` pair. A host
revoking a device MUST NOT affect that device's records on any other host, and a
device removing a host MUST NOT affect that host's records for any other device.
Implementations SHOULD surface a revoked device to the user rather than deleting the
record silently, because a device that vanishes from the list is indistinguishable
from one that was factory-reset.

**Re-pairing.** Re-pairing an existing `(host_id, device_id)` pair with the **same**
key on both sides updates metadata (label, timestamps) and MUST NOT be treated as
an error. Re-pairing an id already known with a **different** key MUST be refused
(§11.4 step 3), unless a valid `cleanup_token` in the same submit first revokes the
old record (§6.6). A token is a bearer cleanup capability, not proof of
same-installation identity; without one, the old record must be revoked by the host
operator. A user who replaced their device's key therefore gets a refusal rather
than a silently new identity, which is the point.

**Rate limiting.** `RATE_PAIRING` and `RATE_AUTH` are counted per
`(host, device)` pair, not globally on either side. A user with several paired PCs
MUST NOT have one busy machine consume the whole budget, and an attacker MUST NOT be
able to exhaust a device's budget by flooding it from a host the user has never
paired.

### 11.4 Ordering requirement (host, on `PAIRING_SUBMIT`)

1. Verify `mac_d` against the session secret (§6.4).
2. Process `cleanup_tokens`: revoke every old record whose stored token hash
   matches. Invalid tokens are ignored and audited.
3. Check the device is not already known with a different key among records that
   remain paired.
4. Check `device_id` is not already registered to a different key among records
   that remain paired.
5. **Only then** persist the device record and increment pairing rate limit.

Verification precedes persistence. A failed `mac_d` MUST NOT create a registry
entry, not even a "pending" one, and MUST NOT revoke anything through
`cleanup_tokens`.

---

## 12. Rate limiting

Hosts MUST rate limit pairing attempts and authentication attempts and MUST count
malformed frames, unsupported versions, and signature failures. Exceeding a limit
MUST produce `RATE_LIMITED` and MUST NOT prompt the user.

Devices MUST hold at most one open prompt, MUST refuse a second concurrent
request for the same session, and MUST NOT auto-fire prompts on receipt of a
frame: a request becomes a prompt only when the signed context can be displayed
to the user. A flood results in `RATE_LIMITED`, not a flood of dialogs.

---

## 13. Transport rules

The protocol is transport-independent. Transport selection changes nothing in
§3–§12.

### 13.1 Wi-Fi

```text
mDNS/DNS-SD discovery  ->  TCP  ->  TLS 1.3  ->  this protocol
```

Discovery advertises only non-secret metadata:

Service type: `_rba._tcp.local.`

| TXT key | Value |
|---|---|
| `v` | `1` |
| `id` | `device_id` as hex |
| `name` | host label, informational; SHOULD be the machine hostname |
| `fp` | first 16 hex chars of `key_id` |
| `caps` | `auth` |

MUST NOT be published: keys, secrets, tokens, usernames, or derived material.
The `name` label is operator-facing only and MUST NOT be treated as identity or
trust evidence; the paired key and TLS pin remain authoritative.

The TLS peer MUST be verified against the paired host identity. Because a
self-signed host certificate with a self-generated keypair cannot by itself be
mapped onto a Keystore-resident key, the host's TLS key is a **separate,
pinned-at-pairing-time** transport credential, and the authoritative
authentication decision remains the §8.2 signature. Pinning, not the public PKI,
is what defeats a MITM proxy: an attacker presenting its own certificate fails
pinning even if TLS negotiates successfully. "TLS connected" is never an
authentication result.

### 13.2 BLE

```text
BLE scan (discovery only)  ->  GATT  ->  this protocol
```

| Concept | UUID (128-bit, project-assigned) |
|---|---|
| Service | `8f1c0001-9d2b-4a7e-b0c4-5f6a71c3d801` |
| RX (host → device) characteristic | `8f1c0002-9d2b-4a7e-b0c4-5f6a71c3d801` |
| TX (device → host) characteristic | `8f1c0003-9d2b-4a7e-b0c4-5f6a71c3d801` |

BLE characteristics carry at most 20 bytes of payload, so **frames are
segmented**: the transport adapter splits a frame into segments and reassembles
identical frames on the other side. The frame format of §4 is unchanged and the
adapter MUST NOT alter frame bytes. Segmentation is an adapter concern; the
protocol above it is byte-identical to Wi-Fi.

Identity MUST NOT be taken from: device name, MAC address, resolvable private
address, advertised local name, or service UUID. Identity is the paired public
key, verified per §8.2. BLE link encryption SHOULD be used but MUST NOT be
relied upon.

---

## 14. Host-side local IPC contract

The daemon exposes a Unix domain socket. It is connectable by **any local user**;
filesystem permissions are not the user boundary. Every request is authorised from
the caller's kernel credentials and the device's account binding. Local
authorisation decisions:

1. A request MUST be bound to the **verified peer credentials** (`SO_PEERCRED`),
   never to a username supplied in the request body.
2. If the peer is not root, the requested `username` MUST resolve, via the
   local user database, to the same UID as the peer. Mismatch MUST deny with
   `CONTEXT_MISMATCH`.
3. `username` is used for the *signed request context*; the *authenticated
   principal* is always the peer UID.
4. A device MAY authenticate only the accounts in its host-side policy. Pairing
   binds the device to the local principal that opened the session; `root` is
   denied unless the operator explicitly opted in at pairing time. A request for
   an account outside the policy MUST deny with `CONTEXT_MISMATCH` before any
   challenge is issued, even when the peer is root.
5. Pairing codes and confirmation belong to the principal that opened the
   session; another local caller MUST NOT read, confirm or cancel it. Revocation
   is root-only.

Rules 1–3 stop an unprivileged process from asking the daemon to authenticate as
another user. Rule 4 stops a paired device from becoming a host-wide approval
oracle for accounts it was never paired to.

---

## 15. Logging rules

MUST log: device label, `device_id` hex, username, purpose, service, result,
`request_id` hex, transport, timings.

MUST NOT log: private keys, session secrets, `challenge` values, signatures,
pairing codes or MACs, `revocation_token` or `cleanup_tokens`, TLS payloads,
biometric data.

Anyone with the logs MUST NOT be able to reconstruct a credential. Since
`challenge` values are single-use, logging them is unnecessary risk; the
`request_id` is sufficient to correlate.

---

## 16. Conformance test vectors

`protocol/test-vectors/` contains JSON fixtures covering: valid request, valid
signature, invalid signature, wrong device, wrong host, wrong user, wrong
purpose, wrong operation, wrong service, expired request, future `issued_at`,
replayed request, malformed frame, unsupported version, unknown message,
non-canonical CBOR (each of R1–R8), canonical-encoding edge cases, pairing MAC
computation, and the signing-input digest.

Both implementations MUST pass all vectors. A vector file records the
canonical `sig_input` and its SHA-256 digest so that an implementation can be
checked for byte-exact agreement without reproducing the ECDSA operation.

---

## 17. Version policy

* `protocol_version` is a single integer, currently `1`.
* A receiver MUST reject any version it does not implement. It MUST NOT attempt
  a best-effort parse.
* Breaking changes get a new integer. Adding optional fields requires updating
  this document, both implementations, and the vectors atomically.