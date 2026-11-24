# Pairing — six-digit SPAKE2 enrollment

The default `rba pair` displays a random six-digit code on the host; type it
on the authenticator. `rba pair --code-entry host` displays the code on the
phone; enter it at the host terminal and confirm Allow on the phone.
No camera is required. Leading zeros matter. Codes are single-use and expire.

The enrollment profile is specified in [PROTOCOL.md §6](../protocol/specification/PROTOCOL.md#6-pairing-spake2-enrollment-profile-v2).
The portable Rust implementation uses RFC 9382 SPAKE2 via pakery, and Android
calls it through a narrow JNI boundary. No custom curve arithmetic or legacy
SAS pairing fallback is used. The actual TLS server certificate and both
identities and public keys are bound to the confirmation. TLS enrollment
is required; non-TLS transports cannot use this profile without a properly
specified channel binding.

The host stages enrollment after mutual confirmation. The phone persists the
verified record and acknowledges; the host commits and returns a receipt.
Both sides report completion only at their respective commit/receipt points.
If a connection fails before acknowledgement, the host discards the pending
record. A lost final receipt can require re-enrollment; revoke stale trust
explicitly. Existing previously enrolled credentials are not automatically
upgraded to SPAKE2 assurance. Re-enroll them for the new assurance baseline.

A six-digit secret permits a limited online guess per admitted exchange, not
arbitrary offline dictionary testing of a captured exchange under the PAKE
security assumptions. The durable pairing budget limits session creation.
Do not disclose codes or copy them into argv or logs. Neither PAKE nor TLS
proves hardware-backed biometric assurance; SEC-005 is separate.

Integration candidate: verify both directions, storage failures, cancellation,
wrong codes and real Android JNI packaging before release. See
[SEC-026-SPAKE2.md](SEC-026-SPAKE2.md).
