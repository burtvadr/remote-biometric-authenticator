# B.3.5 — Background authentication rendezvous

Status: source candidate, not runtime acceptance. Based on the original uploaded
snapshot plus the previously delivered patch chain through Android foreground.
The current V1 launcher, manifest and daemon are not switched by this delivery.

## Protocol correction

The old V2 HELLO_ACK identified a transport credential but did not distinguish
an authentication waiter from a policy, enrollment-recovery or revocation
connection. The new required unsigned `purpose` field is 0, 1, 2 or 3 respectively.
Both peers restrict normal inbound/outbound messages to that class. A revoked
transport pin can enter revocation only. The field is inside authenticated TLS;
it is routing metadata, never authorization. Existing pre-cutover V2 peers with
the old schema fail closed. No compatibility decoder. No database change.
The independent Python generator adds six cases (three valid alternative values,
missing field, wrong type, and unknown value).

## Host scheduler

`v2_tls::dispatch::scheduler::AuthScheduler` owns a maximum of 32 locally admitted
requests, one per credential. The future verified IPC adapter supplies LocalIntent,
locally verified source/detail, and the original receiver; submit performs Authority
admission. Remote connections do not create requests. Only a matching classified
mutually authenticated authentication-purpose channel can consume a queued route.
Authority checks the exact owner, interaction, credential and original deadline
again before dispatch; the original prompt reservation and number display remain
unchanged. Stale or disconnected callers are removed on queue access, and the
IPC owner must independently close its receiver at its operation deadline. No
queue lock is held across await. While idle, any inbound application byte or EOF
ends the wait; no read is restarted after consuming a byte. The wait is bounded
to 25 seconds to stay within the 30-second pre-auth idle profile. The scheduler
is wired into both existing real-TLS auth loopbacks. Two new Rust tests exercise
purpose partitioning and queue duplicate/disconnected-caller handling.

## Android listener and notifications

The V2 foreground activity selects one existing active credential and a manual
host endpoint, then explicitly starts the listener. The service shares the
process-wide existing startup and connection owner. Its process-memory selection
is generation-bound; no endpoint, credential, proof or policy comes from an
Intent. START_NOT_STICKY: process death/reboot stops listening. No auto boot,
full-screen intent, overlay, background biometric dialog, or approval action.
The listener reconnects no sooner than ten seconds after a completed/failed
attempt (at most six starts/minute for this one listener); healthy idle attempts
wait on the authenticated connection, not on an unauthenticated discovery probe.
A notification is published only inside the operation wire's existing cancellable
interaction, after V2Authentication.acceptRequest validates signature, exact
channel, identity, policy and expiry. Generic notification text contains no
operation details or secret. The immutable one-shot PendingIntent carries a
random in-process locator, not an approval. V2NotificationActivity is intended
nonexported, FLAG_SECURE, and only attaches after unlock. A stale, expired or
duplicate notification cannot attach. The same TLS socket and original operation
deadline survive handoff; the existing UI explicitly reviews signed context,
requires number matching and uses the actual biometric key operation. Closing
that activity cancels the whole operation. Peer EOF, unexpected messages and
expiry cancel the handoff; service stop cancels the attempt. No permission
expansion or enrollment is available in background. Notification permission
or blocked channels stop the listener. Foreground management is disabled while
the listener owns the runtime; explicit stop is available.

## Coordinated activation requirements

Do not register these alongside the legacy runtime. At cutover, use only the
V2 launcher, register `.ui.v2.V2NotificationActivity` nonexported with no intent
filters, and `.service.V2BackgroundService` nonexported with foregroundServiceType
`specialUse` and a justified PROPERTY_SPECIAL_USE_FGS_SUBTYPE. Keep the declared
foreground-service and notification permissions; remove obsolete V1 service,
receiver, overlay and full-screen-intent paths. Use the host scheduler in the
actual production listener's purpose dispatch; policy and enrollment use their
existing separately owned drivers, recovery and revoke use peer_terminal.
B.4 must connect actual IPC provenance, deadline/owner teardown and event delivery.
This patch does not enable background authentication in the active app or daemon.
Persistence/reboot auto-resume and multi-endpoint listening are not implemented;
this listener deliberately requires fresh opt-in after process death. Broader
feature requirements should be evaluated before final acceptance.

## Evidence and remaining tests

Standalone Kotlin/JDK 21 run (target 17): 745 protocol checks, including 312
message/transcript fixtures, exhaustive repertoire comparison; 24 independent
notification-gate JVM checks; host and device schema checks 8 each. The gate
checks stale token, duplicate attach, expiration, stop, owner cancellation,
and old UI release isolation. Rust, Android compile, native TLS integration,
notification permission/lifecycle tests and physical Keystore/UI testing were
not run in the delivery environment. The 2 new host tests and updated real TLS
loopbacks need Cargo verification. Check the actual device on Android API 28 and
newer: notification permission denial, lock screen, process kill, stale click,
stop during idle, disconnect before/after attach, screen backgrounding during
biometric, operation expiry, and no second owner. Test V2-only route partition,
queued caller teardown/expiry, genuine full TLS across Android and Linux, and
actual notification handoff before SEC findings may close.
