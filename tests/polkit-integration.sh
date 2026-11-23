#!/usr/bin/env bash
# polkit integration test.
#
# Registers a real authentication agent with the running polkitd over the system bus
# and drives a real authorization through it:
#
#   pkcheck -> polkitd -> Authenticate() -> rba-polkit-agent
#           -> rbad -> TLS -> rba-sim
#           -> agent -> CheckAuthorization() -> polkitd -> decision
#
# The test uses its own action id, its own rule file and its own policy file, and
# removes all three on exit. It does not touch any system action, so nothing here can
# change what a desktop session is permitted to do.
#
# KNOWN GAP: registration is verified here; *routing* is blocked by polkit.
#
# What is confirmed: the agent exports the right interface and polkitd accepts the
# registration. What does not work: polkitd never delivers a challenge to it.
#
# Two polkit behaviours, both measured rather than guessed:
#
#   * one authentication agent per subject -- gnome-shell already holds the active seat
#     session, so registering there returns "An authentication agent already exists";
#   * an agent on an inactive session is not offered challenges. This test runs in an
#     inactive session, so polkitd logs the operator "FAILED to authenticate" and no
#     Authenticate is ever delivered.
#
# Steps A and B therefore fail, and a green run here must not be read as "polkit is
# done". See docs/threat-model.md for the full finding and what it means for the
# product.
#
# It also asserts the negative cases, which matter more than the positive one: an
# action must not be authorized after the device declines, and it must not stay
# authorized once the agent that granted it is gone. An authorization that outlives its
# evidence is the failure mode that actually bites.
set -uo pipefail

REPO="${RBA_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BIN="$REPO/linux/target/debug"
SOCKET=/run/rba/control.sock
RULE=/etc/polkit-1/rules.d/50-rba-test.rules
# polkitd's compiled-in search path is /usr/share/polkit-1/actions,
# /etc/polkit-1/actions and /run/polkit-1/actions. It does NOT read
# /usr/share/polkit-1/actions.d -- despite that directory existing here -- so a policy
# written there is silently ignored and the action never exists.
#
# Of those three, only /usr/share/polkit-1/actions works for a test fixture. polkitd
# watches the directories that existed when it started, and /run/polkit-1/actions does
# not exist at boot, so creating it later fires no file-monitor events and the action
# never appears -- which looks exactly like the agent failing. The file is removed on
# exit, and the name makes its origin obvious.
POLICY=/usr/share/polkit-1/actions/io.github.burtvadr.rba.test.policy
WORK="${RBA_POLKIT_WORK:-/var/tmp/rba-polkit}"
PORT="${RBA_POLKIT_PORT:-47951}"
ACTION=io.github.burtvadr.rba.test

# pkcheck must name a process owned by the user running it. Using the script's own
# pid does not work: the script is root while pkcheck is not, and polkit rejects a
# caller that tries to check another identity ("Only trusted callers ...").
#
# The backgrounded sleep must not inherit stdout: a command substitution waits for
# every writer to close it, so leaving it attached hangs the whole script for the
# sleep's full duration.
subject_pid() {
    asuser bash -c 'sleep 600 >/dev/null 2>&1 & echo $!'
}

pass=0; fail=0
ok()  { echo "  PASS: $*"; pass=$((pass+1)); }
bad() { echo "  FAIL: $*"; fail=$((fail+1)); }
step(){ echo; echo "=== $* ==="; }

SPAWNED_GROUPS=()
DAEMON_PID=""; SIM_PID=""
# Starts a long-running helper in its own process group and records the group id.
#
# `$!` alone is not enough when the helper is launched through sudo: it captures the
# sudo wrapper, and killing that leaves the real daemon running. A leaked daemon keeps
# holding /run/rba/control.sock, so the next run talks to a *stale* daemon on a
# different port -- which does not fail loudly, it pairs against the wrong process and
# reports success. That is a false pass, which is worse than a failure.
spawn_grouped() {
    setsid "$@" &
    SPAWNED_GROUPS+=("$!")
}

# spawn_grouped, but as the ordinary user. Written out rather than calling `asuser`
# because setsid execs a program, not a shell function: handing it `asuser` fails with
# "setsid: failed to execute asuser" and the daemon silently never starts.
spawn_asuser() {
    spawn_grouped /usr/sbin/runuser -u "$ME" -- "$@"
}
kill_groups() {
    local g
    for g in "${SPAWNED_GROUPS[@]:-}"; do
        [ -n "$g" ] && kill -TERM -- "-$g" 2>/dev/null
    done
    sleep 0.3
    for g in "${SPAWNED_GROUPS[@]:-}"; do
        [ -n "$g" ] && kill -KILL -- "-$g" 2>/dev/null
    done
    SPAWNED_GROUPS=()
}
AGENT_PID=""

cleanup() {
    # Unregistering on SIGTERM is handled inside the agent; kill_groups is the belt to
    # that braces, in case it is killed uncleanly.
    kill_groups
    rm -f "$RULE" "$POLICY"
    return 0
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM HUP

# This script needs root to install the action and rule files, but polkit authorizes
# root unconditionally -- a root pkcheck would succeed without ever consulting an
# agent, which would make every assertion here vacuous. So the interactive half runs
# as an ordinary admin user.
ME="${RBA_TEST_USER:-${SUDO_USER:-user}}"
if [ "$(id -u)" -eq 0 ] && [ "$ME" = root ]; then
    echo "need a non-root admin user; set RBA_TEST_USER" >&2
    exit 1
fi
# runuser by absolute path, and a real binary rather than a shell function: spawn_grouped
# hands the command to setsid, which can only exec a program. A function here fails with
# "setsid: failed to execute asuser" and the daemon silently never starts.
asuser() { /usr/sbin/runuser -u "$ME" -- "$@"; }

# Refuse to run if something already owns the control socket.
#
# A daemon left behind by an interrupted run keeps the socket, so this run's own daemon
# fails to bind it and every request quietly goes to the *old* daemon instead. The
# pairing still succeeds and the assertions still pass, against the wrong process.
# That is a false pass, so it is checked rather than assumed.
require_free_socket() {
    local sock="$1"
    if [ -S "$sock" ] && asuser rba --socket "$sock" status >/dev/null 2>&1; then
        echo "ERROR: something is already serving $sock." >&2
        echo "       A previous run leaked a daemon. Stop it first, or the test would" >&2
        echo "       silently exercise that one instead of a fresh daemon." >&2
        exit 1
    fi
    rm -f "$sock"
}

echo "=== polkit integration (as $ME, agent and daemon unprivileged) ==="
[ "$(id -u)" -eq 0 ] || { echo "must run as root: the action and rule files live under /etc and /usr/share"; exit 1; }

step "state before: can this action be authorized without any agent?"
before=$(asuser pkcheck -p "$(subject_pid)" --action-id "$ACTION" 2>&1); rc=$?
echo "    | $before (rc=$rc)"
if [ $rc -ne 0 ]; then
    ok "the action is refused without authentication, so a success later means something"
else
    bad "the action is already allowed; the test would prove nothing"
fi

step "declare the test action and a rule requiring admin authentication"
# An action id that has no .policy file is not a registered action at all: pkcheck
# fails with "Action ... is not registered" and never reaches the agent. The policy
# declares it and asks for admin authentication; the rule makes the requirement
# explicit and independent of the emulated backend's defaults.
mkdir -p /etc/polkit-1/rules.d /usr/share/polkit-1/actions
cat > "$POLICY" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>Android Remote Authenticator</vendor>
  <action id="$ACTION">
    <description>Device authenticator integration test</description>
    <message>Authentication is required for the device authenticator test action</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
  </action>
</policyconfig>
EOF
cat > "$RULE" <<EOF
// Temporary rule for the authenticator integration test. Removed on exit.
polkit.addRule(function (action, subject) {
    if (action.id == "$ACTION") {
        return polkit.Result.AUTH_ADMIN;
    }
});
EOF
echo "    | wrote $RULE"

# polkitd caches its action list and reloads it by watching the directories, so the
# action is not usable the instant the file lands. Poll briefly instead of asserting
# against a stale cache, which would otherwise look like the agent failing.
before=""
for _ in $(seq 1 20); do
    before=$(asuser pkcheck -p "$(subject_pid)" --action-id "$ACTION" --allow-user-interaction 2>&1) && rc=0 || rc=$?
    case "$before" in
        *"is not registered"*) sleep 0.5 ;;
        *) break ;;
    esac
done
echo "    | $before (rc=$rc)"
if [ $rc -ne 0 ] && echo "$before" | grep -qi 'agent'; then
    ok "polkit now requires an agent, which is exactly what this test provides"
else
    bad "expected polkit to report that no agent is available, got: $before"
fi

step "start the daemon and pair a simulator"
require_free_socket "$SOCKET"

rm -rf "$WORK"; mkdir -p "$WORK"
# /run may already hold a socket from an earlier test; it is root-owned, so this has
# to happen as root rather than being done by the daemon.
rm -rf /run/rba; mkdir -p /run/rba
chown "$ME":"$ME" "$WORK" /run/rba
rm -f /tmp/rba-sim-*.json
start_daemon() {
    spawn_asuser "$BIN/rbad" --state-dir "$WORK/state" --socket "$SOCKET" --audit-log "$WORK/audit.log" \
        --port "$PORT" --bind "127.0.0.1:$PORT" --no-mdns >"$WORK/daemon.log" 2>&1
    for _ in $(seq 1 60); do [ -S "$SOCKET" ] && return 0; sleep 0.2; done
    echo "daemon failed to start"; cat "$WORK/daemon.log"; exit 1
}
start_daemon
asuser "$BIN/rba" --socket "$SOCKET" pair --yes --timeout 45000 >"$WORK/pair.log" 2>&1 &
PAIR=$!
sleep 1
asuser timeout 45 "$BIN/rba-sim" pair --host "127.0.0.1:$PORT" --name "Pixel 9" \
    --daemon "$BIN/rbad" --daemon-arg --state-dir --daemon-arg "$WORK/state" \
    >"$WORK/simpair.log" 2>&1
wait $PAIR
ok "paired"

serve() {
    spawn_asuser "$BIN/rba-sim" serve --host "127.0.0.1:$PORT" --name "Pixel 9" \
        --ca "$WORK/state/host.crt" --timeout "$1" --behaviour "$2" >"$WORK/sim.log" 2>&1
    sleep 1.5
}
stop_sim() { kill_groups; }

step "A. the device approves: polkit authorizes the action"
serve 90 approve
spawn_asuser "$BIN/rba-polkit-agent" --socket "$SOCKET" >"$WORK/agent.log" 2>&1
for _ in $(seq 1 40); do grep -q 'waiting for challenges' "$WORK/agent.log" 2>/dev/null && break; sleep 0.25; done
if grep -q 'registered with polkit' "$WORK/agent.log"; then
    ok "the agent registered with polkitd (polkitd accepted the subject and object path)"
else
    bad "the agent did not register"; sed 's/^/    | /' "$WORK/agent.log"
fi

out=$(asuser timeout 90 pkcheck -p "$(subject_pid)" --action-id "$ACTION" --allow-user-interaction 2>&1); rc=$?
echo "    | $out (rc=$rc)"
if [ $rc -eq 0 ]; then
    ok "pkcheck was authorized after the device authenticated the user"
elif echo "$out" | grep -q 'no agent is available'; then
    bad "polkitd registered no eligible agent: it says none is available for this subject.
         The agent registered successfully, so this is polkit deciding the agent is not
         eligible for this session, not the agent failing to register. See the note at
         the top of this script."
else
    bad "pkcheck was not authorized (rc=$rc)"
fi
if grep -q 'authenticated' "$WORK/agent.log"; then
    ok "the agent reports the device authenticated the challenge"
else
    bad "the agent never authenticated"; sed 's/^/    | /' "$WORK/agent.log"
fi
if grep -q 'Authorize:' "$WORK/sim.log"; then
    ok "the device was asked, naming the action: $(grep -m1 'Authorize:' "$WORK/sim.log" | sed 's/.*Authorize: //')"
else
    bad "the device was never asked"
fi
if grep -q '"service":"'"$ACTION"'"' "$WORK/audit.log" 2>/dev/null; then
    ok "the daemon recorded the polkit action id as the service"
else
    bad "no audit record naming the action"
fi
stop_sim

step "B. the device declines: polkit must refuse"
serve 90 deny
out=$(asuser timeout 90 pkcheck -p "$(subject_pid)" --action-id "$ACTION" --allow-user-interaction 2>&1); rc=$?
stop_sim
echo "    | $out (rc=$rc)"
if [ $rc -ne 0 ]; then
    ok "polkit refused after the device declined"
else
    bad "polkit authorized even though the device declined"
fi
if grep -q '"code":"USER_CANCELLED"' "$WORK/audit.log" 2>/dev/null; then
    ok "the decline is in the audit log"
else
    bad "the decline was not recorded"
fi

step "C. no agent registered: polkit must fall back to refusing"
kill_groups
sleep 1
out=$(asuser timeout 60 pkcheck -p "$(subject_pid)" --action-id "$ACTION" --allow-user-interaction 2>&1); rc=$?
echo "    | $out (rc=$rc)"
if [ $rc -ne 0 ]; then
    ok "the action is refused again once the agent is gone"
else
    bad "the action stayed authorized with no agent: an authorisation outlived its evidence"
fi

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]