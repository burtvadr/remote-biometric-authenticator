#!/usr/bin/env bash
# Proves the thing the whole project actually wants: a password prompt anywhere on the
# system authenticates with the device, with no per-service editing.
#
# The single insertion into /etc/pam.d/common-auth is the entire change. Debian and
# Ubuntu deliberately factor every auth stack through it, and /etc/pam.d/other is the
# fallback for any service with no file of its own -- which is why polkit, whose service
# name is "polkit-1", is covered even though no such file exists.
#
# This is the same mechanism pam_fprintd uses, and it is why a fingerprint reader works
# in sudo, the login screen and a GNOME polkit dialog without anyone editing those
# stacks.
#
# Backups up common-auth and restores it on exit, however it exits.
set -uo pipefail

REPO="${RBA_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
B="$REPO/linux/target/debug"
SECDIR=/usr/lib/x86_64-linux-gnu/security
COMMON=/etc/pam.d/common-auth
BAK=$COMMON.rba.bak
SOCKET=/run/rba/control.sock
W=/var/tmp/rba-common
PORT="${RBA_PORT:-48201}"

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


cleanup() {
    kill_groups
    if [ -f "$BAK" ]; then
        cat "$BAK" > "$COMMON"
        rm -f "$BAK"
        echo
        echo "Restored $COMMON from backup."
        echo "rba references now: $(grep -c rba "$COMMON" || true)"
    fi
    return 0
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM HUP

ME="${RBA_TEST_USER:-${SUDO_USER:-user}}"
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

echo "=== one-line common-auth test (edits $COMMON, restores it on exit) ==="
[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }

# Restarts the daemon and simulator with a chosen behaviour.
#
# Restarting rather than sleeping is deliberate: it resets RATE_AUTH, so each phase
# starts with a full budget and a rate-limited request cannot be mistaken for a declined
# one. Sleeping out a 60s window would work but makes the test slow and its failures
# dependent on timing.
restart_stack() {
    local behaviour="$1" log="$2"
    kill_groups
    spawn_asuser "$B/rbad" --state-dir "$W/state" --socket "$SOCKET" \
        --audit-log "$W/audit.log" --port "$PORT" --bind "127.0.0.1:$PORT" --no-mdns \
        >>"$W/daemon.log" 2>&1
    for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 0.2; done
    sleep 1
    spawn_asuser "$B/rba-sim" serve --host "127.0.0.1:$PORT" --name "Pixel 9" \
        --ca "$W/state/host.crt" --timeout 600 --behaviour "$behaviour" >"$log" 2>&1
    sleep 2
}

step "install the module"
( cd "$REPO/linux" && cargo build --release -p pam-rba ) >/dev/null 2>&1
install -m 0755 "$REPO/linux/target/release/libpam_rba.so" "$SECDIR/pam_rba.so"
echo "  installed $(ls -la "$SECDIR/pam_rba.so" | awk '{print $5}') bytes"

step "start the daemon and pair a simulator"
require_free_socket "$SOCKET"

rm -rf "$W"; mkdir -p "$W" /run/rba; chown "$ME":"$ME" "$W" /run/rba
rm -f /tmp/rba-sim-*.json
spawn_asuser "$B/rbad" --state-dir "$W/state" --socket "$SOCKET" --audit-log "$W/audit.log" \
    --port "$PORT" --bind "127.0.0.1:$PORT" --no-mdns >"$W/daemon.log" 2>&1
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 0.2; done
asuser "$B/rba" --socket "$SOCKET" pair --yes --timeout 45000 >"$W/pair.log" 2>&1 &
PAIR=$!
sleep 1
sed -n 's/^Code: \([0-9]\{6\}\).*/\1/p' "$W/pair.log" | asuser timeout 45 "$B/rba-sim" pair --host "127.0.0.1:$PORT" --name "Pixel 9" \
    --daemon "$B/rbad" --daemon-arg --state-dir --daemon-arg "$W/state" >"$W/simpair.log" 2>&1
wait $PAIR
ok "paired"
echo 1234 | sudo -S -p "" chown "$ME":"$ME" "$W/pair.log" 2>/dev/null

restart_stack approve "$W/sim.log"

step "insert one sufficient line into common-auth"
cp -a "$COMMON" "$BAK"
python3 - "$COMMON" <<'PY'
import sys
path = sys.argv[1]
lines = open(path).read().splitlines()
line = "auth\tsufficient\tpam_rba.so purpose=auth debug"
out, done = [], False
for l in lines:
    # Before the per-package block, which is the place pam-auth-update's own comment
    # recommends for a local module.
    if not done and l.startswith("auth") and "pam_unix" in l:
        out.append("# Android remote authenticator (inserted by the rba test; remove to roll back)")
        out.append(line)
        done = True
    out.append(l)
if not done:
    sys.exit("no pam_unix line to insert before; refusing to guess")
open(path, "w").write("\n".join(out) + "\n")
PY
grep -nE '^\s*auth' "$COMMON" | head -4 | sed 's/^/    /'

# The harness performs exactly the calls polkitd makes: pam_start(<service>) then
# pam_authenticate. polkitd's service name is "polkit-1", which has no file and so
# resolves through /etc/pam.d/other to common-auth.
gcc -O2 -o "$W/pam-test" "$REPO/tests/pam-test.c" -lpam

step "authenticate through each real service, as that service's own stack"
# gdm-password is GNOME's screen unlock. polkit-1 is GNOME's admin dialog. sudo and
# login are the obvious ones. None of these files is edited: they all include
# common-auth.
# No file-existence guard on purpose. polkit-1 has no /etc/pam.d file at all, and that
# is exactly why it is the interesting case: libpam falls back to /etc/pam.d/other,
# which includes common-auth. Skipping services with no file would silently drop the one
# this whole approach exists to cover.
# Five services, which is exactly the RATE_AUTH budget of 5 per 60s per device per
# user. Going past it is not a bug -- see the rate-limit assertion below -- but it does
# mean this list cannot simply grow.
for svc in polkit-1 gdm-password sudo login su; do
    if [ ! -f "/etc/pam.d/$svc" ]; then
        echo "    | $svc -> (no service file; libpam falls back to other -> common-auth)"
    fi
    out=$(asuser "$W/pam-test" "$svc" "$ME" 2>&1); rc=$?
    verdict=$(printf '%s' "$out" | grep -oE 'authenticate: [A-Z_]+ \([0-9]+\)' | head -1)
    echo "    | $svc -> ${verdict:-<no verdict>}"
    if [ $rc -eq 0 ]; then ok "$svc authenticated on the device's word"
    else bad "$svc did not authenticate (rc=$rc)"; fi
done

step "the sixth prompt in a minute must be rate-limited, not prompted for"
# RATE_AUTH is 5 per 60s per device per user (PROTOCOL §12). The five services above
# spend the whole budget, so this one must be refused *without* disturbing the device --
# which is the property that matters: a flood of requests must not turn into a flood of
# fingerprint dialogs on someone's device.
out=$(asuser "$W/pam-test" sudo "$ME" 2>&1); rc=$?
echo "    | $(printf '%s' "$out" | grep -oE 'authenticate: [A-Z_]+ \([0-9]+\)' | head -1)"
if [ $rc -ne 0 ] && grep -q '"code":"RATE_LIMITED"' "$W/audit.log"; then
    ok "the sixth prompt was rate-limited and recorded as RATE_LIMITED"
else
    bad "expected RATE_LIMITED on the sixth prompt"
fi
BEFORE_PROMPTS=$(grep -c 'Authorize:' "$W/sim.log" 2>/dev/null || echo 0)
out=$(asuser "$W/pam-test" login "$ME" 2>&1) || true
AFTER_PROMPTS=$(grep -c 'Authorize:' "$W/sim.log" 2>/dev/null || echo 0)
if [ "$BEFORE_PROMPTS" = "$AFTER_PROMPTS" ]; then
    ok "a rate-limited request never reached the device ($AFTER_PROMPTS prompts total)"
else
    bad "a rate-limited request still prompted the device ($BEFORE -> $AFTER)"
fi

step "the device declines: every one of those must fall back to the password"
# A fresh daemon, so this exercises the decline rather than the rate limit.
restart_stack deny "$W/sim2.log"
out=$(asuser "$W/pam-test" sudo "$ME" 2>&1); rc=$?
echo "    | $(printf '%s' "$out" | grep -oE 'authenticate: [A-Z_]+ \([0-9]+\)' | head -1)"
if [ $rc -ne 0 ]; then
    ok "a decline did not authenticate; the stack fell through to the password"
else
    bad "authenticated despite the device declining"
fi

step "audit trail"
if [ -f "$W/audit.log" ]; then
    grep '"kind":"auth"' "$W/audit.log" | python3 -c "
import sys, json
for l in sys.stdin:
    r = json.loads(l)
    print(f\"    {r['result']:8s} user={r.get('user')} service={r.get('service')} code={r.get('code','-')}\")"
    if grep -Eqi '"(challenge|signature|mac|private_key)"[[:space:]]*:' "$W/audit.log"; then
        bad "the audit log contains credential material"
    else
        ok "the audit log carries no credential material"
    fi
fi

echo
echo "=== $pass passed, $fail failed (common-auth restored on exit) ==="
[ "$fail" -eq 0 ]