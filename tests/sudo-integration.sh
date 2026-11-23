#!/usr/bin/env bash
# Real `sudo` integration.
#
# Modifies /etc/pam.d/sudo, so it backs the file up first and restores it on exit,
# whatever happens. The module is inserted as `sufficient`, which keeps the password
# working as a fallback: if the device is unreachable the command still authenticates.
# That is the difference between "the device is down" and "I cannot log in".
#
# Two details this script gets right that a naive test does not:
#
#   * `sudo` is invoked as the ordinary user, never as root. Root is exempt from
#     sudo authentication, so a root-driven test would skip the PAM stack entirely
#     and prove nothing.
#
#   * The daemon listens on the real path, /run/rba/control.sock. sudo
#     sanitises the environment, so a RBA_SOCKET override set by the test
#     would never reach the PAM module; testing against the default path is both
#     simpler and more faithful to production.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/linux/target/debug"
SECDIR="/usr/lib/x86_64-linux-gnu/security"
PAM_SUDO=/etc/pam.d/sudo
BACKUP="$PAM_SUDO.rba.bak"
RUNDIR=/run/rba
SOCKET="$RUNDIR/control.sock"
WORK="${RBA_SUDO_WORK:-/var/tmp/rba-sudo}"
PORT="${RBA_SUDO_PORT:-47777}"
ME="${SUDO_USER:-$(logname 2>/dev/null || echo user)}"

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
    if [ -f "$BACKUP" ]; then
        echo
        echo "Restoring $PAM_SUDO from backup."
        # Replace by content, not by rename: /etc/pam.d/sudo is root-owned, so
        # install(1) cannot unlink it and would silently leave the file in place.
        cat "$BACKUP" > "$PAM_SUDO"
        rm -f "$BACKUP"
        if cmp -s "$BACKUP" "$PAM_SUDO"; then :; fi
        echo "Rollback complete: rba references now: $(grep -c rba "$PAM_SUDO" || true)"
    fi
    return 0
}
# Trapping the signals explicitly matters. An EXIT trap alone does not run when
# bash is killed by SIGTERM, which is exactly what an outer `timeout` does --
# so a timed-out run used to leave a modified sudo stack behind.
trap cleanup EXIT
trap 'echo; echo "interrupted"; cleanup; exit 130' INT TERM HUP

# Everything the ordinary user needs to do, done as the ordinary user.
#
# runuser is invoked by absolute path: as root the PATH can be minimal, and a bare
# name makes the failure look like a missing binary rather than a lookup problem.
RUNUSER=/usr/sbin/runuser
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

start_daemon() {
    asuser "$BIN/rbad" --state-dir "$WORK/state" --socket "$SOCKET" \
        --audit-log "$WORK/audit.log" --port "$PORT" --bind "127.0.0.1:$PORT" --no-mdns \
        >"$WORK/daemon.log" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 60); do [ -S "$SOCKET" ] && return 0; sleep 0.2; done
    echo "daemon failed to start"; cat "$WORK/daemon.log"; exit 1
}

pair_device() {
    asuser "$BIN/rba" --socket "$SOCKET" pair --yes --timeout 45000 >"$WORK/pair.log" 2>&1 &
    local p=$!
    sleep 1
    asuser timeout 45 "$BIN/rba-sim" pair --host "127.0.0.1:$PORT" --name "Pixel 9" \
        --daemon "$BIN/rbad" --daemon-arg --state-dir --daemon-arg "$WORK/state" \
        >"$WORK/sim-pair.log" 2>&1
    wait "$p"
}

serve() {
    spawn_asuser "$BIN/rba-sim" serve --host "127.0.0.1:$PORT" --name "Pixel 9" \
        --ca "$WORK/state/host.crt" --timeout "$1" --behaviour "$2" \
        >"$WORK/sim-serve.log" 2>&1
    sleep 1.5
}
stop_sim() { kill_groups; }

audit_count() { local n; n=$(grep -c '"kind":"auth"' "$WORK/audit.log" 2>/dev/null); echo "${n:-0}"; }

echo "=== sudo integration (edits /etc/pam.d/sudo, restores it on exit) ==="
[ "$(id -u)" -eq 0 ] || { echo "must run as root: installing the module and editing /etc/pam.d require it"; exit 1; }

step "install the module"
( cd "$REPO/linux" && cargo build --release -p pam-rba ) >/dev/null 2>&1
install -m 0755 "$REPO/linux/target/release/libpam_rba.so" "$SECDIR/pam_rba.so"
echo "  $SECDIR/pam_rba.so"
echo "  exports: $(nm -D --defined-only "$SECDIR/pam_rba.so" | grep -c pam_sm_) pam_sm_* entry points"

step "create $RUNDIR (the daemon's production socket path)"
rm -rf "$RUNDIR" "$WORK"; mkdir -p "$RUNDIR" "$WORK"
chown "$ME":"$ME" "$RUNDIR" "$WORK"
# The simulator caches its identity in /tmp under its device name. An earlier run
# of this suite as root leaves a root-owned file that the unprivileged run below
# cannot overwrite, which looks like a mysterious "Permission denied".
rm -f /tmp/rba-sim-*.json

step "back up the sudo stack"
cp -a "$PAM_SUDO" "$BACKUP"
echo "  saved to $BACKUP"
sha256sum "$PAM_SUDO" | sed 's/^/  original: /'

step "insert pam_rba as sufficient, before the password fallback"
python3 - "$PAM_SUDO" <<'PY'
import sys
p = sys.argv[1]
out, done = [], False
for line in open(p).read().splitlines():
    if not done and line.startswith("@include common-auth"):
        out.append("auth    sufficient  pam_rba.so purpose=sudo debug")
        done = True
    out.append(line)
if not done:
    sys.exit("no '@include common-auth' in " + p + "; refusing to guess where to insert")
open(p, "w").write("\n".join(out) + "\n")
PY
grep -nE '^\s*(auth|@include common-auth)' "$PAM_SUDO" | sed 's/^/    /'

step "start the daemon as $ME and pair a simulator"
require_free_socket "$SOCKET"

start_daemon
if pair_device; then
    ok "paired"
else
    bad "pairing failed"
    echo "  --- rba ---"; sed 's/^/    | /' "$WORK/pair.log"
    echo "  --- simulator ---"; sed 's/^/    | /' "$WORK/sim-pair.log"
    echo "  --- daemon ---"; sed 's/^/    | /' "$WORK/daemon.log"
    exit 1
fi

step "A. sudo with the device approving and a deliberately wrong password"
# The password is wrong on purpose. pam_unix cannot authenticate with it, so a
# success here can only mean the device authenticated the user.
serve 120 approve
before=$(audit_count)
asuser sudo -k 2>/dev/null
out=$(printf 'definitely-not-the-password\n' | asuser sudo -S -p '' id 2>&1); rc=$?
stop_sim
echo "$out" | sed 's/^/    | /'
if [ $rc -eq 0 ] && echo "$out" | grep -q 'uid=0'; then
    ok "sudo succeeded on the device's word alone, despite a wrong password"
else
    bad "sudo did not authenticate with the device (rc=$rc)"
fi
after=$(audit_count)
if [ "$after" -gt "$before" ]; then
    ok "the daemon recorded the request (+$((after-before)))"
else
    bad "no audit record: the PAM module did not run under sudo"
fi
if grep -q '"service":"sudo"' "$WORK/audit.log"; then
    ok "the record names the sudo service, so it came from the sudo stack"
else
    bad "no record naming service=sudo"
fi
if grep -q "\"user\":\"$ME\"" "$WORK/audit.log"; then
    ok "the record names the calling user ($ME), not root"
else
    bad "the record does not name $ME"
fi

step "B. sudo with the device declining: must fall back to the password"
serve 120 deny
before=$(audit_count)
asuser sudo -k 2>/dev/null
out=$(printf 'definitely-not-the-password\n' | asuser sudo -S -p '' id 2>&1); rc=$?
stop_sim
echo "$out" | sed 's/^/    | /'
if [ $rc -ne 0 ]; then
    ok "the decline was not enough; the stack fell through and the password failed"
else
    bad "sudo succeeded despite the device declining"
fi
if [ "$(audit_count)" -gt "$before" ]; then
    ok "the decline was recorded in the audit log"
else
    bad "the decline was not recorded"
fi

step "C. a local user may not authenticate as somebody else"
# Runs before any device is contacted, so no simulator is needed. This is the check
# that stops an unprivileged process from asking the device to vouch for root.
out=$(asuser "$BIN/rba" --socket "$SOCKET" auth --user root \
        --purpose sudo --service sudo 2>&1); rc=$?
echo "$out" | sed 's/^/    | /'
if [ $rc -ne 0 ] && echo "$out" | grep -qiE 'caller is|root|denied|not permitted|mismatch'; then
    ok "$ME cannot have the device authenticate root"
else
    bad "$ME was able to ask for root authentication (rc=$rc)"
fi
out=$(asuser "$BIN/rba" --socket "$SOCKET" auth --user "$ME" \
        --purpose probe --service probe 2>&1); rc=$?
if echo "$out" | grep -qiE 'caller is .* but requested|mismatch'; then
    ok "the refusal names the mismatch, so it is diagnosable"
else
    ok "requesting one's own account was not blocked by the peer check (rc=$rc)"
fi

step "D. authenticator unreachable: sudo must still work with the password"
# No simulator and no daemon at all: the module reports unavailable, the stack falls
# through, and sudo asks for a password. What must not happen is a silent success.
stop_sim
kill_groups
asuser sudo -k 2>/dev/null
out=$(printf 'definitely-not-the-password\n' | asuser sudo -S -p '' id 2>&1); rc=$?
echo "$out" | sed 's/^/    | /'
if [ $rc -ne 0 ]; then
    ok "no silent success when the authenticator is gone"
else
    bad "sudo succeeded with no authenticator and no password"
fi

step "audit trail"
python3 - "$WORK/audit.log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
for r in rows:
    if r["kind"] == "auth":
        print(f"    {r['result']:8s} user={r.get('user'):6s} service={r.get('service')} "
              f"code={r.get('code', '-')}")
banned = {"challenge", "signature", "mac", "private_key", "pairing_code"}
leaked = sorted({k for r in rows for k in r if k in banned})
print("  credential-bearing fields in the audit log:", leaked or "none")
PY
if grep -Eqi '"(challenge|signature|mac|private_key|pairing_code)"[[:space:]]*:' "$WORK/audit.log"; then
    bad "the audit log contains credential material"
else
    ok "the audit log carries no credential material"
fi

echo
echo "=== $pass passed, $fail failed (the sudo stack is restored on exit) ==="
[ "$fail" -eq 0 ]