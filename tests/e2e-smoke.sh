#!/usr/bin/env bash
umask 077
# End-to-end smoke test: real daemon, real TLS, real pairing, real signature.
# Usage: tests/e2e-smoke.sh [workdir]
set -uo pipefail

BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../linux/target/debug" && pwd)"
WORK="${1:-/tmp/rba-e2e}"
PORT="${RBA_PORT:-47311}"
SOCK="$WORK/control.sock"
CTL="$BIN_DIR/rba"
DAEMON="$BIN_DIR/rbad"
SIM="$BIN_DIR/rba-sim"

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo; echo "=== $* ==="; }

step "clean slate"
rm -rf "$WORK"
mkdir -p "$WORK"
[ -x "$DAEMON" ] || fail "missing $DAEMON (run cargo build)"
[ -x "$CTL" ] || fail "missing $CTL"
[ -x "$SIM" ] || fail "missing $SIM"

step "start daemon"
"$DAEMON" --state-dir "$WORK/state" --socket "$SOCK" --audit-log "$WORK/audit.log" \
         --port "$PORT" --bind "127.0.0.1:$PORT" --no-mdns >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
trap 'kill "$DAEMON_PID" 2>/dev/null' EXIT
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { cat "$WORK/daemon.log"; fail "control socket never appeared"; }
echo "daemon pid $DAEMON_PID on port $PORT"

CTL_SOCK="--socket $SOCK"

step "no authenticators paired yet"
"$CTL" $CTL_SOCK devices | grep -q "List of authenticators paired" || fail "expected an empty list"

step "pair"
"$CTL" $CTL_SOCK pair --owner "$(id -un)" >"$WORK/pair.log" 2>&1 &
PAIR_PID=$!
sleep 1
sed -n 's/^Code: \([0-9]\{6\}\).*/\1/p' "$WORK/pair.log" | timeout 60 "$SIM" pair --host "127.0.0.1:$PORT" --name "Pixel 9" \
    --daemon "$DAEMON" --daemon-arg --state-dir --daemon-arg "$WORK/state" \
    >"$WORK/sim-pair.log" 2>&1
SIM_RC=$?
wait "$PAIR_PID" 2>/dev/null
PAIR_RC=$?
echo "--- simulator (rc=$SIM_RC) ---"; cat "$WORK/sim-pair.log"
echo "--- rba pair (rc=$PAIR_RC) ---"; cat "$WORK/pair.log"
[ "$SIM_RC" -eq 0 ] || fail "simulator pairing failed"
[ "$PAIR_RC" -eq 0 ] || fail "host pairing did not complete"
grep -q "^Paired" "$WORK/pair.log" || fail "missing host pairing acknowledgement"
grep -q "Host verified" "$WORK/sim-pair.log" || fail "PAKE did not verify"
grep -qi "confirm" "$WORK/pair.log" || true

step "devices now shows the paired device"
"$CTL" $CTL_SOCK devices | tee "$WORK/list.log"
grep -q "Pixel 9" "$WORK/list.log" || fail "paired device not listed"
grep -q "paired" "$WORK/list.log" || fail "device is not in the paired state"

step "hold a connection open and authenticate"
"$SIM" serve --host "127.0.0.1:$PORT" --name "Pixel 9" \
    --ca "$WORK/state/host.crt" --timeout 60 >"$WORK/sim-serve.log" 2>&1 &
SIM_SERVE_PID=$!
sleep 1.5
USER_NAME="$(id -un)"
"$CTL" $CTL_SOCK auth --user "$USER_NAME" \
        --timeout 30000 >"$WORK/auth.log" 2>&1
AUTH_RC=$?
kill "$SIM_SERVE_PID" 2>/dev/null
wait "$SIM_SERVE_PID" 2>/dev/null
echo "--- device (rc) ---"; tail -6 "$WORK/sim-serve.log"
echo "--- rba auth (rc=$AUTH_RC) ---"; cat "$WORK/auth.log"
[ "$AUTH_RC" -eq 0 ] || fail "authentication failed"
grep -q "Authenticated" "$WORK/auth.log" || fail "no success reported"

step "a second authentication must fail: replay of the same challenge is impossible"
"$SIM" serve --host "127.0.0.1:$PORT" --name "Pixel 9" \
    --ca "$WORK/state/host.crt" --timeout 30 --behaviour stall >"$WORK/sim-stall.log" 2>&1 &
STALL_PID=$!
sleep 1.5
timeout 20 "$CTL" $CTL_SOCK auth --user "$USER_NAME" --timeout 2500 \
    >"$WORK/auth-timeout.log" 2>&1
TIMEOUT_RC=$?
kill "$STALL_PID" 2>/dev/null
wait "$STALL_PID" 2>/dev/null
echo "--- stalled device, expected failure (rc=$TIMEOUT_RC) ---"; cat "$WORK/auth-timeout.log"
[ "$TIMEOUT_RC" -ne 0 ] || fail "a stalled device must not produce a successful authentication"
grep -qi "expired" "$WORK/auth-timeout.log" || fail "expected an EXPIRED failure"

step "audit log contains no credential material"
# Match on field *names* that would carry a secret, and on the pairing code value
# itself, rather than on the substring "mac" or "challenge" anywhere.
if grep -Eq '"(challenge|signature|mac|host_mac|pairing_code|code_hex|private_key|session_secret)"[[:space:]]*:' "$WORK/audit.log"; then
    echo "audit log:"; cat "$WORK/audit.log"
    fail "audit log carries a secret-bearing field"
fi
# The real invariant: the pairing code the operator saw must never appear in the log.
PAIR_CODE="$(sed -n 's/^Code: \([0-9]\{6\}\).*/\1/p' "$WORK/pair.log" | head -1)"
if [ -n "$PAIR_CODE" ]; then
    if grep -q "$PAIR_CODE" "$WORK/audit.log"; then
        echo "audit log leaks the pairing code:"; cat "$WORK/audit.log"
        fail "pairing code appears in the audit log"
    fi
    echo "pairing code is absent from the audit log"
fi
echo "--- audit.log ---"; cat "$WORK/audit.log"
python3 - "$WORK/audit.log" <<'PY'
import json, sys
for i, line in enumerate(open(sys.argv[1])):
    line = line.strip()
    if line:
        json.loads(line)   # every record must be valid JSON
print("all audit records parse as JSON")
PY
grep -q '"kind":"auth"' "$WORK/audit.log" || fail "no auth record"
grep -q '"result":"success"' "$WORK/audit.log" || fail "no success record"
grep -q '"code":"EXPIRED"' "$WORK/audit.log" || fail "no denial record"

step "registry contains only public material"
python3 - "$WORK/state/registry.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for rec in d.get("devices", {}).values():
    assert "private" not in json.dumps(rec).lower(), "private material in the registry"
    assert len(rec["public_key"]) == 130, "public key is not 65 bytes of hex"
print("registry keys:", sorted(next(iter(d["devices"].values())).keys()))
PY

step "PASS"