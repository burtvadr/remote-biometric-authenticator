#!/usr/bin/env bash
# V2 candidate does not expose the legacy local ABI.
echo "V2 candidate: live legacy integration test blocked until B.4/B.5 acceptance." >&2
exit 1
# PAM integration test: loads the real module into the real libpam and drives real
# authentication through the whole stack.
#
#   pam-test -> libpam -> pam_rba.so -> rbad -> TLS -> rba-sim
#
# Nothing here modifies a real service. It installs the module into libpam's
# security directory and reads two dedicated test services under /etc/pam.d.
#
# Requires root (libpam's module directory is root-owned).
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/linux/target/debug"
SECDIR="/usr/lib/x86_64-linux-gnu/security"
WORK="${RBA_PAM_WORK:-/tmp/rba-pam}"
PORT="${RBA_PAM_PORT:-47555}"
export RBA_SOCKET="$WORK/control.sock"

pass=0; fail=0
ok()   { echo "  PASS: $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $*"; fail=$((fail+1)); }
step() { echo; echo "=== $* ==="; }

cleanup() {
    [ -n "${SIM_PID:-}" ] && kill "$SIM_PID" 2>/dev/null
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
    return 0
}
trap cleanup EXIT

require_root() {
    [ "$(id -u)" -eq 0 ] || { echo "must run as root (needs to install the PAM module)"; exit 1; }
}

install_module() {
    ( cd "$REPO/linux" && cargo build --release -p pam-rba ) >/dev/null 2>&1
    install -m 0755 "$REPO/linux/target/release/libpam_rba.so" "$SECDIR/pam_rba.so"
}

# `sufficient` so the password remains a fallback: a device failure must not lock
# anyone out.
write_services() {
    cat > /etc/pam.d/rba-test <<EOF
auth    sufficient  pam_rba.so purpose=sudo debug
auth    required    pam_unix.so
EOF
    # `required` so a device denial is directly observable rather than hidden behind
    # a fallthrough. Test service only.
    cat > /etc/pam.d/rba-required <<EOF
auth    required    pam_rba.so purpose=sudo debug
EOF
    # A short module timeout, so the real timeout path can be exercised without
    # waiting out the production default.
    cat > /etc/pam.d/rba-timeout <<EOF
auth    required    pam_rba.so purpose=sudo timeout_ms=3000 debug
EOF
}

start_daemon() {
    "$BIN/rbad" --state-dir "$WORK/state" --socket "$RBA_SOCKET" \
        --audit-log "$WORK/audit.log" --port "$PORT" --bind "127.0.0.1:$PORT" --no-mdns \
        >"$WORK/daemon.log" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 50); do [ -S "$RBA_SOCKET" ] && return 0; sleep 0.1; done
    echo "daemon did not start"; cat "$WORK/daemon.log"; exit 1
}

pair_device() {
    "$BIN/rba" --socket "$RBA_SOCKET" pair --owner "$(id -un)" >"$WORK/pair.log" 2>&1 &
    local pair_pid=$!
    sleep 1
    sed -n 's/^Code: \([0-9]\{6\}\).*/\1/p' "$WORK/pair.log" | timeout 60 "$BIN/rba-sim" pair --host "127.0.0.1:$PORT" --name "Pixel 9" \
        --daemon "$BIN/rbad" --daemon-arg --state-dir --daemon-arg "$WORK/state" \
        >"$WORK/sim-pair.log" 2>&1
    wait "$pair_pid" || return 1
    for service in rba-test rba-required rba-short; do
        "$BIN/rba" --socket "$RBA_SOCKET" grant-scope --device "Pixel 9" --user "$ME" --purpose sudo --service "$service" || return 1
    done
}

# serve <behaviour> <seconds>; sets SIM_PID
serve() {
    local behaviour="$1" seconds="$2"
    "$BIN/rba-sim" serve --host "127.0.0.1:$PORT" --name "Pixel 9" \
        --ca "$WORK/state/host.crt" --timeout "$seconds" --behaviour "$behaviour" \
        >"$WORK/sim-serve.log" 2>&1 &
    SIM_PID=$!
    sleep 1.5
}

stop_sim() {
    [ -n "${SIM_PID:-}" ] && kill "$SIM_PID" 2>/dev/null
    wait "$SIM_PID" 2>/dev/null
    SIM_PID=""
}

# expect <label> <service> <wanted: success|fail> <harness> [args...]
#
# The harness must actually have run. A missing binary, or output that does not
# contain a PAM verdict, is a failure of the test rather than a pass: otherwise a
# broken harness silently reports success.
expect() {
    local label="$1" service="$2" want="$3"
    shift 3
    local out rc got
    out=$("$@" 2>&1); rc=$?
    if ! printf '%s' "$out" | grep -q '^authenticate:'; then
        bad "$label: the harness did not run (rc=$rc)"
        printf '%s\n' "$out" | sed 's/^/    | /'
        return
    fi
    [ $rc -eq 0 ] && got=success || got=fail
    printf '%s\n' "$out" | sed 's/^/    | /'
    if [ "$got" = "$want" ]; then
        ok "$label ($got)"
    else
        bad "$label: wanted $want, got $got"
    fi
}

main() {
    require_root
    step "build and install the module into libpam"
    install_module
    ok "installed $(ls -la "$SECDIR/pam_rba.so" | awk '{print $5" bytes"}')"
    ok "exports: $(nm -D --defined-only "$SECDIR/pam_rba.so" | grep -c pam_sm_) pam_sm_* entry points"

    write_services

    rm -rf "$WORK"; mkdir -p "$WORK"
    gcc -O2 -o "$WORK/pam-test" "$REPO/tests/pam-test.c" -lpam \
        || { echo "cannot build the PAM harness"; exit 1; }
    ok "harness built at $WORK/pam-test"

    ME="$(id -un)"

    step "1. daemon not running: the device path must not authenticate"
    expect "no daemon" rba-test fail "$WORK/pam-test" rba-test "$ME"

    step "2. daemon running, nothing paired"
    start_daemon
    expect "nothing paired" rba-required fail "$WORK/pam-test" rba-required "$ME"

    step "3. pair a simulator"
    if pair_device; then
        ok "paired: $(grep -c . "$WORK/sim-pair.log") simulator lines"
        "$BIN/rba" --socket "$RBA_SOCKET" devices | grep -q "Pixel 9" \
            && ok "registry shows Pixel 9" || bad "registry does not show Pixel 9"
    else
        bad "pairing failed"; cat "$WORK/sim-pair.log"
    fi

    step "4. daemon up, device paired, but not connected"
    expect "paired but offline" rba-required fail "$WORK/pam-test" rba-required "$ME"

    step "5. device connected and approves: PAM_SUCCESS"
    serve approve 60
    expect "device approves" rba-test success "$WORK/pam-test" rba-test "$ME"
    echo "    --- simulator view of the request ---"
    grep 'Authorize:' "$WORK/sim-serve.log" | tail -2 | sed 's/^/    | /'
    stop_sim

    step "6. device connected but the user declines: must deny"
    serve deny 60
    expect "device declines" rba-required fail "$WORK/pam-test" rba-required "$ME"
    stop_sim

    step "7. device stalls past the module timeout: must time out closed"
    # The sim stays connected and simply never answers, so the only way out is the
    # module's own deadline. Exercises the timeout path rather than a disconnect.
    serve stall 60
    start_ts=$(date +%s)
    expect "device stalls" rba-timeout fail "$WORK/pam-test" rba-timeout "$ME"
    elapsed=$(( $(date +%s) - start_ts ))
    if [ "$elapsed" -ge 3 ] && [ "$elapsed" -le 40 ]; then
        ok "gave up after ${elapsed}s, on the configured deadline"
    else
        bad "expected to give up at ~3s, took ${elapsed}s"
    fi
    stop_sim

    step "7b. device disappears mid-request: must deny, not hang"
    serve stall 2
    expect "device vanishes" rba-required fail "$WORK/pam-test" rba-required "$ME"
    stop_sim

    step "8. tamper: device signs a different scope"
    serve sign-wrong-request 60
    expect "wrong scope" rba-required fail "$WORK/pam-test" rba-required "$ME"
    stop_sim

    step "9. misconfiguration must not lock the user out"
    cat > /etc/pam.d/rba-badcfg <<EOF
auth    sufficient  pam_rba.so nosuchoption=1
auth    required    pam_unix.so
EOF
    # The password fallback is still in the stack, so this must reach pam_unix
    # rather than abort: an abort here is what locks users out.
    out=$("$WORK/pam-test" rba-badcfg "$ME" 2>&1)
    echo "$out" | sed 's/^/    | /'
    if echo "$out" | grep -qE 'PAM_ABORT'; then
        bad "a config typo returned PAM_ABORT, which removes the password fallback"
    else
        ok "a config typo does not abort the stack"
    fi

    step "audit trail"
    if [ -f "$WORK/audit.log" ]; then
        grep -q '"result":"success"' "$WORK/audit.log" && ok "success recorded" || bad "no success in the audit log"
        grep -q '"code":"EXPIRED"' "$WORK/audit.log" && ok "timeout recorded (EXPIRED)" || bad "no timeout in the audit log"
        grep -q '"code":"USER_CANCELLED"' "$WORK/audit.log" && ok "decline recorded (USER_CANCELLED)" || bad "no decline in the audit log"
        grep -q '"code":"SIGNATURE_INVALID"' "$WORK/audit.log" && ok "tamper recorded (SIGNATURE_INVALID)" || bad "tamper not recorded"
        grep -q '"user":"'"$ME"'"' "$WORK/audit.log" && ok "username recorded" || bad "no username in the audit log"
        if grep -Eqi '"(challenge|signature|mac|private_key)"[[:space:]]*:' "$WORK/audit.log"; then
            bad "audit log contains a secret-bearing field"
        else
            ok "audit log carries no credential material"
        fi
    else
        bad "no audit log"
    fi

    echo
    echo "=== $pass passed, $fail failed ==="
    [ "$fail" -eq 0 ]
}

main "$@"