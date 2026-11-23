#!/usr/bin/env bash
# Install the Remote Biometric Authenticator for Arch Linux.
#
# Run as root:
#   sudo ./packaging/arch/install-local.sh
#
# There is no state migration: the daemon starts with a fresh host identity and
# every device must pair again.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
    cat <<EOF
Usage: sudo $0

This installs:
  /usr/libexec/rbad
  /usr/local/bin/rba
  /usr/lib/security/pam_rba.so
  /etc/systemd/system/rbad.service

It does not modify any PAM stack. Enable the scoped GDM or polkit integration
separately with packaging/arch/pam-gdm-rba.sh or pam-polkit-rba.sh.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo/root." >&2
    exit 1
fi

for f in \
    "$ROOT/linux/target/release/rbad" \
    "$ROOT/linux/target/release/rba" \
    "$ROOT/linux/target/release/libpam_rba.so"; do
    [ -x "$f" ] || {
        echo "missing $f" >&2
        echo "Build it first as your normal user: make release" >&2
        exit 1
    }
done

echo "==> creating the rba account"
if ! getent group rba >/dev/null; then
    groupadd --system rba
fi
if ! id -u rba >/dev/null 2>&1; then
    useradd --system \
        --gid rba \
        --home-dir /var/lib/rba \
        --no-create-home \
        --shell /usr/bin/nologin \
        rba
fi

echo "==> installing binaries"
install -Dm0755 "$ROOT/linux/target/release/rbad" /usr/libexec/rbad
install -Dm0755 "$ROOT/linux/target/release/rba" /usr/local/bin/rba
install -Dm0755 "$ROOT/linux/target/release/libpam_rba.so" \
    /usr/lib/security/pam_rba.so

echo "==> installing PAM helper scripts"
install -d /usr/libexec/rba
for script in pam-gdm-rba.sh pam-polkit-rba.sh pam-sudo-rba.sh; do
    install -Dm0755 "$ROOT/packaging/arch/$script" "/usr/libexec/rba/$script"
done

echo "==> installing the service"
install -Dm0644 "$ROOT/linux/systemd/rbad.service" \
    /etc/systemd/system/rbad.service

echo "==> preparing state and log directories"
install -d -o rba -g rba -m 0700 /var/lib/rba
install -d -o rba -g rba -m 0750 /var/log/rba

if ss -ltn 'sport = :47123' 2>/dev/null | grep -q LISTEN; then
    # An upgrade runs while the old service is still listening. Stop our own
    # service first; refuse only if some other process owns the port.
    if systemctl is-active --quiet rbad 2>/dev/null; then
        echo "==> stopping the existing rbad service"
        systemctl stop rbad
    fi
fi

if ss -ltn 'sport = :47123' 2>/dev/null | grep -q LISTEN; then
    echo "port 47123 is already in use by another process; stop it first:" >&2
    ss -ltnp 'sport = :47123' >&2 || true
    exit 1
fi

echo "==> enabling and starting rbad"
systemctl daemon-reload
systemctl enable rbad
systemctl restart rbad

for _ in $(seq 1 40); do
    if [ -S /run/rba/control.sock ]; then
        break
    fi
    sleep 0.25
done
if [ ! -S /run/rba/control.sock ]; then
    echo "rbad did not create /run/rba/control.sock" >&2
    systemctl --no-pager --full status rbad >&2 || true
    exit 1
fi

# No group setup: the control socket authorises each request from the caller's
# kernel credentials and the device's account binding, so `rba` works for the
# invoking user immediately, with no newgrp or re-login.

echo
echo "==> installed"
systemctl --no-pager --full status rbad | sed -n '1,12p'
echo
echo "Pair from the device if this is a fresh state:"
echo "  rba pair"
echo
echo "Then enable one scoped integration and keep a root TTY open:"
echo "  sudo $ROOT/packaging/arch/pam-gdm-rba.sh --dry-run"
echo "  sudo $ROOT/packaging/arch/pam-polkit-rba.sh --dry-run"
echo
echo "The sudo, sshd, su, login and gdm-fingerprint stacks are left unchanged."
