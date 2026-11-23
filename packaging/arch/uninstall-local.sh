#!/usr/bin/env bash
# Cleanly uninstall the Remote Biometric Authenticator from Arch Linux.
#
# Run as root:
#   sudo ./packaging/arch/uninstall-local.sh [--purge]
#
# Default: roll back the scoped PAM overrides, stop and remove the service, the
# binaries and the PAM module. State (/var/lib/rba) and logs (/var/log/rba) are
# kept so a reinstall can start from them if you choose.
#
#   --purge   also delete state, logs and the rba account. Irreversible.
#
# The Android app is separate; remove it with:
#   adb uninstall io.github.burtvadr.rba.debug
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PURGE=0

usage() {
    cat <<EOF
Usage: sudo $0 [--purge]

  --purge   also remove /var/lib/rba, /var/log/rba and the rba account

Rolls back the gdm-password and polkit-1 PAM overrides first, then removes the
service, binaries and PAM module. Does not touch sudo, sshd, su, login or
gdm-fingerprint.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --purge) PURGE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo/root." >&2
    exit 1
fi

# 1. Roll back the scoped PAM overrides BEFORE removing the module, so no stack
#    is left pointing at a module that no longer exists.
if [ -f /etc/pam.d/.gdm-password.device.rollback ]; then
    echo "==> rolling back the gdm-password PAM override"
    bash "$ROOT/packaging/arch/pam-gdm-rba.sh" --rollback
fi
if [ -f /etc/pam.d/.polkit-1.device.rollback ]; then
    echo "==> rolling back the polkit-1 PAM override"
    bash "$ROOT/packaging/arch/pam-polkit-rba.sh" --rollback
fi

# Safety: refuse to remove the module while any PAM stack still references it.
if grep -rls 'pam_rba' /etc/pam.d/ 2>/dev/null; then
    echo "error: the PAM files listed above still reference pam_rba." >&2
    echo "Roll them back or remove those lines first, then re-run." >&2
    exit 1
fi

# 2. Stop and disable the service.
echo "==> stopping rbad"
systemctl stop rbad.service 2>/dev/null || true
systemctl disable rbad.service 2>/dev/null || true

# 3. Remove the binaries, PAM module and units.
echo "==> removing binaries, PAM module and units"
rm -f /usr/libexec/rbad \
      /usr/local/bin/rba \
      /usr/lib/security/pam_rba.so \
      /etc/systemd/system/rbad.service \
      /etc/systemd/system/rbad.socket
rm -rf /run/rba
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

# 4. Optionally purge state, logs and the service account.
if [ "$PURGE" -eq 1 ]; then
    echo "==> purging state, logs and the rba account"
    rm -rf /var/lib/rba /var/log/rba
    userdel rba 2>/dev/null || true
    groupdel rba 2>/dev/null || true
else
    echo "==> keeping /var/lib/rba and /var/log/rba (use --purge to remove)"
fi

echo
echo "==> uninstalled"
echo "The Android app is separate. To remove it:  adb uninstall io.github.burtvadr.rba.debug"
