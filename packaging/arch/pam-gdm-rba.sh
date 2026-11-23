#!/usr/bin/env bash
# Install, update or roll back the device authenticator in the GNOME/gdm-password
# stack.
#
# This is intentionally scoped to gdm-password. It does not touch system-auth,
# sshd, su or gdm-fingerprint. gdm-password is used by both the GDM password
# login and the GNOME screen lock, so it is the smallest end-to-end test.
#
# Run with sudo. Keep a root TTY open while testing.
set -euo pipefail

VENDOR="/usr/lib/pam.d/gdm-password"
TARGET="/etc/pam.d/gdm-password"
RECORD="/etc/pam.d/.gdm-password.device.rollback"
TIMEOUT_SECONDS=5
LINE=""
TMP_FILE=""

usage() {
    cat <<EOF
Usage: sudo $0 [--dry-run] [--timeout SECONDS] [--rollback]

  --dry-run           show the proposed change and exit
  --timeout SECONDS   device wait before the password fallback (default: 5)
  --rollback          restore the file saved by the last install

The change is a local /etc/pam.d/gdm-password override. It adds or updates one
sufficient line before the existing auth stack and preserves everything else.
It does not modify /etc/pam.d/system-auth.
EOF
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run this with sudo/root." >&2
        exit 1
    fi
}

rollback() {
    require_root
    if [ ! -f "$RECORD" ]; then
        echo "No rollback record at $RECORD." >&2
        echo "Restore your own gdm-password backup manually." >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    . "$RECORD"
    if [ "${RBA_BACKUP:-absent}" = "absent" ]; then
        rm -f "$TARGET"
        echo "Removed $TARGET (it did not exist before install)."
    else
        cp -a "$RBA_BACKUP" "$TARGET"
        echo "Restored $TARGET from $RBA_BACKUP."
    fi
    rm -f "$RECORD"
    echo "GNOME will use the restored PAM stack on the next authentication."
}

validate_timeout() {
    case "$TIMEOUT_SECONDS" in
        ''|*[!0-9]*)
            echo "--timeout must be a whole number of seconds" >&2
            exit 2
            ;;
    esac
    if [ "$TIMEOUT_SECONDS" -lt 1 ] || [ "$TIMEOUT_SECONDS" -gt 60 ]; then
        echo "--timeout must be between 1 and 60 seconds" >&2
        exit 2
    fi
    LINE="auth        sufficient    pam_rba.so purpose=gdm timeout_ms=$((TIMEOUT_SECONDS * 1000))"
}

main() {
    local dry_run=0

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --dry-run)
                dry_run=1
                ;;
            --timeout)
                if [ "$#" -lt 2 ]; then
                    echo "--timeout needs a value" >&2
                    usage >&2
                    exit 2
                fi
                TIMEOUT_SECONDS="$2"
                shift
                ;;
            --rollback)
                rollback
                return
                ;;
            -h|--help)
                usage
                return
                ;;
            *)
                echo "unknown argument: $1" >&2
                usage >&2
                exit 2
                ;;
        esac
        shift
    done

    validate_timeout
    require_root

    TMP_FILE="$(mktemp)"
    trap 'rm -f "${TMP_FILE:-}"' EXIT

    # Already installed: update the existing device line in place. This is how a
    # 15 s timeout becomes 5 s without losing the rollback record.
    if [ -f "$TARGET" ] && grep -q 'pam_rba\.so' "$TARGET"; then
        awk -v line="$LINE" '
            /pam_rba\.so/ { print line; next }
            { print }
        ' "$TARGET" > "$TMP_FILE"

        if cmp -s "$TARGET" "$TMP_FILE"; then
            echo "$TARGET already uses timeout_ms=$((TIMEOUT_SECONDS * 1000)); nothing to do."
            exit 0
        fi

        echo "==> proposed change"
        diff -u "$TARGET" "$TMP_FILE" || true

        if [ "$dry_run" -eq 1 ]; then
            echo
            echo "Dry run only; no files changed."
            exit 0
        fi

        local backup="$TARGET.bak.$(date +%Y%m%d-%H%M%S)"
        cp -a "$TARGET" "$backup"
        install -m 0644 -o root -g root "$TMP_FILE" "$TARGET"

        echo
        echo "Updated the device line in $TARGET to timeout_ms=$((TIMEOUT_SECONDS * 1000))."
        echo "Backup: $backup"
        echo "Existing rollback record left unchanged: $RECORD"
        return
    fi

    if [ ! -f "$VENDOR" ]; then
        echo "Missing vendor file $VENDOR." >&2
        exit 1
    fi

    local base="$VENDOR"
    [ -f "$TARGET" ] && base="$TARGET"

    if ! awk -v line="$LINE" '
        BEGIN { inserted = 0 }
        /^[[:space:]]*auth[[:space:]]+include[[:space:]]+system-local-login[[:space:]]*$/ && !inserted {
            print line
            inserted = 1
        }
        { print }
        END { if (!inserted) exit 42 }
    ' "$base" > "$TMP_FILE"; then
        echo "Could not find 'auth include system-local-login' in $base." >&2
        echo "No change made. Inspect the file before trying a manual edit." >&2
        exit 1
    fi

    echo "==> proposed change"
    diff -u "$base" "$TMP_FILE" || true

    if [ "$dry_run" -eq 1 ]; then
        echo
        echo "Dry run only; no files changed."
        exit 0
    fi

    local backup="absent"
    if [ -f "$TARGET" ]; then
        backup="$TARGET.bak.$(date +%Y%m%d-%H%M%S)"
        cp -a "$TARGET" "$backup"
    fi

    install -m 0644 -o root -g root "$TMP_FILE" "$TARGET"
    {
        echo "RBA_BACKUP=$backup"
    } > "$RECORD"
    chmod 0600 "$RECORD"

    echo
    echo "Installed the device line in $TARGET with timeout_ms=$((TIMEOUT_SECONDS * 1000))."
    if [ "$backup" != "absent" ]; then
        echo "Backup: $backup"
    else
        echo "There was no local override before; rollback will remove $TARGET."
    fi
    echo "Rollback: sudo $0 --rollback"
    echo
    echo "Keep a root TTY open. Then test:"
    echo "  1. Lock the screen with Super+L."
    echo "  2. Press Enter or submit the password form."
    echo "  3. Approve the device prompt."
    echo "  4. If it fails, switch to a TTY and run: sudo $0 --rollback"
}

main "$@"
