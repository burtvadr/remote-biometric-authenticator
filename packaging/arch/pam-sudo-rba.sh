#!/usr/bin/env bash
# Install, update or roll back the device authenticator in the sudo PAM stack.
#
# Scoped to sudo only. Does not touch system-auth, sshd, su, login or
# gdm-password. Run with sudo. Keep a root TTY open while testing.
set -euo pipefail

TARGET="/etc/pam.d/sudo"
RECORD="/etc/pam.d/.sudo.device.rollback"
TIMEOUT_SECONDS=5
LINE=""
TMP_FILE=""

usage() {
    cat <<EOF
Usage: sudo $0 [--dry-run] [--timeout SECONDS] [--rollback] [--verbose]

  --dry-run           show the proposed change and exit
  --verbose           show the diff and test instructions
  --timeout SECONDS   device wait before the password fallback (default: 5)
  --rollback          restore the file saved by the last install
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
        echo "Restore your own sudo backup manually." >&2
        exit 1
    fi
    . "$RECORD"
    if [ "${RBA_BACKUP:-absent}" = "absent" ]; then
        rm -f "$TARGET"
        echo "Removed $TARGET (it did not exist before install)."
    else
        cp -a "$RBA_BACKUP" "$TARGET"
        echo "Restored $TARGET from $RBA_BACKUP."
    fi
    rm -f "$RECORD"
    echo "sudo will use the restored PAM stack."
}

validate_timeout() {
    case "$TIMEOUT_SECONDS" in
        ''|*[!0-9]*) echo "--timeout must be a whole number" >&2; exit 2 ;;
    esac
    if [ "$TIMEOUT_SECONDS" -lt 1 ] || [ "$TIMEOUT_SECONDS" -gt 60 ]; then
        echo "--timeout must be between 1 and 60 seconds" >&2
        exit 2
    fi
    LINE="auth        sufficient    pam_rba.so purpose=sudo timeout_ms=$((TIMEOUT_SECONDS * 1000))"
}

main() {
    local dry_run=0 VERBOSE=0

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --dry-run) dry_run=1 ;;
            --verbose) VERBOSE=1 ;;
            --timeout)
                [ "$#" -lt 2 ] && { echo "--timeout needs a value" >&2; usage >&2; exit 2; }
                TIMEOUT_SECONDS="$2"; shift ;;
            --rollback) rollback; return ;;
            -h|--help) usage; return ;;
            *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
        esac
        shift
    done

    validate_timeout
    require_root

    if [ ! -f "$TARGET" ]; then
        echo "Missing $TARGET." >&2
        exit 1
    fi

    TMP_FILE="$(mktemp)"
    trap 'rm -f "${TMP_FILE:-}"' EXIT

    # Already installed: update the existing device line in place.
    if grep -q 'pam_rba\.so' "$TARGET"; then
        awk -v line="$LINE" '
            /pam_rba\.so/ { print line; next }
            { print }
        ' "$TARGET" > "$TMP_FILE"

        if cmp -s "$TARGET" "$TMP_FILE"; then
            echo "$TARGET already uses timeout_ms=$((TIMEOUT_SECONDS * 1000)); nothing to do."
            exit 0
        fi

        if [ "$VERBOSE" -eq 1 ] || [ "$dry_run" -eq 1 ]; then
            echo "==> proposed change"
            diff -u "$TARGET" "$TMP_FILE" || true
        fi
        if [ "$dry_run" -eq 1 ]; then
            echo; echo "Dry run only; no files changed."; exit 0
        fi

        local backup="$TARGET.bak.$(date +%Y%m%d-%H%M%S)"
        cp -a "$TARGET" "$backup"
        install -m 0644 -o root -g root "$TMP_FILE" "$TARGET"
        echo "Updated $TARGET (timeout_ms=$((TIMEOUT_SECONDS * 1000)))."
        [ "$VERBOSE" -eq 1 ] && echo "Backup: $backup"
        return
    fi

    # Insert before the first 'auth include system-auth' line.
    if ! awk -v line="$LINE" '
        BEGIN { inserted = 0 }
        /^[[:space:]]*auth[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$/ && !inserted {
            print line
            inserted = 1
        }
        { print }
        END { if (!inserted) exit 42 }
    ' "$TARGET" > "$TMP_FILE"; then
        echo "Could not find 'auth include system-auth' in $TARGET." >&2
        echo "No change made." >&2
        exit 1
    fi

    if [ "$VERBOSE" -eq 1 ] || [ "$dry_run" -eq 1 ]; then
        echo "==> proposed change"
        diff -u "$TARGET" "$TMP_FILE" || true
    fi
    if [ "$dry_run" -eq 1 ]; then
        echo; echo "Dry run only; no files changed."; exit 0
    fi

    local backup="$TARGET.bak.$(date +%Y%m%d-%H%M%S)"
    cp -a "$TARGET" "$backup"
    install -m 0644 -o root -g root "$TMP_FILE" "$TARGET"
    {
        echo "RBA_BACKUP=$backup"
    } > "$RECORD"
    chmod 0600 "$RECORD"

    echo "Installed $TARGET (timeout_ms=$((TIMEOUT_SECONDS * 1000)))."
    [ "$VERBOSE" -eq 1 ] && echo "Backup: $backup"
    echo "Rollback: sudo $0 --rollback"
}

main "$@"
