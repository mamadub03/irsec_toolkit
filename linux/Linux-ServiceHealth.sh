#!/usr/bin/env bash
# IRSeC 2026 - L04 Linux Service Health
# READ ONLY
# Debian 12 / Ubuntu 22.04 / Ubuntu 24.04 / Rocky Linux 9
#
# Usage:
# sudo bash Linux-ServiceHealth.sh
# sudo bash Linux-ServiceHealth.sh pitlane
# sudo bash Linux-ServiceHealth.sh grandstand /opt/irc

set -uo pipefail

ROLE="${1:-$(hostname -s)}"
ROLE="${ROLE,,}"
COMPOSE_DIR="${2:-}"

PASS=0
WARN=0
FAIL=0
INFO=0

declare -a PROBLEMS=()

report() {
    local status="$1"
    local component="$2"
    local detail="$3"
    local suggestion="${4:-}"

    printf '[%-4s] %-26s %s\n' \
        "$status" "$component" "$detail"

    case "$status" in
        PASS) ((PASS+=1)) ;;
        WARN) ((WARN+=1)) ;;
        FAIL) ((FAIL+=1)) ;;
        INFO) ((INFO+=1)) ;;
    esac

    if [[ "$status" == FAIL || "$status" == WARN ]]; then
        PROBLEMS+=("$status|$component|$detail|$suggestion")
    fi
}

check_service() {
    local unit="$1"
    local label="$2"

    if ! command -v systemctl >/dev/null 2>&1; then
        report WARN "$label" "systemctl unavailable" \
            "Identify the service manager."
        return
    fi

    local load active
    load="$(systemctl show "$unit" -p LoadState --value 2>/dev/null)"
    active="$(systemctl is-active "$unit" 2>/dev/null || true)"

    if [[ "$load" == not-found || -z "$load" ]]; then
        report WARN "$label" "$unit not installed/found" \
            "Check whether the service uses another unit name."
    elif [[ "$active" == active ]]; then
        report PASS "$label" "$unit running"
    else
        report FAIL "$label" "$unit status: $active" \
            "Inspect: systemctl status $unit; journalctl -u $unit -n 30"
    fi
}

check_any_service() {
    local label="$1"
    shift

    local unit
    for unit in "$@"; do
        local load
        load="$(systemctl show "$unit" -p LoadState --value 2>/dev/null)"

        if [[ "$load" != not-found && -n "$load" ]]; then
            check_service "$unit" "$label"
            return
        fi
    done

    report WARN "$label" "No expected service unit detected" \
        "Identify installed daemon and its systemd unit."
}

# SSH can be served by a running daemon OR by systemd socket activation.
# An inactive ssh.service is normal when ssh.socket is active and listening.
check_ssh_activation() {
    if ! command -v systemctl >/dev/null 2>&1; then
        report WARN "SSH activation" "systemctl unavailable" \
            "Inspect the SSH daemon and TCP 22 listener manually."
        return
    fi
