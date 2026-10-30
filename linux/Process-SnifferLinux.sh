#!/usr/bin/env bash
# IRSeC L05 - Linux Session & Process Investigator
# Debian / Ubuntu / Rocky Linux
# Run with sudo for complete process visibility.
# No automatic firewall blocking or file deletion.

set -uo pipefail

MINUTES="${1:-60}"
FAILURE_THRESHOLD=5

if [[ ! "$MINUTES" =~ ^[0-9]+$ ]] ||
   (( MINUTES < 1 || MINUTES > 10080 )); then
    echo "Usage: sudo bash $0 [minutes]"
    exit 1
fi

PROTECTED_NAMES=(
    systemd init sshd
    dockerd containerd
    mariadbd mysqld
    cron crond
    systemd-journald
    systemd-logind
    rsyslogd
    wazuh-agentd
    datadog-agent
    inetd xinetd
    vsftpd proftpd
)

PROTECTED_USERS=(
    root whiteteam
    dd-agent ddagentuser
)

contains() {
    local needle="$1"
    shift
    local x

    for x in "$@"; do
        [[ "$needle" == "$x" ]] && return 0
    done

    return 1
}

get_owner() {
    local pid="$1"
    ps -p "$pid" -o user= 2>/dev/null |
        awk '{$1=$1;print}'
}

get_name() {
    local pid="$1"
    ps -p "$pid" -o comm= 2>/dev/null |
        awk '{$1=$1;print}'
}

get_executable() {
    local pid="$1"
    readlink "/proc/$pid/exe" 2>/dev/null || true
}

get_command() {
    local pid="$1"

    if [[ -r "/proc/$pid/cmdline" ]]; then
        tr '\0' ' ' < "/proc/$pid/cmdline"
        echo
    else
        echo "Unavailable"
    fi
}

get_starttime() {
    local pid="$1"
    ps -p "$pid" -o lstart= 2>/dev/null |
        awk '{$1=$1;print}'
}

is_protected() {
    local pid="$1"
    local name owner exe

    [[ "$pid" =~ ^[0-9]+$ ]] || return 0
    (( pid <= 2 )) && return 0

    [[ "$pid" == "$$" || "$pid" == "$PPID" ]] && return 0

    name="$(get_name "$pid")"
    owner="$(get_owner "$pid")"
    exe="$(get_executable "$pid")"

    contains "$name" "${PROTECTED_NAMES[@]}" && return 0
    contains "$owner" "${PROTECTED_USERS[@]}" && return 0

    # Avoid terminating system/service executables.
    case "$exe" in
        /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/opt/datadog/*)
            return 0
            ;;
    esac

    # Protect systemd main service PIDs.
    if command -v systemctl >/dev/null 2>&1; then
        while IFS= read -r unit; do
            [[ -n "$unit" ]] || continue

            mainpid="$(
                systemctl show "$unit" \
                    -p MainPID --value 2>/dev/null || true
            )"

            [[ "$mainpid" == "$pid" ]] && return 0

        done < <(
            systemctl list-units \
                --type=service --state=running \
                --plain --no-legend 2>/dev/null |
                awk '{print $1}'
        )
    fi

    return 1
}

show_sessions() {
    echo
    echo "=== LOGGED-IN USERS ==="

    who 2>/dev/null || true

    echo
    echo "=== USER SESSIONS ==="

    w -h 2>/dev/null || true
}

show_connections() {
    echo
    echo "=== ACTIVE TCP CONNECTIONS ==="

    if ! command -v ss >/dev/null 2>&1; then
        echo "ss is unavailable."
        return
    fi

    printf '%-8s %-8s %-24s %-24s %-8s %s\n' \
        PID STATE LOCAL REMOTE USER PROCESS

    while IFS= read -r line; do
        [[ -n "$line" ]] || continue

        # ss -H -tnp format:
        # STATE Recv-Q Send-Q Local Peer Process
        read -r state recvq sendq localaddr remoteaddr rest <<< "$line"

        pid="$(grep -oE 'pid=[0-9]+' <<< "$line" |
            head -1 | cut -d= -f2)"

        [[ -n "$pid" ]] || pid="?"

        if [[ "$pid" != "?" ]]; then
            user="$(get_owner "$pid")"
            name="$(get_name "$pid")"
        else
            user="?"
            name="?"
        fi

        printf '%-8s %-8s %-24s %-24s %-8s %s\n' \
            "$pid" "$state" "$localaddr" "$remoteaddr" \
            "${user:-?}" "${name:-?}"

    done < <(ss -H -tnp 2>/dev/null)
}

show_authentication() {
    echo
    echo "=== RECENT SSH AUTHENTICATION ACTIVITY ==="
    echo "Window: last $MINUTES minutes"

    local logs

    if command -v journalctl >/dev/null 2>&1; then
        logs="$(
            journalctl --since "$MINUTES minutes ago" \
                -u ssh -u sshd --no-pager \
                -o cat 2>/dev/null |
                grep -E 'Failed password|Accepted password|Accepted publickey|Invalid user' ||
                true
        )"
    else
        echo "journalctl unavailable."
        return
    fi

    if [[ -z "$logs" ]]; then
        echo "No matching SSH authentication records."
        return
    fi

    printf '%s\n' "$logs" | tail -40

    echo
    echo "=== FAILED AUTHENTICATION IP COUNTS ==="

    printf '%s\n' "$logs" |
        grep 'Failed password' |
        sed -nE \
            's/.* from ([^ ]+) port .*/\1/p' |
        sort |
        uniq -c |
        sort -nr |
        while read -r count ip; do
            [[ -n "$ip" ]] || continue

            if (( count >= FAILURE_THRESHOLD )); then
                printf '[REVIEW] %-24s %s failures\n' "$ip" "$count"
            else
                printf '[INFO]   %-24s %s failures\n' "$ip" "$count"
            fi
        done

    echo
    echo "An unfamiliar IP or authentication failure"
    echo "does not automatically mean the source is malicious."
}

inspect_pid() {
    local pid="$1"

    if [[ ! "$pid" =~ ^[0-9]+$ || ! -d "/proc/$pid" ]]; then
        echo "Invalid or missing PID."
        return 1
    fi

    local owner name exe parent start
    owner="$(get_owner "$pid")"
    name="$(get_name "$pid")"
    exe="$(get_executable "$pid")"
    parent="$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ')"
    start="$(get_starttime "$pid")"

    echo
    echo "========================================"
    echo "           PROCESS INVESTIGATION"
    echo "========================================"
    echo "PID:          $pid"
    echo "Process:      $name"
    echo "Owner:        $owner"
    echo "Parent PID:   $parent"
    echo "Parent:       $(get_name "$parent")"
    echo "Started:      $start"
    echo "Executable:   $exe"
    echo "Working dir:  $(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
    echo
    echo "Command line:"
    get_command "$pid"

    if [[ -f "$exe" ]]; then
        echo
        echo "SHA256:"
        sha256sum -- "$exe" 2>/dev/null || true
    fi

    echo
    echo "=== PROCESS CONNECTIONS ==="

    if command -v ss >/dev/null 2>&1; then
        ss -tunap 2>/dev/null |
            grep -F "pid=$pid," || true
    fi

    echo
    echo "=== PROCESS TREE ==="

    if command -v pstree >/dev/null 2>&1; then
        pstree -sp "$pid" 2>/dev/null || true
    else
        ps -p "$pid" -o pid,ppid,user,comm,args
    fi

    echo
    if is_protected "$pid"; then
        echo "[PROTECTED] Process matches a safety rule."
    else
        echo "[REVIEW] Process does not match a protected rule."
        echo "This is not proof that the process is malicious."
    fi
}

kill_pid() {
    local pid="$1"

    if [[ ! "$pid" =~ ^[0-9]+$ || ! -d "/proc/$pid" ]]; then
        echo "Invalid or missing PID."
        return 1
    fi

    if is_protected "$pid"; then
        echo "REFUSED: Protected or service-associated process."
        return 1
    fi

    local original_start original_exe
    original_start="$(get_starttime "$pid")"
    original_exe="$(get_executable "$pid")"

    inspect_pid "$pid"

    echo
    echo "WARNING: This will terminate PID $pid."
    echo "It may disrupt running applications."
    read -r -p "Type KILL $pid to confirm: " confirm

    [[ "$confirm" == "KILL $pid" ]] || {
        echo "Cancelled."
        return
    }

    if [[ ! -d "/proc/$pid" ]]; then
        echo "Process exited before termination."
        return
    fi

    if [[ "$(get_starttime "$pid")" != "$original_start" ||
          "$(get_executable "$pid")" != "$original_exe" ]]; then
        echo "Process identity changed. Refusing."
        return 1
    fi

    if is_protected "$pid"; then
        echo "Process became protected. Refusing."
        return 1
    fi

    # Graceful termination first.
    kill -TERM "$pid" || {
        echo "Unable to send SIGTERM."
        return 1
    }

    echo "SIGTERM sent to PID $pid."
    echo "Executable location: $original_exe"
    echo "No executable deleted and no IP blocked."
    echo "Refresh the scan to confirm the process exited."
}

while true; do
    echo
    echo "========================================"
    echo "       IRSeC LINUX INVESTIGATOR"
    echo "========================================"
    echo "[1] Live TCP connections"
    echo "[2] Inspect a process PID"
    echo "[3] Sessions and SSH authentication IPs"
    echo "[4] Terminate selected process"
    echo "[5] Refresh all"
    echo "[Q] Exit"

    read -r -p "Choose: " choice

    case "${choice^^}" in
        1)
            show_connections
            ;;
        2)
            read -r -p "PID to inspect: " pid
            inspect_pid "$pid"
            ;;
        3)
            show_sessions
            show_authentication
            ;;
        4)
            read -r -p "PID to terminate: " pid
            kill_pid "$pid"
            ;;
        5)
            show_sessions
            show_connections
            show_authentication
            ;;
        Q)
            exit 0
            ;;
        *)
            echo "Invalid option."
            ;;
    esac
done