#!/usr/bin/env bash
# IRSeC L08 - Linux Persistence Scanner
# READ ONLY - Debian / Ubuntu / Rocky Linux
# Run with sudo for complete visibility.

set -uo pipefail

SHOW_ALL=0
[[ "${1:-}" == "--all" ]] && SHOW_ALL=1

section() {
    printf '\n========== %s ==========\n' "$1"
}

indicators() {
    local text="$1"
    local result=""

    if grep -Eqi '(/tmp/|/var/tmp/|/dev/shm/)' <<< "$text"; then
        result+="TEMP_PATH "
    fi

    if grep -Eqi '(curl|wget).*(http://|https://)' <<< "$text"; then
        result+="NETWORK_DOWNLOAD "
    fi

    if grep -Eqi '(^|[[:space:]])(nc|ncat|socat)[[:space:]]' \
        <<< "$text"; then
        result+="NETWORK_TOOL "
    fi

    if grep -Eqi '(base64[[:space:]]+(-d|--decode)|bash[[:space:]]+-c)' \
        <<< "$text"; then
        result+="ENCODED_OR_SHELL_COMMAND "
    fi

    printf '%s' "$result"
}

show_entry() {
    local type="$1"
    local location="$2"
    local content="$3"

    local flags
    flags="$(indicators "$content")"

    if (( SHOW_ALL == 0 )) && [[ -z "$flags" ]]; then
        return
    fi

    echo
    echo "TYPE: $type"
    echo "LOCATION: $location"
    echo "INDICATORS: ${flags:-None}"
    printf '%s\n' "$content"
}

section "SYSTEM CRON FILES"

for file in /etc/crontab /etc/anacrontab; do
    [[ -f "$file" ]] || continue
    content="$(cat "$file" 2>/dev/null)"
    show_entry "System cron" "$file" "$content"
done

for dir in /etc/cron.d /etc/cron.hourly \
           /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$dir" ]] || continue

    while IFS= read -r -d '' file; do
        content="$(head -n 50 "$file" 2>/dev/null)"
        show_entry "Cron file" "$file" "$content"
    done < <(find "$dir" -maxdepth 1 -type f -print0 2>/dev/null)
done

section "USER CRONTABS"

if command -v crontab >/dev/null 2>&1; then
    while IFS=: read -r user _ uid gid info home shell; do
        output="$(crontab -u "$user" -l 2>/dev/null || true)"

        [[ -n "$output" ]] || continue

        show_entry "User crontab ($user)" \
            "crontab -u $user -l" "$output"
    done < /etc/passwd
fi

section "SYSTEMD UNIT FILES"

UNIT_DIRS=(
    /etc/systemd/system
    /usr/local/lib/systemd/system
    /lib/systemd/system
    /usr/lib/systemd/system
)

for dir in "${UNIT_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue

    while IFS= read -r -d '' file; do
        content="$(grep -E \
            '^(ExecStart|ExecStartPre|ExecStartPost|User|WorkingDirectory|OnCalendar|OnBootSec|OnUnitActiveSec)=' \
            "$file" 2>/dev/null || true)"

        [[ -n "$content" ]] || continue
        show_entry "Systemd unit" "$file" "$content"
    done < <(
        find "$dir" -type f \
            \( -name '*.service' -o -name '*.timer' \) \
            -print0 2>/dev/null
    )
done

section "ENABLED SYSTEMD TIMERS"

if command -v systemctl >/dev/null 2>&1; then
    systemctl list-timers --all --no-pager 2>/dev/null || true
fi

section "USER SYSTEMD UNITS"

while IFS=: read -r user _ uid gid info home shell; do
    dir="$home/.config/systemd/user"
    [[ -d "$dir" ]] || continue

    while IFS= read -r -d '' file; do
        content="$(grep -E \
            '^(ExecStart|ExecStartPre|ExecStartPost|WorkingDirectory|OnCalendar|OnBootSec)=' \
            "$file" 2>/dev/null || true)"

        [[ -n "$content" ]] || continue
        show_entry "User systemd ($user)" "$file" "$content"
    done < <(
        find "$dir" -type f \
            \( -name '*.service' -o -name '*.timer' \) \
            -print0 2>/dev/null
    )
done < /etc/passwd

section "STARTUP SCRIPTS"

for file in /etc/rc.local /etc/profile /etc/bash.bashrc \
            /etc/profile.d/*.sh; do
    [[ -f "$file" ]] || continue

    content="$(head -n 80 "$file" 2>/dev/null)"
    show_entry "Startup script" "$file" "$content"
done

section "SSH AUTHORIZED KEYS"

while IFS=: read -r user _ uid gid info home shell; do
    file="$home/.ssh/authorized_keys"

    [[ -f "$file" ]] || continue

    count="$(grep -cv '^[[:space:]]*$' "$file" 2>/dev/null || true)"

    echo
    echo "USER: $user"
    echo "FILE: $file"
    echo "NONEMPTY LINES: $count"
    echo "PERMISSIONS: $(stat -c '%a %U:%G' "$file" 2>/dev/null)"

    # Show fingerprints, not complete public keys.
    if command -v ssh-keygen >/dev/null 2>&1; then
        ssh-keygen -lf "$file" 2>/dev/null || true
    fi

    echo "Inspect any unfamiliar keys and forced-command options."
done < /etc/passwd

section "OPERATOR NOTES"
echo "Flagged commands are candidates for investigation."
echo "No entry is confirmed malicious by these checks alone."
echo "Protected accounts, Datadog, scoring, and Wazuh components"
echo "must be preserved."
echo
echo "No cron, systemd, SSH, or startup files were modified."