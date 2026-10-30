#!/usr/bin/env bash
# IRSeC L01 - Linux Local Password Rotator
# Debian / Ubuntu / Rocky Linux
# Run using sudo.

set -euo pipefail
set +x
umask 077

[[ $EUID -eq 0 ]] || {
    echo "Run as root with sudo."
    exit 1
}

command -v chpasswd >/dev/null || {
    echo "chpasswd unavailable."
    exit 1
}

ADMINS=(scrutineer techdirector crewchief firecrew)
REGULAR=(jackcrew garagecrew celebrity pitlaner reserve gunners)
APPROVED=("${ADMINS[@]}" "${REGULAR[@]}")
PROTECTED=(root whiteteam dd-agent ddagentuser nobody)

contains() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        [[ "$needle" == "$item" ]] && return 0
    done
    return 1
}

# Protect users referenced by systemd service definitions.
declare -A SERVICE_USERS=()

if command -v systemctl >/dev/null; then
    while IFS= read -r unit; do
        [[ -n "$unit" ]] || continue
        svc_user="$(
            systemctl show "$unit" -p User --value 2>/dev/null || true
        )"
        [[ -n "$svc_user" ]] && SERVICE_USERS["$svc_user"]=1
    done < <(
        systemctl list-unit-files --type=service --no-legend |
            awk '{print $1}'
    )
fi

eligible() {
    local user="$1"
    local uid

    contains "$user" "${APPROVED[@]}" || return 1
    contains "$user" "${PROTECTED[@]}" && return 1
    [[ -z "${SERVICE_USERS[$user]:-}" ]] || return 1

    # Require an actual local passwd entry.
    local entry
    entry="$(awk -F: -v n="$user" '$1==n {print}' /etc/passwd)"
    [[ -n "$entry" ]] || return 1

    uid="$(printf '%s\n' "$entry" | cut -d: -f3)"
    [[ "$uid" =~ ^[0-9]+$ ]] || return 1
    (( uid >= 1000 && uid != 65534 )) || return 1

    return 0
}

available=()
for user in "${APPROVED[@]}"; do
    if eligible "$user"; then
        available+=("$user")
    fi
done

(( ${#available[@]} > 0 )) || {
    echo "No eligible local users found."
    exit 1
}

echo "=== IRSeC LINUX LOCAL ROTATOR ==="
printf 'Eligible: %s\n' "${available[*]}"
echo '[1] ONE'
echo '[2] SELECTED'
echo '[3] ALL'
echo '[4] REGULAR only'
echo '[5] Exit'

read -r -p "Choose: " choice
targets=()

case "$choice" in
    1)
        read -r -p "Username: " user
        targets=("$user")
        ;;
    2)
        read -r -p "Comma-separated usernames: " input
        IFS=, read -r -a targets <<< "$input"
        ;;
    3)
        targets=("${available[@]}")
        ;;
    4)
        for user in "${available[@]}"; do
            contains "$user" "${REGULAR[@]}" &&
                targets+=("$user")
        done
        ;;
    5) exit 0 ;;
    *) echo "Invalid option."; exit 1 ;;
esac

(( ${#targets[@]} > 0 )) || {
    echo "No accounts selected."
    exit 1
}

declare -A seen=()
for i in "${!targets[@]}"; do
    user="${targets[$i]}"
    user="${user#"${user%%[![:space:]]*}"}"
    user="${user%"${user##*[![:space:]]}"}"
    targets[$i]="$user"

    [[ -n "$user" ]] || {
        echo "Empty username."
        exit 1
    }

    [[ -z "${seen[$user]:-}" ]] || {
        echo "Duplicate: $user"
        exit 1
    }
    seen["$user"]=1

    eligible "$user" || {
        echo "Unapproved or protected account: $user"
        exit 1
    }
done

# Current operator goes LAST when selected.
CURRENT="${SUDO_USER:-$(id -un)}"
ordered=()
for user in "${targets[@]}"; do
    [[ "$user" != "$CURRENT" ]] && ordered+=("$user")
done
for user in "${targets[@]}"; do
    [[ "$user" == "$CURRENT" ]] && ordered+=("$user")
done
targets=("${ordered[@]}")

printf '\nSelected: %s\n' "${targets[*]}"
read -r -p "Type ROTATE ${#targets[@]}: " confirm
[[ "$confirm" == "ROTATE ${#targets[@]}" ]] || exit 0

for user in "${targets[@]}"; do
    if contains "$user" "${ADMINS[@]}"; then
        read -r -p "Admins selected. Type ADMINS: " confirm
        [[ "$confirm" == ADMINS ]] || exit 0
        break
    fi
done

if contains "$CURRENT" "${targets[@]}"; then
    echo "Current account $CURRENT will rotate LAST."
    read -r -p "Type CURRENT: " confirm
    [[ "$confirm" == CURRENT ]] || exit 0
fi

echo '[1] Unique passwords (recommended)'
echo '[2] Shared password'
read -r -p "Choose: " mode
[[ "$mode" == 1 || "$mode" == 2 ]] || exit 0

if [[ "$mode" == 2 && ${#targets[@]} -gt 1 ]]; then
    read -r -p "Shared-password risk. Type SHARED: " confirm
    [[ "$confirm" == SHARED ]] || exit 0
fi

read_password() {
    local label="$1"
    local a b

    while true; do
        read -r -s -p "Password for $label: " a
        echo
        read -r -s -p "Confirm password: " b
        echo

        if [[ -n "$a" && "$a" == "$b" ]]; then
            REPLY="$a"
            unset a b
            return
        fi

        unset a b
        echo "Passwords did not match."
    done
}

declare -a PASSWORDS=()
cleanup() {
    unset PASSWORDS REPLY shared
}
trap cleanup EXIT

if [[ "$mode" == 2 ]]; then
    read_password 'ALL SELECTED'
    shared="$REPLY"
fi

# Collect all passwords before making changes.
for user in "${targets[@]}"; do
    if [[ "$mode" == 1 ]]; then
        read_password "$user"
        PASSWORDS+=("$REPLY")
    else
        PASSWORDS+=("$shared")
    fi
    unset REPLY
done
unset shared

echo "=== ROTATION RESULTS ==="
success=0

for i in "${!targets[@]}"; do
    user="${targets[$i]}"

    if ! eligible "$user"; then
        echo "[STOP] Account no longer eligible: $user"
        break
    fi

    # Password is supplied via stdin, never as a command argument.
    if printf '%s:%s\n' "$user" "${PASSWORDS[$i]}" |
        chpasswd; then
        echo "[SUCCESS] $user"
        ((success+=1))
    else
        echo "[STOP] Reset failed: $user"
        break
    fi
done

echo "Completed: $success / ${#targets[@]}"
echo "Verify login with the new credentials."