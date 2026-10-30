#!/bin/bash
# IRSeC 2026 - Linux Account Checker
# Read-only: does not modify accounts.

APPROVED=(
    scrutineer techdirector crewchief firecrew
    jackcrew garagecrew celebrity
    pitlaner reserve gunners
)

PROTECTED=(
    root whiteteam nobody
    dd-agent ddagentuser
)

contains() {
    local item="$1"
    shift

    for entry in "$@"; do
        [[ "$entry" == "$item" ]] && return 0
    done

    return 1
}

echo "=== LINUX ACCOUNT CHECK ==="
printf "%-22s %-8s %-12s %s\n" \
    "ACCOUNT" "UID" "ENABLED" "STATUS"

SUSPICIOUS=()

# Read actual local accounts.
while IFS=: read -r user pass uid gid info home shell; do

    if contains "$user" "${PROTECTED[@]}"; then
        status="PROTECTED"

    elif contains "$user" "${APPROVED[@]}"; then
        status="APPROVED"

    elif [[ "$uid" -lt 1000 ]]; then
        # System and service identities.
        # Not automatically considered malicious.
        status="SYSTEM_REVIEW"

    else
        status="INVESTIGATE"
        SUSPICIOUS+=("$user")
    fi

    if [[ "$shell" == *nologin || "$shell" == */false ]]; then
        enabled="NO_LOGIN"
    else
        enabled="CHECK"
    fi

    printf "%-22s %-8s %-12s %s\n" \
        "$user" "$uid" "$enabled" "$status"

done < /etc/passwd

echo
echo "=== UNRECOGNIZED ACCOUNTS ==="

if [[ ${#SUSPICIOUS[@]} -eq 0 ]]; then
    echo "No unrecognized regular accounts found."
else
    printf '%s\n' "${SUSPICIOUS[@]}"
fi

echo
echo "No accounts were modified."