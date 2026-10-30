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

check_port() {
    local port="$1"
    local label="$2"

    if ! command -v ss >/dev/null 2>&1; then
        report WARN "$label" "ss unavailable" \
            "Install or use an available socket inspection utility."
        return
    fi

    local matches
    matches="$(
        ss -H -ltn "( sport = :$port )" 2>/dev/null || true
    )"

    if [[ -n "$matches" ]]; then
        report PASS "$label" "TCP $port listening"
    else
        report FAIL "$label" "TCP $port not listening" \
            "Inspect the service listener, binding address, and config."
    fi
}

check_tcp_response() {
    local port="$1"
    local label="$2"

    if ! command -v timeout >/dev/null 2>&1; then
        report WARN "$label" "timeout command unavailable"
        return
    fi

    if timeout 2 bash -c \
        'exec 3<>/dev/tcp/127.0.0.1/"$1"' _ "$port" \
        >/dev/null 2>&1; then
        report PASS "$label" "Local TCP $port accepted"
    else
        report FAIL "$label" "Local TCP $port failed" \
            "Inspect service logs, listener address, and configuration."
    fi
}

echo
echo "========================================"
echo "       IRSeC LINUX SERVICE HEALTH"
echo "========================================"
echo "Host: $(hostname)"
echo "Profile: $ROLE"
echo "Time: $(date -Is)"
echo "Mode: READ ONLY"
echo

# ------------------------------------------------------------
# General networking
# ------------------------------------------------------------

if command -v ip >/dev/null 2>&1; then
    addresses="$(
        ip -o -4 addr show scope global 2>/dev/null |
        awk '{print $4}' | paste -sd ',' -
    )"

    if [[ -n "$addresses" ]]; then
        report PASS "IPv4 addresses" "$addresses"
    else
        report FAIL "IPv4 addresses" "No global-scope IPv4 address" \
            "Inspect: ip addr; ip link"
    fi

    routes="$(ip -4 route show default 2>/dev/null || true)"

    if [[ -n "$routes" ]]; then
        report PASS "Default route" "$routes"
    else
        report WARN "Default route" "No default IPv4 route" \
            "Inspect: ip route; verify this host requires a default gateway."
    fi
else
    report WARN "Network tools" "ip command unavailable"
fi

# Read-only firewall overview.
if command -v ufw >/dev/null 2>&1; then
    fw="$(ufw status 2>/dev/null | head -n 1)"
    report INFO "UFW status" "${fw:-Unavailable}"
fi

if command -v firewall-cmd >/dev/null 2>&1; then
    fw="$(firewall-cmd --state 2>/dev/null || true)"
    report INFO "firewalld" "${fw:-Not running or inaccessible}"
fi

if command -v nft >/dev/null 2>&1; then
    rules="$(nft list ruleset 2>/dev/null | wc -l)"
    report INFO "nftables" "$rules lines in current ruleset"
fi

# ------------------------------------------------------------
# SSH - pitlane
# ------------------------------------------------------------

case "$ROLE" in

    pitlane)
        check_any_service "SSH daemon" ssh sshd
        check_port 22 "SSH listener"
        check_tcp_response 22 "SSH TCP response"

        if command -v sshd >/dev/null 2>&1; then
            sshd_path="$(command -v sshd)"
        elif [[ -x /usr/sbin/sshd ]]; then
            sshd_path="/usr/sbin/sshd"
        else
            sshd_path=""
        fi

        if [[ -n "$sshd_path" ]]; then
            if "$sshd_path" -t >/dev/null 2>&1; then
                report PASS "SSH configuration" "Syntax valid"
            else
                report FAIL "SSH configuration" "Syntax validation failed" \
                    "Inspect sshd_config and included configuration files."
            fi
        else
            report WARN "SSH configuration" "sshd binary not found"
        fi
        ;;

# ------------------------------------------------------------
# FTP - garage
# ------------------------------------------------------------

    garage)
        check_any_service "FTP daemon" \
            vsftpd proftpd pure-ftpd

        check_port 21 "FTP control listener"
        check_tcp_response 21 "FTP TCP response"

        report INFO "FTP authentication" \
            "Login and transfer not tested" \
            "Verify authorized FTP login and file operations."
        ;;

# ------------------------------------------------------------
# Docker / IRC - grandstand
# ------------------------------------------------------------

    grandstand)
        check_service docker "Docker daemon"

        if ! command -v docker >/dev/null 2>&1; then
            report FAIL "Docker CLI" "docker unavailable" \
                "Check Docker installation."
        else
            containers="$(
                docker ps -a --format \
                    '{{.Names}}|{{.Status}}|{{.Ports}}' \
                    2>/dev/null
            )"
            docker_rc=$?

            if (( docker_rc != 0 )); then
                report FAIL "Docker access" "Cannot inspect containers" \
                    "Inspect Docker daemon and local permissions."
            elif [[ -z "$containers" ]]; then
                report FAIL "Docker containers" "No containers found" \
                    "Inspect the expected Compose project."
            else
                echo
                echo "=== DOCKER CONTAINERS ==="

                while IFS='|' read -r name status ports; do
                    [[ -n "$name" ]] || continue

                    if [[ "$status" == Up* ]]; then
                        report PASS "Container $name" "$status"
                    else
                        report FAIL "Container $name" "$status" \
                            "Inspect docker logs and the Compose project."
                    fi

                    [[ -n "$ports" ]] && \
                        report INFO "$name ports" "$ports"
                done <<< "$containers"
            fi

            if [[ -n "$COMPOSE_DIR" ]]; then
                if [[ -d "$COMPOSE_DIR" ]] &&
                    docker compose version >/dev/null 2>&1; then

                    echo
                    echo "=== COMPOSE PROJECT ==="

                    (
                        cd "$COMPOSE_DIR" &&
                        docker compose ps
                    ) 2>/dev/null || \
                        report WARN "Compose project" \
                            "Unable to list project containers" \
                            "Inspect the Compose path and project definition."
                else
                    report WARN "Compose project" \
                        "Directory or Compose plugin unavailable"
                fi
            else
                report INFO "Compose project" \
                    "No project path supplied; container inventory only"
            fi
        fi

        report INFO "IRC functionality" \
            "IRC protocol and bot connection not automatically verified" \
            "Inspect IRC listener, bot logs, and Hermes scoring."
        ;;

# ------------------------------------------------------------
# MariaDB - scrutineering
# ------------------------------------------------------------

    scrutineering)
        check_any_service "MariaDB daemon" mariadb mysqld

        check_port 3306 "MariaDB listener"
        check_tcp_response 3306 "MariaDB TCP response"

        if command -v mariadb-admin >/dev/null 2>&1; then
            if timeout 3 mariadb-admin ping \
                --protocol=socket >/dev/null 2>&1; then
                report PASS "MariaDB ping" "Local server responded"
            else
                report WARN "MariaDB ping" "Socket ping unavailable/failed" \
                    "Inspect server socket, credentials, and logs."
            fi
        elif command -v mysqladmin >/dev/null 2>&1; then
            if timeout 3 mysqladmin ping \
                --protocol=socket >/dev/null 2>&1; then
                report PASS "MariaDB ping" "Local server responded"
            else
                report WARN "MariaDB ping" "Socket ping unavailable/failed" \
                    "Inspect server socket, credentials, and logs."
            fi
        fi

        report INFO "Database queries" \
            "Authenticated SQL query not tested" \
            "Verify approved database credentials and Hermes scoring."
        ;;

    *)
        echo "Unknown host profile: $ROLE"
        echo "Valid profiles: pitlane, garage, grandstand, scrutineering"
        exit 1
        ;;
esac

# ------------------------------------------------------------
# Final summary and troubleshooting recommendations
# ------------------------------------------------------------

echo
echo "========================================"
echo "               SUMMARY"
echo "========================================"
printf 'PASS: %d | WARN: %d | FAIL: %d | INFO: %d\n' \
    "$PASS" "$WARN" "$FAIL" "$INFO"

echo
echo "=== SUGGESTED INVESTIGATIONS ==="

if (( ${#PROBLEMS[@]} == 0 )); then
    echo "No obvious failures detected by the configured checks."
else
    for problem in "${PROBLEMS[@]}"; do
        IFS='|' read -r status component detail suggestion \
            <<< "$problem"

        echo "[$status] $component"
        echo "  $detail"

        if [[ -n "$suggestion" ]]; then
            echo "  Suggestion: $suggestion"
        fi
    done
fi

echo
echo "Read-only checks complete. No changes made."