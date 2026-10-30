#!/usr/bin/env bash
# IRSeC L09 - Linux Deep Diagnostics (read-only)
# Debian / Ubuntu / Rocky Linux
# sudo bash Linux-DeepDiagnostics.sh [pitlane|garage|grandstand|scrutineering] [compose_directory]

set -uo pipefail

ROLE="${1:-$(hostname -s)}"
ROLE="${ROLE,,}"
COMPOSE_DIR="${2:-}"

case "$ROLE" in
    pitlane|garage|grandstand|scrutineering) ;;
    *)
        echo "Unknown role: $ROLE"
        exit 2
        ;;
esac

issues=0
pass=0
info=0

header() {
    printf '\n========== %s ==========\n' "$1"
}

check() {
    local status="$1"
    local name="$2"
    local result="$3"
    local suggestion="${4:-}"

    printf '[%-4s] %-24s %s\n' \
        "$status" "$name" "$result"

    case "$status" in
        PASS) ((pass+=1)) ;;
        FAIL|WARN) ((issues+=1)) ;;
        INFO) ((info+=1)) ;;
    esac

    if [[ "$status" == FAIL || "$status" == WARN ]]; then
        if [[ -n "$suggestion" ]]; then
            printf '       -> %s\n' "$suggestion"
        fi
    fi
}

service() {
    local label="$1"
    local unit load state

    shift

    command -v systemctl >/dev/null || {
        check WARN "$label" 'systemctl unavailable'
        return
    }

    for unit in "$@"; do
        load="$(
            systemctl show "$unit" \
                -p LoadState --value 2>/dev/null || true
        )"

        [[ -z "$load" || "$load" == "not-found" ]] && continue

        state="$(systemctl is-active "$unit" 2>/dev/null || true)"

        if [[ "$state" == active ]]; then
            check PASS "$label" "$unit active"
        else
            check FAIL "$label" "$unit: $state" \
                "Inspect systemctl status $unit; journalctl -u $unit"
        fi

        return
    done

    check WARN "$label" \
        'No expected systemd unit detected' \
        'Check the actual daemon name'
}

listener() {
    local port="$1"
    local label="$2"
    local data addresses nonloop

    command -v ss >/dev/null || {
        check WARN "$label" 'ss unavailable'
        return
    }

    data="$(
        ss -H -ltn "( sport = :$port )" 2>/dev/null || true
    )"

    if [[ -z "$data" ]]; then
        check FAIL "$label" "No TCP $port listener" \
            'Review daemon, binding and configuration'
        return
    fi

    addresses="$(
        awk '{print $4}' <<< "$data" |
            sort -u |
            paste -sd, -
    )"

    nonloop="$(
        awk '{print $4}' <<< "$data" |
            grep -Ev '^(127\.[0-9.]+|\[::1\]|::1):[0-9]+$' ||
            true
    )"

    if [[ -z "$nonloop" ]]; then
        check WARN "$label" "Only loopback: $addresses" \
            'Remote clients cannot use this binding'
    else
        check PASS "$label" \
            "TCP $port listening at $addresses"
    fi
}

probe() {
    local port="$1"
    local label="$2"

    if timeout 2 bash -c \
        'exec 3<>/dev/tcp/127.0.0.1/"$1"' \
        _ "$port" 2>/dev/null; then

        check PASS "$label" "Local TCP $port connected"
    else
        check FAIL "$label" \
            "Local TCP $port could not connect" \
            'Inspect listener and local firewall'
    fi
}

banner() {
    local port="$1"
    local label="$2"
    local line=""

    if ! command -v timeout >/dev/null; then
        check WARN "$label" 'timeout unavailable'
        return
    fi

    line="$(
        timeout 3 bash -c \
            'exec 3<>/dev/tcp/127.0.0.1/"$1"; IFS= read -r -t 2 x <&3; printf "%s" "$x"' \
            _ "$port" 2>/dev/null || true
    )"

    line="${line:0:160}"

    if [[ -n "$line" ]]; then
        check PASS "$label" "Initial server text: $line"
    else
        check WARN "$label" \
            'No initial text within 2 seconds' \
            'TCP connection alone cannot prove application login readiness'
    fi
}

firewall() {
    local pattern="$1"
    local rules=""

    header "HOST FIREWALL HINTS ($pattern)"

    if command -v ufw >/dev/null; then
        ufw status verbose 2>/dev/null |
            grep -Ei "(^Status:|$pattern|deny|reject)" |
            head -n 25 || true
    fi

    if command -v firewall-cmd >/dev/null; then
        echo "firewalld: $(
            firewall-cmd --state 2>/dev/null || echo inactive
        )"

        firewall-cmd --list-all 2>/dev/null |
            head -n 35 || true
    fi

    if command -v nft >/dev/null; then
        nft -a list ruleset 2>/dev/null |
            grep -Ein "($pattern|drop|reject|policy|icmp)" |
            head -n 55 || true
    fi

    if command -v iptables-save >/dev/null; then
        iptables-save 2>/dev/null |
            grep -Ein "($pattern|DROP|REJECT|^:INPUT)" |
            head -n 35 || true
    fi

    check INFO Firewall \
        'Rule text is evidence, not an evaluated allow/block decision'
}

logs() {
    local unit="$1"

    header "RECENT $unit ERRORS"

    if command -v journalctl >/dev/null; then
        journalctl -u "$unit" \
            --since '30 minutes ago' \
            -p warning \
            --no-pager \
            -n 15 \
            -o short-iso 2>/dev/null || true
    else
        echo 'journalctl unavailable'
    fi
}

icmp() {
    header 'ICMP ECHO CONFIGURATION'

    if [[ -r /proc/sys/net/ipv4/icmp_echo_ignore_all ]]; then
        local value

        value="$(
            cat /proc/sys/net/ipv4/icmp_echo_ignore_all
        )"

        if [[ "$value" == 1 ]]; then
            check FAIL 'IPv4 echo replies' \
                'icmp_echo_ignore_all=1' \
                'Review /etc/sysctl.conf and /etc/sysctl.d/*.conf'
        else
            check PASS 'IPv4 echo replies' \
                "icmp_echo_ignore_all=$value"
        fi
    fi

    if [[ -r /proc/sys/net/ipv6/icmp/echo_ignore_all ]]; then
        check INFO 'IPv6 echo replies' \
            "echo_ignore_all=$(
                cat /proc/sys/net/ipv6/icmp/echo_ignore_all
            )"
    fi

    check INFO 'Remote ping' \
        'Not verified locally; test from a second authorized machine'
}

# ============================================================
# HOST / NETWORK
# ============================================================

header 'HOST / NETWORK'

echo "Host: $(hostname) | Role: $ROLE | $(date -Is) | READ-ONLY"

if command -v ip >/dev/null; then
    ip -brief -4 address
    ip -4 route
fi

icmp

# ============================================================
# SERVICE-SPECIFIC DIAGNOSTICS
# ============================================================

case "$ROLE" in

    # --------------------------------------------------------
    # PITLANE - SSH
    # --------------------------------------------------------

    pitlane)
        header 'SSH DETAILS'

        service SSH ssh sshd
        listener 22 SSH
        probe 22 'SSH TCP'
        banner 22 'SSH banner'

        sshd_bin="$(
            command -v sshd 2>/dev/null || true
        )"

        if [[ -z "$sshd_bin" && -x /usr/sbin/sshd ]]; then
            sshd_bin=/usr/sbin/sshd
        fi

        if [[ -n "$sshd_bin" ]]; then

            if "$sshd_bin" -t >/dev/null 2>&1; then
                check PASS 'sshd syntax' 'Valid'
            else
                check FAIL 'sshd syntax' \
                    'Invalid' \
                    'Inspect sshd_config and includes'
            fi

            echo 'Effective SSH configuration (selected fields):'

            "$sshd_bin" -T 2>/dev/null |
                grep -E \
                '^(port|listenaddress|passwordauthentication|pubkeyauthentication|permitrootlogin|allowusers|denyusers|authenticationmethods) ' |
                head -n 25 || true

            check INFO 'SSH effective settings' \
                'Match blocks may require sshd -T -C user=...,host=...,addr=...'

        else
            check WARN 'sshd binary' 'Not found'
        fi

        firewall '22|ssh'

        logs ssh
        logs sshd
        ;;

    # --------------------------------------------------------
    # GARAGE - FTP
    # --------------------------------------------------------

    garage)
        header 'FTP DETAILS'

        service FTP vsftpd proftpd pure-ftpd
        listener 21 FTP
        probe 21 'FTP TCP'
        banner 21 'FTP greeting'

        for f in \
            /etc/vsftpd.conf \
            /etc/vsftpd/vsftpd.conf \
            /etc/proftpd/proftpd.conf
        do
            if [[ -r "$f" ]]; then
                echo "FTP settings in $f:"

                grep -Ei \
                    '^[[:space:]]*(listen|listen_ipv6|listen_address|pasv_enable|pasv_min_port|pasv_max_port|pasv_address|anonymous_enable|local_enable|port|PassivePorts|RequireValidShell)' \
                    "$f" |
                    head -n 35 || true
            fi
        done

        check INFO 'Passive FTP' \
            'Control port 21 is not enough; verify configured passive data port range'

        firewall '21|ftp|pasv'

        logs vsftpd
        logs proftpd
        ;;

    # --------------------------------------------------------
    # GRANDSTAND - DOCKER / IRC
    # --------------------------------------------------------

    grandstand)
        header 'DOCKER / IRC DETAILS'

        service Docker docker

        if command -v docker >/dev/null; then

            docker ps -a \
                --format \
                'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
                2>/dev/null ||
                check WARN Docker 'Cannot query daemon'

            if [[ -n "$COMPOSE_DIR" ]]; then

                if [[ -d "$COMPOSE_DIR" ]]; then
                    (
                        cd "$COMPOSE_DIR" &&
                        docker compose ps
                    ) 2>/dev/null ||
                        check WARN Compose \
                            'Cannot inspect project'
                else
                    check WARN Compose \
                        "Directory missing: $COMPOSE_DIR"
                fi

            else
                check INFO Compose \
                    'Supply actual project directory as second argument for project-specific status'
            fi

            check INFO IRC \
                'Inspect published IRC port and bot container status above; no universal port assumed'

        else
            check FAIL Docker \
                'docker executable missing'
        fi

        firewall '6667|6697|irc|docker'

        logs docker
        ;;

    # --------------------------------------------------------
    # SCRUTINEERING - MARIADB
    # --------------------------------------------------------

    scrutineering)
        header 'MARIADB DETAILS'

        service MariaDB mariadb mysqld
        listener 3306 MariaDB
        probe 3306 'MariaDB TCP'

        for dir in \
            /etc/mysql/mariadb.conf.d \
            /etc/my.cnf.d \
            /etc/mysql/conf.d
        do
            if [[ -d "$dir" ]]; then

                grep -EinH \
                    '^[[:space:]]*(bind-address|port|skip-networking|socket)[[:space:]]*=' \
                    "$dir"/*.cnf 2>/dev/null |
                    head -n 35 || true
            fi
        done

        for f in \
            /etc/my.cnf \
            /etc/mysql/my.cnf
        do
            if [[ -r "$f" ]]; then
                grep -Ein \
                    '^[[:space:]]*(bind-address|port|skip-networking|socket)[[:space:]]*=' \
                    "$f" 2>/dev/null || true
            fi
        done

        if command -v mariadb-admin >/dev/null; then
            admin=mariadb-admin
        elif command -v mysqladmin >/dev/null; then
            admin=mysqladmin
        else
            admin=''
        fi

        if [[ -n "$admin" ]]; then

            if timeout 3 "$admin" \
                --protocol=socket ping \
                >/dev/null 2>&1; then

                check PASS 'MariaDB server ping' \
                    'Server responded (does NOT prove SQL authentication)'

            else
                check WARN 'MariaDB server ping' \
                    'No local socket response'
            fi
        fi

        if command -v mariadb >/dev/null; then

            if timeout 4 mariadb \
                --protocol=socket \
                --batch \
                --skip-column-names \
                -e 'SELECT 1' \
                >/dev/null 2>&1; then

                check PASS 'Local SQL query' \
                    'SELECT 1 succeeded with existing local credentials'

            else
                check INFO 'Local SQL query' \
                    'Not verified with current local credentials; this is not proof database is down'
            fi
        fi

        check INFO 'Remote SQL access' \
            'Not verified: check bind-address, grants, and external scoring path'

        firewall '3306|mysql|mariadb'

        logs mariadb
        logs mysqld
        ;;
esac

# ============================================================
# SUMMARY
# ============================================================

header 'SUMMARY'

echo "PASS: $pass | WARN/FAIL: $issues | INFO: $info"
echo 'Read-only diagnostics complete.'
echo 'This host cannot prove external Hermes/pfSense access.'