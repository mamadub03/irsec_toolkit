#!/usr/bin/env bash
# IRSeC L06 - Linux Firewall Viewer
# READ ONLY
#
# sudo bash Linux-FirewallViewer.sh
# sudo bash Linux-FirewallViewer.sh --port 22
# sudo bash Linux-FirewallViewer.sh --port 3306
# sudo bash Linux-FirewallViewer.sh --ip 10.1.1.45

set -uo pipefail

PORT=""
IP=""

while (( $# > 0 )); do
    case "$1" in
        --port)
            [[ $# -ge 2 ]] || exit 2
            PORT="$2"
            shift 2
            ;;
        --ip)
            [[ $# -ge 2 ]] || exit 2
            IP="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 2
            ;;
    esac
done

if [[ -n "$PORT" ]]; then
    if [[ ! "$PORT" =~ ^[0-9]+$ ]] ||
       (( 10#$PORT < 1 || 10#$PORT > 65535 )); then
        echo "Invalid port."
        exit 2
    fi
fi

if (( EUID != 0 )); then
    echo "Run with sudo for full firewall visibility."
fi

section() {
    printf '\n========== %s ==========\n' "$1"
}

show_output() {
    local result="$1"

    if [[ -z "$PORT" && -z "$IP" ]]; then
        printf '%s\n' "$result"
        return
    fi

    echo "--- Matching lines (not a complete ruleset evaluation) ---"

    if [[ -n "$PORT" ]]; then
        printf '%s\n' "$result" |
            grep -nE "(^|[^0-9])${PORT}([^0-9]|$)" || true
    fi

    if [[ -n "$IP" ]]; then
        printf '%s\n' "$result" |
            grep -nF -- "$IP" || true
    fi

    echo "Use without filters to examine surrounding rules and chains."
}

section "HOST NETWORK INFORMATION"
hostname
ip -brief address 2>/dev/null || true
ip -4 route 2>/dev/null || true

section "UFW"
if command -v ufw >/dev/null 2>&1; then
    output="$(ufw status verbose 2>&1)"
    show_output "$output"
else
    echo "UFW not installed."
fi

section "FIREWALLD"
if command -v firewall-cmd >/dev/null 2>&1; then
    state="$(firewall-cmd --state 2>/dev/null || true)"
    echo "State: ${state:-unavailable}"

    if [[ "$state" == running ]]; then
        zones="$(firewall-cmd --get-active-zones 2>&1)"
        echo "$zones"

        output="$(firewall-cmd --list-all-zones 2>&1)"
        show_output "$output"
    fi
else
    echo "firewalld not installed."
fi

section "NFTABLES"
if command -v nft >/dev/null 2>&1; then
    output="$(nft -a list ruleset 2>&1)"
    show_output "$output"
else
    echo "nft unavailable."
fi

section "IPTABLES - IPv4"
if command -v iptables-save >/dev/null 2>&1; then
    output="$(iptables-save -c 2>&1)"
    show_output "$output"
else
    echo "iptables-save unavailable."
fi

section "IPTABLES - IPv6"
if command -v ip6tables-save >/dev/null 2>&1; then
    output="$(ip6tables-save -c 2>&1)"
    show_output "$output"
else
    echo "ip6tables-save unavailable."
fi

if [[ -n "$PORT" ]]; then
    section "LOCAL TCP LISTENER ON $PORT"

    if command -v ss >/dev/null 2>&1; then
        ss -ltnp "( sport = :$PORT )" 2>/dev/null || true
    fi
fi

section "OPERATOR NOTES"
echo "Check the active interface, default policy, rule order,"
echo "source IP restrictions, and the actual listening address."
echo "Docker may add its own forwarding and NAT rules."
echo "Do not treat text matches as a definitive allow/block result."
echo "If local access works, inspect pfSense and test from another host."
echo
echo "No firewall or network settings were modified."