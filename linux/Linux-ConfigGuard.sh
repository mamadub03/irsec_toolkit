#!/usr/bin/env bash
# IRSeC L03 - Linux Service Configuration Guard
# Debian 12 / Ubuntu 22.04 / Ubuntu 24.04 / Rocky Linux 9
#
# Usage:
# sudo bash Linux-ConfigGuard.sh SERVICE ACTION [COMPOSE_DIR]
#
# SERVICES: ssh, ftp, docker, mariadb
# ACTIONS:  backup, compare, restore

set -euo pipefail
umask 077

SERVICE="${1:-}"
ACTION="${2:-}"
COMPOSE_DIR="${3:-}"

ROOT="/var/backups/irsec-configguard"

if (( EUID != 0 )); then
    echo "Run as root using sudo."
    exit 1
fi

case "$SERVICE" in
    ssh|ftp|docker|mariadb) ;;
    *)
        echo "Invalid service."
        echo "Choose: ssh, ftp, docker, mariadb"
        exit 1
        ;;
esac

case "$ACTION" in
    backup|compare|restore) ;;
    *)
        echo "Invalid action."
        echo "Choose: backup, compare, restore"
        exit 1
        ;;
esac

command -v sha256sum >/dev/null || {
    echo "sha256sum is required."
    exit 1
}

BACKUP="$ROOT/$SERVICE"
FILESTORE="$BACKUP/files"
MANIFEST="$BACKUP/manifest.tsv"
PATHLIST="$BACKUP/paths.txt"

declare -a CONFIG_FILES=()

add_file() {
    local file="$1"

    [[ -f "$file" && ! -L "$file" ]] || return 0

    local absolute
    absolute="$(realpath -e -- "$file")"

    # Only track normal files.
    [[ -f "$absolute" ]] || return 0

    local existing
    for existing in "${CONFIG_FILES[@]}"; do
        [[ "$existing" == "$absolute" ]] && return 0
    done

    CONFIG_FILES+=("$absolute")
}

add_directory_files() {
    local dir="$1"
    [[ -d "$dir" ]] || return 0

    while IFS= read -r -d '' file; do
        add_file "$file"
    done < <(
        find "$dir" -type f -print0
    )
}

case "$SERVICE" in
    ssh)
        add_file /etc/ssh/sshd_config
        add_directory_files /etc/ssh/sshd_config.d
        ;;

    ftp)
        add_file /etc/vsftpd.conf
        add_file /etc/vsftpd/vsftpd.conf
        add_directory_files /etc/vsftpd
        add_file /etc/proftpd/proftpd.conf
        add_directory_files /etc/proftpd
        add_directory_files /etc/pure-ftpd/conf
        ;;

    mariadb)
        add_file /etc/my.cnf
        add_directory_files /etc/my.cnf.d
        add_file /etc/mysql/my.cnf
        add_directory_files /etc/mysql/mariadb.conf.d
        add_directory_files /etc/mysql/conf.d
        ;;

    docker)
        if [[ -z "$COMPOSE_DIR" || ! -d "$COMPOSE_DIR" ]]; then
            echo "Supply the actual Docker Compose project directory."
            echo "Example: sudo bash $0 docker backup /opt/irc"
            exit 1
        fi

        COMPOSE_DIR="$(realpath -e -- "$COMPOSE_DIR")"

        add_file "$COMPOSE_DIR/compose.yaml"
        add_file "$COMPOSE_DIR/compose.yml"
        add_file "$COMPOSE_DIR/docker-compose.yaml"
        add_file "$COMPOSE_DIR/docker-compose.yml"
        add_file "$COMPOSE_DIR/.env"

        # Include common Compose override files.
        while IFS= read -r -d '' file; do
            add_file "$file"
        done < <(
            find "$COMPOSE_DIR" -maxdepth 1 -type f \
                \( -name '*compose*.yaml' \
                -o -name '*compose*.yml' \) -print0
        )
        ;;
esac

# Sort discovered paths consistently.
if (( ${#CONFIG_FILES[@]} > 0 )); then
    mapfile -t CONFIG_FILES < <(
        printf '%s\n' "${CONFIG_FILES[@]}" | sort -u
    )
fi

if [[ "$ACTION" == backup ]]; then
    if [[ -e "$BACKUP" ]]; then
        echo "Backup already exists: $BACKUP"
        echo "Refusing to overwrite."
        exit 1
    fi

    if (( ${#CONFIG_FILES[@]} == 0 )); then
        echo "No configuration files detected."
        exit 1
    fi

    install -d -m 700 "$FILESTORE"

    : > "$MANIFEST"
    : > "$PATHLIST"

    count=0

    for file in "${CONFIG_FILES[@]}"; do
        saved="$FILESTORE/$count.bak"

        cp -a -- "$file" "$saved"

        original_hash="$(sha256sum "$file" | awk '{print $1}')"
        saved_hash="$(sha256sum "$saved" | awk '{print $1}')"

        if [[ "$original_hash" != "$saved_hash" ]]; then
            echo "Backup verification failed: $file"
            exit 1
        fi

        printf '%s\t%s\t%s\n' \
            "$file" "$count.bak" "$original_hash" >> "$MANIFEST"

        printf '%s\n' "$file" >> "$PATHLIST"

        ((count+=1))
    done

    chmod 600 "$MANIFEST" "$PATHLIST"

    echo
    echo "[+] Backup completed."
    echo "Service: $SERVICE"
    echo "Backup: $BACKUP"
    echo "Files: $count"
    echo
    echo "Review the captured configuration before trusting it."
    exit 0
fi

if [[ ! -f "$MANIFEST" ]]; then
    echo "No backup exists. Run backup first."
    exit 1
fi

# Read original manifest.
declare -a ORIGINAL_PATHS=()
declare -a SAVED_NAMES=()
declare -a ORIGINAL_HASHES=()

while IFS=$'\t' read -r path saved hash; do
    [[ -n "$path" ]] || continue

    ORIGINAL_PATHS+=("$path")
    SAVED_NAMES+=("$saved")
    ORIGINAL_HASHES+=("$hash")
done < "$MANIFEST"

if [[ "$ACTION" == compare ]]; then
    echo
    echo "=== CONFIGURATION DIFFERENCES ==="

    changes=0

    for i in "${!ORIGINAL_PATHS[@]}"; do
        path="${ORIGINAL_PATHS[$i]}"

        if [[ ! -e "$path" ]]; then
            echo "[MISSING] $path"
            ((changes+=1))
            continue
        fi

        if [[ -L "$path" || ! -f "$path" ]]; then
            echo "[TYPE CHANGED] $path"
            ((changes+=1))
            continue
        fi

        current_hash="$(sha256sum "$path" | awk '{print $1}')"

        if [[ "$current_hash" != "${ORIGINAL_HASHES[$i]}" ]]; then
            echo "[MODIFIED] $path"
            ((changes+=1))
        fi
    done

    # Detect newly introduced files within our tracked paths.
    for file in "${CONFIG_FILES[@]}"; do
        known=0

        for old in "${ORIGINAL_PATHS[@]}"; do
            if [[ "$file" == "$old" ]]; then
                known=1
                break
            fi
        done

        if (( known == 0 )); then
            echo "[ADDED] $file"
            ((changes+=1))
        fi
    done

    if (( changes == 0 )); then
        echo "[+] No tracked configuration differences."
    else
        echo
        echo "Total changes detected: $changes"
    fi

    echo
    echo "Comparison finished. No changes were made."
    exit 0
fi

if [[ "$ACTION" == restore ]]; then
    echo
    echo "=== SELECT CONFIGURATION TO RESTORE ==="

    for i in "${!ORIGINAL_PATHS[@]}"; do
        printf '%d. %s\n' \
            "$((i+1))" "${ORIGINAL_PATHS[$i]}"
    done

    echo
    read -r -p "Enter file number: " number

    if [[ ! "$number" =~ ^[0-9]+$ ]]; then
        echo "Invalid number."
        exit 1
    fi

    # Force base-10 interpretation.
    number=$((10#$number))

    if (( number < 1 || number > ${#ORIGINAL_PATHS[@]} )); then
        echo "Selection out of range."
        exit 1
    fi

    index=$((number-1))

    target="${ORIGINAL_PATHS[$index]}"
    source="$FILESTORE/${SAVED_NAMES[$index]}"
    expected_hash="${ORIGINAL_HASHES[$index]}"

    if [[ ! -f "$source" || -L "$source" ]]; then
        echo "Backup file missing or unsafe."
        exit 1
    fi

    actual_hash="$(sha256sum "$source" | awk '{print $1}')"

    if [[ "$actual_hash" != "$expected_hash" ]]; then
        echo "Backup integrity verification failed."
        exit 1
    fi

    if [[ -L "$target" ]]; then
        echo "Target is a symbolic link. Manual review required."
        exit 1
    fi

    if [[ -e "$target" && ! -f "$target" ]]; then
        echo "Target is not a regular file. Refusing."
        exit 1
    fi

    if [[ ! -d "$(dirname "$target")" ]]; then
        echo "Target directory missing."
        exit 1
    fi

    echo
    echo "File selected: $target"
    echo "Service: $SERVICE"
    echo
    echo "The current file will be preserved for rollback."
    echo "The service will NOT automatically restart."

    read -r -p "Type RESTORE to proceed: " confirmation

    if [[ "$confirmation" != "RESTORE" ]]; then
        echo "Cancelled."
        exit 0
    fi

    rollback_dir="$BACKUP/rollback"
    install -d -m 700 "$rollback_dir"

    if [[ -f "$target" ]]; then
        rollback="$rollback_dir/$(date +%Y%m%d%H%M%S)-${SAVED_NAMES[$index]}"
        cp -a -- "$target" "$rollback"
        echo "Current file saved to: $rollback"
    fi

    cp -a -- "$source" "$target"

    restored_hash="$(sha256sum "$target" | awk '{print $1}')"

    if [[ "$restored_hash" != "$expected_hash" ]]; then
        echo "Restoration hash verification FAILED."
        exit 1
    fi

    echo
    echo "[+] Configuration file restored successfully."
    echo "Service was not restarted."
    echo "Verify syntax and service availability."
fi