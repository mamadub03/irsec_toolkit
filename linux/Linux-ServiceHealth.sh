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
