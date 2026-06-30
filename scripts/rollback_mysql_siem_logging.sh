#!/usr/bin/env bash
set -euo pipefail
CONFIG_MARKER_BEGIN="# BEGIN MYSQL SIEM LOGGING CONFIG"
CONFIG_MARKER_END="# END MYSQL SIEM LOGGING CONFIG"

fail(){ echo "[ERROR] $*" >&2; exit 1; }
info(){ echo "[INFO] $*"; }
[[ ${EUID} -eq 0 ]] || fail "Run as root or with sudo."

candidates=("/etc/mysql/mysql.conf.d/mysqld.cnf" "/etc/mysql/my.cnf" "/etc/my.cnf" "/etc/my.cnf.d/mysql-server.cnf" "/etc/my.cnf.d/mysqld.cnf")
MYSQL_CONFIG_FILE=""
for file in "${candidates[@]}"; do [[ -f "$file" ]] && MYSQL_CONFIG_FILE="$file" && break; done
[[ -n "$MYSQL_CONFIG_FILE" ]] || fail "MySQL config file not found."

cp "$MYSQL_CONFIG_FILE" "${MYSQL_CONFIG_FILE}.rollback.bak.$(date +%Y%m%d_%H%M%S)"
sed -i "/$CONFIG_MARKER_BEGIN/,/$CONFIG_MARKER_END/d" "$MYSQL_CONFIG_FILE"

if systemctl list-unit-files | grep -q '^mysql.service'; then MYSQL_SERVICE="mysql"; else MYSQL_SERVICE="mysqld"; fi
systemctl restart "$MYSQL_SERVICE"
mysql -e "SET GLOBAL general_log = 'OFF';" 2>/dev/null || true
info "Rollback completed and MySQL restarted."
