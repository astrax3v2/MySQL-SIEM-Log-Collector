#!/usr/bin/env bash
set -euo pipefail
MYSQL_LOG_DIR="${MYSQL_LOG_DIR:-/var/log/mysql}"
logs=("$MYSQL_LOG_DIR/mysql.log" "$MYSQL_LOG_DIR/error.log" "$MYSQL_LOG_DIR/mysql-slow.log" "$MYSQL_LOG_DIR/audit.log")

echo "[INFO] MySQL variable validation"
mysql -e "SHOW VARIABLES WHERE Variable_name IN ('general_log','general_log_file','log_output','slow_query_log','slow_query_log_file','log_error');" || echo "[WARN] Could not query MySQL. Check credentials/socket."

echo
echo "[INFO] Log file validation"
for log in "${logs[@]}"; do
  if [[ -e "$log" ]]; then
    ls -lh "$log"
  else
    echo "[WARN] Missing: $log"
  fi
done

echo
echo "[INFO] Generate sample events with: mysql < tests/mysql_test_queries.sql"
echo "[INFO] Tail general log with: sudo tail -f $MYSQL_LOG_DIR/mysql.log"
