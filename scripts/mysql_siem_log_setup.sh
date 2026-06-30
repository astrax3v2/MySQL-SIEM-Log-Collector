#!/usr/bin/env bash
set -euo pipefail

MYSQL_LOG_DIR="${MYSQL_LOG_DIR:-/var/log/mysql}"
MYSQL_GENERAL_LOG="${MYSQL_GENERAL_LOG:-${MYSQL_LOG_DIR}/mysql.log}"
MYSQL_ERROR_LOG="${MYSQL_ERROR_LOG:-${MYSQL_LOG_DIR}/error.log}"
MYSQL_SLOW_LOG="${MYSQL_SLOW_LOG:-${MYSQL_LOG_DIR}/mysql-slow.log}"
MYSQL_AUDIT_LOG="${MYSQL_AUDIT_LOG:-${MYSQL_LOG_DIR}/audit.log}"
LONG_QUERY_TIME="${LONG_QUERY_TIME:-2}"
FORWARDER="${FORWARDER:-none}"
SIEM_COLLECTOR_IP="${SIEM_COLLECTOR_IP:-}"
SIEM_COLLECTOR_PORT="${SIEM_COLLECTOR_PORT:-514}"
SIEM_PROTOCOL="${SIEM_PROTOCOL:-tcp}"
FILEBEAT_INPUT_FILE="${FILEBEAT_INPUT_FILE:-/etc/filebeat/inputs.d/mysql-siem.yml}"
WAZUH_CONF="${WAZUH_CONF:-/var/ossec/etc/ossec.conf}"
CONFIG_MARKER_BEGIN="# BEGIN MYSQL SIEM LOGGING CONFIG"
CONFIG_MARKER_END="# END MYSQL SIEM LOGGING CONFIG"

info(){ echo "[INFO] $*"; }
warn(){ echo "[WARN] $*"; }
fail(){ echo "[ERROR] $*" >&2; exit 1; }

require_root(){ [[ ${EUID} -eq 0 ]] || fail "Run this script as root or with sudo."; }

detect_mysql_service(){
  if systemctl list-unit-files | grep -q '^mysql.service'; then MYSQL_SERVICE="mysql";
  elif systemctl list-unit-files | grep -q '^mysqld.service'; then MYSQL_SERVICE="mysqld";
  elif systemctl status mysql >/dev/null 2>&1; then MYSQL_SERVICE="mysql";
  elif systemctl status mysqld >/dev/null 2>&1; then MYSQL_SERVICE="mysqld";
  else fail "MySQL service not found. Install/start MySQL first."; fi
  info "Detected MySQL service: ${MYSQL_SERVICE}"
}

detect_mysql_config_file(){
  local candidates=(
    "/etc/mysql/mysql.conf.d/mysqld.cnf"
    "/etc/mysql/my.cnf"
    "/etc/my.cnf"
    "/etc/my.cnf.d/mysql-server.cnf"
    "/etc/my.cnf.d/mysqld.cnf"
  )
  for file in "${candidates[@]}"; do
    [[ -f "$file" ]] && MYSQL_CONFIG_FILE="$file" && info "Detected MySQL config: $file" && return
  done
  fail "MySQL config file not found. Checked: ${candidates[*]}"
}

backup_config(){
  local backup="${MYSQL_CONFIG_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
  cp "$MYSQL_CONFIG_FILE" "$backup"
  info "Backup created: $backup"
}

prepare_logs(){
  mkdir -p "$MYSQL_LOG_DIR"
  touch "$MYSQL_GENERAL_LOG" "$MYSQL_ERROR_LOG" "$MYSQL_SLOW_LOG" "$MYSQL_AUDIT_LOG"
  if id mysql >/dev/null 2>&1; then
    chown -R mysql:adm "$MYSQL_LOG_DIR" 2>/dev/null || chown -R mysql:mysql "$MYSQL_LOG_DIR"
  fi
  chmod 750 "$MYSQL_LOG_DIR"
  chmod 640 "$MYSQL_GENERAL_LOG" "$MYSQL_ERROR_LOG" "$MYSQL_SLOW_LOG" "$MYSQL_AUDIT_LOG"
  info "Prepared log directory: $MYSQL_LOG_DIR"
}

ensure_mysqld_section(){
  grep -q '^\[mysqld\]' "$MYSQL_CONFIG_FILE" || printf '\n[mysqld]\n' >> "$MYSQL_CONFIG_FILE"
}

apply_mysql_config(){
  sed -i "/$CONFIG_MARKER_BEGIN/,/$CONFIG_MARKER_END/d" "$MYSQL_CONFIG_FILE" || true
  cat >> "$MYSQL_CONFIG_FILE" <<EOC

${CONFIG_MARKER_BEGIN}
general_log = 1
general_log_file = ${MYSQL_GENERAL_LOG}
log_output = FILE

slow_query_log = 1
slow_query_log_file = ${MYSQL_SLOW_LOG}
long_query_time = ${LONG_QUERY_TIME}
log_queries_not_using_indexes = 0

log_error = ${MYSQL_ERROR_LOG}
${CONFIG_MARKER_END}
EOC
  info "Applied MySQL SIEM logging configuration."
}

configure_logrotate(){
  cat > /etc/logrotate.d/mysql-siem-logs <<EOL
${MYSQL_LOG_DIR}/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    create 640 mysql adm
    sharedscripts
    postrotate
        systemctl reload ${MYSQL_SERVICE} >/dev/null 2>&1 || true
    endscript
}
EOL
  info "Configured logrotate: /etc/logrotate.d/mysql-siem-logs"
}

restart_mysql(){
  systemctl restart "$MYSQL_SERVICE"
  sleep 2
  systemctl is-active --quiet "$MYSQL_SERVICE" || fail "MySQL failed to restart. Restore backup and check syntax."
  info "MySQL restarted successfully."
}

configure_filebeat(){
  command -v filebeat >/dev/null 2>&1 || { warn "Filebeat not installed. Install Filebeat and copy configs/filebeat/mysql-siem-filestream.yml."; return; }
  mkdir -p /etc/filebeat/inputs.d
  cat > "$FILEBEAT_INPUT_FILE" <<EOFBEAT
- type: filestream
  id: mysql-general-log
  enabled: true
  paths: ["${MYSQL_GENERAL_LOG}"]
  fields:
    log_type: mysql_general
    database_engine: mysql
    event_dataset: mysql.general
  fields_under_root: true

- type: filestream
  id: mysql-error-log
  enabled: true
  paths: ["${MYSQL_ERROR_LOG}"]
  fields:
    log_type: mysql_error
    database_engine: mysql
    event_dataset: mysql.error
  fields_under_root: true

- type: filestream
  id: mysql-slow-log
  enabled: true
  paths: ["${MYSQL_SLOW_LOG}"]
  fields:
    log_type: mysql_slow
    database_engine: mysql
    event_dataset: mysql.slow
  fields_under_root: true

- type: filestream
  id: mysql-audit-log
  enabled: true
  paths: ["${MYSQL_AUDIT_LOG}"]
  fields:
    log_type: mysql_audit
    database_engine: mysql
    event_dataset: mysql.audit
  fields_under_root: true
EOFBEAT
  id filebeat >/dev/null 2>&1 && usermod -aG adm filebeat || true
  filebeat test config || warn "Filebeat config test returned a warning. Verify output section."
  systemctl enable filebeat >/dev/null 2>&1 || true
  systemctl restart filebeat || warn "Could not restart Filebeat."
  info "Configured Filebeat input: $FILEBEAT_INPUT_FILE"
}

configure_wazuh(){
  [[ -f "$WAZUH_CONF" ]] || { warn "Wazuh config not found at $WAZUH_CONF. Install Wazuh Agent first."; return; }
  cp "$WAZUH_CONF" "${WAZUH_CONF}.bak.$(date +%Y%m%d_%H%M%S)"
  if ! grep -q "mysql-siem-general-log" "$WAZUH_CONF"; then
    sed -i '/<\/ossec_config>/i \
  <!-- mysql-siem-general-log -->\
  <localfile>\
    <log_format>syslog</log_format>\
    <location>/var/log/mysql/mysql.log</location>\
  </localfile>\
  <!-- mysql-siem-error-log -->\
  <localfile>\
    <log_format>syslog</log_format>\
    <location>/var/log/mysql/error.log</location>\
  </localfile>\
  <!-- mysql-siem-slow-log -->\
  <localfile>\
    <log_format>syslog</log_format>\
    <location>/var/log/mysql/mysql-slow.log</location>\
  </localfile>\
  <!-- mysql-siem-audit-log -->\
  <localfile>\
    <log_format>syslog</log_format>\
    <location>/var/log/mysql/audit.log</location>\
  </localfile>' "$WAZUH_CONF"
  fi
  id wazuh >/dev/null 2>&1 && usermod -aG adm wazuh || true
  systemctl restart wazuh-agent || warn "Could not restart Wazuh Agent."
  info "Configured Wazuh localfile monitoring."
}

configure_rsyslog(){
  [[ -n "$SIEM_COLLECTOR_IP" ]] || { warn "SIEM_COLLECTOR_IP not set. Skipping rsyslog."; return; }
  local prefix="@@"; [[ "$SIEM_PROTOCOL" == "udp" ]] && prefix="@"
  cat > /etc/rsyslog.d/30-mysql-siem.conf <<EORSYS
module(load="imfile" PollingInterval="10")

input(type="imfile" File="${MYSQL_GENERAL_LOG}" Tag="mysql-general:" Severity="info" Facility="local6")
input(type="imfile" File="${MYSQL_ERROR_LOG}" Tag="mysql-error:" Severity="error" Facility="local6")
input(type="imfile" File="${MYSQL_SLOW_LOG}" Tag="mysql-slow:" Severity="info" Facility="local6")
input(type="imfile" File="${MYSQL_AUDIT_LOG}" Tag="mysql-audit:" Severity="info" Facility="local6")

local6.* ${prefix}${SIEM_COLLECTOR_IP}:${SIEM_COLLECTOR_PORT}
EORSYS
  rsyslogd -N1 || warn "Rsyslog validation returned warnings."
  systemctl restart rsyslog
  info "Configured rsyslog forwarding."
}

configure_forwarder(){
  case "$FORWARDER" in
    none) info "No forwarder selected." ;;
    filebeat) configure_filebeat ;;
    wazuh) configure_wazuh ;;
    rsyslog) configure_rsyslog ;;
    *) fail "Unsupported FORWARDER=$FORWARDER. Use none, filebeat, wazuh, or rsyslog." ;;
  esac
}

main(){
  require_root
  detect_mysql_service
  detect_mysql_config_file
  backup_config
  prepare_logs
  ensure_mysqld_section
  apply_mysql_config
  configure_logrotate
  restart_mysql
  configure_forwarder
  echo
  info "Setup completed. Run scripts/validate_mysql_siem_logging.sh to validate."
}
main "$@"
