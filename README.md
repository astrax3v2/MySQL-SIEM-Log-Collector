# MySQL SIEM Log Collector & Parser Pack

A GitHub-ready implementation pack for collecting, forwarding, parsing, and detecting security-relevant MySQL database activity in a SIEM environment.

This repository is designed for SIEM engineers, SOC teams, database administrators, and security auditors who need to onboard MySQL database logs into platforms such as Wazuh, Elastic/OpenSearch, Splunk, QRadar, Microsoft Sentinel, Logpoint, Trident SIEM, or any custom SIEM pipeline.

---

## Contents

```text
mysql-siem-log-collector/
├── README.md
├── LICENSE
├── .gitignore
├── scripts/
│   ├── mysql_siem_log_setup.sh
│   ├── rollback_mysql_siem_logging.sh
│   └── validate_mysql_siem_logging.sh
├── configs/
│   ├── mysql/
│   │   └── mysql-siem-logging.cnf
│   ├── filebeat/
│   │   └── mysql-siem-filestream.yml
│   ├── wazuh/
│   │   ├── ossec-localfile-mysql.xml
│   │   ├── mysql_decoders.xml
│   │   └── mysql_rules.xml
│   ├── rsyslog/
│   │   └── 30-mysql-siem.conf
│   └── logrotate/
│       └── mysql-siem-logs
├── parsers/
│   ├── parser_mapping_sheet.csv
│   ├── mysql_regex_patterns.md
│   └── normalized_event_examples.json
├── detections/
│   ├── mysql_detection_use_cases.csv
│   ├── sigma_mysql_rules.yml
│   └── generic_siem_rules.md
├── samples/
│   ├── sample_mysql_general.log
│   ├── sample_mysql_error.log
│   └── sample_mysql_slow.log
├── tests/
│   └── mysql_test_queries.sql
└── docs/
    ├── SOP_MySQL_SIEM_Log_Collection.md
    └── CLIENT_HANDOVER_CHECKLIST.md
```

---

## What This Pack Does

This pack helps you:

- Enable MySQL file-based security logging.
- Collect:
  - General query logs
  - Error logs
  - Slow query logs
  - Optional Enterprise Audit logs where available
- Forward MySQL logs using:
  - Filebeat
  - Wazuh Agent
  - Rsyslog
- Parse security-relevant MySQL fields.
- Normalize events into SIEM-friendly fields.
- Build detection rules for suspicious database activity.
- Validate log generation and SIEM ingestion.
- Provide a clean SOP and client handover checklist.

---

## Supported MySQL Editions

| MySQL Edition | Supported Logging Method |
|---|---|
| MySQL Community Edition | General query log, error log, slow query log |
| MySQL Commercial Edition | General query log, error log, slow query log |
| MySQL Enterprise Edition | General query log, error log, slow query log, Enterprise Audit log |

> MySQL Enterprise Audit is recommended for compliance-grade production database auditing when available.

---

## Supported Linux Distributions

The setup script is designed for common Linux MySQL deployments, including:

- Ubuntu
- Debian
- RHEL
- CentOS
- Rocky Linux
- AlmaLinux

The script attempts to detect:

- MySQL service name: `mysql` or `mysqld`
- MySQL configuration file location
- Log directory
- Available forwarding agent

---

## Important Production Warning

The MySQL general query log can generate very high log volume because it records all SQL statements received by the MySQL server. It may also contain sensitive data such as tokens, customer data, passwords in queries, or personally identifiable information.

Before enabling it in production, confirm:

- DBA approval
- Change approval
- Disk sizing
- SIEM EPS/license impact
- Sensitive data handling requirements
- Log retention policy
- Masking/redaction requirements
- Maintenance window

For production systems, prefer MySQL Enterprise Audit where available, or enable query logging only for approved systems and monitoring windows.

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/<your-org>/mysql-siem-log-collector.git
cd mysql-siem-log-collector
```

### 2. Review the Script

```bash
less scripts/mysql_siem_log_setup.sh
```

### 3. Make Scripts Executable

```bash
chmod +x scripts/*.sh
```

### 4. Run Basic Setup Without Forwarder

```bash
sudo ./scripts/mysql_siem_log_setup.sh
```

This enables local MySQL file-based logs only.

---

## Run with Forwarding Options

### Option A: Configure Filebeat Input

```bash
sudo FORWARDER=filebeat ./scripts/mysql_siem_log_setup.sh
```

This creates:

```text
/etc/filebeat/inputs.d/mysql-siem.yml
```

You must configure Filebeat output separately according to your SIEM architecture, such as Logstash, Elasticsearch, OpenSearch, or another collector endpoint.

---

### Option B: Configure Wazuh Agent Local Log Collection

```bash
sudo FORWARDER=wazuh ./scripts/mysql_siem_log_setup.sh
```

This inserts MySQL `<localfile>` entries into:

```text
/var/ossec/etc/ossec.conf
```

Wazuh decoder and rule examples are available under:

```text
configs/wazuh/mysql_decoders.xml
configs/wazuh/mysql_rules.xml
```

---

### Option C: Configure Rsyslog Forwarding

```bash
sudo SIEM_COLLECTOR_IP=10.10.10.10 SIEM_COLLECTOR_PORT=514 SIEM_PROTOCOL=tcp FORWARDER=rsyslog ./scripts/mysql_siem_log_setup.sh
```

For UDP forwarding:

```bash
sudo SIEM_COLLECTOR_IP=10.10.10.10 SIEM_COLLECTOR_PORT=514 SIEM_PROTOCOL=udp FORWARDER=rsyslog ./scripts/mysql_siem_log_setup.sh
```

TCP is recommended over UDP for reliability.

---

## Default Log Paths

| Log Type | Default Path |
|---|---|
| General Query Log | `/var/log/mysql/mysql.log` |
| Error Log | `/var/log/mysql/error.log` |
| Slow Query Log | `/var/log/mysql/mysql-slow.log` |
| Enterprise Audit Log | `/var/log/mysql/audit.log` |

---

## MySQL Configuration Applied

The setup script appends a managed block to the detected MySQL configuration file:

```ini
# BEGIN MYSQL SIEM LOGGING CONFIG
general_log = 1
general_log_file = /var/log/mysql/mysql.log
log_output = FILE

slow_query_log = 1
slow_query_log_file = /var/log/mysql/mysql-slow.log
long_query_time = 2
log_queries_not_using_indexes = 0

log_error = /var/log/mysql/error.log
# END MYSQL SIEM LOGGING CONFIG
```

The script backs up the original configuration before modifying it.

---

## Validate MySQL Logging

Run:

```bash
sudo ./scripts/validate_mysql_siem_logging.sh
```

Manual validation:

```bash
mysql -e "SHOW VARIABLES LIKE 'general_log';"
mysql -e "SHOW VARIABLES LIKE 'general_log_file';"
mysql -e "SHOW VARIABLES LIKE 'log_output';"
mysql -e "SHOW VARIABLES LIKE 'slow_query_log';"
mysql -e "SHOW VARIABLES LIKE 'slow_query_log_file';"
mysql -e "SHOW VARIABLES LIKE 'log_error';"
```

Check logs:

```bash
sudo tail -f /var/log/mysql/mysql.log
sudo tail -f /var/log/mysql/error.log
sudo tail -f /var/log/mysql/mysql-slow.log
```

---

## Generate Test Events

Run:

```bash
mysql < tests/mysql_test_queries.sql
```

Or manually:

```sql
SELECT NOW();
CREATE DATABASE IF NOT EXISTS siem_test;
CREATE TABLE IF NOT EXISTS siem_test.test_table(id INT, name VARCHAR(50));
INSERT INTO siem_test.test_table VALUES(1, 'test');
UPDATE siem_test.test_table SET name='updated' WHERE id=1;
DELETE FROM siem_test.test_table WHERE id=1;
DROP DATABASE siem_test;
```

---

## Expected Parsed Fields

| Parsed Field | Normalized Field | Example |
|---|---|---|
| `event_time` | `@timestamp` | `2026-07-01T10:15:25.567890Z` |
| `db_host` | `host.name` | `mysql-db-01` |
| `db_thread_id` | `mysql.thread_id` | `12` |
| `db_action` | `event.action` | `Query` |
| `db_user` | `user.name` | `root` |
| `src_ip` | `source.ip` | `192.168.1.50` |
| `database_name` | `database.name` | `finance_db` |
| `sql_query` | `database.query` | `SELECT * FROM users;` |
| `query_type` | `database.operation` | `SELECT` |
| `table_name` | `database.table` | `users` |
| `raw_log` | `event.original` | Full log line |

Full parser mapping is available at:

```text
parsers/parser_mapping_sheet.csv
```

---

## Core Detection Use Cases

| Rule Name | Severity |
|---|---|
| MySQL - Root Login from Remote Host | High |
| MySQL - Failed Login Attempt | Medium |
| MySQL - Multiple Failed Login Attempts | High |
| MySQL - Database User Created | High |
| MySQL - Privilege Granted | High |
| MySQL - Table Dropped | Critical |
| MySQL - Database Dropped | Critical |
| MySQL - Table Truncated | Critical |
| MySQL - Delete Query Without WHERE Clause | High |
| MySQL - Update Query Without WHERE Clause | High |
| MySQL - Data Export Using INTO OUTFILE | Critical |
| MySQL - SQL Injection Pattern Detected | High |
| MySQL - Sensitive Table Access | Medium / High |
| MySQL - Configuration Changed Using SET GLOBAL | High |
| MySQL - Plugin Installed | Critical |

Full list is available at:

```text
detections/mysql_detection_use_cases.csv
```

---

## Rollback

Run:

```bash
sudo ./scripts/rollback_mysql_siem_logging.sh
```

Or manually remove the managed block between:

```ini
# BEGIN MYSQL SIEM LOGGING CONFIG
# END MYSQL SIEM LOGGING CONFIG
```

Then restart MySQL:

```bash
sudo systemctl restart mysql
```

or:

```bash
sudo systemctl restart mysqld
```

To disable runtime general logging immediately:

```bash
mysql -e "SET GLOBAL general_log = 'OFF';"
```

---

## Recommended SIEM Search Queries

Generic searches:

```text
log_type:mysql_general
log_type:mysql_error
log_type:mysql_slow
database_engine:mysql
database.operation:GRANT
database.operation:DROP
database.query:"INTO OUTFILE"
database.query:"UNION SELECT"
```

Wazuh example:

```text
rule.groups:mysql
```

Elastic/OpenSearch example:

```text
event.dataset:mysql.general OR database_engine:mysql
```

Splunk example:

```text
index=<db_index> sourcetype=mysql:general
```

---

## Recommended Deployment Approach

| Phase | Activity |
|---|---|
| Phase 1 | Enable in lab/UAT |
| Phase 2 | Validate log generation |
| Phase 3 | Validate parser extraction |
| Phase 4 | Tune noisy events |
| Phase 5 | Enable selected production servers |
| Phase 6 | Create dashboards and alerts |
| Phase 7 | Client sign-off |

---

## Client Deliverables

- SOP for MySQL SIEM log collection
- Parser mapping sheet
- Detection use-case list
- Sample parser regex
- Wazuh decoder and rule examples
- Filebeat input configuration
- Rsyslog forwarding configuration
- Logrotate configuration
- Validation script
- Rollback script
- Test SQL queries
- Handover checklist

---

## Disclaimer

This repository provides baseline implementation templates. Always review, test, and tune configurations before production deployment. Database logging may expose sensitive information and may increase storage, CPU, I/O, and SIEM ingestion volume.
