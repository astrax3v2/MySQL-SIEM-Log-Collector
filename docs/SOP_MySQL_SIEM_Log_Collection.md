# SOP: MySQL SIEM Log Collection and Parsing

## Objective

Define the standard process to enable MySQL logging, forward database logs to a SIEM, parse security-relevant fields, and validate monitoring coverage.

## Scope

This SOP applies to MySQL Community, Commercial, and Enterprise editions running on Linux servers.

## Log Sources

| Log Source | Purpose | Default Path |
|---|---|---|
| General Query Log | Query execution, connect, disconnect | `/var/log/mysql/mysql.log` |
| Error Log | Authentication failures, startup, shutdown, server errors | `/var/log/mysql/error.log` |
| Slow Query Log | Long-running queries and possible large data extraction | `/var/log/mysql/mysql-slow.log` |
| Enterprise Audit Log | Compliance-grade audit events | `/var/log/mysql/audit.log` |

## Implementation Steps

1. Obtain client/DBA approval.
2. Back up MySQL configuration.
3. Enable file-based logs.
4. Restart MySQL.
5. Confirm local log generation.
6. Configure log forwarding.
7. Validate SIEM ingestion.
8. Apply parser mapping.
9. Enable detection rules.
10. Complete client sign-off.

## Recommended Log Flow

```text
MySQL Server -> Local log files -> Forwarder -> SIEM Collector -> Parser -> Detection Rules -> SOC Monitoring
```

## Production Risk

The general query log may generate high log volume and may contain sensitive data. Use controlled deployment and tune log ingestion based on volume, privacy, and compliance requirements.

## Validation

Run:

```bash
sudo ./scripts/validate_mysql_siem_logging.sh
mysql < tests/mysql_test_queries.sql
```

Verify in SIEM:

- Logs are received.
- Timestamp is parsed.
- Username is extracted.
- Source IP is extracted.
- SQL query is extracted.
- Query type is identified.
- Rule severity is applied.

## Rollback

Run:

```bash
sudo ./scripts/rollback_mysql_siem_logging.sh
```
