# Generic SIEM Rules for MySQL

## MySQL - Root Login from Remote Host

Condition:

```text
db_action = Connect AND db_user = root AND src_ip NOT IN (127.0.0.1, ::1, localhost)
```

Severity: High

## MySQL - Table or Database Dropped

```text
database.query CONTAINS "DROP TABLE" OR database.query CONTAINS "DROP DATABASE"
```

Severity: Critical

## MySQL - Privilege Granted

```text
database.query CONTAINS "GRANT "
```

Severity: High

## MySQL - Delete Without WHERE

```text
database.operation = DELETE AND database.query NOT CONTAINS "WHERE"
```

Severity: High

## MySQL - Update Without WHERE

```text
database.operation = UPDATE AND database.query NOT CONTAINS "WHERE"
```

Severity: High

## MySQL - Data Export

```text
database.query CONTAINS "INTO OUTFILE" OR database.query CONTAINS "INTO DUMPFILE"
```

Severity: Critical
