# MySQL SIEM Regex Patterns

## ISO General Log Base Pattern

```regex
^(?<event_time>\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+(?<db_thread_id>\d+)\s+(?<db_action>\w+(?:\sDB)?)\s+(?<message>.*)$
```

## Connect Event

```regex
^(?<event_time>\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+(?<db_thread_id>\d+)\s+Connect\s+(?<db_user>[^@]+)@(?<src>[^\s]+)\s+on\s+(?<database_name>\S*)
```

## Query Event

```regex
^(?<event_time>\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+(?<db_thread_id>\d+)\s+Query\s+(?<sql_query>.*)$
```

## Query Type

```regex
(?i)^\s*(?<query_type>SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|SET|SHOW|USE|CALL|LOAD|REPLACE)\b
```

## Table/Object Name

```regex
(?i)(?:FROM|INTO|UPDATE|TABLE|DATABASE)\s+`?(?<table_name>[a-zA-Z0-9_.$-]+)`?
```

## Suspicious SQL Patterns

```regex
(?i)(UNION\s+SELECT|OR\s+1\s*=\s*1|SLEEP\s*\(|BENCHMARK\s*\(|INFORMATION_SCHEMA|INTO\s+OUTFILE|INTO\s+DUMPFILE|LOAD_FILE\s*\()
```
