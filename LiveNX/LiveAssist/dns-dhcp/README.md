# DNS and DHCP OpenTelemetry Log Data for LiveAssist

This script creates a ClickHouse view that exposes DNS and DHCP event logs from OpenTelemetry data for LiveAssist analysis.

Next, run the create_dns_dhcp_otel_view.sh script on LiveNX.

This creates a ClickHouse view that filters OpenTelemetry logs for DNS and DHCP events:

```sql
CREATE VIEW IF NOT EXISTS liveassist.DNS_DHCP_OpenTelemetry_Log_Data AS
SELECT *
FROM default.otel_logs
WHERE
  LogAttributes['event_description'] ILIKE '%dns%'
  OR LogAttributes['event_description'] ILIKE '%dhcp%';
```

This script does **one thing** and does it idempotently. If the view already exists, nothing changes.

---

- The database `liveassist` **must already exist**.
- The source table `default.otel_logs` **must already exist** and be readable by your ClickHouse user.

> If `liveassist` or `default.otel_logs` don't exist, ClickHouse will error. That's by design—this script only creates the view.

---

## Usage

```bash
./create_dns_dhcp_otel_view.sh
```

---

## Quick start

```bash
# Make it executable
chmod +x create_dns_dhcp_otel_view.sh

# Run it (defaults usually work on a local dev setup)
./create_dns_dhcp_otel_view.sh
```

Expected output:

```
OK: Ensured view liveassist.DNS_DHCP_OpenTelemetry_Log_Data exists.
```

---

## Verify

Confirm the view exists and points where you think it does:

```bash
docker exec -it clickhouse-server clickhouse-client \
  --query "SHOW CREATE VIEW liveassist.DNS_DHCP_OpenTelemetry_Log_Data\G"
```

Optionally, run a quick count to verify the wiring:

```bash
docker exec -it clickhouse-server clickhouse-client \
  --query "SELECT count() FROM liveassist.DNS_DHCP_OpenTelemetry_Log_Data"
```

Check sample DNS/DHCP events:

```bash
docker exec -it clickhouse-server clickhouse-client \
  --query "SELECT Timestamp, LogAttributes['event_description'] AS event,
                  LogAttributes['source_ip'] AS source_ip
           FROM liveassist.DNS_DHCP_OpenTelemetry_Log_Data
           LIMIT 10" \
  --format PrettyCompact
```

---

## Common failures (and straight fixes)

- **`Code: 60, DB::Exception: Database liveassist doesn't exist`**
  Create it first:

  ```bash
  docker exec -it clickhouse-server clickhouse-client \
    --query "CREATE DATABASE IF NOT EXISTS liveassist"
  ```

- **`Code: 60, DB::Exception: Table default.otel_logs doesn't exist`**
  Verify that OpenTelemetry log collection is configured and running. Check if the source table exists:

  ```bash
  docker exec -it clickhouse-server clickhouse-client \
    --query "SHOW TABLES FROM default LIKE '%otel%'"
  ```

- **`Docker container ... is not running (or not found)`**
  Start the container or pass `--docker-container <name>`.

- **No DNS/DHCP events returned**
  Ensure OpenTelemetry collectors are configured to capture DNS and DHCP events. Verify raw data exists:

  ```bash
  docker exec -it clickhouse-server clickhouse-client \
    --query "SELECT count(*) FROM default.otel_logs
             WHERE LogAttributes['event_description'] ILIKE '%dns%'
                OR LogAttributes['event_description'] ILIKE '%dhcp%'"
  ```

---

## What data does this expose?

The view filters OpenTelemetry logs for network events related to:

- **DNS**: Domain name resolution queries and responses
- **DHCP**: Dynamic Host Configuration Protocol lease assignments and renewals

The filtering is case-insensitive and matches any log where the `event_description` attribute contains "dns" or "dhcp".

Common use cases:
- Tracking DNS query patterns
- Monitoring DHCP lease assignments
- Analyzing network service availability
- Troubleshooting name resolution issues

---

## Security notes

- This view exposes DNS queries and DHCP lease information which can reveal user behavior and network topology.
- DNS logs may contain sensitive domain names accessed by users.
- DHCP logs reveal device identity and network location information.
- Ensure appropriate access controls are in place for the `liveassist` database.

---

## Exit codes

- `0` : View ensured (created or already existed)
- `≠0`: Something failed (missing DB/table, auth, container not running, etc.)

---

## Maintenance

This view is a thin filter over `default.otel_logs`. If you change or drop that table, this view follows the consequences. Keep source schema ownership and view consumers aligned.

The filter uses case-insensitive pattern matching (`ILIKE`) which may impact query performance on large datasets. Consider adding appropriate indexes on the source table if query performance becomes an issue.

If you need to capture additional event types, modify the WHERE clause to include additional patterns.
