# create_portnox_otel_view.sh

Create (or ensure) the Portnox OpenTelemetry view in ClickHouse:

```sql
CREATE VIEW IF NOT EXISTS liveassist.Portnox_OpenTelemetry_Log_Data AS
  SELECT * FROM default.otel_logs WHERE ServiceName = 'portnox';
```

This script does one job and does it idempotently. If the view already exists, nothing changes.

---

## What this version does

Executes **inside the container** using:

```bash
docker exec clickhouse-server clickhouse-client --query "<SQL>"
```

No direct host connections to ClickHouse; everything runs via `docker exec` against the `clickhouse-server` container.

---

## Requirements

- `docker` available on the host.
- A running ClickHouse container named **`clickhouse-server`** with `clickhouse-client` installed.
- The database `liveassist` **already exists**.
- The source table `default.otel_logs` exists and is readable by your ClickHouse user.

> If `liveassist` or `default.otel_logs` doesn’t exist, ClickHouse will error. This script intentionally **only** creates the view.

---

## Usage

```bash
chmod +x create_portnox_otel_view.sh
./create_portnox_otel_view.sh
```

Expected output:

```
OK: Ensured view liveassist.Portnox_OpenTelemetry_Log_Data exists.
```

### Optional: auth

If your container requires credentials, modify the command in the script to include flags on `clickhouse-client`, for example:

```bash
docker exec clickhouse-server clickhouse-client \
  --user my_user --password 'my_pass' \
  --query "CREATE VIEW IF NOT EXISTS liveassist.Portnox_OpenTelemetry_Log_Data AS SELECT * FROM default.otel_logs WHERE ServiceName = 'portnox';"
```

---

## Verify

Check the view definition:

```bash
docker exec clickhouse-server clickhouse-client \
  --query "SHOW CREATE VIEW liveassist.Portnox_OpenTelemetry_Log_Data\\G"
```

Sanity-check row access (optional):

```bash
docker exec clickhouse-server clickhouse-client \
  --query "SELECT count() FROM liveassist.Portnox_OpenTelemetry_Log_Data"
```

---

## Common failures (and straight fixes)

- **`Code: 60, DB::Exception: Database liveassist doesn't exist`**  
  Create it first:  
  ```bash
  docker exec clickhouse-server clickhouse-client \
    --query "CREATE DATABASE IF NOT EXISTS liveassist"
  ```

- **`Code: 60, DB::Exception: Table default.otel_logs doesn't exist`**  
  Create/restore the OTEL logs table or adjust the source DB/table name.

- **`Docker container ... is not running (or not found)`**  
  Start the container named `clickhouse-server`.

- **Auth errors**  
  Add `--user` and `--password` to the `clickhouse-client` invocation.

---

## Exit codes

- `0` : View ensured (created or already existed)
- `≠0`: Something failed (missing DB/table, auth, container not running, etc.)

---

## Maintenance

This view is a pass-through filter over `default.otel_logs`. If you rename or drop the source table, the view will fail accordingly. Keep schema ownership and consumers aligned.
