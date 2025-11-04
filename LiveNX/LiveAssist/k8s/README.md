# create_k8s_otel_views.sh

Create (or ensure) Kubernetes-focused OpenTelemetry views in ClickHouse:

```sql
CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_histogram AS
  SELECT * FROM default.otel_metrics_histogram WHERE Attributes['k8s'] = 'k8s';

CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_sum AS
  SELECT * FROM default.otel_metrics_sum WHERE Attributes['k8s'] = 'k8s';

CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_gauge AS
  SELECT * FROM default.otel_metrics_gauge WHERE Attributes['k8s'] = 'k8s';

CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_logs AS
  SELECT * FROM default.otel_logs WHERE LogAttributes['k8s'] = 'k8s';
```

This script does one job and does it idempotently. If the views already exist, nothing changes.

---

## What this version does

Executes **inside the container** using:

```bash
docker exec clickhouse-server clickhouse-client --multiquery --query "<SQL>"
```

No direct host connections to ClickHouse; everything runs via `docker exec` against the `clickhouse-server` container.

---

## Requirements

- `docker` available on the host.
- A running ClickHouse container named **`clickhouse-server`** with `clickhouse-client` installed.
- The database `liveassist` **already exists**.
- Source tables exist and are readable by your ClickHouse user:
  - `default.otel_metrics_histogram`
  - `default.otel_metrics_sum`
  - `default.otel_metrics_gauge`
  - `default.otel_logs`

> If `liveassist` or any source table doesn’t exist, ClickHouse will error. This script intentionally **only** creates views.

---

## Usage

```bash
chmod +x create_k8s_otel_views.sh
./create_k8s_otel_views.sh
```

Expected output:

```
OK: Ensured Kubernetes OTEL views exist in 'liveassist'.
```

### Optional: auth

If your container requires credentials, modify the command in the script to include flags on `clickhouse-client`, for example:

```bash
docker exec clickhouse-server clickhouse-client   --user my_user --password 'my_pass'   --multiquery --query "
CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_histogram AS
  SELECT * FROM default.otel_metrics_histogram WHERE Attributes['k8s'] = 'k8s';
CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_sum AS
  SELECT * FROM default.otel_metrics_sum WHERE Attributes['k8s'] = 'k8s';
CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_gauge AS
  SELECT * FROM default.otel_metrics_gauge WHERE Attributes['k8s'] = 'k8s';
CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_logs AS
  SELECT * FROM default.otel_logs WHERE LogAttributes['k8s'] = 'k8s';
"
```

---

## Verify

Check each view definition:

```bash
docker exec clickhouse-server clickhouse-client   --query "SHOW CREATE VIEW liveassist.Kubernetes_OpenTelemetry_otel_metrics_histogram\G"

docker exec clickhouse-server clickhouse-client   --query "SHOW CREATE VIEW liveassist.Kubernetes_OpenTelemetry_otel_metrics_sum\G"

docker exec clickhouse-server clickhouse-client   --query "SHOW CREATE VIEW liveassist.Kubernetes_OpenTelemetry_otel_metrics_gauge\G"

docker exec clickhouse-server clickhouse-client   --query "SHOW CREATE VIEW liveassist.Kubernetes_OpenTelemetry_otel_logs\G"
```

Sanity-check row access (optional):

```bash
docker exec clickhouse-server clickhouse-client   --query "SELECT count() FROM liveassist.Kubernetes_OpenTelemetry_otel_metrics_histogram"
```

---

## Common failures (and straight fixes)

- **`Code: 60, DB::Exception: Database liveassist doesn't exist`**  
  Create it first:  
  ```bash
  docker exec clickhouse-server clickhouse-client     --query "CREATE DATABASE IF NOT EXISTS liveassist"
  ```

- **`Code: 60, DB::Exception: Table default.otel_* doesn't exist`**  
  Create/restore the OTEL metrics/logs tables or adjust the source DB/table names.

- **`Docker container ... is not running (or not found)`**  
  Start the container named `clickhouse-server`.

- **Auth errors**  
  Add `--user` and `--password` to the `clickhouse-client` invocation.

---

## Exit codes

- `0` : Views ensured (created or already existed)
- `≠0`: Something failed (missing DB/table, auth, container not running, etc.)

---

## Maintenance

These views are pass-through filters over OTEL metric/log tables. If you rename or drop the source tables, the views will fail accordingly. Keep schema ownership and consumers aligned.
