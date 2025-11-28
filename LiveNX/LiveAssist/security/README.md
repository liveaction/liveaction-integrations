# create_security_events_view.sh

Create the **Security_Events** view in ClickHouse (executed inside the container):

```sql
CREATE VIEW liveassist.Security_Events AS
  SELECT * FROM livenx_platformdb.si_findings_dist;
```

> **Important:** This uses the exact statement you provided — there is **no** `IF NOT EXISTS`.  
> If the view already exists, ClickHouse will return an error. Use `DROP VIEW` first or change to `CREATE OR REPLACE VIEW` if you want idempotent behavior (and your CH version supports it).

---

## What this script does

Runs the SQL **inside** the container using:

```bash
docker exec clickhouse-server clickhouse-client --query "<SQL>"
```

No direct host connections; everything goes through `docker exec` into the `clickhouse-server` container.

---

## Requirements

- `docker` available on the host.
- A running ClickHouse container named **`clickhouse-server`** with `clickhouse-client` installed.
- The database `liveassist` exists.
- Source table exists and is readable:
  - `livenx_platformdb.si_findings_dist`

---

## Usage

```bash
chmod +x create_security_events_view.sh
./create_security_events_view.sh
```

Expected output on success:

```
OK: Created view liveassist.Security_Events.
```

### Optional: auth

If your container requires credentials, modify the command in the script to include flags on `clickhouse-client`, for example:

```bash
docker exec clickhouse-server clickhouse-client \
  --user my_user --password 'my_pass' \
  --query "CREATE VIEW liveassist.Security_Events AS SELECT * FROM livenx_platformdb.si_findings_dist;"
```

---

## Verify

Check the view definition:

```bash
docker exec clickhouse-server clickhouse-client \
  --query "SHOW CREATE VIEW liveassist.Security_Events\\G"
```

Row sanity-check (optional):

```bash
docker exec clickhouse-server clickhouse-client \
  --query "SELECT count() FROM liveassist.Security_Events"
```

---

## Common failures (and straight fixes)

- **`Code: 60, DB::Exception: Database liveassist doesn't exist`**  
  Create it first:  
  ```bash
  docker exec clickhouse-server clickhouse-client \
    --query "CREATE DATABASE IF NOT EXISTS liveassist"
  ```

- **`Code: 60, DB::Exception: Table livenx_platformdb.si_findings_dist doesn't exist`**  
  Create/restore the source table or adjust the source DB/table name.

- **`Code: 57, DB::Exception: View liveassist.Security_Events already exists`**  
  Drop it (or switch to `CREATE OR REPLACE VIEW` if supported):  
  ```bash
  docker exec clickhouse-server clickhouse-client \
    --query "DROP VIEW liveassist.Security_Events"
  ```

- **`Docker container ... is not running (or not found)`**  
  Start the `clickhouse-server` container.

- **Auth errors**  
  Add `--user` and `--password` to the `clickhouse-client` invocation.

---

## Exit codes

- `0` : View created
- `≠0`: Failure (already exists, missing DB/table, auth, container not running, etc.)
