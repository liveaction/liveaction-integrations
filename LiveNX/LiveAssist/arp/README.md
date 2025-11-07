# ARP Information Data for LiveAssist

This script creates a ClickHouse view that exposes ARP (Address Resolution Protocol) information from SNMP metrics for LiveAssist analysis.

Next, run the create_arp_information_view.sh script on LiveNX.

This creates a ClickHouse view that exposes ARP entry data with flattened fields:

```sql
CREATE OR REPLACE VIEW liveassist.ARP_Information
(
    `time` DateTime,
    `DeviceId` LowCardinality(String),
    `DeviceTimeMillis` UInt64,
    `MetricName` LowCardinality(String),
    `MetricIndex` LowCardinality(String),
    `MetricType` LowCardinality(String),
    `MetricValue` Nullable(Float64),
    `arpEntryMacAddress` Nullable(String),
    `arpEntryIpAddress` Nullable(IPv4),
    `arpEntryIfIndex`   Nullable(UInt32),
    `arpEntryInterface` Nullable(String),
    `metricDescription` Nullable(String),
    `snmpType`          Nullable(String),
    `unit`              Nullable(String)
)
AS
SELECT
    time,
    DeviceId,
    DeviceTimeMillis,
    MetricName,
    MetricIndex,
    MetricType,
    MetricValue,
    Tags['arpEntryMacAddress']                      AS arpEntryMacAddress,
    toIPv4OrNull(Tags['arpEntryIpAddress'])         AS arpEntryIpAddress,
    toUInt32OrNull(Tags['arpEntryIfIndex'])         AS arpEntryIfIndex,
    Tags['arpEntryInterface']                       AS arpEntryInterface,
    Tags['metricDescription']                       AS metricDescription,
    Tags['snmpType']                                AS snmpType,
    Tags['unit']                                    AS unit
FROM livenx_snmpdb.device_metric_dist
WHERE MetricName ILIKE '%arp%';
```

This script does **one thing** and does it idempotently. If the view already exists, it will be replaced with the new definition.

---

- The database `liveassist` **must already exist**.
- The source table `livenx_snmpdb.device_metric_dist` **must already exist** and be readable by your ClickHouse user.

> If `liveassist` or `livenx_snmpdb.device_metric_dist` don't exist, ClickHouse will error. That's by design—this script only creates the view.

---

## Usage

```bash
./create_arp_information_view.sh
```

---

## Quick start

```bash
# Make it executable
chmod +x create_arp_information_view.sh

# Run it (defaults usually work on a local dev setup)
./create_arp_information_view.sh
```

Expected output:

```
OK: Created/replaced view liveassist.ARP_Information.
```

---

## Verify

Confirm the view exists and points where you think it does:

```bash
docker exec -it clickhouse-server clickhouse-client \
  --query "SHOW CREATE VIEW liveassist.ARP_Information\G"
```

Optionally, run a quick count to verify the wiring:

```bash
docker exec -it clickhouse-server clickhouse-client \
  --query "SELECT count() FROM liveassist.ARP_Information"
```

Check sample ARP entries:

```bash
docker exec -it clickhouse-server clickhouse-client \
  --query "SELECT DeviceId, arpEntryIpAddress, arpEntryMacAddress, arpEntryInterface
           FROM liveassist.ARP_Information
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

- **`Code: 60, DB::Exception: Table livenx_snmpdb.device_metric_dist doesn't exist`**
  Verify that SNMP polling is enabled and data is being collected. Check if the source table exists:

  ```bash
  docker exec -it clickhouse-server clickhouse-client \
    --query "SHOW TABLES FROM livenx_snmpdb"
  ```

- **`Docker container ... is not running (or not found)`**
  Start the container or pass `--docker-container <name>`.

- **No ARP data returned**
  Ensure devices are being polled for ARP metrics. Check if raw data exists:

  ```bash
  docker exec -it clickhouse-server clickhouse-client \
    --query "SELECT count() FROM livenx_snmpdb.device_metric_dist
             WHERE MetricName ILIKE '%arp%'"
  ```

---

## Security notes

- This view exposes network ARP cache information which can reveal device-to-device communications.
- Ensure appropriate access controls are in place for the `liveassist` database.
- ARP data can contain sensitive information about network topology and device locations.

---

## Exit codes

- `0` : View ensured (created or replaced)
- `≠0`: Something failed (missing DB/table, auth, container not running, etc.)

---

## Maintenance

This view is a filtered and flattened projection over `livenx_snmpdb.device_metric_dist`. If you change or drop that table, this view follows the consequences. The view uses `CREATE OR REPLACE` so re-running the script will update the view definition if needed.

The view extracts specific fields from the Tags map column for easier querying. If new ARP-related tags are added to the source data, update this script to include them in the view definition.
