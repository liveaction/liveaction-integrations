# BlueCat BAM to ClickHouse Entity Importer

A Python utility that imports IP address management (IPAM) data from BlueCat Address Manager (BAM) into ClickHouse for analytics and reporting.

## Overview

This tool automatically discovers and imports all IPv4 networks and their associated IP addresses from BlueCat BAM, enriching them with DNS records (HostRecord, PTRRecord) and storing them in a ClickHouse database for efficient querying and analysis.

## Features

- **Automatic Network Discovery**: Recursively discovers all IPv4 blocks and networks in BAM
- **Comprehensive Data Collection**: Fetches IP addresses with associated DNS records, MAC addresses, and state information
- **DHCP Lease Enrichment**: Captures DHCP lease information including start/end times and lease state
- **Efficient Storage**: Uses ClickHouse's ReplacingMergeTree engine for deduplication and fast queries
- **TLS/mTLS Support**: Secure connections to both BAM and ClickHouse
- **Batch Processing**: Memory-efficient batch inserts with configurable page sizes
- **LLM-Friendly Output**: Creates denormalized text documents for natural language queries

## Prerequisites

- Python 3.x
- Access to BlueCat Address Manager API
- ClickHouse database instance
- Required Python packages (see requirements.txt)

## Installation

1. Clone the repository and navigate to the bluecat directory:
```bash
cd LiveNX/integrations/bluecat
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp env.sample .env
# Edit .env with your credentials
```

## Configuration

Edit the `.env` file with your environment-specific settings:

### BlueCat BAM Configuration
- `BAM_BASE`: BlueCat BAM server URL (e.g., https://bam.example.com)
- `BAM_USER`: API username
- `BAM_PASS`: API password
- `BAM_VERIFY_TLS`: Verify BAM SSL certificate (true/false)
- `INCLUDE_DHCP`: Include DHCP lease information (true/false, default: true)

### ClickHouse Configuration
- `CH_HOST`: ClickHouse server hostname
- `CH_PORT`: ClickHouse port (8123 for HTTP, 8443 for HTTPS)
- `CH_USER`: ClickHouse username
- `CH_PASS`: ClickHouse password
- `CH_DB`: Target database name (default: netops)
- `CH_TABLE`: Target table name (default: ipam_devices)

### TLS/Security Options
- `CH_SECURE`: Use HTTPS for ClickHouse (true/false)
- `CH_VERIFY`: Verify ClickHouse SSL cert (true/false/path-to-ca)
- `CH_CLIENT_CERT`: Path to client certificate for mTLS (optional)
- `CH_CLIENT_KEY`: Path to client key for mTLS (optional)

### Runtime Options
- `PAGE_SIZE`: Number of entities to fetch per API call (default: 1000)

## Usage

Run the import:
```bash
python3 import_entities.py
```

The script will:
1. Connect to BlueCat BAM and authenticate
2. Discover all IPv4 networks automatically
3. For each network, fetch all IP addresses
4. Enrich IP data with DNS records (HostRecords and PTRRecords)
5. Fetch DHCP lease information for each IP (if enabled)
6. Process DHCP ranges to capture additional lease details
7. Insert data into ClickHouse with proper versioning

## Database Schema

The tool creates a ClickHouse table with the following structure:

| Column | Type | Description |
|--------|------|-------------|
| `network_cidr` | String | Network CIDR notation |
| `ip` | String | IP address |
| `hostname` | String | Device hostname |
| `fqdn` | String | Fully qualified domain name |
| `mac` | String | MAC address |
| `state` | LowCardinality(String) | IP state (e.g., DHCP_ALLOCATED, STATIC) |
| `ip_version` | LowCardinality(String) | IP version (IPv4/IPv6) |
| `ptr_record` | String | PTR record for reverse DNS |
| `bam_network_id` | UInt64 | BlueCat network entity ID |
| `bam_ip_entity_id` | UInt64 | BlueCat IP entity ID |
| `lease_start` | Nullable(DateTime64) | DHCP lease start time |
| `lease_end` | Nullable(DateTime64) | DHCP lease end time |
| `lease_state` | LowCardinality(String) | DHCP lease state (e.g., ACTIVE, EXPIRED) |
| `source_system` | LowCardinality(String) | Source system identifier |
| `tenant` | LowCardinality(String) | Tenant identifier (for multi-tenancy) |
| `document` | String | Denormalized text for full-text search |
| `snapshot_at` | DateTime64 | When the snapshot was taken |
| `_ingested_at` | DateTime64 | When data was ingested |
| `_version` | UInt64 | Version for deduplication |

## Output

The script provides progress updates during execution:
```
Discovering all IPv4 blocks and networks from BAM...
Found 5 IPv4 networks to process
Processing network: 10.0.0.0/24 (ID: 12345)
  Ingested 254 IP entries from 10.0.0.0/24
Processing network: 192.168.1.0/24 (ID: 12346)
  Ingested 150 IP entries from 192.168.1.0/24
...
Completed: Ingested 404 total IP entries from 2 networks into netops.ipam_devices at 2024-01-15T10:30:00.000Z.
```

## Querying Data

Once imported, you can query the data in ClickHouse:

```sql
-- Find all devices in a specific network
SELECT hostname, ip, mac, state, lease_start, lease_end
FROM netops.ipam_devices
WHERE network_cidr = '10.0.0.0/24'
  AND hostname != ''
ORDER BY ip;

-- Find devices by hostname pattern
SELECT hostname, ip, network_cidr, fqdn
FROM netops.ipam_devices
WHERE hostname LIKE '%router%'
ORDER BY network_cidr, ip;

-- Get network utilization summary
SELECT
    network_cidr,
    count(*) as total_ips,
    countIf(state = 'DHCP_ALLOCATED') as dhcp_allocated,
    countIf(state = 'STATIC') as static_ips,
    countIf(hostname != '') as named_devices
FROM netops.ipam_devices
GROUP BY network_cidr
ORDER BY total_ips DESC;

-- Find active DHCP leases
SELECT hostname, ip, mac, lease_start, lease_end, lease_state
FROM netops.ipam_devices
WHERE lease_start IS NOT NULL
  AND lease_end > now()
ORDER BY lease_end ASC;

-- Find expiring DHCP leases (next 24 hours)
SELECT hostname, ip, mac, lease_start, lease_end,
       dateDiff('hour', now(), lease_end) as hours_until_expiry
FROM netops.ipam_devices
WHERE lease_end IS NOT NULL
  AND lease_end BETWEEN now() AND now() + INTERVAL 1 DAY
ORDER BY lease_end ASC;
```

## Scheduling

For regular updates, schedule the script using cron:

```bash
# Run every hour
0 * * * * cd /path/to/bluecat && /usr/bin/python3 import_entities.py >> /var/log/bluecat-import.log 2>&1

# Run daily at 2 AM
0 2 * * * cd /path/to/bluecat && /usr/bin/python3 import_entities.py >> /var/log/bluecat-import.log 2>&1
```

## Docker Support

Build and run with Docker:

```bash
# Build image
docker build -t bluecat-importer .

# Run with environment file
docker run --env-file .env bluecat-importer
```

## Troubleshooting

### Connection Issues
- Verify BAM API is accessible: `curl -k https://your-bam-server/Services/REST/v1/login`
- Check ClickHouse connectivity: `clickhouse-client --host your-ch-host --query "SELECT 1"`
- Review TLS settings if using HTTPS

### Performance Tuning
- Increase `PAGE_SIZE` for faster imports (may increase memory usage)
- Adjust batch size in code (currently 5000) for memory optimization
- Consider running during off-peak hours for large datasets

### Data Quality
- Empty hostnames are normal for unassigned IPs
- MAC addresses may be empty for static assignments
- PTR records are optional and may not exist for all IPs

## BAM Alerts to LiveNX OTEL Collector

`bam_alerts_to_otel.py` is a separate script from the entity importer above. It polls the
BAM RESTful v2 API (`/api/v2/events`) at a regular interval and forwards new system events
(deployment failures, DHCP alerts, server monitoring, etc.) as OpenTelemetry logs to the
OTEL collector on LiveNX. The collector stores them in ClickHouse (`default.otel_logs`).

It runs directly on the LiveNX host with the stock Python 3 (3.10 on Ubuntu 22.04) and needs
**no pip packages**: it uses only the standard library. Because Python has no built-in gRPC
client, the script includes its own minimal protobuf encoder and HTTP/2 client for the single
OTLP `Export` call.

### How it works

1. Logs in with `POST /api/v2/sessions` and re-logs in automatically if the session expires.
2. Fetches events newer than the saved cursor (`id:gt(<last id>)`, ordered by id).
3. Keeps events at or above `MIN_SEVERITY` and sends them to the collector over OTLP/gRPC
   (default `127.0.0.1:4317`, TLS, bearer token).
4. Saves the cursor only after a successful send, so failed deliveries are retried on the
   next poll. On the very first run it starts after the latest event unless
   `INITIAL_BACKFILL` is set.

Severity mapping (BAM `eventType` to OTel severity):

| BAM eventType | OTel severity |
|---------------|---------------|
| INFO, SUCCESS, VALID | INFO |
| WARNING, NOT_DEPLOYED, RESPONSE_POLICY_ZONES_NOT_DEPLOYED | WARN |
| ERROR, FAILED, INVALID, NO_ROLE | ERROR |

The default `MIN_SEVERITY=WARN` forwards only warnings and failures. Set `MIN_SEVERITY=INFO`
to also forward things like "Deployment Started/Finished".

### Configuration

Settings come from environment variables or an env file (`--env-file`); real environment
variables win over the file. See `bam_alerts.env.sample`.

| Variable | Default | Description |
|----------|---------|-------------|
| `BAM_BASE` | (required) | BAM base URL, e.g. `https://10.244.29.80` |
| `BAM_USER` / `BAM_PASS` | (required) | BAM API credentials |
| `BAM_VERIFY_TLS` | `false` | `true`, `false`, or path to a CA bundle |
| `OTEL_ENDPOINT` | `127.0.0.1:4317` | Collector OTLP/gRPC `host:port` |
| `OTEL_AUTH_TOKEN` | read from `/etc/la-otelcol.yaml` | Collector bearer token (`bearertokenauth`) |
| `OTEL_VERIFY_TLS` | `false` | `true`, `false`, or path to a CA bundle |
| `POLL_INTERVAL` | `60` | Seconds between polls |
| `MIN_SEVERITY` | `WARN` | `INFO`, `WARN` or `ERROR` |
| `PAGE_SIZE` | `200` | Events requested per API call |
| `INITIAL_BACKFILL` | `0` | Events to send on first run (0 = only new events) |
| `STATE_FILE` | `~/.bam_alerts_state.json` | Cursor file |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### Usage

```bash
cp bam_alerts.env.sample bam_alerts.env   # edit BAM_BASE, BAM_USER, BAM_PASS
./bam_alerts_to_otel.py --env-file bam_alerts.env                 # run continuously
./bam_alerts_to_otel.py --env-file bam_alerts.env --once          # single poll
./bam_alerts_to_otel.py --env-file bam_alerts.env --once --dry-run  # print OTLP JSON, send nothing
./bam_alerts_to_otel.py --env-file bam_alerts.env --reset-state   # forget the saved cursor
```

### Install as a systemd service

On the LiveNX host, from this directory:

```bash
sudo ./install_bam_alerts.sh
sudo vi /etc/bam-alerts/bam_alerts.env     # set BAM_BASE, BAM_USER, BAM_PASS (file is mode 600)
sudo systemctl start bam-alerts-to-otel
journalctl -u bam-alerts-to-otel -f
```

The installer copies the script to `/opt/bam-alerts/`, installs
`bam-alerts-to-otel.service` (runs as `admin`, restarts on failure), and keeps the cursor in
`/var/lib/bam-alerts/state.json`. It enables the service but does not start it.

### Data in ClickHouse

Records are written with `ServiceName = 'bluecat-address-manager'`, the event message as
`Body`, and these `LogAttributes`: `alert.source`, `bluecat.event.id`, `.type`, `.category`,
`.subcategory`, `.source_name`, `.source.id/.type/.name`, `.user`, `.task_id`, `.payload`
and `.details` (JSON). The log timestamp is the BAM event time.

```sql
SELECT Timestamp, SeverityText, LogAttributes['bluecat.event.category'], Body
FROM default.otel_logs
WHERE ServiceName = 'bluecat-address-manager'
ORDER BY Timestamp DESC
LIMIT 20;
```

### Notes and limitations

- **Network access:** the LiveNX host must reach BAM on TCP 443. Otherwise the script logs
  `POST /api/v2/sessions failed: timed out` and keeps retrying.
- **Retention:** `otel_logs` has a 3-day TTL on the log timestamp, so events older than three
  days are dropped by ClickHouse. `INITIAL_BACKFILL` therefore only helps for recent events.
- **Collector rejections:** a missing or wrong bearer token is reported as
  `collector rejected Export`. The detail text is not decoded (the script has no HPACK Huffman
  decoder), so check `OTEL_AUTH_TOKEN` first.
- Each Export message is kept under about 48 KB to stay inside the default HTTP/2 flow-control
  window; larger batches are split automatically.

## License

This project is licensed under the MIT License.