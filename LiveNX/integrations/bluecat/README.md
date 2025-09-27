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

## License

This project is licensed under the MIT License.