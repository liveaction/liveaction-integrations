# ClickHouse Site Aggregation Tool

A powerful Python script for performing hierarchical time-based aggregations of flow data in ClickHouse, supporting multiple aggregation intervals, parallel processing, and custom IP-to-site mappings.

## Features

- **Hierarchical Aggregation**: Supports 4 aggregation levels (1m, 5m, 60m, 360m)
- **Parallel Processing**: Execute multiple batches concurrently for improved performance
- **Batch Processing**: Process large time ranges in configurable batch sizes
- **Site IP Mapping**: Map IP addresses to site names using CSV configuration
- **SSL/TLS Support**: Secure HTTPS connections with certificate verification
- **Duplicate Detection**: Check for duplicate records
- **Dry Run Mode**: Preview queries before execution
- **Custom Tables**: Support for user-defined source and destination tables

## Installation

The script uses only Python standard library modules - no external dependencies required.

### Requirements

- Python 3.10 or higher
- Access to a ClickHouse server (HTTP/HTTPS interface on port 8123)
- Appropriate permissions to read from source tables and write to destination tables

## Quick Start

### Basic Usage

```bash
# Aggregate yesterday's raw data to 1-minute intervals
python3 clickhouse_site_aggregation.py -H clickhouse.example.com --time-range yesterday

# Aggregate 1-minute data to 5-minute intervals
python3 clickhouse_site_aggregation.py -H clickhouse.example.com --time-range yesterday --level 5m

# Run all aggregation levels in sequence (1m → 5m → 60m → 360m)
python3 clickhouse_site_aggregation.py -H clickhouse.example.com --time-range yesterday --all-levels
```

### With Authentication

```bash
# HTTPS connection with authentication
python3 clickhouse_site_aggregation.py -H secure.clickhouse.com --https \
  -u myuser -P mypass --time-range yesterday --level 5m
```

## Aggregation Levels

The tool supports four hierarchical aggregation levels, each building upon the previous:

| Level | Source Table | Destination Table | Interval | Description |
|-------|-------------|-------------------|----------|-------------|
| **1m** | `basic_raw` | `basic_entity_app_site_1m` | 1 minute | Raw data to 1-minute aggregates |
| **5m** | `basic_entity_app_site_1m` | `basic_entity_app_site_5m` | 5 minutes | 1-minute to 5-minute aggregates |
| **60m** | `basic_entity_app_site_5m` | `basic_entity_app_site_60m` | 60 minutes | 5-minute to 60-minute aggregates |
| **360m** | `basic_entity_app_site_60m` | `basic_entity_app_site_360m` | 6 hours | 60-minute to 6-hour aggregates |

### Table Types

The script supports three types of flow tables:

#### Basic Tables
Standard network flow metrics:
- Flow count, packet count, octet count
- Sampling flag preservation

## Command Line Options

### Connection Options

| Option | Description | Default |
|--------|-------------|---------|
| `-H, --host` | ClickHouse host | localhost |
| `-p, --port` | ClickHouse HTTP port | 8123 |
| `-u, --user` | Username | default |
| `-P, --password` | Password | (empty) |
| `-d, --database` | Database name | livenx_flowdb |
| `-t, --timeout` | Query timeout in seconds | 300 |

### SSL/TLS Options

| Option | Description |
|--------|-------------|
| `--https` | Use HTTPS instead of HTTP |
| `--no-verify-ssl` | Disable SSL certificate verification |
| `--verify-hostname` | Verify hostname in SSL certificate |
| `--ca-cert PATH` | Path to CA certificate file |
| `--client-cert PATH` | Path to client certificate for mutual TLS |
| `--client-key PATH` | Path to client key for mutual TLS |

### Aggregation Options

| Option | Description |
|--------|-------------|
| `--time-range` | **Required.** Time range to aggregate (see Time Ranges section) |
| `--level` | Aggregation level: 1m, 5m, 60m, or 360m (default: 1m) |
| `--all-levels` | Run all aggregation levels in sequence |
| `--source-table` | Custom source table (overrides defaults) |
| `--dest-table` | Custom destination table (overrides defaults) |
| `--batch-size N` | Process in batches of N intervals (0 = no batching) |
| `--parallel N` | Number of parallel workers for batch processing |
| `--site-mapping FILE` | CSV file with site IP mappings (see Site Mapping section) |

### Action Options

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview queries without executing |
| `--check-duplicates` | Check for duplicate records in destination |
| `--info` | Show table information and exit |

## Time Ranges

The `--time-range` parameter accepts several formats:

### Predefined Ranges
- `yesterday` - Previous day (00:00 to 00:00)
- `today` - Current day (00:00 to now)
- `last-hour` - Last complete hour
- `last-24h` - Last 24 hours from now

### Custom Ranges
Specify exact start and end times:
```bash
--time-range "2024-01-01 00:00:00,2024-01-02 00:00:00"
```

## Site IP Mapping

When aggregating from raw tables, you can map IP addresses to site names using a CSV file. If the site to IP range mapping is already defined in LiveNX you can use the CSV export file for this.

### CSV Format

```csv
Site Name,Site IP Ranges
"New York","10.1.0.0/16,192.168.1.0/24"
"London","10.2.0.0/16,172.16.0.0/20"
"Tokyo","192.168.0.0/24"
```

### Usage

```bash
python3 clickhouse_site_aggregation.py -H ch.example.com \
  --time-range yesterday --level 1m \
  --site-mapping LiveAction_sites.csv
```

### Overlapping IP Ranges

The script automatically handles overlapping IP ranges using **longest prefix match**:

```csv
Site Name,Site IP Ranges
"Global Network","10.0.0.0/8"      # /8 - least specific
"North America","10.1.0.0/12"      # /12 - more specific
"New York Office","10.1.1.0/24"    # /24 - even more specific
"NYC Data Center","10.1.1.0/26"    # /26 - most specific
```

For IP `10.1.1.5`:
- Matches all four ranges
- Assigned to "NYC Data Center" (most specific /26)

### Example Files Provided

- `LiveAction_sites_example.csv` - Basic example with 15 sites
- `LiveAction_sites_overlapping_example.csv` - Demonstrates prefix priority
- `LiveAction_sites_large_example.csv` - Comprehensive example with 263 sites

## Batch Processing

For large time ranges, use batch processing to manage memory and improve reliability:

```bash
# Process 60 intervals at a time
# For 1m level: 60 x 1 minute = 60 minutes per batch
# For 5m level: 60 x 5 minutes = 300 minutes per batch
python3 clickhouse_site_aggregation.py -H ch.example.com \
  --time-range "2024-01-01 00:00:00,2024-01-02 00:00:00" \
  --level 5m --batch-size 60
```

## Parallel Processing

Combine batch processing with parallel execution for optimal performance:

```bash
# Use 4 parallel workers with 120 intervals per batch
# For 1m level: 120 x 1 minute = 2 hours per batch
python3 clickhouse_site_aggregation.py -H ch.example.com \
  --time-range yesterday --batch-size 120 --parallel 4
```

## Advanced Examples

### Complete Pipeline for All Table Types

```bash
# Basic tables - all levels
python3 clickhouse_site_aggregation.py -H ch.example.com \
  --time-range yesterday --all-levels --batch-size 60 --parallel 4
```

### Handling Duplicates

```bash
# Check for duplicates first
python3 clickhouse_site_aggregation.py -H ch.example.com \
  --time-range yesterday --level 5m --check-duplicates
```

### Custom Tables

```bash
# Aggregate custom tables with specific time function
python3 clickhouse_site_aggregation.py -H ch.example.com \
  --source-table mydb.raw_flows \
  --dest-table mydb.aggregated_flows_5m \
  --level 5m --time-range today
```

### Secure Connection with Mutual TLS

```bash
python3 clickhouse_site_aggregation.py -H secure.ch.example.com \
  --https --ca-cert /path/to/ca.pem \
  --client-cert /path/to/client.crt \
  --client-key /path/to/client.key \
  --time-range yesterday --level 5m
```

## Performance Considerations

### Batch Size Guidelines

- **Small datasets (<1M rows)**: No batching needed
- **Medium datasets (1M-100M rows)**: Use batch-size 60-120
- **Large datasets (>100M rows)**: Use batch-size 30-60 with parallel workers

### Parallel Workers

- **CPU cores**: Set workers to number of CPU cores - 1
- **Memory**: Each worker uses separate memory, monitor usage
- **ClickHouse load**: Consider server capacity and concurrent users

### Time Alignment

Batches are automatically aligned to natural time boundaries:
- 1m: Aligned to minutes
- 5m: Aligned to 5-minute intervals
- 60m: Aligned to hours
- 360m: Aligned to 6-hour intervals

## Monitoring and Troubleshooting

### Progress Tracking

The script provides real-time progress updates:
- Batch completion status
- Rows read and inserted
- Execution time per batch
- Total runtime upon completion

### Common Issues

#### Connection Errors
```bash
# Test connection first
python3 clickhouse_site_aggregation.py -H ch.example.com --info
```

#### SSL Certificate Issues
```bash
# For self-signed certificates
python3 clickhouse_site_aggregation.py -H ch.example.com --https --no-verify-ssl
```

#### Timeout Errors
```bash
# Increase timeout for slow queries
python3 clickhouse_site_aggregation.py -H ch.example.com -t 600 --time-range yesterday
```

#### Memory Issues
```bash
# Reduce batch size
python3 clickhouse_site_aggregation.py -H ch.example.com --batch-size 30 --time-range yesterday
```

## Output Format

The script uses color-coded output for clarity:
- 🟢 **Green**: Successful operations
- 🔵 **Blue**: Informational messages
- 🟡 **Yellow**: Warnings
- 🔴 **Red**: Errors

## Exit Codes

- `0`: Success
- `1`: Operation failed

## License

This tool is provided as-is for use with ClickHouse databases. Please ensure you have appropriate permissions before running aggregation queries.

## Support

For issues or feature requests, please contact your system administrator or refer to the ClickHouse documentation for query optimization guidelines.
