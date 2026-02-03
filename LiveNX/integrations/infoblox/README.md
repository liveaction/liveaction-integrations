# NAT data from LiveNX and DHCP leases from Infoblox

Script to fetch NAT data from LiveNX and DHCP leases from Infoblox, then consolidate into a report.

## Overview

This tool fetch the device NAT data.

## Prerequisites

- Python 3.x
- Access to LiveNX API
- Access to Infoblox API

## Installation

1. Clone this repository

## Usage

### Basic Command
```bash
# Run monitor script (polls every minute and writes to ClickHouse)
python infoblox_script.py \
  --livenx_host=<livenx.host> \
  --livenx_token=<livenx-api-token> \
  --report_id=<livenx-report-id> \
  --device_serial=<livenx-device-serial> \
  --infoblox_host=<inflox-host> \
  --infoblox_username=<inflox-username> \
  --infoblox_password=<inflox-password> \
  --clickhouse_host=<clickhouse-host> \
  --clickhouse_username=<clickhouse-user> \
  --clickhouse_password=<clickhouse-pass>
```

The script:
- polls Infoblox DHCP leases and LiveNX NAT data serially. 
- gets Infoblox DHCP lease information by calling APIs. By default, it returns 1000 records. If there are more records, it calls the API with pagination until all records are fetched.
- uses LiveNX asynchronous API to get the data. When the app starts, it sets flow logs limit to 100K by default. You can update it via `LIVENX_REPORT_RESULTS_LIMIT` parameter in the script. Also, there is one more parameter: `LIVENX_POLL_INTERVAL_IN_SECONDS`. If it is zero, the LiveNX report queue is called with poll start and end time. In case of large data, it is tuned with less interval. The API is called for the configured interval multiple times sequentially until the poll duration is covered.
- consolidates LiveNX data with Infoblox data.
- writes matches into ClickHouse (default database `inventory_db`, table `infoblox_nat_dhcp`) when ClickHouse connection info is provided
- otherwise prints the per-poll records to stdout
- creates the database/table if they do not already exist when ClickHouse is enabled

Set ClickHouse connection values via flags or environment variables: `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT` (default `9440`), `CLICKHOUSE_USERNAME`, `CLICKHOUSE_PASSWORD`, `CLICKHOUSE_DATABASE`, `CLICKHOUSE_TABLE`, `CLICKHOUSE_CACERTS`, `CLICKHOUSE_CERTFILE`, `CLICKHOUSE_KEYFILE`.

### Command Line Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `--livenx_host` | Livenx hostname/IP address | Yes |
| `--livenx_token` | Livenx API token | Yes |
| `--report_id` | Livenx Report ID | Yes |
| `--device_serial` | Livenx Device Serial | Yes |
| `--infoblox_host` | Infoblox host | Yes |
| `--infoblox_username` | Infoblox username | Yes |
| `--infoblox_password` | Infoblox password | Yes |
| `--clickhouse_host` | ClickHouse host (or env `CLICKHOUSE_HOST`) | Yes |
| `--clickhouse_port` | ClickHouse port (default 9440 or env) | Yes |
| `--clickhouse_username` | ClickHouse username (or env) | Yes |
| `--clickhouse_password` | ClickHouse password (or env) | Yes |
| `--clickhouse_database` | ClickHouse database (default `inventory_db`) | No |
| `--clickhouse_table` | ClickHouse table (default `infoblox_nat_dhcp`) | No |
| `--clickhouse_cacerts` | CA bundle for ClickHouse TLS | No |
| `--clickhouse_certfile` | Client cert for ClickHouse TLS | No |
| `--clickhouse_keyfile` | Client key for ClickHouse TLS | No |
| `--poll_interval_seconds` | Poll interval in seconds (default 60) | No |
| `--trace_src_ip` | source ip to trace(troubleshooting purpose only) | No |
| `--trace_dst_ip` | destination ip to trace(troubleshooting purpose only) | No |
