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

The script supports two modes of operation: **continuous** (default) and **single-run**.

### Continuous Mode (default)

Polls LiveNX and Infoblox repeatedly at a configurable interval. Use this for production deployments where the script runs as a service.

```bash
python infoblox_script.py \
  --livenx_host=<livenx.host> \
  --livenx_token=<livenx-api-token> \
  --report_id=<livenx-report-id> \
  --device_serial=<livenx-device-serial> \
  --infoblox_host=<infoblox-host> \
  --infoblox_username=<infoblox-username> \
  --infoblox_password=<infoblox-password> \
  --clickhouse_host=<clickhouse-host> \
  --clickhouse_username=<clickhouse-user> \
  --clickhouse_password=<clickhouse-pass> \
  --poll_interval_seconds 60
```

### Single-Run Mode (`--once`)

Runs a single poll iteration and exits. Useful for testing, cron jobs, or one-off data pulls.

```bash
python infoblox_script.py \
  --livenx_host=<livenx.host> \
  --livenx_token=<livenx-api-token> \
  --report_id=<livenx-report-id> \
  --device_serial=<livenx-device-serial> \
  --infoblox_host=<infoblox-host> \
  --infoblox_username=<infoblox-username> \
  --infoblox_password=<infoblox-password> \
  --clickhouse_host=<clickhouse-host> \
  --clickhouse_username=<clickhouse-user> \
  --clickhouse_password=<clickhouse-pass> \
  --once
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
| `--once` | Run a single poll iteration and exit | No |
| `--trace_src_ip` | source ip to trace(troubleshooting purpose only) | No |
| `--trace_dst_ip` | destination ip to trace(troubleshooting purpose only) | No |

## Systemd Service Installation

The included `install_systemd_service.sh` script automates deploying the integration as a systemd service on a Linux server. This is the recommended approach for production use.

### Interactive Installation

Run the installer as root on the target server:

```bash
sudo bash install_systemd_service.sh
```

The installer will prompt for all required configuration values, then:
1. Copies the script to `/opt/livenx-infoblox/`
2. Creates a Python virtual environment and installs dependencies
3. Stores configuration in `/etc/livenx-infoblox/livenx-infoblox.env` (mode 600)
4. Creates and enables a systemd service unit
5. Starts the service

### Non-Interactive Installation

For automated deployments, copy the script files to the server and run the setup manually:

```bash
# Copy files to the server
INSTALL_DIR="/opt/livenx-infoblox"
sudo mkdir -p "$INSTALL_DIR"
sudo cp infoblox_script.py requirements.txt "$INSTALL_DIR/"

# Create virtual environment
sudo python3 -m venv "$INSTALL_DIR/venv"
sudo "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Create environment file with arguments
sudo mkdir -p /etc/livenx-infoblox
sudo tee /etc/livenx-infoblox/livenx-infoblox.env > /dev/null <<'EOF'
INFOBLOX_ARGS=--livenx_host localhost --livenx_token "<token>" --report_id 90 --device_serial <serial> --infoblox_host <infoblox-host> --infoblox_username admin --infoblox_password "<password>" --poll_interval_seconds 60 --clickhouse_host localhost --clickhouse_port 9440 --clickhouse_username default --clickhouse_password "<password>" --clickhouse_database default --clickhouse_table infoblox_nat_dhcp
EOF
sudo chmod 600 /etc/livenx-infoblox/livenx-infoblox.env

# Create systemd unit file
sudo tee /etc/systemd/system/livenx-infoblox.service > /dev/null <<EOF
[Unit]
Description=LiveNX Infoblox NAT/DHCP Integration Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/livenx-infoblox/livenx-infoblox.env
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/infoblox_script.py \$INFOBLOX_ARGS
WorkingDirectory=$INSTALL_DIR

Restart=on-failure
RestartSec=10

StandardOutput=journal
StandardError=journal
SyslogIdentifier=livenx-infoblox

NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$INSTALL_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable livenx-infoblox
sudo systemctl start livenx-infoblox
```

### Managing the Service

```bash
# Check status
systemctl status livenx-infoblox

# View live logs
journalctl -u livenx-infoblox -f

# Restart after config changes
systemctl restart livenx-infoblox

# Stop the service
systemctl stop livenx-infoblox

# Uninstall
systemctl stop livenx-infoblox
systemctl disable livenx-infoblox
rm /etc/systemd/system/livenx-infoblox.service
rm -rf /opt/livenx-infoblox
rm -rf /etc/livenx-infoblox
systemctl daemon-reload
```
