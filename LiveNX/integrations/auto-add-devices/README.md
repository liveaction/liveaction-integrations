# LiveNX Auto Add Devices

A Python utility that monitors and automatically adds unknown devices to LiveNX from samplicator log files.

## Overview

This tool identifies IP addresses from network flows that aren't registered in LiveNX and automatically adds them as managed devices. It supports continuous monitoring, device load balancing across nodes, automatic interface discovery, and integrated samplicator management.

## Prerequisites

- Python 3.x
- Access to LiveNX API
- Required environment variables:
  - `LIVENX_API_HOST`: LiveNX server hostname
  - `LIVENX_API_PORT`: LiveNX API port
  - `LIVENX_API_TOKEN`: Authentication token for LiveNX API
  - `LOGLEVEL`: (Optional) Log level (INFO, DEBUG, etc.)

For interface monitoring (optional):
  - `CLICKHOUSE_HOST`: ClickHouse server hostname
  - `CLICKHOUSE_PORT`: ClickHouse server port
  - `CLICKHOUSE_USERNAME`: ClickHouse username
  - `CLICKHOUSE_PASSWORD`: ClickHouse password (or configured in users.xml)
  - `CLICKHOUSE_CACERTS`: Path to CA certificates
  - `CLICKHOUSE_CERTFILE`: Path to certificate file
  - `CLICKHOUSE_KEYFILE`: Path to key file

## Installation

1. Clone this repository
2. Set up the required environment variables:
```bash
export LIVENX_API_HOST="your.livenx.host"
export LIVENX_API_PORT="8093"
export LIVENX_API_TOKEN="your-api-token"
```
3. Create the configuration files in the `config` directory:
   - `device_defaults.json`
   - `interface_defaults.json`

## Usage

### Continuous Monitoring

```bash
# Monitor an IP file continuously
python adddevice.py --monitoripfile /path/to/ip/list/file --samplicatorpath /path/to/samplicator --samplicatorconfigfilepath /path/to/config --samplicatorhost <host> --samplicatorport <port>
```

### Samplicator Management

```bash
# Restart the samplicator service
python adddevice.py --restartsamplicator --samplicatorpath /path/to/samplicator --samplicatorconfigfilepath /path/to/config --monitoripfile /path/to/ip/list/file --samplicatorhost <host> --samplicatorport <port>

# Write samplicator configuration
python adddevice.py --writesamplicatorconfig --samplicatorconfigfilepath /path/to/config --writesamplicatorconfigmaxsubnets <max_subnets>
```

### Load Balancing

```bash
# Rebalance devices across nodes
python adddevice.py --writesamplicatorconfig --movedevices --samplicatorconfigfilepath /path/to/config --writesamplicatorconfigmaxsubnets <max_subnets>
```

### Interface Auto-Discovery

```bash
# Enable automatic interface discovery
python adddevice.py --monitoripfile /path/to/ip/list/file --addinterfaces
```

### Test Devices

```bash
# Add test devices
python adddevice.py --addtestdevices <number_of_devices> --addtestdevicesstartnum <start_num>
```

## Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--monitoripfile` | Path to the file containing IP addresses to monitor | None |
| `--samplicatorpath` | Path to the samplicator executable | None |
| `--samplicatorconfigfilepath` | Path to the samplicator configuration file | None |
| `--samplicatorhost` | Host address for samplicator | None |
| `--samplicatorport` | Port for samplicator | None |
| `--restartsamplicator` | Restart the samplicator service | False |
| `--movedevices` | Enable moving devices between nodes for load balancing | False |
| `--includeserver` | Include the LiveNX server in the node list | False |
| `--addinterfaces` | Enable automatic interface configuration | False |
| `--writesamplicatorconfig` | Write out the samplicator configuration | False |
| `--writesamplicatorconfigmaxsubnets` | Maximum number of subnets in the samplicator config | None |
| `--addtestdevices` | Number of test devices to add | None |
| `--addtestdevicesstartnum` | Starting index for test device IP addresses | None |
| `--numsecstowaitbeforerebalance` | Seconds to wait before rebalancing | 300 |
| `--numsecstowaitbeforeaddinginterfaces` | Seconds to wait before adding interfaces | 300 |

## Features

### IP Monitoring
- Monitors files containing IP addresses
- Uses sets to efficiently track unique addresses
- Continuously checks for new addresses at regular intervals

### Device Registration
- Automatically creates virtual device entries in LiveNX
- Sets up interface configurations based on defaults
- Uses IP address as hostname in dotted format
- Processes devices in batches to avoid memory issues

### Load Balancing
- Distributes devices across multiple LiveNX nodes
- Groups IP addresses into subnets for efficient management
- Uses optimized subnet grouping algorithm
- Rebalances devices when no new devices are added for a specified time

### Interface Discovery
- Automatically discovers device interfaces from flow data in ClickHouse
- Updates device configurations with discovered interfaces
- Runs periodic interface discovery based on configured interval

### Samplicator Integration
- Manages samplicator process lifecycle
- Configures subnet distribution for optimal flow collection
- Automatically restarts samplicator when configuration changes

## Docker Support

### Building Docker Image
```bash
docker build -t addautodevice-app .
```

### Running Docker Image
```bash
docker run -v /data/livenx-server/data/log:/data/livenx-server/data/log \
  -e LIVENX_API_HOST=10.0.0.1 \
  -e LIVENX_API_PORT=8093 \
  -e LIVENX_API_TOKEN=your_token_here \
  -e CLICKHOUSE_HOST=localhost \
  -e CLICKHOUSE_USERNAME=default \
  -e CLICKHOUSE_PORT=9440 \
  -e CLICKHOUSE_CACERTS=/path/to/ca.pem \
  -e CLICKHOUSE_CERTFILE=clickhouse-server/cacerts/ca.crt \
  -e CLICKHOUSE_KEYFILE=clickhouse-server/cacerts/ca.key \
  addautodevice-app
```

### Using Docker Compose
Edit the docker-compose.yml with the necessary parameters, then execute:
```bash
docker compose up -d
```

## Security Considerations
- SSL certificate verification is disabled by default for internal networks
- API tokens should be kept secure
- Environment variables used for sensitive configuration

## Known Limitations
- Requires specific environment setup for interface monitoring
- SSL certificate verification disabled
- Currently only supports IPv4 addresses (IPv6 support commented out)