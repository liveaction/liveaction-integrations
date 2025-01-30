# LiveNX Integration Tool

A Python3 utility for synchronizing inventory and alerts between LiveNX, NetLD, BlueCat and ServiceNow platforms.

## Overview

This tool provides bidirectional synchronization capabilities for:
- Device inventory between LiveNX, NetLD and BlueCat
- Alerts/incidents between LiveNX, NetLD, and ServiceNow
- Sites between LiveNX and BlueCat

## Prerequisites

- Python 3.x
- Access to LiveNX, NetLD, BlueCat and/or ServiceNow APIs
- Required Python packages (install via pip):
  - `argparse`
  - Additional dependencies from the `common`, `netld`, and `servicenow` modules

## Installation

1. Clone this repository
2. Ensure the following directory structure exists:
```
.
├── common/
│   ├── livenx_inventory.py
│   └── livenx_alerts.py
├── netld/
│   ├── inventory.py
│   └── incidents.py
├── servicenow/
│   └── incidents.py
├── helper/
│   ├── timer.py
│   └── prompt.py
└── config/
    └── logger.py
```

## Usage

### Basic Commands

```bash
# Sync inventory from LiveNX to NetLD
python3 main.py --inventory --fromproduct livenx --toproduct netld

# Sync alerts from LiveNX to ServiceNow
python3 main.py --alerts --fromproduct livenx --toproduct servicenow

# Run continuously with no prompts
python3 main.py --alerts --fromproduct livenx --toproduct servicenow --continuous --noprompt

# Sync sites from BlueCat to Linenx
python3 main.py --sites --fromproduct bluecat_integrity --toproduct livenx

# Sync custom applications from snow to Linenx
python3 main.py --custom_applications --fromproduct snow_csv --toproduct livenx --csv_input /data/mdb_ci_server.csv

# Sync alerts from LiveNX to Freshwork
python3 main.py --alerts --fromproduct livenx --toproduct freshwork
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--inventory` | Enable inventory synchronization | False |
| `--alerts` | Enable alerts synchronization | False |
| `--sites` | Enable sites synchronization | False |
| `--fromproduct` | Source platform (livenx/netld/bluecat_integrity) | '' |
| `--toproduct` | Destination platform (livenx/netld/servicenow) | '' |
| `--starttimesecs` | Start time in epoch seconds | 0 |
| `--endtimesecs` | End time in epoch seconds | 0 |
| `--continuous` | Run continuously | False |
| `--noprompt` | Skip confirmation prompts | False |
| `--logstdout` | Log to stdout instead of file | False |
| `--num_minutes_behind` | Minutes to run behind wall clock | 2 |
| `--custom_applications` | Enable custom application synchronization | False |
| `--csv_input` | CSV file path | '' |

## Features

### Inventory Synchronization
- Bidirectional sync between LiveNX, BlueCat and NetLD
- Differential updates (only changed devices)
- Interactive prompts for additions/removals (unless --noprompt is used)
- Hostname-based verification

### Alert/Incident Synchronization
- Support for LiveNX → ServiceNow incident creation
- Alert ID matching to prevent duplicates
- Continuous monitoring mode with configurable delay
- Time-based synchronization windows

### Sites Synchronization
- Support for BlueCat → LiveNX sites creation
- SiteName matching to prevent duplicates
- Continuous monitoring mode with configurable delay
- Time-based synchronization windows

## Continuous Operation

When running in continuous mode (`--continuous`):
- The tool processes data in 1-minute intervals
- Default lag time is 2 minutes behind wall clock
- Adjustable via `--num_minutes_behind`
- Automatically calculates time windows if start/end times aren't specified

## Logging

- Default: Logs to file
- Use `--logstdout` to redirect logs to standard output
- Debug level logging available
- Timestamps and operation tracking

## Error Handling

- Validation of inventory changes before application
- Interactive confirmation for critical operations
- Continuous operation recovery on failures

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

This project is licensed under the MIT License.

Building Docker Image
---------------------

docker build -t liveaction/livenx-integrations .

Running Docker Image
--------------------

docker run -e LIVENX_API_HOST=10.0.0.1 -e LIVENX_API_PORT=8093 -e LIVENX_API_TOKEN=your_token_here -e THIRDEYE_API_HOST=10.100.155.150 -e THIRDEYE_API_USER=netlduser -e THIRDEYE_API_PASSWORD="netldpass" -e THIRDEYE_NETWORK=Default your_image_name --inventory --fromproduct livenx --toproduct netld --continuous

Examples:
---------


netLD
-----

From the command line
---------------------

To run the following examples these environment variables must be set (example):

LIVENX_API_HOST=10.4.205.201
LIVENX_API_PORT=8093
LIVENX_API_TOKEN="foobar"
THIRDEYE_API_HOST=10.100.155.150
THIRDEYE_API_USER=netlduser
THIRDEYE_API_PASSWORD="netldpass"
THIRDEYE_NETWORK=Default
BLUECAT_API_HOST=1.0.0.1
BLUECAT_API_USER="username"
BLUECAT_API_PASSWORD="password"
FRESHWORK_HOST=1.0.0.1
FRESHWORK_USERNAME="username"
FRESHWORK_PASSWORD="password"


Push inventory continuously from LiveAction LiveNX to LogicVein NetLD:

python3 main.py --inventory --fromproduct livenx --toproduct netld --continuous


Push all current inventory from LogicVein NetLD to LiveAction LiveNX:

python3 main.py --inventory --fromproduct netld --toproduct livenx

Using Docker Run
----------------

docker run -e LIVENX_API_HOST=10.0.0.1 -e LIVENX_API_PORT=8093 -e LIVENX_API_TOKEN=your_token_here -e THIRDEYE_API_HOST=10.100.155.150 -e THIRDEYE_API_USER=netlduser -e THIRDEYE_API_PASSWORD="netldpass" -e THIRDEYE_NETWORK=Default liveaction/LiveNX-Integrations --inventory --fromproduct livenx --toproduct netld --continuous

Using Docker Compose
--------------------

Edit the docker-compose.yml with the nescessary parameters.

then execute:

docker compose up -d


| LiveWire Product | External Product | Attribute in LiveNX | Attribute in External Product |
| ---------------- | ---------------- | ------------------- | ----------------------------- |
| LiveNX | LiveNCA/NetLD | hostName | hostname |
| LiveNX | LiveNCA/NetLD | network | network |
| LiveNX | LiveNCA/NetLD | hostName | hostname |
| LiveNX | LiveNCA/NetLD | address | ipAddress |
| LiveNX | LiveNCA/NetLD | vendorProduct>displayName | adapterId |
| LiveNX | LiveNCA/NetLD | vendorProduct>displayName | softwareVendor |
| LiveNX | LiveNCA/NetLD | osVersionString | osVersion |
| LiveNX | LiveNCA/NetLD | serialNumber | serialNumber |
