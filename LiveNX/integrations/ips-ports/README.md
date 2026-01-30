## Overview

The `ips-ports.py` script runs a LiveNX Flow report (report ID 79) against a
targeted IP/port criteria, writes the summarized results to JSON, and logs
threshold evaluations for destination networks defined in a B2B mapping file.
It is intended for monitoring outbound traffic to specific network ranges and
alerting when average bit rate thresholds are exceeded.

## How it works

1. Builds a LiveNX report request using a flex search filter.
2. Submits the report to the LiveNX API and waits for completion.
3. Extracts `summaryData` from the report results.
4. Writes the summarized results to a JSON file.
5. Compares each record against the B2B network thresholds and logs matches.

## Requirements

- Python 3
- `requests` (see `LiveNX/integrations/requirements.txt`)
- Network access to your LiveNX server

## Configuration (environment variables)

The script uses these environment variables. If `NX_SERVER` or `API_KEY` are
missing, you will be prompted interactively.

- `NX_SERVER` (required or prompted): LiveNX hostname or IP
- `API_KEY` (required or prompted): LiveNX API key (the script adds `Bearer`)
- `B2B_NETWORK_FILE_PATH` (default: `/opt/app/Files/B2B_Networks_l200.txt`)
- `LOG_FILE_PATH` (default: `/opt/app/Files/LiveNX_B2Bl200.log`)
- `OUTPUT_JSON_FILE` (default: `/opt/app/Files/LiveNX_Results_l200.json`)
- `FLEX_CRITERIA` (default: built-in flex search string)
- `SYSLOG_SERVER` (optional): remote syslog host
- `SYSLOG_PORT` (optional): remote syslog port

## B2B network file format

Each line is expected to contain three whitespace-separated fields:

```
<cidr_range> <name> <threshold>
```

Example:

```
192.0.2.0/24 ExamplePartner 12.5
```

## Usage

From the repository root:

```
cd LiveNX/integrations/ips-ports
NX_SERVER=your-livenx-host API_KEY=your-api-key python3 ips-ports.py
```

Or export variables first:

```
export NX_SERVER=your-livenx-host
export API_KEY=your-api-key
export B2B_NETWORK_FILE_PATH=/path/to/B2B_Networks_l200.txt
python3 ips-ports.py
```

## Output

- JSON results: written to `OUTPUT_JSON_FILE`
- Logs: written to `LOG_FILE_PATH` (and optionally sent to syslog)
- Console: prints report status, processing counts, and timings
