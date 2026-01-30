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

Sample file (`B2B_NETWORK_FILE_PATH`):

```
192.0.2.0/24 ExamplePartner 12.5
198.51.100.0/24 AnotherPartner 8
203.0.113.0/25 LegacyPartner #N/A
```

## Output JSON format

`OUTPUT_JSON_FILE` contains the `summaryData` array from the LiveNX report
results. Each element is a record with a `data` list; the script reads specific
indexes (source/destination IPs and ports, plus average bit rate).

Sample (abbreviated) `OUTPUT_JSON_FILE`:

```
[
  {
    "data": [
      { "value": "user-a" },
      { "value": "user-b" },
      { "value": "10.0.0.10" },
      { "value": "site-a" },
      { "value": 443 },
      { "value": "203.0.113.25" },
      { "value": "site-b" },
      { "value": 8443 },
      { "value": "TCP" },
      { "value": "0" },
      { "value": "app-name" },
      { "value": 120 },
      { "value": 98000 },
      { "value": 700 },
      { "value": 12.345 }
    ]
  }
]
```

Note: The exact fields and ordering in `data` are determined by the LiveNX
report configuration. This script uses `data[2]`, `data[4]`, `data[5]`,
`data[7]`, and `data[14]`.

Field meanings (based on the report layout used by this script):

```
Index  Field              Notes
-----  -----------------  -----------------------------
0      source_username    String
1      destination_user   String
2      source_ip          IP string (letters stripped)
3      source_site        String
4      source_port        Integer or numeric string
5      destination_ip     IP string (letters stripped)
6      destination_site   String
7      destination_port   Integer or numeric string
8      protocol           String (e.g., TCP)
9      dscp               String/number
10     app_name           String
11     total_flows        Integer
12     total_bytes        Integer
13     total_packets      Integer
14     average_bit_rate   Float, rounded to 3 decimals
15     packet_rate        Float
16     peak_bit_rate      Float
17     peak_packet_rate   Float
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
