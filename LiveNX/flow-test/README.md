# LiveNX Flow Test

`getflows.py` is a small LiveNX flow-report runner used to:

- submit a flow report request to the LiveNX reporting API
- wait for the report result to become available
- write the returned summary data to JSON
- compare each returned destination IP against a local network list
- log an `ALERT` when a flow exceeds the configured threshold for a matching network

The helper script `run.sh` loads variables from `.env` and runs `getflows.py`.

## What The Script Does

On each run, the script:

1. sets the LiveNX flow report limit to `15000`
2. submits report `79` in the `flow` category
3. requests outbound flow data for all devices
4. queries the last `1200` seconds of data
5. waits until the result endpoint is ready
6. writes the report summary to `OUTPUT_JSON_FILE`
7. checks each record against the networks in `FLOW_NETWORK_FILE_PATH`
8. writes matches and threshold violations to the log file

## Files In This Folder

- `getflows.py`: main script
- `run.sh`: loads `.env` and starts the script
- `.env`: local environment variables for the script
- `FLOW_Networks_rfc10.txt`: example network/threshold list
- `LiveNX_Results_l200.json`: output JSON written by the script
- `LiveNX_FLOWl200.log`: log file written by the script

## Requirements

- Python 3
- `requests`
- network access to the LiveNX server on port `8093`
- a valid LiveNX API token

Example setup in this folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests
```

If you are using the repo-level virtualenv instead, activate that environment before running the script.

## Configuration

The script reads settings from environment variables.

### Required

- `NX_SERVER`: LiveNX hostname or IP
- `API_KEY`: bearer token used for the LiveNX API
- `FLEX_CRITERIA`: LiveNX flex search used in the report request

### Optional

- `FLOW_NETWORK_FILE_PATH`: path to the network threshold file
  Default: `/opt/app/Files/FLOW_Networks_rfc10.txt`
- `LOG_FILE_PATH`: path to the log file
  Default: `/opt/app/Files/LiveNX_FLOWl200.log`
- `OUTPUT_JSON_FILE`: path to the output JSON file
  Default: `/opt/app/Files/LiveNX_Results_l200.json`
- `REPORT_DATA_SOURCE`: `flowstore` or `flowstore_v2`
  Default: `flowstore_v2`
- `MAX_WORKERS`: thread count for record processing
  Default: `16`
- `REPORT_POLL_INTERVAL`: seconds between result polls
  Default: `1`
- `REPORT_WAIT_TIMEOUT`: maximum seconds to wait for the report result
  Default: `300`
- `SYSLOG_SERVER`: optional syslog host
- `SYSLOG_PORT`: optional syslog port

Example `.env`:

```bash
NX_SERVER=10.0.0.10
API_KEY=replace-with-your-token
FLEX_CRITERIA='flow.protocol!=ESP & flow.protocol!=UDP & flow.dstIp=10.48.0.0/14'

FLOW_NETWORK_FILE_PATH=./FLOW_Networks_rfc10.txt
LOG_FILE_PATH=./LiveNX_FLOWl200.log
OUTPUT_JSON_FILE=./LiveNX_Results_l200.json
REPORT_DATA_SOURCE=flowstore_v2
MAX_WORKERS=16
REPORT_POLL_INTERVAL=1
REPORT_WAIT_TIMEOUT=300
```

Do not commit real API tokens or local `.env` files.

## Network File Format

The network file must contain one entry per line in this format:

```text
<cidr> <name> <threshold>
```

Example:

```text
10.48.0.0/14 AWS 5000000
172.20.64.0/24 AZURE 3000000
0.0.0.0/0 LEGACY1 0
```

Notes:

- lines that do not have exactly 3 fields are ignored
- invalid CIDRs are ignored
- if the threshold is not numeric, the match is logged as invalid and not alerted
- destination IP matching is based on the returned flow record's destination address

## Usage

From this directory:

```bash
cd /Users/spendleton/git/liveaction-integrations/LiveNX/flow-test
source ../../.venv/bin/activate
sh run.sh
```

You can also run the script directly:

```bash
cd /Users/spendleton/git/liveaction-integrations/LiveNX/flow-test
set -a
source .env
set +a
python3 getflows.py
```

## Output

Console output typically includes:

- the LiveNX result URL
- whether the report is still processing
- how long the report took to become ready
- how many records were processed
- total runtime

The script also writes:

- JSON summary data to `OUTPUT_JSON_FILE`
- log messages to `LOG_FILE_PATH`

Threshold violations are logged in this form:

```text
ALERT src=<src_ip>:<src_port> dst=<dst_ip>:<dst_port> bitrate=<value> exceeded <name> (<threshold>)
```

## Troubleshooting

- A temporary `400 Bad Request` from the LiveNX result URL usually means the report is not ready yet. The script now retries until the report is ready or `REPORT_WAIT_TIMEOUT` is reached.
- `Processing 0 records` means the report completed successfully but returned no matching summary rows.
- The script uses `verify=False` for HTTPS requests, so self-signed certificates will not block the request.
- If the script exits with a timeout, increase `REPORT_WAIT_TIMEOUT` or confirm the LiveNX server can complete the requested report.
