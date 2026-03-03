# Device Observability Report

Builds an HTML device observability table from ClickHouse flow data and LiveNX REST APIs.

## What it reports

The generated table includes:

- Serial number
- Device name
- Device IP
- Manufacturer
- Model
- Receiving Flow Types (AVC/Basic/Medianet)
- Highest Flow Supported
- Are we collecting SNMP metrics
- Are we Receiving Traps
- Are we Receiving Logs
- Are we Receiving Configs

## Data sources

- ClickHouse (`livenx_flowdb.*`) for flow coverage
- LiveNX REST API for:
  - SNMP metric presence (QoS report run endpoint)
  - Device enrichment (name, IP, manufacturer, model)

## Requirements

- Python 3.6 (tested with 3.6.15)
- Access to:
  - ClickHouse native interface (default port `9000` or TLS `9440`)
  - LiveNX API (`https://<LIVENX_HOST>:8093`)

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

If using Python 3.6 and old bundled pip, you may need:

```bash
python -m pip install --upgrade 'pip<22' setuptools wheel
```

## Environment variables

Create a `.env` file in this directory (or pass `--env-file`) with:

```dotenv
CLICKHOUSE_HOST=
CLICKHOUSE_PORT=
CLICKHOUSE_DATABASE=
CLICKHOUSE_USER=
CLICKHOUSE_PASSWORD=
CLICKHOUSE_TLS_ENABLE=
CLICKHOUSE_TLS_SKIP_VERIFY=

LIVENX_HOST=
LIVENX_API_TOKEN=
LIVENX_API_TLS_SKIP_VERIFY=

# Optional (defaults to 9)
LIVENX_SNMP_QOS_REPORT_ID=
```

## Usage

Write report to stdout:

```bash
python device_observability_report.py
```

Write report to a file:

```bash
python device_observability_report.py --lookback-hours 24 --output report.html
```

Enable debug logs:

```bash
python device_observability_report.py --debug --output report.html
```

Use a custom env file:

```bash
python device_observability_report.py --env-file /path/to/.env --output report.html
```

## Notes

- The script uses `livenx_openapi.json` in this folder to choose supported LiveNX endpoints.
- SNMP collection status is determined from LiveNX QoS report metric data, not hardcoded values.
