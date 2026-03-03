# Device Observability Report Script

This folder contains `device_observability_report.py`, a Python script that queries ClickHouse and outputs an HTML table with per-device observability coverage.

The report includes:
- Serial #
- Device IP
- Manufacturer
- Model
- Receiving Flow Types (`AVC` / `Basic` / `Medianet`)
- Highest Flow Supported (`AVC > Medianet > Basic`)
- Are we collecting SNMP metrics
- Are we Receiving Traps
- Are we Receiving Logs
- Are we Receiving Configs

## Data Sources Used

The script **does not** query `liveassist` or `network_observability` databases.

It uses:
- `livenx_modeldb.device_dist` (device inventory)
- `livenx_flowdb.avc_raw_dist`
- `livenx_flowdb.basic_raw_dist`
- `livenx_flowdb.medianet_raw_dist`
- `livenx_snmpdb.device_metric_dist`
- `default.otel_logs`

## Requirements

Install Python dependencies from repo root:

```bash
pip install -r ../requirements.txt
```

Or install directly:

```bash
pip install clickhouse-driver lz4 clickhouse-cityhash
```

## Configuration

The script loads environment variables from `.env` by default (override with `--env-file`).

Key variables:
- `CLICKHOUSE_HOST` (native host:port, example `54.145.144.207:9440`)
- `CLICKHOUSE_DATABASE` (default `default`)
- `CLICKHOUSE_USER` or `CLICKHOUSE_USERNAME`
- `CLICKHOUSE_PASSWORD`
- `CLICKHOUSE_TLS_ENABLE` (`true`/`false`)
- `CLICKHOUSE_TLS_SKIP_VERIFY` (`true`/`false`)
- `CLICKHOUSE_CONNECT_TIMEOUT` (seconds, optional)
- `CLICKHOUSE_QUERY_TIMEOUT` (seconds, optional)

Native protocol port defaults:
- TLS enabled: `9440`
- TLS disabled: `9000`

If `CLICKHOUSE_HOST` is set to `:8443` or `:8123`, the script remaps to native ports (`9440` / `9000`).

## Usage

Run from this folder:

```bash
python3 device_observability_report.py --output out.html
```

Print HTML to stdout:

```bash
python3 device_observability_report.py
```

Change lookback window (used for "receiving" checks):

```bash
python3 device_observability_report.py --lookback-hours 168 --output out.html
```

Enable debug diagnostics:

```bash
python3 device_observability_report.py --debug
```

Or:

```bash
DEVICE_OBSERVABILITY_DEBUG=1 python3 device_observability_report.py
```

## Debug Output

With debug enabled, the script logs:
- Resolved native ClickHouse host/port and TLS settings
- DNS resolution and TCP probe results
- Query timing
- Row counts
- Detailed timeout/connection errors
