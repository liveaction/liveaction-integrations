#!/usr/bin/env python3
"""
Build an HTML device observability table from ClickHouse data.

The script intentionally avoids `liveassist` and `network_observability`
databases and uses:
  - livenx_modeldb.device_dist
  - livenx_flowdb.* flow tables
  - livenx_snmpdb.device_metric_dist
  - default.otel_logs
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

try:
    from clickhouse_driver import Client as ClickHouseNativeClient
except ImportError:  # pragma: no cover - runtime dependency
    ClickHouseNativeClient = None


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def debug_log(enabled: bool, message: str) -> None:
    if enabled:
        print(f"[debug] {message}", file=sys.stderr)


def mask_secret(value: str) -> str:
    if not value:
        return "(empty)"
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def load_dotenv(env_path: Path) -> None:
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        quoted = (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        )
        if quoted and len(value) >= 2:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()

        if key not in os.environ:
            os.environ[key] = value


def resolve_clickhouse_native_target(debug: bool = False) -> tuple[str, int, bool]:
    raw_host = (os.getenv("CLICKHOUSE_HOST") or "localhost").strip()
    database = os.getenv("CLICKHOUSE_DATABASE", "default")
    _ = database  # consumed by caller; this keeps related settings together
    tls_enabled = parse_bool(os.getenv("CLICKHOUSE_TLS_ENABLE"), default=False)
    default_port = 9440 if tls_enabled else 9000

    parsed_host = raw_host
    if raw_host.startswith("http://") or raw_host.startswith("https://"):
        parsed = urllib.parse.urlparse(raw_host)
        parsed_host = parsed.netloc or parsed.path

    host_name = parsed_host
    port_text = ""

    if parsed_host.startswith("[") and "]" in parsed_host:
        close_idx = parsed_host.find("]")
        host_name = parsed_host[: close_idx + 1]
        rest = parsed_host[close_idx + 1 :]
        if rest.startswith(":"):
            port_text = rest[1:]
    elif ":" in parsed_host and parsed_host.count(":") == 1:
        host_name, port_text = parsed_host.rsplit(":", 1)

    if not port_text:
        port = default_port
    else:
        try:
            port = int(port_text)
        except ValueError as exc:
            raise RuntimeError(f"Invalid CLICKHOUSE_HOST port: {port_text!r}") from exc

    # If a prior HTTP endpoint/port was used, force native-equivalent port.
    if port == 8443:
        debug_log(debug, "mapping native port 8443 -> 9440")
        port = 9440
    elif port == 8123:
        debug_log(debug, "mapping native port 8123 -> 9000")
        port = 9000

    debug_log(debug, f"clickhouse_host_raw={raw_host}")
    debug_log(debug, f"clickhouse_host_resolved={host_name}")
    debug_log(debug, f"clickhouse_port_resolved={port}")
    debug_log(debug, f"clickhouse_tls_enabled={tls_enabled}")
    return host_name.strip("[]"), port, tls_enabled


def clickhouse_query(sql: str, debug: bool = False) -> list[dict[str, Any]]:
    if ClickHouseNativeClient is None:
        raise RuntimeError(
            "Missing dependency 'clickhouse-driver'. Install with: pip install clickhouse-driver"
        )

    host, port, tls_enabled = resolve_clickhouse_native_target(debug=debug)
    database = os.getenv("CLICKHOUSE_DATABASE", "default")
    username = os.getenv("CLICKHOUSE_USERNAME") or os.getenv("CLICKHOUSE_USER", "default")
    password = os.getenv("CLICKHOUSE_PASSWORD", "")
    connect_timeout = int(os.getenv("CLICKHOUSE_CONNECT_TIMEOUT", "10"))
    timeout = int(os.getenv("CLICKHOUSE_QUERY_TIMEOUT", os.getenv("CLICKHOUSE_HTTP_TIMEOUT", "120")))

    tls_skip_verify = parse_bool(os.getenv("CLICKHOUSE_TLS_SKIP_VERIFY"), default=False)

    debug_log(debug, "clickhouse_protocol=native")
    debug_log(debug, f"clickhouse_database={database}")
    debug_log(debug, f"clickhouse_username={username}")
    debug_log(debug, f"clickhouse_password={mask_secret(password)}")
    debug_log(debug, f"clickhouse_connect_timeout_seconds={connect_timeout}")
    debug_log(debug, f"clickhouse_query_timeout_seconds={timeout}")
    debug_log(debug, f"tls_skip_verify={tls_skip_verify}")
    debug_log(debug, f"sql_length_bytes={len(sql.encode('utf-8'))}")
    sql_preview = " ".join(sql.strip().split())
    debug_log(debug, f"sql_preview={sql_preview[:400]}")

    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        resolved_ips = sorted({item[4][0] for item in addresses})
        debug_log(debug, f"dns_host={host} resolved_ips={resolved_ips}")
    except OSError as exc:
        debug_log(debug, f"dns_lookup_failed host={host} port={port} error={exc}")

    probe_timeout = max(1, min(connect_timeout, 10))
    probe_start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=probe_timeout):
            probe_ms = int((time.monotonic() - probe_start) * 1000)
            debug_log(debug, f"tcp_probe_ok host={host} port={port} duration_ms={probe_ms}")
    except OSError as exc:
        probe_ms = int((time.monotonic() - probe_start) * 1000)
        debug_log(
            debug,
            f"tcp_probe_failed host={host} port={port} duration_ms={probe_ms} error={exc}",
        )

    client = ClickHouseNativeClient(
        host=host,
        port=port,
        database=database,
        user=username,
        password=password,
        secure=tls_enabled,
        verify=not tls_skip_verify,
        connect_timeout=connect_timeout,
        send_receive_timeout=timeout,
        sync_request_timeout=timeout,
        compression=True,
    )

    request_start = time.monotonic()
    try:
        result_rows, column_types = client.execute(sql, with_column_types=True)
    except (TimeoutError, socket.timeout) as exc:
        elapsed_ms = int((time.monotonic() - request_start) * 1000)
        raise RuntimeError(
            f"ClickHouse native timeout after {elapsed_ms} ms to {host}:{port} "
            f"(connect_timeout={connect_timeout}s, query_timeout={timeout}s): {exc}"
        ) from exc
    except ssl.SSLError as exc:
        elapsed_ms = int((time.monotonic() - request_start) * 1000)
        raise RuntimeError(
            f"ClickHouse TLS error after {elapsed_ms} ms to {host}:{port}: {exc}"
        ) from exc
    except Exception as exc:  # pylint: disable=broad-except
        elapsed_ms = int((time.monotonic() - request_start) * 1000)
        raise RuntimeError(
            f"ClickHouse native query failed after {elapsed_ms} ms to {host}:{port}: {exc}"
        ) from exc
    finally:
        try:
            client.disconnect_connection()
        except Exception:  # pylint: disable=broad-except
            pass

    elapsed_ms = int((time.monotonic() - request_start) * 1000)
    debug_log(debug, f"native_query_duration_ms={elapsed_ms}")

    columns = [name for name, _ in column_types]
    output = [dict(zip(columns, row)) for row in result_rows]
    debug_log(debug, f"row_count={len(output)}")
    return output


def build_sql(lookback_hours: int) -> str:
    return f"""
WITH
base_devices AS (
    SELECT
        DeviceSerial AS serial,
        argMax(if(DeviceAddress != '', DeviceAddress, ClientAddress), Version) AS device_ip,
        argMax(VendorName, Version) AS manufacturer,
        argMax(VendorModel, Version) AS model,
        lower(argMax(HostName, Version)) AS hostname_lc,
        lower(argMax(SystemName, Version)) AS system_name_lc
    FROM livenx_modeldb.device_dist
    WHERE IsDeleted = false
      AND DeviceSerial != ''
    GROUP BY DeviceSerial
),
avc_flow AS (
    SELECT DeviceSerial AS serial, 1 AS has_avc_flow
    FROM livenx_flowdb.avc_entity_app_5m_dist
    WHERE time >= now() - INTERVAL {lookback_hours} HOUR
    GROUP BY serial
),
basic_flow AS (
    SELECT DeviceSerial AS serial, 1 AS has_basic_flow
    FROM livenx_flowdb.basic_entity_5m_dist
    WHERE time >= now() - INTERVAL {lookback_hours} HOUR
    GROUP BY serial
),
medianet_flow AS (
    SELECT DeviceSerial AS serial, 1 AS has_medianet_flow
    FROM livenx_flowdb.medianet_entity_app_5m_dist
    WHERE time >= now() - INTERVAL {lookback_hours} HOUR
    GROUP BY serial
),
snmp_metrics AS (
    SELECT toString(DeviceId) AS serial, 1 AS has_snmp_metrics
    FROM livenx_snmpdb.device_metric_dist
    WHERE time >= now() - INTERVAL {lookback_hours} HOUR
    GROUP BY serial
),
trap_events AS (
    SELECT
        nullIf(coalesce(
            nullIf(toString(LogAttributes['deviceSerial']), ''),
            nullIf(toString(LogAttributes['sinfo.DEVICE.deviceSerial']), '')
        ), '') AS serial,
        nullIf(lower(coalesce(
            nullIf(toString(ResourceAttributes['host.name']), ''),
            nullIf(toString(LogAttributes['host.name']), ''),
            nullIf(toString(LogAttributes['sinfo.DEVICE.deviceName']), '')
        )), '') AS host_name,
        nullIf(coalesce(
            nullIf(toString(ResourceAttributes['source.ip']), ''),
            nullIf(toString(ResourceAttributes['host.ip']), ''),
            nullIf(toString(LogAttributes['host.ip']), '')
        ), '') AS ip_address
    FROM default.otel_logs
    WHERE TimestampTime >= now() - INTERVAL {lookback_hours} HOUR
      AND ServiceName = 'snmptrapreceiver'
),
trap_serial_seen AS (
    SELECT serial, 1 AS seen FROM trap_events WHERE serial IS NOT NULL GROUP BY serial
),
trap_host_seen AS (
    SELECT host_name, 1 AS seen FROM trap_events WHERE host_name IS NOT NULL GROUP BY host_name
),
trap_ip_seen AS (
    SELECT ip_address, 1 AS seen FROM trap_events WHERE ip_address IS NOT NULL GROUP BY ip_address
),
log_events AS (
    SELECT
        nullIf(coalesce(
            nullIf(toString(LogAttributes['deviceSerial']), ''),
            nullIf(toString(LogAttributes['sinfo.DEVICE.deviceSerial']), '')
        ), '') AS serial,
        nullIf(lower(coalesce(
            nullIf(toString(ResourceAttributes['host.name']), ''),
            nullIf(toString(LogAttributes['host.name']), ''),
            nullIf(toString(LogAttributes['sinfo.DEVICE.deviceName']), '')
        )), '') AS host_name,
        nullIf(coalesce(
            nullIf(toString(ResourceAttributes['source.ip']), ''),
            nullIf(toString(ResourceAttributes['host.ip']), ''),
            nullIf(toString(LogAttributes['host.ip']), '')
        ), '') AS ip_address
    FROM default.otel_logs
    WHERE TimestampTime >= now() - INTERVAL {lookback_hours} HOUR
      AND Body LIKE '%SYS-%'
),
log_serial_seen AS (
    SELECT serial, 1 AS seen FROM log_events WHERE serial IS NOT NULL GROUP BY serial
),
log_host_seen AS (
    SELECT host_name, 1 AS seen FROM log_events WHERE host_name IS NOT NULL GROUP BY host_name
),
log_ip_seen AS (
    SELECT ip_address, 1 AS seen FROM log_events WHERE ip_address IS NOT NULL GROUP BY ip_address
),
config_events AS (
    SELECT
        nullIf(coalesce(
            nullIf(toString(LogAttributes['deviceSerial']), ''),
            nullIf(toString(LogAttributes['sinfo.DEVICE.deviceSerial']), '')
        ), '') AS serial,
        nullIf(lower(coalesce(
            nullIf(toString(ResourceAttributes['host.name']), ''),
            nullIf(toString(LogAttributes['host.name']), ''),
            nullIf(toString(LogAttributes['sinfo.DEVICE.deviceName']), '')
        )), '') AS host_name,
        nullIf(coalesce(
            nullIf(toString(ResourceAttributes['source.ip']), ''),
            nullIf(toString(ResourceAttributes['host.ip']), ''),
            nullIf(toString(LogAttributes['host.ip']), '')
        ), '') AS ip_address
    FROM default.otel_logs
    WHERE TimestampTime >= now() - INTERVAL {lookback_hours} HOUR
      AND ServiceName IN ('routerconfig', 'recommendrouterconfig')
),
config_serial_seen AS (
    SELECT serial, 1 AS seen FROM config_events WHERE serial IS NOT NULL GROUP BY serial
),
config_host_seen AS (
    SELECT host_name, 1 AS seen FROM config_events WHERE host_name IS NOT NULL GROUP BY host_name
),
config_ip_seen AS (
    SELECT ip_address, 1 AS seen FROM config_events WHERE ip_address IS NOT NULL GROUP BY ip_address
)
SELECT
    d.serial AS serial_number,
    d.device_ip AS device_ip,
    d.manufacturer AS manufacturer,
    d.model AS model,
    coalesce(avc.has_avc_flow, 0) AS has_avc_flow,
    coalesce(basic.has_basic_flow, 0) AS has_basic_flow,
    coalesce(medianet.has_medianet_flow, 0) AS has_medianet_flow,
    coalesce(snmp.has_snmp_metrics, 0) AS has_snmp_metrics,
    greatest(
        coalesce(ts.seen, 0),
        coalesce(th1.seen, 0),
        coalesce(th2.seen, 0),
        coalesce(ti.seen, 0)
    ) AS has_traps,
    greatest(
        coalesce(ls.seen, 0),
        coalesce(lh1.seen, 0),
        coalesce(lh2.seen, 0),
        coalesce(li.seen, 0)
    ) AS has_logs,
    greatest(
        coalesce(cs.seen, 0),
        coalesce(ch1.seen, 0),
        coalesce(ch2.seen, 0),
        coalesce(ci.seen, 0)
    ) AS has_configs
FROM base_devices d
LEFT JOIN avc_flow avc ON avc.serial = d.serial
LEFT JOIN basic_flow basic ON basic.serial = d.serial
LEFT JOIN medianet_flow medianet ON medianet.serial = d.serial
LEFT JOIN snmp_metrics snmp ON snmp.serial = d.serial
LEFT JOIN trap_serial_seen ts ON ts.serial = d.serial
LEFT JOIN trap_host_seen th1 ON th1.host_name = d.hostname_lc
LEFT JOIN trap_host_seen th2 ON th2.host_name = d.system_name_lc
LEFT JOIN trap_ip_seen ti ON ti.ip_address = d.device_ip
LEFT JOIN log_serial_seen ls ON ls.serial = d.serial
LEFT JOIN log_host_seen lh1 ON lh1.host_name = d.hostname_lc
LEFT JOIN log_host_seen lh2 ON lh2.host_name = d.system_name_lc
LEFT JOIN log_ip_seen li ON li.ip_address = d.device_ip
LEFT JOIN config_serial_seen cs ON cs.serial = d.serial
LEFT JOIN config_host_seen ch1 ON ch1.host_name = d.hostname_lc
LEFT JOIN config_host_seen ch2 ON ch2.host_name = d.system_name_lc
LEFT JOIN config_ip_seen ci ON ci.ip_address = d.device_ip
ORDER BY serial_number
"""


def yes_no(value: Any) -> str:
    return "Yes" if int(value or 0) > 0 else "No"


def row_to_output(row: dict[str, Any]) -> dict[str, str]:
    has_avc = int(row.get("has_avc_flow", 0) or 0) > 0
    has_basic = int(row.get("has_basic_flow", 0) or 0) > 0
    has_medianet = int(row.get("has_medianet_flow", 0) or 0) > 0

    flow_types: list[str] = []
    if has_avc:
        flow_types.append("AVC")
    if has_basic:
        flow_types.append("Basic")
    if has_medianet:
        flow_types.append("Medianet")

    if has_avc:
        highest_flow = "AVC"
    elif has_medianet:
        highest_flow = "Medianet"
    elif has_basic:
        highest_flow = "Basic"
    else:
        highest_flow = "None"

    return {
        "serial_number": str(row.get("serial_number", "") or ""),
        "device_ip": str(row.get("device_ip", "") or ""),
        "manufacturer": str(row.get("manufacturer", "") or ""),
        "model": str(row.get("model", "") or ""),
        "receiving_flow_types": "/".join(flow_types) if flow_types else "None",
        "highest_flow_supported": highest_flow,
        "collecting_snmp_metrics": yes_no(row.get("has_snmp_metrics", 0)),
        "receiving_traps": yes_no(row.get("has_traps", 0)),
        "receiving_logs": yes_no(row.get("has_logs", 0)),
        "receiving_configs": yes_no(row.get("has_configs", 0)),
    }


def render_html(rows: list[dict[str, str]], lookback_hours: int) -> str:
    generated_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    headers = [
        ("serial_number", "Serial #"),
        ("device_ip", "Device IP"),
        ("manufacturer", "Manufacturer"),
        ("model", "Model"),
        ("receiving_flow_types", "Receiving Flow Types (AVC/Basic/Medianet)"),
        ("highest_flow_supported", "Highest Flow Supported"),
        ("collecting_snmp_metrics", "Are we collecting SNMP metrics"),
        ("receiving_traps", "Are we Receiving Traps"),
        ("receiving_logs", "Are we Receiving Logs"),
        ("receiving_configs", "Are we Receiving Configs"),
    ]

    parts: list[str] = [
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head>",
        "  <meta charset=\"utf-8\"/>",
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>",
        "  <title>LiveNX Device Observability Report</title>",
        "  <style>",
        "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 24px; color: #111827; }",
        "    h1 { margin: 0 0 8px 0; font-size: 20px; }",
        "    .meta { margin: 0 0 16px 0; color: #4b5563; font-size: 14px; }",
        "    table { border-collapse: collapse; width: 100%; font-size: 14px; }",
        "    th, td { border: 1px solid #d1d5db; padding: 8px; text-align: left; vertical-align: top; }",
        "    th { background: #f3f4f6; position: sticky; top: 0; }",
        "    tr:nth-child(even) { background: #f9fafb; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <h1>LiveNX Device Observability Report</h1>",
        f"  <p class=\"meta\">Generated: {html.escape(generated_at)} | Lookback window: {lookback_hours} hours</p>",
        "  <table>",
        "    <thead>",
        "      <tr>",
    ]

    for _, label in headers:
        parts.append(f"        <th>{html.escape(label)}</th>")

    parts.extend(
        [
            "      </tr>",
            "    </thead>",
            "    <tbody>",
        ]
    )

    for row in rows:
        parts.append("      <tr>")
        for key, _ in headers:
            value = row.get(key, "")
            parts.append(f"        <td>{html.escape(str(value))}</td>")
        parts.append("      </tr>")

    parts.extend(
        [
            "    </tbody>",
            "  </table>",
            "</body>",
            "</html>",
        ]
    )
    return "\n".join(parts)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Output an HTML table with per-device LiveNX observability coverage."
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to env file to load before querying ClickHouse (default: .env)",
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=24,
        help="How many trailing hours define 'receiving' signals (default: 24)",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Output HTML file path. If omitted, HTML is written to stdout.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print detailed diagnostics to stderr (endpoint resolution, timing, and errors).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.lookback_hours <= 0:
        print("--lookback-hours must be greater than 0", file=sys.stderr)
        return 2

    debug_enabled = args.debug or parse_bool(os.getenv("DEVICE_OBSERVABILITY_DEBUG"), default=False)
    env_path = Path(args.env_file)
    debug_log(debug_enabled, f"env_file={env_path} exists={env_path.exists()}")
    load_dotenv(env_path)
    sql = build_sql(args.lookback_hours)

    try:
        raw_rows = clickhouse_query(sql, debug=debug_enabled)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    output_rows = [row_to_output(r) for r in raw_rows]
    debug_log(debug_enabled, f"render_rows={len(output_rows)}")
    html_text = render_html(output_rows, args.lookback_hours)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_text, encoding="utf-8")
        print(f"Wrote {len(output_rows)} rows to {output_path}")
    else:
        sys.stdout.write(html_text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
