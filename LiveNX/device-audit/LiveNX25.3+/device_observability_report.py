#!/usr/bin/env python3
"""


Python 3.6.8 compatible.

Changes Made:
  1. Python 3.6.8 compatible — removed 'from __future__ import annotations',
     replaced str|None unions with Optional[str], replaced list[x]/dict[x,y]
     type hints with List[x]/Dict[x,y] from typing module.
  2. Serial # column replaced with Hostname (HostName from livenx_modeldb).
     Serial is still selected internally and used for the SNMP API fallback join.
  3. SNMP metrics API fallback — if ClickHouse has no SNMP data for a device,
     the script calls the LiveNX Device Status report via the synchronous
     GET /api/nx/reports/qos/29/run endpoint (single request, no polling).
     Checks whether CpuAverage (infoElementId=6) is non-null per serial.
     Requires LIVENX_HOST and LIVENX_API_TOKEN to be set; if missing the API
     step is silently skipped and ClickHouse result is used as-is.

Data sources (unchanged from old script):
  - livenx_modeldb.device_dist          (device inventory / spine)
  - livenx_flowdb.*                     (AVC / Basic / Medianet flow)
  - livenx_snmpdb.device_metric_dist    (SNMP metrics — primary check)
  - default.otel_logs                   (traps / syslog / configs)

New environment variables for API fallback:
  LIVENX_HOST                LiveNX server host.
  LIVENX_API_TOKEN           Bearer token (JWT) from the LiveNX UI session
  LIVENX_API_TLS_SKIP_VERIFY true/false — skip TLS cert verification
                             (default: false)
  LIVENX_API_TIMEOUT         HTTP timeout in seconds (default: 60)
"""

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
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from clickhouse_driver import Client as ClickHouseNativeClient
except ImportError:  # pragma: no cover - runtime dependency
    ClickHouseNativeClient = None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def parse_bool(value, default=False):
    # type: (Optional[str], bool) -> bool
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def debug_log(enabled, message):
    # type: (bool, str) -> None
    if enabled:
        sys.stderr.write("[debug] {}\n".format(message))


def mask_secret(value):
    # type: (str) -> str
    if not value:
        return "(empty)"
    if len(value) <= 4:
        return "*" * len(value)
    return "{}{}{}".format(value[:2], "*" * (len(value) - 4), value[-2:])


def load_dotenv(env_path):
    # type: (Path) -> None
    """Load a .env file into os.environ. Existing env vars are never overwritten."""
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
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


# ---------------------------------------------------------------------------
# ClickHouse connectivity
# ---------------------------------------------------------------------------

def resolve_clickhouse_native_target(debug=False):
    # type: (bool) -> Tuple[str, int, bool]
    raw_host = (os.getenv("CLICKHOUSE_HOST") or "localhost").strip()
    _ = os.getenv("CLICKHOUSE_DATABASE", "default")  # kept for settings cohesion
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
        host_name = parsed_host[:close_idx + 1]
        rest = parsed_host[close_idx + 1:]
        if rest.startswith(":"):
            port_text = rest[1:]
    elif ":" in parsed_host and parsed_host.count(":") == 1:
        host_name, port_text = parsed_host.rsplit(":", 1)

    if not port_text:
        port = default_port
    else:
        try:
            port = int(port_text)
        except ValueError:
            raise RuntimeError("Invalid CLICKHOUSE_HOST port: {!r}".format(port_text))

    # Remap HTTP ports to native equivalents if someone copy-pasted an HTTP URL
    if port == 8443:
        debug_log(debug, "mapping port 8443 -> 9440")
        port = 9440
    elif port == 8123:
        debug_log(debug, "mapping port 8123 -> 9000")
        port = 9000

    debug_log(debug, "clickhouse_host_raw={}".format(raw_host))
    debug_log(debug, "clickhouse_host_resolved={}".format(host_name))
    debug_log(debug, "clickhouse_port_resolved={}".format(port))
    debug_log(debug, "clickhouse_tls_enabled={}".format(tls_enabled))
    return host_name.strip("[]"), port, tls_enabled


def clickhouse_query(sql, debug=False):
    # type: (str, bool) -> List[Dict[str, Any]]
    if ClickHouseNativeClient is None:
        raise RuntimeError(
            "Missing dependency 'clickhouse-driver'. "
            "Install with: pip install clickhouse-driver"
        )

    host, port, tls_enabled = resolve_clickhouse_native_target(debug=debug)
    database = os.getenv("CLICKHOUSE_DATABASE", "default")
    username = os.getenv("CLICKHOUSE_USERNAME") or os.getenv("CLICKHOUSE_USER", "default")
    password = os.getenv("CLICKHOUSE_PASSWORD", "")
    connect_timeout = int(os.getenv("CLICKHOUSE_CONNECT_TIMEOUT", "10"))
    timeout = int(os.getenv("CLICKHOUSE_QUERY_TIMEOUT",
                            os.getenv("CLICKHOUSE_HTTP_TIMEOUT", "120")))
    tls_skip_verify = parse_bool(os.getenv("CLICKHOUSE_TLS_SKIP_VERIFY"), default=False)

    debug_log(debug, "clickhouse_protocol=native")
    debug_log(debug, "clickhouse_database={}".format(database))
    debug_log(debug, "clickhouse_username={}".format(username))
    debug_log(debug, "clickhouse_password={}".format(mask_secret(password)))
    debug_log(debug, "clickhouse_connect_timeout_seconds={}".format(connect_timeout))
    debug_log(debug, "clickhouse_query_timeout_seconds={}".format(timeout))
    debug_log(debug, "tls_skip_verify={}".format(tls_skip_verify))
    debug_log(debug, "sql_length_bytes={}".format(len(sql.encode("utf-8"))))
    sql_preview = " ".join(sql.strip().split())
    debug_log(debug, "sql_preview={}".format(sql_preview[:400]))

    # DNS probe (diagnostic only — does not affect execution)
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        resolved_ips = sorted(set(item[4][0] for item in addresses))
        debug_log(debug, "dns_host={} resolved_ips={}".format(host, resolved_ips))
    except OSError as exc:
        debug_log(debug, "dns_lookup_failed host={} port={} error={}".format(
            host, port, exc))

    # TCP probe — gives a fast, clear error if host is unreachable before
    # the driver attempts its own connection
    probe_timeout = max(1, min(connect_timeout, 10))
    probe_start = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=probe_timeout)
        s.close()
        probe_ms = int((time.monotonic() - probe_start) * 1000)
        debug_log(debug, "tcp_probe_ok host={} port={} duration_ms={}".format(
            host, port, probe_ms))
    except OSError as exc:
        probe_ms = int((time.monotonic() - probe_start) * 1000)
        debug_log(debug, "tcp_probe_failed host={} port={} duration_ms={} error={}".format(
            host, port, probe_ms, exc))

    client = ClickHouseNativeClient(
        host=host,
        port=port,
        database=database,
        user=username,
        password=password,
        secure=tls_enabled,
        verify=(not tls_skip_verify),
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
            "ClickHouse native timeout after {} ms to {}:{} "
            "(connect_timeout={}s, query_timeout={}s): {}".format(
                elapsed_ms, host, port, connect_timeout, timeout, exc)
        )
    except ssl.SSLError as exc:
        elapsed_ms = int((time.monotonic() - request_start) * 1000)
        raise RuntimeError(
            "ClickHouse TLS error after {} ms to {}:{}: {}".format(
                elapsed_ms, host, port, exc)
        )
    except Exception as exc:  # pylint: disable=broad-except
        elapsed_ms = int((time.monotonic() - request_start) * 1000)
        raise RuntimeError(
            "ClickHouse native query failed after {} ms to {}:{}: {}".format(
                elapsed_ms, host, port, exc)
        )
    finally:
        try:
            client.disconnect_connection()
        except Exception:  # pylint: disable=broad-except
            pass

    elapsed_ms = int((time.monotonic() - request_start) * 1000)
    debug_log(debug, "native_query_duration_ms={}".format(elapsed_ms))

    columns = [name for name, _ in column_types]
    output = [dict(zip(columns, row)) for row in result_rows]
    debug_log(debug, "row_count={}".format(len(output)))
    return output


# ---------------------------------------------------------------------------
# SQL builder
# ---------------------------------------------------------------------------

def build_sql(lookback_hours):
    # type: (int) -> str
    """
    Returns the main ClickHouse query. Selects one row per device from
    livenx_modeldb.device_dist (the spine) and left-joins presence flags
    from flow, SNMP, traps, logs, and config tables.

    CHANGE: Added `argMax(HostName, Version) AS host_name` to base_devices
    and exposed it in the final SELECT alongside serial_number. serial_number
    is kept internally so the SNMP API fallback can match on it.

    ORDER BY is now host_name for a more human-readable sort order.
    """
    return """
WITH
base_devices AS (
    SELECT
        DeviceSerial AS serial,
        argMax(if(DeviceAddress != '', DeviceAddress, ClientAddress), Version) AS device_ip,
        argMax(VendorName, Version) AS manufacturer,
        argMax(VendorModel, Version) AS model,
        argMax(HostName, Version) AS host_name,
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
    d.serial        AS serial_number,
    d.host_name     AS host_name,
    d.device_ip     AS device_ip,
    d.manufacturer  AS manufacturer,
    d.model         AS model,
    coalesce(avc.has_avc_flow, 0)      AS has_avc_flow,
    coalesce(basic.has_basic_flow, 0)  AS has_basic_flow,
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
LEFT JOIN avc_flow      avc  ON avc.serial       = d.serial
LEFT JOIN basic_flow    basic ON basic.serial     = d.serial
LEFT JOIN medianet_flow medianet ON medianet.serial = d.serial
LEFT JOIN snmp_metrics  snmp ON snmp.serial       = d.serial
LEFT JOIN trap_serial_seen ts  ON ts.serial       = d.serial
LEFT JOIN trap_host_seen   th1 ON th1.host_name   = d.hostname_lc
LEFT JOIN trap_host_seen   th2 ON th2.host_name   = d.system_name_lc
LEFT JOIN trap_ip_seen     ti  ON ti.ip_address   = d.device_ip
LEFT JOIN log_serial_seen  ls  ON ls.serial       = d.serial
LEFT JOIN log_host_seen    lh1 ON lh1.host_name   = d.hostname_lc
LEFT JOIN log_host_seen    lh2 ON lh2.host_name   = d.system_name_lc
LEFT JOIN log_ip_seen      li  ON li.ip_address   = d.device_ip
LEFT JOIN config_serial_seen cs  ON cs.serial     = d.serial
LEFT JOIN config_host_seen   ch1 ON ch1.host_name = d.hostname_lc
LEFT JOIN config_host_seen   ch2 ON ch2.host_name = d.system_name_lc
LEFT JOIN config_ip_seen     ci  ON ci.ip_address = d.device_ip
ORDER BY host_name
""".format(lookback_hours=lookback_hours)


# ---------------------------------------------------------------------------
# LiveNX REST API — SNMP fallback (synchronous /run endpoint)
# ---------------------------------------------------------------------------

def fetch_snmp_from_api(lookback_hours, debug=False):
    # type: (int, bool) -> Dict[str, bool]
    """
    Calls the LiveNX Device Status report via the synchronous /run endpoint:

        GET /api/nx/reports/qos/29/run
            ?startTime=<ms>
            &endTime=<ms>
            &view=detailed
            &businessHours=none

    This is a single blocking HTTP GET that returns the full result immediately
    with no job queue and no polling required.

    Returns a dict mapping device serial (str) -> bool where True means
    CpuAverage (infoElementId=6) is not null, i.e. SNMP CPU/Memory data
    is available for that device in the requested time window.

    Reads from environment:
      LIVENX_HOST                — host with optional https:// prefix
      LIVENX_API_TOKEN           — Bearer JWT token
      LIVENX_API_TLS_SKIP_VERIFY — skip TLS cert check (default: false)
      LIVENX_API_TIMEOUT         — request timeout seconds (default: 60)
    """
    raw_host = (os.getenv("LIVENX_HOST") or "").strip()
    token = (os.getenv("LIVENX_API_TOKEN") or "").strip()
    skip_verify = parse_bool(os.getenv("LIVENX_API_TLS_SKIP_VERIFY"), default=False)
    timeout = int(os.getenv("LIVENX_API_TIMEOUT", "60"))

    if not raw_host:
        raise RuntimeError("LIVENX_HOST is not set")
    if not token:
        raise RuntimeError("LIVENX_API_TOKEN is not set")

    # Normalise host — add https:// if no scheme provided
    if not raw_host.startswith("http://") and not raw_host.startswith("https://"):
        raw_host = "https://" + raw_host

    # Build time range matching the ClickHouse lookback window
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - (lookback_hours * 3600 * 1000)

    # Build the URL with query parameters
    # Path is /v1/reports/qos/29/run (LiveNX native API, not /api/nx/)
    query_params = urllib.parse.urlencode({
        "startTime": start_ms,
        "endTime": now_ms,
        "view": "detailed",
        "businessHours": "none",
        "useFastLane": "false",
    })
    url = "{}/v1/reports/qos/29/run?{}".format(
        raw_host.rstrip("/"), query_params
    )

    debug_log(debug, "api_snmp_url={}".format(url))
    debug_log(debug, "api_snmp_start_ms={} end_ms={}".format(start_ms, now_ms))

    # Build SSL context
    ctx = ssl.create_default_context()
    if skip_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": "Bearer {}".format(token),
            "Accept": "application/json",
        },
        method="GET",
    )

    # Execute the single synchronous request
    request_start = time.monotonic()
    try:
        response = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        resp_body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            "LiveNX API HTTP {} for GET {}: {}".format(exc.code, url, exc.reason)
        )
    except Exception as exc:  # pylint: disable=broad-except
        raise RuntimeError(
            "LiveNX API request failed for GET {}: {}".format(url, exc)
        )

    elapsed_ms = int((time.monotonic() - request_start) * 1000)
    debug_log(debug, "api_snmp_duration_ms={}".format(elapsed_ms))

    # Parse the JSON response
    try:
        data = json.loads(resp_body)
    except ValueError as exc:
        raise RuntimeError("LiveNX API returned non-JSON response: {}".format(exc))

    # Verify the report ran successfully
    state = data.get("state", "")
    if state != "SUCCESS":
        raise RuntimeError(
            "LiveNX API report state={} (expected SUCCESS)".format(state)
        )

    # Navigate to summaryData.
    # Synchronous /run response structure:
    #   data["results"][0]["summary"]["summaryData"] -> list of per-device entries
    # (one less nesting level than the async results endpoint)
    snmp_by_serial = {}  # type: Dict[str, bool]
    try:
        summary_data = data["results"][0]["summary"]["summaryData"]
    except (KeyError, IndexError, TypeError):
        debug_log(debug, "api_snmp_parse_failed: unexpected response structure")
        return snmp_by_serial

    for entry in summary_data:
        serial = None           # infoElementId=2  DeviceSerial
        cpu_avg = None          # infoElementId=6  CpuAverage value
        cpu_field_present = False

        for field in entry.get("data", []):
            elem_id = str(field.get("infoElementId", ""))
            val = field.get("value")
            if elem_id == "2":
                serial = val            # device serial string (join key)
            elif elem_id == "6":
                cpu_avg = val           # integer % or None
                cpu_field_present = True

        if serial is not None:
            # True only when CpuAverage field exists AND has a real value.
            # null means LiveNX has no SNMP CPU/Memory data for this device.
            snmp_by_serial[str(serial)] = (cpu_field_present and cpu_avg is not None)

    debug_log(debug, "api_snmp_devices_parsed={}".format(len(snmp_by_serial)))
    debug_log(debug, "api_snmp_devices_with_data={}".format(
        sum(1 for v in snmp_by_serial.values() if v)
    ))
    return snmp_by_serial


def apply_snmp_api_fallback(raw_rows, lookback_hours, debug=False):
    # type: (List[Dict[str, Any]], int, bool) -> None
    """
    For every device row where ClickHouse has_snmp_metrics == 0, check the
    LiveNX API. If the API reports CPU/Memory data for that serial, override
    has_snmp_metrics to 1 in-place.

    Uses the synchronous GET /api/nx/reports/qos/29/run endpoint — single
    request covering all devices, no polling required.

    This function modifies raw_rows in-place and returns nothing.

    If LIVENX_HOST or LIVENX_API_TOKEN are not set, the API step is skipped
    entirely — the ClickHouse result stands as-is with a warning to stderr.

    If the API call itself fails (network error, timeout, bad token, etc.)
    the error is caught, a warning is printed to stderr, and the script
    continues — the ClickHouse result stands as-is for affected devices.
    """
    # Identify devices that need the API fallback
    no_snmp_rows = [
        r for r in raw_rows
        if int(r.get("has_snmp_metrics", 0) or 0) == 0
    ]

    if not no_snmp_rows:
        debug_log(debug, "api_fallback_skipped: all devices have snmp data in clickhouse")
        return

    debug_log(debug, "api_fallback_candidates={}".format(len(no_snmp_rows)))

    # Check credentials before attempting the call
    if not os.getenv("LIVENX_HOST") or not os.getenv("LIVENX_API_TOKEN"):
        sys.stderr.write(
            "Warning: {} device(s) have no SNMP data in ClickHouse but "
            "LIVENX_HOST / LIVENX_API_TOKEN are not set — skipping API fallback.\n"
            "Set these env vars to enable the API check.\n".format(len(no_snmp_rows))
        )
        return

    try:
        api_snmp = fetch_snmp_from_api(lookback_hours, debug=debug)
    except Exception as exc:  # pylint: disable=broad-except
        sys.stderr.write(
            "Warning: LiveNX API fallback failed — using ClickHouse result only. "
            "Error: {}\n".format(exc)
        )
        return

    # Apply API results back to raw_rows for devices that had no CH data
    override_count = 0
    for row in raw_rows:
        if int(row.get("has_snmp_metrics", 0) or 0) == 0:
            serial = str(row.get("serial_number", "") or "")
            if api_snmp.get(serial, False):
                row["has_snmp_metrics"] = 1   # override: API confirms SNMP data
                override_count += 1

    debug_log(debug, "api_fallback_overrides={}".format(override_count))


# ---------------------------------------------------------------------------
# Row transformation and HTML rendering
# ---------------------------------------------------------------------------

def yes_no(value):
    # type: (Any) -> str
    try:
        return "Yes" if int(value or 0) > 0 else "No"
    except Exception:  # pylint: disable=broad-except
        return "No"


def row_to_output(row):
    # type: (Dict[str, Any]) -> Dict[str, str]
    """
    CHANGE: 'serial_number' key replaced with 'host_name' for display.
    serial_number is no longer included in the output dict because it is
    not rendered in the HTML table.
    """
    has_avc = int(row.get("has_avc_flow", 0) or 0) > 0
    has_basic = int(row.get("has_basic_flow", 0) or 0) > 0
    has_medianet = int(row.get("has_medianet_flow", 0) or 0) > 0

    flow_types = []  # type: List[str]
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
        # CHANGE: host_name replaces serial_number as the first display column
        "host_name": str(row.get("host_name", "") or ""),
        "device_ip": str(row.get("device_ip", "") or ""),
        "manufacturer": str(row.get("manufacturer", "") or ""),
        "model": str(row.get("model", "") or ""),
        "receiving_flow_types": "/".join(flow_types) if flow_types else "None",
        "highest_flow_supported": highest_flow,
        # SNMP metrics: populated from ClickHouse OR API fallback
        "collecting_snmp_metrics": yes_no(row.get("has_snmp_metrics", 0)),
        "receiving_traps": yes_no(row.get("has_traps", 0)),
        "receiving_logs": yes_no(row.get("has_logs", 0)),
        "receiving_configs": yes_no(row.get("has_configs", 0)),
    }


def render_html(rows, lookback_hours):
    # type: (List[Dict[str, str]], int) -> str
    """
    Render the list of output rows as a self-contained HTML table.

    CHANGE: First column header is now 'Device' instead of 'Serial #'.
    """
    generated_at = (
        dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    )

    # CHANGE: ('serial_number', 'Serial #') replaced with ('host_name', 'Hostname')
    headers = [
        ("host_name",              "Device"),
        ("device_ip",              "Device IP"),
        ("manufacturer",           "Manufacturer"),
        ("model",                  "Model"),
        ("receiving_flow_types",   "Receiving Flow Types (AVC/Basic/Medianet)"),
        ("highest_flow_supported", "Highest Flow Supported"),
        ("collecting_snmp_metrics","Are we collecting SNMP metrics"),
        ("receiving_traps",        "Are we Receiving Traps"),
        ("receiving_logs",         "Are we Receiving Logs"),
        ("receiving_configs",      "Are we Receiving Configs"),
    ]

    parts = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '  <meta charset="utf-8"/>',
        '  <meta name="viewport" content="width=device-width, initial-scale=1"/>',
        "  <title>LiveNX Device Observability Report</title>",
        "  <style>",
        "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', "
        "sans-serif; margin: 24px; color: #111827; }",
        "    h1 { margin: 0 0 8px 0; font-size: 20px; }",
        "    .meta { margin: 0 0 16px 0; color: #4b5563; font-size: 14px; }",
        "    table { border-collapse: collapse; width: 100%; font-size: 14px; }",
        "    th, td { border: 1px solid #d1d5db; padding: 8px; text-align: left; "
        "vertical-align: top; }",
        "    th { background: #f3f4f6; position: sticky; top: 0; }",
        "    tr:nth-child(even) { background: #f9fafb; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <h1>LiveNX Device Observability Report</h1>",
        '  <p class="meta">Generated: {} | Lookback window: {} hours</p>'.format(
            html.escape(generated_at), lookback_hours
        ),
    ]

    parts.extend([
        "  <table>",
        "    <thead>",
        "      <tr>",
    ])

    for _, label in headers:
        parts.append("        <th>{}</th>".format(html.escape(label)))

    parts.extend(["      </tr>", "    </thead>", "    <tbody>"])

    for row in rows:
        parts.append("      <tr>")
        for key, _ in headers:
            value = row.get(key, "")
            parts.append("        <td>{}</td>".format(html.escape(str(value))))
        parts.append("      </tr>")

    parts.extend(["    </tbody>", "  </table>", "</body>", "</html>"])
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# CLI and entry point
# ---------------------------------------------------------------------------

def parse_args():
    # type: () -> argparse.Namespace
    parser = argparse.ArgumentParser(
        description="Output an HTML table with per-device LiveNX observability coverage."
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to .env file to load before running (default: .env)",
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=24,
        help="Trailing hours that define 'receiving' for all signals (default: 24)",
    )
    parser.add_argument(
        "--output",
        default="Device_Observability_Report.html",
        help="Output HTML file path (default: 'Device_Observability_Report.html')",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print detailed diagnostics to stderr.",
    )
    return parser.parse_args()


def main():
    # type: () -> int
    args = parse_args()
    if args.lookback_hours <= 0:
        sys.stderr.write("--lookback-hours must be greater than 0\n")
        return 2

    debug_enabled = args.debug or parse_bool(
        os.getenv("DEVICE_OBSERVABILITY_DEBUG"), default=False
    )

    env_path = Path(args.env_file)
    debug_log(debug_enabled, "env_file={} exists={}".format(env_path, env_path.exists()))
    load_dotenv(env_path)

    # ------------------------------------------------------------------
    # Step A — Run ClickHouse query
    # ------------------------------------------------------------------
    sql = build_sql(args.lookback_hours)
    try:
        raw_rows = clickhouse_query(sql, debug=debug_enabled)
    except Exception as exc:  # pylint: disable=broad-except
        sys.stderr.write("Error: {}\n".format(exc))
        return 1

    # ------------------------------------------------------------------
    # Step B — SNMP API fallback for devices with no ClickHouse SNMP data
    # ------------------------------------------------------------------
    no_snmp_count_before = sum(
        1 for r in raw_rows if int(r.get("has_snmp_metrics", 0) or 0) == 0
    )

    if no_snmp_count_before > 0:
        apply_snmp_api_fallback(raw_rows, args.lookback_hours, debug=debug_enabled)

    # ------------------------------------------------------------------
    # Step C — Transform rows and render HTML
    # ------------------------------------------------------------------
    output_rows = [row_to_output(r) for r in raw_rows]
    debug_log(debug_enabled, "render_rows={}".format(len(output_rows)))
    html_text = render_html(output_rows, args.lookback_hours)

    if args.output:
        output_path = Path(args.output)
        if not output_path.parent.exists():
            output_path.parent.mkdir(parents=True)
        output_path.write_text(html_text, encoding="utf-8")
        sys.stdout.write("Wrote {} rows to {}\n".format(len(output_rows), output_path))
    else:
        sys.stdout.write(html_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
