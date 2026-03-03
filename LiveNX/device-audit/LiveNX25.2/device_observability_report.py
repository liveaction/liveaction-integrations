#!/usr/bin/env python3
"""
Build an HTML device observability table from ClickHouse data.

Flow coverage comes from livenx_flowdb.* tables.
SNMP coverage comes from LiveNX report endpoints (QoS report run), by matching device serials.
Device details (name/IP/manufacturer/model) come from LiveNX device REST endpoints.

The script intentionally avoids `liveassist` and `network_observability` databases and uses:
  - livenx_flowdb.* flow tables

No livenx_modeldb.
No livenx_snmpdb.
No default.otel_logs.

Environment variables (match your .env):
  CLICKHOUSE_HOST
  CLICKHOUSE_PORT
  CLICKHOUSE_DATABASE
  CLICKHOUSE_USER
  CLICKHOUSE_PASSWORD
  CLICKHOUSE_TLS_ENABLE
  CLICKHOUSE_TLS_SKIP_VERIFY
  LIVENX_API_TOKEN
  LIVENX_HOST
  LIVENX_API_TLS_SKIP_VERIFY
  LIVENX_SNMP_QOS_REPORT_ID (optional, default: 9)
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
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from clickhouse_driver import Client as ClickHouseNativeClient
except ImportError:  # pragma: no cover
    ClickHouseNativeClient = None

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


# ------------------ utilities ------------------

def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def debug_log(enabled: bool, message: str) -> None:
    if enabled:
        sys.stderr.write(f"[debug] {message}\n")


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


# ------------------ ClickHouse native client ------------------

def resolve_clickhouse_native_target(debug: bool = False) -> Tuple[str, int, bool]:
    raw_host = (os.getenv("CLICKHOUSE_HOST") or "localhost").strip()
    tls_enabled = parse_bool(os.getenv("CLICKHOUSE_TLS_ENABLE"), default=False)

    # If CLICKHOUSE_PORT is set, it wins.
    port_env = (os.getenv("CLICKHOUSE_PORT") or "").strip()
    default_port = 9440 if tls_enabled else 9000

    parsed_host = raw_host
    if raw_host.startswith("http://") or raw_host.startswith("https://"):
        parsed = urllib.parse.urlparse(raw_host)
        parsed_host = parsed.netloc or parsed.path

    # Strip any accidental credentials (user:pass@host:port)
    if "@" in parsed_host:
        parsed_host = parsed_host.split("@", 1)[1]

    host_name = parsed_host
    port_text = ""

    # IPv6 in brackets: [::1]:9000
    if parsed_host.startswith("[") and "]" in parsed_host:
        close_idx = parsed_host.find("]")
        host_name = parsed_host[1:close_idx]
        rest = parsed_host[close_idx + 1 :]
        if rest.startswith(":"):
            port_text = rest[1:]
    else:
        # only treat ":" as port separator if there's exactly one ":" (avoid IPv6)
        if ":" in parsed_host and parsed_host.count(":") == 1:
            host_name, port_text = parsed_host.rsplit(":", 1)

    # Decide port: CLICKHOUSE_PORT > host:port > default
    if port_env:
        try:
            port = int(port_env)
        except ValueError as exc:
            raise RuntimeError(f"Invalid CLICKHOUSE_PORT: {port_env!r}") from exc
    elif port_text:
        try:
            port = int(port_text)
        except ValueError as exc:
            raise RuntimeError(f"Invalid CLICKHOUSE_HOST port: {port_text!r}") from exc
    else:
        port = default_port

    debug_log(debug, f"clickhouse_host_raw={raw_host}")
    debug_log(debug, f"clickhouse_host_resolved={host_name}")
    debug_log(debug, f"clickhouse_port_resolved={port} (CLICKHOUSE_PORT={'set' if port_env else 'unset'})")
    debug_log(debug, f"clickhouse_tls_enabled={tls_enabled}")

    return host_name, port, tls_enabled


def clickhouse_query(sql: str, debug: bool = False) -> List[Dict[str, Any]]:
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

    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        resolved_ips = sorted({item[4][0] for item in addresses})
        debug_log(debug, f"dns_host={host} resolved_ips={resolved_ips}")
    except OSError as exc:
        debug_log(debug, f"dns_lookup_failed host={host} port={port} error={exc}")

    probe_timeout = max(1, min(connect_timeout, 10))
    probe_start = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=probe_timeout)
        s.close()
        probe_ms = int((time.monotonic() - probe_start) * 1000)
        debug_log(debug, f"tcp_probe_ok host={host} port={port} duration_ms={probe_ms}")
    except OSError as exc:
        probe_ms = int((time.monotonic() - probe_start) * 1000)
        debug_log(debug, f"tcp_probe_failed host={host} port={port} duration_ms={probe_ms} error={exc}")

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
            f"ClickHouse native timeout after {elapsed_ms} ms to {host}:{port} "
            f"(connect_timeout={connect_timeout}s, query_timeout={timeout}s): {exc}"
        ) from exc
    except ssl.SSLError as exc:
        elapsed_ms = int((time.monotonic() - request_start) * 1000)
        raise RuntimeError(f"ClickHouse TLS error after {elapsed_ms} ms to {host}:{port}: {exc}") from exc
    except Exception as exc:  # pylint: disable=broad-except
        elapsed_ms = int((time.monotonic() - request_start) * 1000)
        raise RuntimeError(
            f"ClickHouse native query failed after {elapsed_ms} ms to {host}:{port}: {exc}"
        ) from exc
    finally:
        # Correct disconnect for clickhouse-driver
        try:
            client.disconnect()
        except Exception:
            pass

    elapsed_ms = int((time.monotonic() - request_start) * 1000)
    debug_log(debug, f"native_query_duration_ms={elapsed_ms}")

    columns = [name for (name, _) in column_types]
    output = [dict(zip(columns, row)) for row in result_rows]
    debug_log(debug, f"row_count={len(output)}")
    return output


def build_sql(lookback_hours: int) -> str:
    return f"""
WITH
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
device_keys AS (
    SELECT serial FROM avc_flow
    UNION DISTINCT
    SELECT serial FROM basic_flow
    UNION DISTINCT
    SELECT serial FROM medianet_flow
)
SELECT
    d.serial AS serial_number,
    '' AS device_ip,
    '' AS manufacturer,
    '' AS model,
    coalesce(avc.has_avc_flow, 0) AS has_avc_flow,
    coalesce(basic.has_basic_flow, 0) AS has_basic_flow,
    coalesce(medianet.has_medianet_flow, 0) AS has_medianet_flow,
    0 AS has_snmp_metrics,
    0 AS has_traps,
    0 AS has_logs,
    0 AS has_configs
FROM device_keys d
LEFT JOIN avc_flow avc ON avc.serial = d.serial
LEFT JOIN basic_flow basic ON basic.serial = d.serial
LEFT JOIN medianet_flow medianet ON medianet.serial = d.serial
ORDER BY serial_number
"""


# ------------------ LiveNX REST (report + device search) ------------------

OPENAPI_SPEC_FILE = Path(__file__).with_name("livenx_openapi.json")
OPENAPI_QOS_RUN_PATH = "/reports/qos/run"
OPENAPI_QOS_RUN_BY_ID_PATH = "/reports/qos/{id}/run"
OPENAPI_DEVICES_PATH = "/devices"
DEVICES_LIST_PATH = "/v1/devices"
DEVICES_SEARCH_PATH = "/v1/devices/search"


def livenx_base_url() -> str:
    host = (os.getenv("LIVENX_HOST") or "").strip()
    if not host:
        raise ValueError("Missing LIVENX_HOST in env.")
    return f"https://{host}:8093"


def livenx_token() -> str:
    token = (os.getenv("LIVENX_API_TOKEN") or "").strip()
    if not token:
        raise ValueError("Missing LIVENX_API_TOKEN in env.")
    return token


def livenx_verify_tls() -> bool:
    skip = parse_bool(os.getenv("LIVENX_API_TLS_SKIP_VERIFY"), default=False)
    return not skip


def load_openapi_paths() -> Set[str]:
    try:
        with OPENAPI_SPEC_FILE.open("r", encoding="utf-8") as handle:
            spec = json.load(handle)
    except Exception:
        return set()
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return set()
    return set(paths.keys())


def run_qos_report_for_snmp_metrics(
    lookback_hours: int,
    timeout_s: int = 60,
    debug: bool = False,
) -> Dict[str, Any]:
    if requests is None:
        raise RuntimeError("Missing dependency 'requests'. Install with: pip install requests")

    openapi_paths = load_openapi_paths()
    report_id = str(os.getenv("LIVENX_SNMP_QOS_REPORT_ID", "9")).strip() or "9"
    end_time_ms = int(time.time() * 1000)
    start_time_ms = end_time_ms - max(1, lookback_hours) * 3600 * 1000

    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {livenx_token()}",
    }

    if OPENAPI_QOS_RUN_PATH in openapi_paths:
        url = f"{livenx_base_url()}/v1{OPENAPI_QOS_RUN_PATH}"
        body = {
            "view": "detailed",
            "requests": [
                {
                    "reportId": report_id,
                    "startTime": start_time_ms,
                    "endTime": end_time_ms,
                    "businessHours": "none",
                }
            ],
        }
        debug_log(debug, "snmp_metrics_query=POST /v1/reports/qos/run")
        resp = requests.post(
            url,
            headers=headers,
            json=body,
            verify=livenx_verify_tls(),
            timeout=timeout_s,
        )
    elif OPENAPI_QOS_RUN_BY_ID_PATH in openapi_paths:
        url = f"{livenx_base_url()}/v1{OPENAPI_QOS_RUN_BY_ID_PATH.format(id=urllib.parse.quote(report_id))}"
        params = {
            "startTime": start_time_ms,
            "endTime": end_time_ms,
        }
        debug_log(debug, "snmp_metrics_query=GET /v1/reports/qos/{id}/run")
        resp = requests.get(
            url,
            headers=headers,
            params=params,
            verify=livenx_verify_tls(),
            timeout=timeout_s,
        )
    else:
        raise RuntimeError(
            "Could not find /reports/qos/run or /reports/qos/{id}/run in livenx_openapi.json"
        )

    resp.raise_for_status()
    return resp.json()


def _is_present_metric_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True


def extract_snmp_metric_serials(report_json: Dict[str, Any]) -> Set[str]:
    """
    Parse QoS report responses and return device serials where at least one
    metric field has a non-empty value in summaryData.
    """
    serials: Set[str] = set()

    results: List[Dict[str, Any]] = []
    responses = report_json.get("responses")
    if isinstance(responses, list):
        for response in responses:
            response_results = response.get("results")
            if isinstance(response_results, list):
                results.extend([r for r in response_results if isinstance(r, dict)])
    else:
        response_results = report_json.get("results")
        if isinstance(response_results, list):
            results.extend([r for r in response_results if isinstance(r, dict)])

    for result in results:
        report_keys = result.get("reportKeys") or []
        key_field_ids: Set[str] = set()
        serial_field_ids: Set[str] = set()
        for key in report_keys:
            field_id = str(key.get("id") or "").strip()
            if not field_id:
                continue
            key_field_ids.add(field_id)
            if str(key.get("name") or "").strip().lower() == "deviceserial":
                serial_field_ids.add(field_id)

        summary = result.get("summary") or {}
        fields = summary.get("fields") or []
        metric_field_ids: Set[str] = set()
        for field in fields:
            field_id = str(field.get("id") or "").strip()
            if not field_id:
                continue
            field_name = str(field.get("name") or "").strip().lower()
            field_label = str(field.get("label") or field.get("defaultLabel") or "").strip().lower()
            if field_name == "deviceserial" or "device serial" in field_label:
                serial_field_ids.add(field_id)
            if field_id not in key_field_ids:
                metric_field_ids.add(field_id)

        # If we cannot separate key fields, assume first key field is serial when present.
        if not serial_field_ids and len(key_field_ids) == 1:
            serial_field_ids = set(key_field_ids)

        for row in summary.get("summaryData") or []:
            data = row.get("data") or []
            by_id = {}
            for datum in data:
                field_id = str(datum.get("infoElementId") or "").strip()
                if field_id:
                    by_id[field_id] = datum.get("value")

            serial_value = ""
            for serial_field_id in serial_field_ids:
                candidate = by_id.get(serial_field_id)
                if isinstance(candidate, str):
                    candidate = candidate.strip()
                else:
                    candidate = str(candidate or "").strip()
                if candidate:
                    serial_value = candidate
                    break

            if not serial_value:
                key_value = row.get("key")
                if isinstance(key_value, str) and key_value.strip():
                    serial_value = key_value.strip()

            if not serial_value:
                continue

            has_metric_data = False
            for metric_field_id in metric_field_ids:
                if _is_present_metric_value(by_id.get(metric_field_id)):
                    has_metric_data = True
                    break

            if has_metric_data:
                serials.add(serial_value)

    return serials


def fetch_snmp_serials_from_report(lookback_hours: int, debug: bool = False) -> Set[str]:
    """
    Best-effort: returns set of device serials with SNMP metric data in QoS report
    summary rows over the lookback window.
    If anything fails, returns empty set (meaning SNMP=No for all rows).
    """
    try:
        report = run_qos_report_for_snmp_metrics(lookback_hours=lookback_hours, debug=debug)
        serials = extract_snmp_metric_serials(report)
        debug_log(debug, f"snmp_metric_serials={len(serials)}")
        return serials
    except Exception as exc:
        debug_log(debug, f"snmp_metrics_query_failed error={exc}")
        return set()


def _dedupe_serials(serials: List[str]) -> List[str]:
    seen: Set[str] = set()
    uniq: List[str] = []
    for s in serials:
        s = (s or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        uniq.append(s)
    return uniq


def fetch_device_info_from_search_by_serials(
    serials: List[str],
    timeout_s: int = 60,
) -> Dict[str, Dict[str, Any]]:
    """
    OpenAPI-backed fallback:
      POST /v1/devices/search
      body: { "deviceSerials": ["...","..."] }
      resp: { "devices": [ { "serial": "...", ... }, ... ] }
    """
    uniq = _dedupe_serials(serials)
    if not uniq:
        return {}

    url = f"{livenx_base_url()}{DEVICES_SEARCH_PATH}"
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {livenx_token()}",
    }

    out: Dict[str, Dict[str, Any]] = {}
    chunk_size = int(os.getenv("LIVENX_DEVICE_SEARCH_CHUNK_SIZE", "500"))
    for i in range(0, len(uniq), chunk_size):
        chunk = uniq[i : i + chunk_size]
        body = {"deviceSerials": chunk}

        resp = requests.post(
            url,
            headers=headers,
            json=body,
            verify=livenx_verify_tls(),
            timeout=timeout_s,
        )
        resp.raise_for_status()
        payload = resp.json() or {}
        devices = payload.get("devices") or []
        for d in devices:
            serial = (d.get("serial") or d.get("id") or "").strip()
            if serial:
                out[serial] = d

    return out


def fetch_device_info_by_serials(
    serials: List[str],
    timeout_s: int = 60,
    debug: bool = False,
    include_inventory_unmatched: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """
    OpenAPI-backed:
      GET /v1/devices (isCompactResponse=false) for rich details such as:
        - address (Device IP)
        - vendorProduct/model (Model)
        - vendorProduct/vendor (Manufacturer)
    Falls back to /v1/devices/search for unresolved serials.

    If include_inventory_unmatched=True and /devices is available, include
    inventory devices even when they are not present in the incoming serial list.
    """
    if requests is None:
        raise RuntimeError("Missing dependency 'requests'. Install with: pip install requests")

    uniq = _dedupe_serials(serials)
    if not uniq:
        return {}

    wanted = set(uniq)
    out: Dict[str, Dict[str, Any]] = {}

    # Use /devices only when present in the supplied OpenAPI spec.
    openapi_paths = load_openapi_paths()
    if OPENAPI_DEVICES_PATH in openapi_paths:
        url = f"{livenx_base_url()}{DEVICES_LIST_PATH}"
        headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {livenx_token()}",
        }
        params = {
            "isCompactResponse": "false",
            "includeHistorical": "true",
            "includeNonSnmp": "true",
        }

        resp = requests.get(
            url,
            headers=headers,
            params=params,
            verify=livenx_verify_tls(),
            timeout=timeout_s,
        )
        resp.raise_for_status()
        payload = resp.json() or {}
        devices = payload.get("devices") or []

        matched_for_report = 0
        for d in devices:
            serial = (d.get("serial") or d.get("id") or "").strip()
            if not serial:
                continue

            if serial in wanted:
                matched_for_report += 1
                out[serial] = d
            elif include_inventory_unmatched:
                out[serial] = d

        debug_log(
            debug,
            "devices_inventory_total={} matched_for_report={} included_in_output={}".format(
                len(devices),
                matched_for_report,
                len(out),
            ),
        )

    unresolved = [s for s in uniq if s not in out]
    if unresolved:
        fallback = fetch_device_info_from_search_by_serials(unresolved, timeout_s=timeout_s)
        for serial, info in fallback.items():
            if serial not in out:
                out[serial] = info
        debug_log(debug, f"devices_search_fallback_resolved={len(fallback)}")

    return out


def device_display_name(device: Dict[str, Any]) -> str:
    """
    Prefer displayHostName / displaySystemName, then hostName/systemName.
    Fall back to serial/id.
    """
    for key in ("displayHostName", "displaySystemName", "hostName", "systemName", "serial", "id"):
        v = device.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def first_non_empty_str(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            trimmed = value.strip()
        else:
            trimmed = str(value).strip()
        if trimmed:
            return trimmed
    return ""


# ------------------ output shaping / HTML ------------------

def row_to_output(
    row: Dict[str, Any],
    snmp_serials: Set[str],
    device_info: Dict[str, Dict[str, Any]],
) -> Dict[str, str]:
    serial = str(row.get("serial_number", "") or "").strip()

    has_avc = int(row.get("has_avc_flow", 0) or 0) > 0
    has_basic = int(row.get("has_basic_flow", 0) or 0) > 0
    has_medianet = int(row.get("has_medianet_flow", 0) or 0) > 0

    flow_types: List[str] = []
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

    collecting_snmp = "Yes" if serial and serial in snmp_serials else "No"

    info = device_info.get(serial, {})
    name = device_display_name(info) if info else ""

    # Device IP from REST API device payload.
    device_ip = str(row.get("device_ip", "") or "")
    if info:
        device_ip = first_non_empty_str(info.get("address"), info.get("clientIp"), device_ip)

    # Manufacturer/model from REST API device payload.
    manufacturer = str(row.get("manufacturer", "") or "")
    model = str(row.get("model", "") or "")
    if info and isinstance(info.get("vendorProduct"), dict):
        vp = info["vendorProduct"]
        vendor = vp.get("vendor")
        product = vp.get("product")
        if isinstance(vendor, dict):
            manufacturer = first_non_empty_str(
                vendor.get("vendorName"),
                vendor.get("name"),
                vendor.get("vendor"),
                vendor.get("displayName"),
                manufacturer,
            )
        manufacturer = first_non_empty_str(vp.get("vendorName"), manufacturer)

        model = first_non_empty_str(vp.get("model"), vp.get("displayName"), model)
        if isinstance(product, dict):
            model = first_non_empty_str(
                product.get("name"),
                product.get("model"),
                product.get("displayName"),
                model,
            )

    return {
        "serial_number": serial,
        "device_name": name,
        "device_ip": device_ip,
        "manufacturer": manufacturer,
        "model": model,
        "receiving_flow_types": "/".join(flow_types) if flow_types else "None",
        "highest_flow_supported": highest_flow,
        "collecting_snmp_metrics": collecting_snmp,
        "receiving_traps": "No",
        "receiving_logs": "No",
        "receiving_configs": "No",
    }


def build_no_flow_row(serial: str) -> Dict[str, Any]:
    return {
        "serial_number": serial,
        "device_ip": "",
        "manufacturer": "",
        "model": "",
        "has_avc_flow": 0,
        "has_basic_flow": 0,
        "has_medianet_flow": 0,
        "has_snmp_metrics": 0,
        "has_traps": 0,
        "has_logs": 0,
        "has_configs": 0,
    }


def render_html(rows: List[Dict[str, str]], lookback_hours: int) -> str:
    generated_at = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    headers = [
        ("serial_number", "Serial #"),
        ("device_name", "Device Name"),
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

    parts: List[str] = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '  <meta charset="utf-8"/>',
        '  <meta name="viewport" content="width=device-width, initial-scale=1"/>',
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
        f'  <p class="meta">Generated: {html.escape(generated_at)} | Lookback window: {lookback_hours} hours</p>',
        "  <table>",
        "    <thead>",
        "      <tr>",
    ]

    for _, label in headers:
        parts.append(f"        <th>{html.escape(label)}</th>")

    parts.extend(["      </tr>", "    </thead>", "    <tbody>"])

    for row in rows:
        parts.append("      <tr>")
        for key, _ in headers:
            value = row.get(key, "")
            parts.append(f"        <td>{html.escape(str(value))}</td>")
        parts.append("      </tr>")

    parts.extend(["    </tbody>", "  </table>", "</body>", "</html>"])
    return "\n".join(parts)


# ------------------ CLI / main ------------------

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
        sys.stderr.write("--lookback-hours must be greater than 0\n")
        return 2

    debug_enabled = args.debug or parse_bool(os.getenv("DEVICE_OBSERVABILITY_DEBUG"), default=False)

    env_path = Path(args.env_file)
    debug_log(debug_enabled, f"env_file={env_path} exists={env_path.exists()}")
    load_dotenv(env_path)

    # 1) SNMP coverage: best-effort from QoS CPU report
    snmp_serials = fetch_snmp_serials_from_report(args.lookback_hours, debug=debug_enabled)

    # 2) ClickHouse flow data
    sql = build_sql(args.lookback_hours)
    try:
        raw_rows = clickhouse_query(sql, debug=debug_enabled)
    except Exception as exc:
        sys.stderr.write(f"Error (ClickHouse): {exc}\n")
        return 1

    # 3) Resolve device serial -> device info (best-effort)
    device_info: Dict[str, Dict[str, Any]] = {}
    try:
        serials = [str(r.get("serial_number", "") or "").strip() for r in raw_rows]
        device_info = fetch_device_info_by_serials(
            serials,
            debug=debug_enabled,
            include_inventory_unmatched=True,
        )
        debug_log(debug_enabled, f"device_info_resolved={len(device_info)}")
    except Exception as exc:
        debug_log(debug_enabled, f"device_info_failed error={exc}")

    # 4) Include inventory devices that have no flow rows.
    existing_serials = {str(r.get("serial_number", "") or "").strip() for r in raw_rows}
    added_no_flow_rows = 0
    for serial in sorted(device_info.keys()):
        if serial and serial not in existing_serials:
            raw_rows.append(build_no_flow_row(serial))
            existing_serials.add(serial)
            added_no_flow_rows += 1
    debug_log(debug_enabled, f"added_no_flow_rows={added_no_flow_rows}")

    # Keep output stable and easy to diff.
    raw_rows.sort(key=lambda r: str(r.get("serial_number", "") or ""))

    # 5) Render
    output_rows = [row_to_output(r, snmp_serials, device_info) for r in raw_rows]
    debug_log(debug_enabled, f"render_rows={len(output_rows)}")

    html_text = render_html(output_rows, args.lookback_hours)

    if args.output:
        output_path = Path(args.output)
        if output_path.parent and not output_path.parent.exists():
            output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_text, encoding="utf-8")
        sys.stdout.write(f"Wrote {len(output_rows)} rows to {output_path}\n")
    else:
        sys.stdout.write(html_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
