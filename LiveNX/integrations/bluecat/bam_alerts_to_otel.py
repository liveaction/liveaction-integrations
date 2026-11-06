#!/usr/bin/env python3
"""
BlueCat Address Manager (BAM) alerts -> LiveNX OTEL collector.

Polls the BAM RESTful v2 API (/api/v2/events) at a regular interval and forwards
new events as OpenTelemetry log records to the OTEL collector running on LiveNX
(la-otelcol) over OTLP/gRPC on port 4317 (TLS + bearer token).

Runs on the LiveNX host with the stock Python 3 (3.10 on Ubuntu 22.04) and uses
only the Python standard library -- no pip packages required (the gRPC/HTTP2 and
protobuf wire handling needed for a single unary Export call is built in).

Configuration (environment variables, or the same names in an env file passed
with --env-file; command line flags override both):

  BAM_BASE            BAM base URL                      (required) e.g. https://10.244.29.80
  BAM_USER            BAM API user                      (required)
  BAM_PASS            BAM API password                  (required)
  BAM_VERIFY_TLS      true|false|/path/to/ca.pem        (default: false)
  OTEL_ENDPOINT       collector OTLP/gRPC host:port     (default: 127.0.0.1:4317)
  OTEL_AUTH_TOKEN     bearer token for the collector    (default: read from the
                      bearertokenauth entry in /etc/la-otelcol.yaml)
  OTEL_VERIFY_TLS     true|false|/path/to/ca.pem        (default: false)
  POLL_INTERVAL       seconds between polls             (default: 60)
  MIN_SEVERITY        INFO|WARN|ERROR minimum to forward (default: WARN)
  PAGE_SIZE           events requested per API call     (default: 200)
  INITIAL_BACKFILL    events to send on very first run  (default: 0 = only new events)
  STATE_FILE          cursor file                       (default: ~/.bam_alerts_state.json)
  LOG_LEVEL           DEBUG|INFO|WARNING|ERROR          (default: INFO)

Examples:
  ./bam_alerts_to_otel.py --env-file bam_alerts.env               # run forever
  ./bam_alerts_to_otel.py --env-file bam_alerts.env --once        # single poll
  ./bam_alerts_to_otel.py --env-file bam_alerts.env --dry-run --once   # print OTLP, send nothing
"""

import argparse
import base64
import json
import logging
import os
import signal
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

SERVICE_NAME = "bluecat-address-manager"
SCOPE_NAME = "bam_alerts_to_otel"
SCOPE_VERSION = "1.0.0"

# BAM eventType -> (OTel severityNumber, severityText)
SEV_INFO = (9, "INFO")
SEV_WARN = (13, "WARN")
SEV_ERROR = (17, "ERROR")
EVENT_SEVERITY = {
    "INFO": SEV_INFO,
    "SUCCESS": SEV_INFO,
    "VALID": SEV_INFO,
    "WARNING": SEV_WARN,
    "NOT_DEPLOYED": SEV_WARN,
    "RESPONSE_POLICY_ZONES_NOT_DEPLOYED": SEV_WARN,
    "ERROR": SEV_ERROR,
    "FAILED": SEV_ERROR,
    "INVALID": SEV_ERROR,
    "NO_ROLE": SEV_ERROR,
}
MIN_SEVERITY_NUMBER = {"INFO": 9, "WARN": 13, "WARNING": 13, "ERROR": 17}

log = logging.getLogger("bam_alerts")
_stop = False


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def load_env_file(path):
    """Minimal KEY=VALUE parser (supports comments and quoted values)."""
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            val = val.strip()
            if val[:1] in ("'", '"') and val[-1:] == val[:1] and len(val) >= 2:
                val = val[1:-1]
            else:
                val = val.split(" #", 1)[0].strip()  # inline comment
            os.environ.setdefault(key.strip(), val)  # real env wins


def make_ssl_context(verify):
    """verify: 'true' | 'false' | path to CA bundle."""
    v = str(verify).strip()
    if v.lower() in ("false", "0", "no", ""):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if v.lower() in ("true", "1", "yes"):
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=v)


def parse_args():
    p = argparse.ArgumentParser(
        description="Forward BlueCat Address Manager events to the LiveNX OTEL collector (stdlib only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Configuration", 1)[1] if "Configuration" in __doc__ else "",
    )
    p.add_argument("--env-file", help="file with KEY=VALUE settings")
    p.add_argument("--once", action="store_true", help="poll once and exit")
    p.add_argument("--dry-run", action="store_true", help="fetch from BAM and print OTLP JSON instead of sending")
    p.add_argument("--interval", type=int, help="poll interval seconds (overrides POLL_INTERVAL)")
    p.add_argument("--min-severity", help="INFO|WARN|ERROR (overrides MIN_SEVERITY)")
    p.add_argument("--reset-state", action="store_true", help="forget the saved cursor before starting")
    return p.parse_args()


class Config:
    def __init__(self, args):
        if args.env_file:
            load_env_file(args.env_file)
        e = os.environ.get
        self.bam_base = (e("BAM_BASE") or "").rstrip("/")
        self.bam_user = e("BAM_USER")
        self.bam_pass = e("BAM_PASS")
        self.bam_verify = e("BAM_VERIFY_TLS", "false")
        self.otel_endpoint = e("OTEL_ENDPOINT", "127.0.0.1:4317")
        self.otel_token = e("OTEL_AUTH_TOKEN") or discover_collector_token()
        self.otel_verify = e("OTEL_VERIFY_TLS", "false")
        self.interval = args.interval or int(e("POLL_INTERVAL", "60"))
        self.min_sev_name = (args.min_severity or e("MIN_SEVERITY", "WARN")).upper()
        self.page_size = int(e("PAGE_SIZE", "200"))
        self.backfill = int(e("INITIAL_BACKFILL", "0"))
        self.state_file = e("STATE_FILE", os.path.expanduser("~/.bam_alerts_state.json"))
        self.log_level = e("LOG_LEVEL", "INFO").upper()
        self.once = args.once
        self.dry_run = args.dry_run
        self.reset_state = args.reset_state

        missing = [n for n, v in (("BAM_BASE", self.bam_base), ("BAM_USER", self.bam_user),
                                  ("BAM_PASS", self.bam_pass)) if not v]
        if missing:
            sys.exit("Missing required setting(s): " + ", ".join(missing))
        if self.min_sev_name not in MIN_SEVERITY_NUMBER:
            sys.exit("MIN_SEVERITY must be one of INFO, WARN, ERROR")
        self.min_sev = MIN_SEVERITY_NUMBER[self.min_sev_name]
        self.bam_ctx = make_ssl_context(self.bam_verify)
        self.otel_ctx = make_ssl_context(self.otel_verify)
        self.otel_ctx.set_alpn_protocols(["h2"])
        if not self.dry_run and not self.otel_token:
            sys.exit("No collector bearer token: set OTEL_AUTH_TOKEN (see bearertokenauth in /etc/la-otelcol.yaml)")


# --------------------------------------------------------------------------- #
# BAM client
# --------------------------------------------------------------------------- #
class BamError(Exception):
    pass


class BamClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.auth_header = None

    def _request(self, method, path, body=None, params=None, auth=True):
        url = self.cfg.bam_base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if auth and self.auth_header:
            headers["Authorization"] = self.auth_header
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.cfg.bam_ctx) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise BamError("%s %s -> HTTP %s: %s" % (method, path, exc.code, detail)) from exc
        except (urllib.error.URLError, socket.timeout, ssl.SSLError) as exc:
            raise BamError("%s %s failed: %s" % (method, path, exc)) from exc

    def login(self):
        resp = self._request("POST", "/api/v2/sessions",
                             {"username": self.cfg.bam_user, "password": self.cfg.bam_pass}, auth=False)
        creds = resp.get("basicAuthenticationCredentials")
        if not creds and resp.get("apiToken"):
            creds = base64.b64encode(("%s:%s" % (self.cfg.bam_user, resp["apiToken"])).encode()).decode()
        if not creds:
            raise BamError("login succeeded but no credentials in response")
        self.auth_header = "Basic " + creds
        log.info("Logged in to BAM at %s as %s", self.cfg.bam_base, self.cfg.bam_user)

    def get(self, path, params=None):
        """GET with one transparent re-login if the session expired."""
        if not self.auth_header:
            self.login()
        try:
            return self._request("GET", path, params=params)
        except BamError as exc:
            if "HTTP 401" not in str(exc):
                raise
            log.info("BAM session expired; logging in again")
            self.login()
            return self._request("GET", path, params=params)

    def events_after(self, last_id, limit):
        """Events with id > last_id, oldest first."""
        resp = self.get("/api/v2/events", {
            "filter": "id:gt(%d)" % last_id,
            "orderBy": "asc(id)",
            "limit": limit,
        })
        return resp.get("data", [])

    def latest_events(self, n):
        """Most recent n events, returned oldest first."""
        resp = self.get("/api/v2/events", {"orderBy": "desc(id)", "limit": n})
        return list(reversed(resp.get("data", [])))


# --------------------------------------------------------------------------- #
# OTLP conversion / export
# --------------------------------------------------------------------------- #
def _attr(key, value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        v = {"boolValue": value}
    elif isinstance(value, int):
        v = {"intValue": str(value)}  # OTLP JSON encodes int64 as string
    elif isinstance(value, (dict, list)):
        v = {"stringValue": json.dumps(value, separators=(",", ":"), sort_keys=True)}
    else:
        v = {"stringValue": str(value)}
    return {"key": key, "value": v}


def _attrs(pairs):
    return [a for a in (_attr(k, v) for k, v in pairs) if a]


def iso_to_nanos(ts):
    if not ts:
        return int(time.time() * 1e9)
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1_000_000_000)
    except ValueError:
        return int(time.time() * 1e9)


def event_severity(ev):
    return EVENT_SEVERITY.get(ev.get("eventType"), SEV_INFO)


def event_to_log_record(ev, observed_ns):
    sev_num, sev_text = event_severity(ev)
    src = ev.get("source") or {}
    user = ev.get("user") or {}
    message = ev.get("message") or "(no message)"
    attrs = _attrs([
        ("alert.source", "bluecat-address-manager"),
        ("bluecat.event.id", ev.get("id")),
        ("bluecat.event.type", ev.get("eventType")),
        ("bluecat.event.category", ev.get("category")),
        ("bluecat.event.subcategory", ev.get("subcategory")),
        ("bluecat.event.source_name", ev.get("sourceName")),
        ("bluecat.event.source.id", src.get("id")),
        ("bluecat.event.source.type", src.get("type")),
        ("bluecat.event.source.name", src.get("name")),
        ("bluecat.event.user", user.get("name") or user.get("username")),
        ("bluecat.event.task_id", ev.get("taskId")),
        ("bluecat.event.payload", ev.get("payload")),
        ("bluecat.event.details", ev.get("details") or None),
    ])
    return {
        "timeUnixNano": str(iso_to_nanos(ev.get("dateTime"))),
        "observedTimeUnixNano": str(observed_ns),
        "severityNumber": sev_num,
        "severityText": sev_text,
        "body": {"stringValue": message},
        "attributes": attrs,
    }


def build_otlp_payload(events, bam_base):
    observed = int(time.time() * 1e9)
    host = urllib.parse.urlparse(bam_base).hostname or bam_base
    return {
        "resourceLogs": [{
            "resource": {"attributes": _attrs([
                ("service.name", SERVICE_NAME),
                ("bluecat.bam.host", host),
            ])},
            "scopeLogs": [{
                "scope": {"name": SCOPE_NAME, "version": SCOPE_VERSION},
                "logRecords": [event_to_log_record(e, observed) for e in events],
            }],
        }]
    }


def discover_collector_token(path="/etc/la-otelcol.yaml"):
    """Pull the bearertokenauth token out of the local collector config, if readable."""
    try:
        in_ext = False
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("extensions:"):
                    in_ext = True
                elif in_ext and line and not line[0].isspace():
                    in_ext = False
                if in_ext and line.strip().startswith("token:"):
                    return line.split(":", 1)[1].strip().strip("'\"")
    except OSError:
        pass
    return None


# --- minimal protobuf encoder for ExportLogsServiceRequest (from the OTLP JSON dict) ---
def _varint(n):
    n &= 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _ld(field, data):  # length-delimited
    return _varint(field << 3 | 2) + _varint(len(data)) + data


def _pb_str(field, text):
    return _ld(field, text.encode("utf-8"))


def _pb_anyvalue(v):
    if "stringValue" in v:
        return _pb_str(1, v["stringValue"])
    if "boolValue" in v:
        return _varint(2 << 3) + _varint(1 if v["boolValue"] else 0)
    if "intValue" in v:
        return _varint(3 << 3) + _varint(int(v["intValue"]))
    return b""


def _pb_kvs(field, attrs):
    return b"".join(_ld(field, _pb_str(1, a["key"]) + _ld(2, _pb_anyvalue(a["value"]))) for a in attrs)


def _pb_logrecord(r):
    return (_varint(1 << 3 | 1) + int(r["timeUnixNano"]).to_bytes(8, "little")
            + _varint(2 << 3) + _varint(r["severityNumber"])
            + _pb_str(3, r["severityText"])
            + _ld(5, _pb_anyvalue(r["body"]))
            + _pb_kvs(6, r["attributes"])
            + _varint(11 << 3 | 1) + int(r["observedTimeUnixNano"]).to_bytes(8, "little"))


def encode_logs_request(payload):
    out = b""
    for rl in payload["resourceLogs"]:
        body = _ld(1, _pb_kvs(1, rl["resource"]["attributes"]))
        for sl in rl["scopeLogs"]:
            scope = sl["scope"]
            sbody = _ld(1, _pb_str(1, scope["name"]) + _pb_str(2, scope["version"]))
            sbody += b"".join(_ld(2, _pb_logrecord(r)) for r in sl["logRecords"])
            body += _ld(2, sbody)
        out += _ld(1, body)
    return out


# --- minimal gRPC-over-HTTP/2 unary client (stdlib: ssl + socket) ---
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_MAX_FRAME = 16384
_MAX_MESSAGE = 48 * 1024  # keep each Export inside the default 64KiB HTTP/2 flow-control window
_LOGS_PATH = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"


def _frame(ftype, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + stream.to_bytes(4, "big") + payload


def _hpack_literal(name, value):
    """Literal header field without indexing, new name, no Huffman."""
    def s(b):
        n = len(b)
        assert n < 127
        return bytes([n]) + b
    return b"\x00" + s(name.encode()) + s(value.encode())


def _read_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("OTLP connection closed by collector")
        buf += chunk
    return bytes(buf)


def _grpc_unary(cfg, path, message):
    host, _, port = cfg.otel_endpoint.rpartition(":")
    host = host or cfg.otel_endpoint
    port = int(port) if port.isdigit() else 4317
    try:
        raw = socket.create_connection((host, port), timeout=30)
        sock = cfg.otel_ctx.wrap_socket(raw, server_hostname=host)
    except (OSError, ssl.SSLError) as exc:
        raise RuntimeError("OTLP connect to %s:%s failed: %s" % (host, port, exc)) from exc
    try:
        if sock.selected_alpn_protocol() != "h2":
            raise RuntimeError("collector did not negotiate HTTP/2")
        sock.settimeout(30)
        hdrs = b"".join(_hpack_literal(k, v) for k, v in (
            (":method", "POST"), (":scheme", "https"), (":path", path),
            (":authority", "%s:%s" % (host, port)),
            ("content-type", "application/grpc"), ("te", "trailers"),
            ("user-agent", "bam-alerts-to-otel/" + SCOPE_VERSION),
            ("authorization", "Bearer " + cfg.otel_token)))
        data = b"\x00" + len(message).to_bytes(4, "big") + message
        out = _H2_PREFACE + _frame(0x4, 0, 0) + _frame(0x1, 0x4, 1, hdrs)  # SETTINGS, HEADERS
        chunks = [data[i:i + _MAX_FRAME] for i in range(0, len(data), _MAX_FRAME)]
        for i, c in enumerate(chunks):
            out += _frame(0x0, 0x1 if i == len(chunks) - 1 else 0, 1, c)
        sock.sendall(out)

        got_data, header_bytes = b"", b""
        while True:
            h = _read_exact(sock, 9)
            length, ftype, flags = int.from_bytes(h[:3], "big"), h[3], h[4]
            stream = int.from_bytes(h[5:], "big") & 0x7FFFFFFF
            body = _read_exact(sock, length) if length else b""
            if ftype == 0x4 and not flags & 0x1:      # SETTINGS -> ack
                sock.sendall(_frame(0x4, 0x1, 0))
            elif ftype == 0x6 and not flags & 0x1:    # PING -> ack
                sock.sendall(_frame(0x6, 0x1, 0, body))
            elif ftype == 0x7:                        # GOAWAY
                raise RuntimeError("collector sent GOAWAY: %r" % body[8:].decode("utf-8", "replace"))
            elif stream == 1:
                if ftype == 0x3:                      # RST_STREAM
                    raise RuntimeError("collector reset stream (code %d)" % int.from_bytes(body[:4], "big"))
                if ftype == 0x0:
                    got_data += body
                elif ftype in (0x1, 0x9):             # HEADERS / CONTINUATION
                    if ftype == 0x1 and flags & 0x8:  # PADDED
                        body = body[1:len(body) - body[0]]
                    if ftype == 0x1 and flags & 0x20:  # PRIORITY
                        body = body[5:]
                    header_bytes += body
                if flags & 0x1 and ftype in (0x0, 0x1):  # END_STREAM
                    break
        # A successful unary Export returns one (empty) response message before the trailers;
        # an error comes back as "trailers-only" with no DATA frame.
        if len(got_data) >= 5:
            return got_data[5:]
        text = "".join(chr(c) if 32 <= c < 127 else " " for c in header_bytes)
        raise RuntimeError("collector rejected Export: %s" % " ".join(text.split())[:300])
    except (OSError, ssl.SSLError) as exc:
        raise RuntimeError("OTLP send failed: %s" % exc) from exc
    finally:
        sock.close()


def send_otlp(cfg, payload):
    """Export the payload via OTLP/gRPC, splitting so each message stays small."""
    records = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    batch = []

    def flush():
        if batch:
            rl = json.loads(json.dumps(payload))  # cheap deep copy
            rl["resourceLogs"][0]["scopeLogs"][0]["logRecords"] = list(batch)
            _grpc_unary(cfg, _LOGS_PATH, encode_logs_request(rl))
            del batch[:]

    for rec in records:
        batch.append(rec)
        if len(encode_logs_request({"resourceLogs": [{
                "resource": payload["resourceLogs"][0]["resource"],
                "scopeLogs": [{"scope": payload["resourceLogs"][0]["scopeLogs"][0]["scope"],
                               "logRecords": batch}]}]})) > _MAX_MESSAGE and len(batch) > 1:
            last = batch.pop()
            flush()
            batch.append(last)
    flush()


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #
def load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return int(json.load(fh)["last_event_id"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save_state(path, last_id):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"last_event_id": last_id,
                   "updated": datetime.now(timezone.utc).isoformat()}, fh)
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# main loop
# --------------------------------------------------------------------------- #
def forward(cfg, events):
    """Filter by severity and ship. Returns number sent. Raises on delivery failure."""
    selected = [e for e in events if event_severity(e)[0] >= cfg.min_sev]
    if not selected:
        return 0
    payload = build_otlp_payload(selected, cfg.bam_base)
    if cfg.dry_run:
        print(json.dumps(payload, indent=2))
    else:
        send_otlp(cfg, payload)
    return len(selected)


def poll_once(cfg, bam, last_id):
    """Fetch & forward everything newer than last_id. Returns the new cursor."""
    if last_id is None:  # first ever run
        if cfg.backfill > 0:
            events = bam.latest_events(cfg.backfill)
            sent = forward(cfg, events)
            log.info("Initial backfill: fetched %d, forwarded %d", len(events), sent)
            last_id = max((e["id"] for e in events), default=0)
        else:
            latest = bam.latest_events(1)
            last_id = latest[0]["id"] if latest else 0
            log.info("First run: starting after event id %d (no backfill)", last_id)
        if not cfg.dry_run:
            save_state(cfg.state_file, last_id)
        return last_id

    total = 0
    while not _stop:
        events = bam.events_after(last_id, cfg.page_size)
        if not events:
            break
        total += forward(cfg, events)  # raises -> cursor not advanced, retried next poll
        last_id = max(e["id"] for e in events)
        if not cfg.dry_run:
            save_state(cfg.state_file, last_id)
        if len(events) < cfg.page_size:
            break
    log.info("Poll complete: forwarded %d event(s), cursor=%d", total, last_id)
    return last_id


def sleep_interruptible(seconds):
    end = time.time() + seconds
    while not _stop and time.time() < end:
        time.sleep(min(1, end - time.time()))


def main():
    global _stop
    cfg = Config(parse_args())
    logging.basicConfig(level=getattr(logging, cfg.log_level, logging.INFO),
                        format="%(asctime)s %(levelname)s %(message)s")

    def _handle(signum, _frame):
        global _stop
        _stop = True
        log.info("Signal %s received, shutting down", signum)
    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    if cfg.reset_state and os.path.exists(cfg.state_file):
        os.remove(cfg.state_file)
    last_id = load_state(cfg.state_file)
    log.info("Starting: bam=%s otel=%s interval=%ds min_severity=%s cursor=%s",
             cfg.bam_base, "(dry-run)" if cfg.dry_run else cfg.otel_endpoint,
             cfg.interval, cfg.min_sev_name, last_id)

    bam = BamClient(cfg)
    rc = 0
    while not _stop:
        try:
            last_id = poll_once(cfg, bam, last_id)
        except (BamError, RuntimeError) as exc:
            log.error("Poll failed (will retry): %s", exc)
            rc = 1
        except Exception:  # keep the service alive on unexpected errors
            log.exception("Unexpected error (will retry)")
            rc = 1
        else:
            rc = 0
        if cfg.once:
            break
        sleep_interruptible(cfg.interval)
    return rc


if __name__ == "__main__":
    sys.exit(main())
