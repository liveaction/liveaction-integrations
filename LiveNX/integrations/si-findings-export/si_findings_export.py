#!/usr/bin/env python3
"""Continuously export LiveNX Security Insight findings (si_findings) to a JSON Lines file.

Two sources are supported (SI_SOURCE):

  api         The Security Insight REST API, reached through the LiveNX web server
              (https://<livenx>/api/security-proxy/...) with a LiveNX API token.
              This is the default and runs from any machine that can reach LiveNX
              on 443. Rows come back with names already decoded (severity "High",
              protocol "TCP", ...).
  clickhouse  The si_findings table over the ClickHouse HTTPS interface, using the
              read-only account LiveNX already provisions. Only usable on the
              LiveNX server itself. Rows carry numeric codes.

Findings have no insert timestamp and can be written several minutes after their
`time` value, so a plain "time > last seen" tail loses rows. Instead every cycle
re-reads the last SI_LOOKBACK_SECONDS and emits only rows it has not written yet.
Delivery is at-least-once: a crash between writing the output and saving the
state file can repeat rows, never drop them.

Standard library only, so the script also runs on its own without the Debian
package: python3 si_findings_export.py --livenx-host HOST --output FILE ...
Every setting is an SI_* environment variable; command-line options override
the environment, which overrides --env-file.
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import signal
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ElementTree
from collections import Counter

log = logging.getLogger("si-findings-export")

IP_FIELDS = ("saddr", "daddr", "data_src")
V4_MAPPED_PREFIX = "::ffff:"
API_PATH = "/api/security-proxy/api/v1/findings"
LOGIN_PATH = "/auth/oauth/login"
# Log in again this long before a JWT expires.
TOKEN_REFRESH_MARGIN = 60
EX_CONFIG = 78  # sysexits.h: configuration error; the systemd unit does not restart on it


class ConfigError(Exception):
    pass


def env(name, default):
    value = os.environ.get(name, "")
    return value if value.strip() else default


class Config:
    def __init__(self):
        self.source = env("SI_SOURCE", "api").lower()
        self.livenx_host = env("SI_LIVENX_HOST", "")
        self.api_url = env("SI_API_URL", "")
        self.api_token = env("SI_API_TOKEN", "")
        self.api_username = env("SI_API_USERNAME", "")
        self.api_password = env("SI_API_PASSWORD", "")
        self.api_login_url = env("SI_API_LOGIN_URL", "")
        self.api_verify_tls = env("SI_API_VERIFY_TLS", "true").lower() not in ("0", "false", "no")
        self.api_ca_file = env("SI_API_CA_FILE", "")
        self.api_page_size = int(env("SI_API_PAGE_SIZE", "5000"))
        self.api_filter = env("SI_API_FILTER", "")
        self.ch_url = env("SI_CH_URL", "https://127.0.0.1:10443")
        self.ch_database = env("SI_CH_DATABASE", "livenx_platformdb")
        self.ch_table = env("SI_CH_TABLE", "si_findings_dist")
        self.ch_user = env("SI_CH_USER", "readonly")
        self.ch_password = env("SI_CH_PASSWORD", "")
        self.ch_users_xml = env("SI_CH_USERS_XML", "/etc/clickhouse-server/users.d/users.xml")
        self.ch_ca_file = env("SI_CH_CA_FILE", "")
        self.output_file = env("SI_OUTPUT_FILE", "/data/si-findings-export/si_findings.jsonl")
        self.state_file = env("SI_STATE_FILE", "/data/si-findings-export/state.json")
        self.poll_interval = float(env("SI_POLL_INTERVAL", "30"))
        self.lookback = int(env("SI_LOOKBACK_SECONDS", "3600"))
        self.backfill = int(float(env("SI_INITIAL_BACKFILL_HOURS", "24")) * 3600)
        self.max_window = max(1, int(env("SI_MAX_WINDOW_SECONDS", "3600")))
        self.rotate_max_bytes = int(env("SI_ROTATE_MAX_BYTES", str(100 * 1024 * 1024)))
        self.rotate_keep = int(env("SI_ROTATE_KEEP", "5"))
        self.http_timeout = float(env("SI_HTTP_TIMEOUT", "120"))
        if self.source not in ("api", "clickhouse"):
            raise ConfigError("SI_SOURCE must be 'api' or 'clickhouse', got %r" % self.source)
        if self.source == "api" and not self.api_url:
            if not self.livenx_host:
                raise ConfigError("set SI_LIVENX_HOST (and SI_API_TOKEN) to the LiveNX server to read from")
            self.api_url = "https://%s%s" % (self.livenx_host, API_PATH)
        if self.source == "api":
            if bool(self.api_username) != bool(self.api_password):
                raise ConfigError("SI_API_USERNAME and SI_API_PASSWORD must be set together")
            if not self.api_login_url:
                parts = urllib.parse.urlsplit(self.api_url)
                self.api_login_url = "%s://%s%s" % (parts.scheme, parts.netloc, LOGIN_PATH)
        if not re.fullmatch(r"[A-Za-z0-9_]+", self.ch_database + self.ch_table):
            raise ConfigError("SI_CH_DATABASE and SI_CH_TABLE must be plain identifiers")


def _jwt_expiry(token):
    """Expiry (epoch seconds) from a JWT's exp claim; 15 minutes from now if unreadable."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return float(claims["exp"])
    except (IndexError, KeyError, ValueError, TypeError):
        return time.time() + 900


class ApiSource:
    """Security Insight Service REST API.

    The API's cursor paging keys on `time` alone and drops rows that share a
    timestamp across a page boundary, so it is never used here. Each window is
    fetched as a single page and split in half whenever it does not fit.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        # A static SI_API_TOKEN wins; otherwise log in with a username and
        # password and keep the short-lived JWT, renewing it before it expires.
        self._jwt = None
        self._jwt_expires = 0.0
        if cfg.api_ca_file:
            self.ssl_context = ssl.create_default_context(cafile=cfg.api_ca_file)
        elif cfg.api_verify_tls:
            self.ssl_context = ssl.create_default_context()
        else:
            self.ssl_context = ssl._create_unverified_context()

    def _login(self):
        """Log in to LiveNX and cache the JWT it returns."""
        body = json.dumps({"username": self.cfg.api_username, "password": self.cfg.api_password}).encode()
        req = urllib.request.Request(
            self.cfg.api_login_url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.http_timeout, context=self.ssl_context) as resp:
                token = json.loads(resp.read())["token"]
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                "LiveNX login HTTP %d: %s" % (exc.code, exc.read(300).decode(errors="replace"))
            ) from exc
        except (KeyError, ValueError, TypeError) as exc:
            raise RuntimeError("LiveNX login returned no token") from exc
        self._jwt = token
        self._jwt_expires = _jwt_expiry(token)
        log.debug("logged in to LiveNX as %s", self.cfg.api_username)

    def _auth_header(self):
        if self.cfg.api_token:
            return "Bearer " + self.cfg.api_token
        if not self.cfg.api_username:
            return None
        if not self._jwt or time.time() >= self._jwt_expires - TOKEN_REFRESH_MARGIN:
            self._login()
        return "Bearer " + self._jwt

    def fetch(self, start, end):
        """Return all findings with start <= time < end (epoch seconds)."""
        return self._fetch(start, end, self.cfg.api_page_size)

    def _get(self, url):
        """GET url as JSON; a 401 on a logged-in session triggers one fresh login and retry."""
        for attempt in (0, 1):
            headers = {"Accept": "application/json"}
            auth = self._auth_header()
            if auth:
                headers["Authorization"] = auth
            req = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.cfg.http_timeout, context=self.ssl_context) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0 and self._jwt:
                    self._jwt = None
                    continue
                raise

    def _fetch(self, start, end, page_size):
        rsql = "time=ge=%d;time=lt=%d" % (start, end)
        if self.cfg.api_filter:
            rsql += ";" + self.cfg.api_filter
        query = urllib.parse.urlencode({"pageSize": page_size, "sort": "time", "filter": rsql})
        try:
            body = self._get(self.cfg.api_url + "?" + query)
        except urllib.error.HTTPError as exc:
            detail = exc.read(300).decode(errors="replace")
            # The service answers an empty time window with 404 rather than an empty list.
            if exc.code == 404 and "findings:not_found" in detail:
                return []
            if exc.code in (401, 403):
                which = "API token (SI_API_TOKEN)" if self.cfg.api_token else "login (SI_API_USERNAME)"
                detail = "LiveNX rejected the %s: %s" % (which, detail)
            raise RuntimeError("findings API HTTP %d: %s" % (exc.code, detail)) from exc
        rows = body.get("data") or []
        if not body.get("hasMore"):
            return rows
        if end - start > 1:
            mid = start + (end - start) // 2
            return self._fetch(start, mid, page_size) + self._fetch(mid, end, page_size)
        # A single second holds more rows than one page: ask for all of them.
        return self._fetch(start, end, max(page_size * 2, int(body.get("totalCount") or 0) + 1))


class ClickHouseSource:
    """si_findings over the ClickHouse HTTPS interface with the read-only account."""

    def __init__(self, cfg):
        self.cfg = cfg
        if cfg.ch_ca_file:
            self.ssl_context = ssl.create_default_context(cafile=cfg.ch_ca_file)
        else:
            # LiveNX generates a self-signed certificate for its local ClickHouse.
            self.ssl_context = ssl._create_unverified_context()

    def _password(self):
        if self.cfg.ch_password:
            return self.cfg.ch_password
        # Read on every request so a LiveNX credential rotation is picked up.
        node = ElementTree.parse(self.cfg.ch_users_xml).find("users/%s/password" % self.cfg.ch_user)
        if node is None or not node.text:
            raise RuntimeError("no password for user %r in %s" % (self.cfg.ch_user, self.cfg.ch_users_xml))
        return node.text

    def fetch(self, start, end):
        sql = (
            "SELECT * FROM %s.%s WHERE time >= toDateTime({a:UInt32}) AND time < toDateTime({b:UInt32}) "
            "ORDER BY time FORMAT JSONEachRow" % (self.cfg.ch_database, self.cfg.ch_table)
        )
        params = urllib.parse.urlencode({"param_a": start, "param_b": end})
        token = base64.b64encode(("%s:%s" % (self.cfg.ch_user, self._password())).encode()).decode()
        req = urllib.request.Request(
            self.cfg.ch_url.rstrip("/") + "/?" + params,
            data=sql.encode(),
            headers={"Authorization": "Basic " + token},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.http_timeout, context=self.ssl_context) as resp:
                text = resp.read().decode()
        except urllib.error.HTTPError as exc:
            raise RuntimeError("ClickHouse HTTP %d: %s" % (exc.code, exc.read(500).decode(errors="replace"))) from exc
        rows = [json.loads(line) for line in text.splitlines() if line]
        for row in rows:
            for field in IP_FIELDS:
                value = row.get(field)
                if isinstance(value, str) and value.startswith(V4_MAPPED_PREFIX) and "." in value:
                    row[field] = value[len(V4_MAPPED_PREFIX):]
        return rows


def row_key(row):
    canonical = json.dumps(row, sort_keys=True, separators=(",", ":"))
    return hashlib.blake2b(canonical.encode(), digest_size=8).hexdigest()


class State:
    """Checkpoint plus the keys of rows already written inside the lookback window.

    `seen` maps row key -> number of copies written, so genuinely identical rows
    are each exported once rather than collapsed into one.
    """

    def __init__(self, path):
        self.path = path
        self.checkpoint = None
        self.seen = {}

    def load(self):
        try:
            with open(self.path) as fh:
                data = json.load(fh)
            self.checkpoint = int(data["checkpoint"])
            self.seen = {str(k): int(v) for k, v in data.get("seen", {}).items()}
        except FileNotFoundError:
            pass
        except (ValueError, KeyError, TypeError) as exc:
            log.warning("ignoring unreadable state file %s (%s); starting fresh", self.path, exc)
        return self

    def save(self, checkpoint, seen):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"checkpoint": checkpoint, "seen": seen}, fh, separators=(",", ":"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
        self.checkpoint, self.seen = checkpoint, seen


class Output:
    """Append-only JSON Lines file with size-based rotation (file -> file.1 -> file.2 ...)."""

    def __init__(self, path, max_bytes, keep):
        self.path, self.max_bytes, self.keep = path, max_bytes, keep

    def _rotate(self):
        if self.keep <= 0:
            os.remove(self.path)
            return
        for index in range(self.keep - 1, 0, -1):
            older = "%s.%d" % (self.path, index)
            if os.path.exists(older):
                os.replace(older, "%s.%d" % (self.path, index + 1))
        os.replace(self.path, self.path + ".1")
        log.info("rotated %s", self.path)

    def write(self, rows):
        if not rows:
            return
        if self.max_bytes > 0 and os.path.exists(self.path) and os.path.getsize(self.path) >= self.max_bytes:
            self._rotate()
        with open(self.path, "a") as fh:
            for row in rows:
                fh.write(json.dumps(row, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())


class Exporter:
    def __init__(self, cfg, source, state, output, clock=time.time):
        self.cfg, self.source, self.state, self.output, self.clock = cfg, source, state, output, clock

    def run_cycle(self):
        """Scan from (checkpoint - lookback) to now and write rows not exported yet."""
        now = int(self.clock())
        end = now + 1
        if self.state.checkpoint is None:
            start = now - self.cfg.backfill
        else:
            start = min(self.state.checkpoint, end) - self.cfg.lookback
        old_seen = self.state.seen
        cycle_counts = Counter()  # copies of each row returned by this cycle's scan
        written = {}  # key -> copies written so far, for rows inside this cycle's range
        total = 0
        lo = start
        while lo < end:
            hi = min(lo + self.cfg.max_window, end)
            fresh = []
            for row in self.source.fetch(lo, hi):
                key = row_key(row)
                cycle_counts[key] += 1
                already = written.get(key, old_seen.get(key, 0))
                if cycle_counts[key] > already:
                    fresh.append(row)
                    written[key] = cycle_counts[key]
                else:
                    written[key] = already
            self.output.write(fresh)
            total += len(fresh)
            lo = hi
            # Until the cycle completes keep the previous keys too, so a restart
            # mid-cycle still recognises everything already written.
            merged = written if lo >= end else {**old_seen, **written}
            self.state.save(min(hi, now), merged)
        return total


# Command-line option -> environment variable it sets.
CLI_OPTIONS = [
    ("--source", "SI_SOURCE", "api (default) or clickhouse"),
    ("--livenx-host", "SI_LIVENX_HOST", "LiveNX hostname or IP to read findings from"),
    ("--api-token", "SI_API_TOKEN", "LiveNX API token; prefer the SI_API_TOKEN variable, which is not visible in ps"),
    ("--api-username", "SI_API_USERNAME", "LiveNX user to log in as when no token is set; the password comes from SI_API_PASSWORD"),
    ("--api-url", "SI_API_URL", "full findings endpoint URL, overriding --livenx-host"),
    ("--ca-file", "SI_API_CA_FILE", "CA bundle used to verify the LiveNX certificate"),
    ("--filter", "SI_API_FILTER", "extra RSQL filter, for example severity==High"),
    ("--output", "SI_OUTPUT_FILE", "JSON Lines output file"),
    ("--state", "SI_STATE_FILE", "export position file"),
    ("--poll-interval", "SI_POLL_INTERVAL", "seconds between polls (default 30)"),
    ("--lookback", "SI_LOOKBACK_SECONDS", "seconds re-read on every poll to catch late findings (default 3600)"),
    ("--backfill-hours", "SI_INITIAL_BACKFILL_HOURS", "history exported on the first run (default 24)"),
    ("--log-level", "SI_LOG_LEVEL", "DEBUG, INFO, WARNING or ERROR"),
]


def load_env_file(path):
    """Apply KEY=VALUE lines from a systemd-style env file without overriding the environment."""
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            os.environ.setdefault(name.strip(), value)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        epilog="Every option can also be set with the SI_* environment variable shown next to it.",
    )
    parser.add_argument("--once", action="store_true", help="run a single cycle and exit")
    parser.add_argument("--env-file", metavar="PATH", help="read SI_* settings from a KEY=VALUE file")
    parser.add_argument(
        "--insecure", action="store_true", help="do not verify the LiveNX certificate (SI_API_VERIFY_TLS=false)"
    )
    for flag, variable, text in CLI_OPTIONS:
        parser.add_argument(flag, metavar="VALUE", help="%s [%s]" % (text, variable))
    args = parser.parse_args(argv)
    if args.env_file:
        load_env_file(args.env_file)
    for flag, variable, _ in CLI_OPTIONS:
        value = getattr(args, flag[2:].replace("-", "_"))
        if value is not None:
            os.environ[variable] = value
    if args.insecure:
        os.environ["SI_API_VERIFY_TLS"] = "false"
    return args


def main(argv=None):
    try:
        args = parse_args(argv)
    except OSError as exc:
        print("cannot read --env-file: %s" % exc, file=sys.stderr)
        return EX_CONFIG

    logging.basicConfig(
        level=env("SI_LOG_LEVEL", "INFO").upper(), stream=sys.stderr, format="%(levelname)s %(message)s"
    )
    try:
        cfg = Config()
        for path in (cfg.output_file, cfg.state_file):
            directory = os.path.dirname(path) or "."
            os.makedirs(directory, exist_ok=True)
            if not os.access(directory, os.W_OK):
                raise ConfigError("%s is not writable; choose another location with --output/--state" % directory)
    except OSError as exc:
        log.error("configuration error: %s; choose another location with --output/--state", exc)
        return EX_CONFIG
    except (ConfigError, ValueError) as exc:
        log.error("configuration error: %s", exc)
        return EX_CONFIG
    source = ApiSource(cfg) if cfg.source == "api" else ClickHouseSource(cfg)
    exporter = Exporter(
        cfg, source, State(cfg.state_file).load(), Output(cfg.output_file, cfg.rotate_max_bytes, cfg.rotate_keep)
    )
    log.info(
        "source=%s%s output=%s poll=%ss lookback=%ss checkpoint=%s",
        cfg.source, " url=" + cfg.api_url if cfg.source == "api" else "",
        cfg.output_file, cfg.poll_interval, cfg.lookback, exporter.state.checkpoint,
    )

    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())

    failures = 0
    while not stop.is_set():
        try:
            count = exporter.run_cycle()
            failures = 0
            if count:
                log.info("exported %d finding(s)", count)
        except Exception as exc:  # keep running: the source may simply be restarting
            failures += 1
            log.error("cycle failed (%d in a row): %s", failures, exc)
            if args.once:
                return 1
        if args.once:
            return 0
        stop.wait(min(cfg.poll_interval * (2 ** min(failures, 4)), 300))
    log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
