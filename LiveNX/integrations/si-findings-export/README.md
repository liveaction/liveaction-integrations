# LiveNX Security Insight findings exporter

A Debian or RHEL 8 package that runs a small Python service which continuously reads
LiveNX Security Insight findings (the `si_findings` table) and appends them to
a JSON Lines file:

```
/data/si-findings-export/si_findings.jsonl
```

One finding per line, ready to be tailed by a log shipper (OTel `filelog`
receiver, Splunk forwarder, Cribl, ...).

## Where the findings come from

| Source | `SI_SOURCE` | Runs where | Notes |
|---|---|---|---|
| LiveNX REST API (default) | `api` | Any host that reaches LiveNX on 443 | `GET https://<livenx>/api/security-proxy/api/v1/findings` with a LiveNX API bearer token. Values are already decoded (`"severity": "High"`, `"protocol_id": "TCP"`). |
| ClickHouse | `clickhouse` | On the LiveNX server only | Reads `livenx_platformdb.si_findings_dist` over ClickHouse HTTPS (`127.0.0.1:10443`) with the read-only account LiveNX provisions. Values are numeric codes (`"severity": 2`, `"protocol_id": 6`). |

The REST API is the Security Insight Service (`ndm-security-insight-service`,
`127.0.0.1:4043` on the server) published through the LiveNX web server. It is
the recommended source: no database credentials, no dependency on the table
schema, and it works off-box. ClickHouse's HTTPS port is not opened by the
LiveNX firewall, so the ClickHouse source is only for installs on the LiveNX
server itself.

## Run without the package

The exporter is a single standard-library script (Python 3.6+, so RHEL 8's default `python3` works), so it also runs
straight from this directory on any machine that reaches LiveNX on port 443:

```bash
export SI_API_TOKEN=<LiveNX API token>
python3 si_findings_export.py --livenx-host livenx.example.com --insecure \
    --output ./si_findings.jsonl --state ./state.json
```

Some LiveNX servers only accept a JWT on the Security Insight path and answer
the API token with `401 ... jwt malformed`, even though the same token works
on port 8093. On those servers log in with a LiveNX user instead:

```bash
export SI_API_USERNAME=<read-only LiveNX user>
export SI_API_PASSWORD='<password>'   # environment only, there is no password option
python3 si_findings_export.py --livenx-host livenx.example.com --insecure \
    --output ./si_findings.jsonl --state ./state.json
```

The exporter logs in at `/auth/oauth/login`, uses the 15 minute JWT it gets
back, and logs in again shortly before it expires or after a 401. If both a
token and a username and password are set, the token is used. SAML, OIDC and
RADIUS-only accounts cannot use this; on the LiveNX server itself,
`SI_SOURCE=clickhouse` needs neither.

It runs until interrupted (Ctrl-C); add `--once` for a single pass. Every
setting has an `SI_*` environment variable and most have an option
(`python3 si_findings_export.py --help`). Command-line options override the
environment, which overrides `--env-file PATH` (the same file format the
package installs). Without `--output` and `--state` the script writes to
`/data/si-findings-export/`, which must exist and be writable.

## Build

```bash
./build_deb.sh        # Debian/Ubuntu; needs dpkg-deb (macOS: brew install dpkg)
./build_rpm.sh        # RHEL 8; uses rpmbuild, or an AlmaLinux 8 container via docker
```

Produces `dist/livenx-si-findings-export_<version>_all.deb` and
`dist/livenx-si-findings-export-<version>-1.noarch.rpm`. Both packages are
architecture independent, carry the same files and need only `python3`
(standard library only).

## Install

Works on any Debian/Ubuntu or RHEL 8 host with systemd, including the LiveNX
server.

Debian/Ubuntu:

```bash
scp dist/livenx-si-findings-export_<version>_all.deb admin@<host>:/tmp/
ssh admin@<host>
sudo dpkg -i /tmp/livenx-si-findings-export_<version>_all.deb
```

RHEL 8 (Rocky, Alma and other rebuilds too):

```bash
scp dist/livenx-si-findings-export-<version>-1.noarch.rpm admin@<host>:/tmp/
ssh admin@<host>
sudo dnf install /tmp/livenx-si-findings-export-<version>-1.noarch.rpm
```

`dnf` installs `python36` if it is missing. The install was tested on AlmaLinux 8
in a container without systemd, so the service start was not exercised there.
If SELinux is enforcing and the service fails to write to `/data`, check
`ausearch -m avc -ts recent`.

Then point it at LiveNX and start it:

```bash
sudo vi /etc/livenx-si-findings-export/si-findings-export.env
#   SI_LIVENX_HOST=livenx.example.com
#   SI_API_TOKEN=<LiveNX API token>
#   SI_API_VERIFY_TLS=false        # only if LiveNX uses a self-signed certificate
sudo systemctl restart livenx-si-findings-export
```

Until `SI_LIVENX_HOST` is set the service logs a configuration error and stays
stopped (it does not restart-loop).

To use ClickHouse instead when installed on the LiveNX server, set
`SI_SOURCE=clickhouse`; no host or token is needed.

### Verify

```bash
systemctl status livenx-si-findings-export
journalctl -u livenx-si-findings-export -f
tail -f /data/si-findings-export/si_findings.jsonl
```

On first start the last 24 hours of findings are exported
(`SI_INITIAL_BACKFILL_HOURS`), so the file fills immediately.

## Surviving a LiveNX reboot

LiveNX boots from a read-only squashfs image with a RAM-backed overlay on `/`.
Anything written to `/usr`, `/opt` or `/lib` is gone after a reboot. Only
`/etc`, `/var`, `/home` and `/data` are persistent, so the package installs
exclusively there:

| Path | Purpose |
|---|---|
| `/var/lib/livenx-si-findings-export/si_findings_export.py` | The exporter |
| `/etc/systemd/system/livenx-si-findings-export.service` | systemd unit (not `/lib/systemd/system`, which is volatile) |
| `/etc/livenx-si-findings-export/si-findings-export.env` | Configuration, mode 0600 (holds the API token) |
| `/data/si-findings-export/` | Output file, rotated files and `state.json` |

The service account (`si-findings-export`, created at install), the
`systemctl enable` symlink and the dpkg database also live under `/etc` and
`/var`, so after a reboot the service starts on its own and `dpkg -l` still
shows the package. The unit waits for the `/data` mount before starting.

A LiveNX **upgrade** replaces the base image. `/etc`, `/var` and `/data` are
expected to carry over, but check `systemctl status livenx-si-findings-export`
after an upgrade and reinstall the package if it is missing.

## Output

```json
{"time":"2026-11-13 15:28:42","saddr":"10.9.100.14","daddr":"54.169.219.143","addrs_are_ipv4":true,"sport":50019,"dport":80,"protocol_id":"TCP","application":"HTTP","indicator_id":"Unknown","source_id":"Flow Indicator","data_src":"10.255.255.41","data_src_is_ipv4":true,"score":1,"description":"Encryption was detected on a port that typically carries unencrypted traffic","category":"Encrypted Traffic Analysis","confidence":"High","domain":"54.169.219.143","hostname":"10.9.100.14","message":"Unexpected Encryption","mitre_category":"Command and Control","mitre_id":"T1571","severity":"Low","interval_finding_id":"00000000-0000-0000-0000-000000000000","interval_rollup_count":0}
```

- `time` is in the LiveNX server's time zone (UTC on a standard install).
- The file is rotated at 100 MB to `si_findings.jsonl.1` ... `.5`
  (`SI_ROTATE_MAX_BYTES`, `SI_ROTATE_KEEP`). Worst case disk use is about
  600 MB with the defaults.

## How it tails the table

Findings have no insert timestamp and are sometimes written many minutes after
their `time` value (18 minutes was observed), so "give me rows newer than the
last one" loses data. Each poll (every 30 s) therefore re-reads the last hour
(`SI_LOOKBACK_SECONDS`) and writes only the rows it has not written before,
tracked in `state.json`.

- **No loss inside the lookback window.** A finding written more than
  `SI_LOOKBACK_SECONDS` after its `time` is missed; raise the value if needed.
- **At-least-once.** A crash between writing the output and saving the state
  can repeat a batch. It never skips one.
- **Downtime is covered.** After a stop or outage the exporter resumes from its
  saved position. LiveNX keeps findings for 14 days.
- **No cursor paging.** The API's `cursor` paging drops rows that share a
  timestamp across a page boundary, so each time window is fetched as a single
  page and halved when it does not fit.

## Configuration

All settings are in `/etc/livenx-si-findings-export/si-findings-export.env`,
with their defaults shown as comments. The file is a dpkg conffile: package
upgrades keep your edits.

| Variable | Default | Meaning |
|---|---|---|
| `SI_LIVENX_HOST` | (required for `api`) | LiveNX hostname or IP |
| `SI_API_TOKEN` | | LiveNX API bearer token |
| `SI_API_USERNAME` / `SI_API_PASSWORD` | | Log in with a LiveNX user instead of using a token (see below). Set both. Ignored when `SI_API_TOKEN` is set |
| `SI_API_LOGIN_URL` | `https://<host>/auth/oauth/login` | Login endpoint override |
| `SI_API_VERIFY_TLS` / `SI_API_CA_FILE` | `true` / none | Certificate verification for the LiveNX HTTPS endpoint |
| `SI_API_FILTER` | | Extra RSQL filter, e.g. `severity==High` |
| `SI_API_URL` | derived from host | Full endpoint URL override |
| `SI_SOURCE` | `api` | `api` or `clickhouse` |
| `SI_OUTPUT_FILE` | `/data/si-findings-export/si_findings.jsonl` | Output file |
| `SI_STATE_FILE` | `/data/si-findings-export/state.json` | Export position |
| `SI_POLL_INTERVAL` | `30` | Seconds between polls |
| `SI_LOOKBACK_SECONDS` | `3600` | Re-read window for late findings |
| `SI_INITIAL_BACKFILL_HOURS` | `24` | History exported on first start |
| `SI_ROTATE_MAX_BYTES` / `SI_ROTATE_KEEP` | `104857600` / `5` | Output rotation |

To re-export from scratch, stop the service, delete `state.json`, and start it.

## Uninstall

```bash
sudo dpkg -r livenx-si-findings-export     # keeps configuration and state
sudo dpkg -P livenx-si-findings-export     # also removes config, state and the service account
```

On RHEL 8:

```bash
sudo dnf remove livenx-si-findings-export  # keeps the account, state and exported files
```

An edited env file is kept as `si-findings-export.env.rpmsave`. Remove the
`si-findings-export` account and `/data/si-findings-export/state.json` by hand
for a full clean-up.

Exported files in `/data/si-findings-export/` are never deleted by the package.

## Development

```bash
pip install pytest
pytest test_si_findings_export.py

```

`dist/` (the built package) is ignored by git; run `./build_deb.sh` or `./build_rpm.sh` to produce it.
