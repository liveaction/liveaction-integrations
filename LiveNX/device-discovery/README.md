# LiveNX Device Discovery

Two small command-line scripts that use the LiveNX REST API (`/v1`) to discover network
devices and to list the devices already onboarded to LiveNX. Both print **CSV on stdout** and
progress/errors on stderr, so output can be redirected straight into a file.

Both scripts use only the Python standard library (Python 3.9+), so there is nothing to
install and they can run on the LiveNX server itself or on any machine that can reach the
LiveNX API.

| Script | Purpose | API calls |
|--------|---------|-----------|
| `livenx_discover.py` | Run SNMP discovery against IP addresses/ranges and print what was found | `POST /v1/deviceDiscovery/start/ipRange`, `GET /v1/deviceDiscovery/jobs/{id}`, `GET /v1/deviceDiscovery/jobs/{id}/results`, `GET /v1/nodes` |
| `livenx_devices_csv.py` | List devices currently onboarded to LiveNX with their primary IPs | `GET /v1/devices` |

## Prerequisites

- A LiveNX API key (passed with `--api-key`, sent as a `Bearer` token).
- Network access to the LiveNX API (default port `8093`).
- Discovery only: SNMP reachability from the LiveNX node to the targets, and either SNMP
  credentials saved in the LiveNX credentials store or an SNMPv2c community string.

LiveNX uses a self-signed certificate by default, so TLS verification is **off** unless you
pass `--verify-tls`.

## livenx_discover.py

Starts a discovery job, polls it until it finishes, and prints the discovered devices. It
**only discovers**: it does not add devices to LiveNX.

Targets are positional arguments and/or one per line in a `--file` (`-` reads stdin; `#`
starts a comment). Anything LiveNX accepts as an address or range is passed through
unchanged, for example `10.0.0.5`, `10.0.0.1-10.0.0.50` or `10.0.1.0/24`.

```bash
# Discover a host and a subnet using the SNMP credentials already stored in LiveNX
./livenx_discover.py --host 10.4.205.50 --api-key '<key>' 10.0.0.5 10.0.1.0/24

# Targets from a file, using an SNMPv2c community string
./livenx_discover.py --host 10.4.205.50 --api-key '<key>' --file targets.txt --community public > found.csv

# Show the request that would be sent (the community string is masked) without running discovery
./livenx_discover.py --host 10.4.205.50 --api-key '<key>' --dry-run 10.0.1.0/24
```

Example `targets.txt`:

```
# core switches
10.0.0.1-10.0.0.10
10.0.1.0/24
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `targets...` / `--file` | (one required) | IPs or ranges to discover; `--file -` reads stdin |
| `--host` | (required) | LiveNX API server IP or hostname |
| `--port` | `8093` | LiveNX API port |
| `--api-key` | (required) | LiveNX API key |
| `--node-ip` / `--node-id` | local server node | Node to run discovery from (mutually exclusive) |
| `--community` | LiveNX credentials store | SNMPv2c community string |
| `--snmp-port` | `161` | SNMP port, used with `--community` |
| `--poll-interval` | `3` | Seconds between job status polls |
| `--timeout` | `1800` | Give up waiting after this many seconds (the job keeps running on the server) |
| `--verify-tls` | off | Verify the server certificate |
| `--dry-run` | off | Print the request and exit |

### Output

Progress goes to stderr while the job runs, for example
`status=RUNNING attempted=40/256 discovered=3`. The CSV on stdout has these columns:

`serial, hostName, systemName, primaryIp, vendor, model, osVersion`

The script exits non-zero if the job finishes with a status other than `SUCCESS` (`ERROR` or
`CANCELLED`), after printing whatever results were returned.

## livenx_devices_csv.py

Prints the devices onboarded to LiveNX.

```bash
./livenx_devices_csv.py --host 10.4.205.50 --port 8093 --api-key '<key>' > devices.csv

# Include historical devices that are no longer onboarded
./livenx_devices_csv.py --host 10.4.205.50 --api-key '<key>' --include-historical
```

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | (required) | LiveNX API server IP or hostname |
| `--port` | `8093` | LiveNX API port |
| `--api-key` | (required) | LiveNX API key |
| `--include-historical` | off | Also include historical (no longer onboarded) devices |
| `--verify-tls` | off | Verify the server certificate |

CSV columns: `id, hostName, systemName, primaryIp, clientIp, site, vendor, model`

## Typical workflow

Use the two scripts together to find devices that LiveNX does not know about yet:

```bash
./livenx_devices_csv.py --host <livenx> --api-key '<key>' > onboarded.csv
./livenx_discover.py    --host <livenx> --api-key '<key>' --file targets.txt > discovered.csv
# compare the primaryIp columns of the two files
```

## Notes

- The API key is passed on the command line and is visible in the process list and shell
  history. On shared systems, prefer a short-lived key.
- The endpoints and fields used are defined in the LiveNX OpenAPI specification
  (`livenx_openapi.json`, available from your LiveNX server); that file is not included here.
