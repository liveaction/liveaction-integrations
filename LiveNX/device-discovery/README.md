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

Starts a discovery job, polls it until it finishes, and prints the discovered devices. By
default it **only discovers**: it does not add devices to LiveNX. Add `--add-devices` to also
add the newly discovered ones (see [Adding new devices](#adding-new-devices-to-livenx)).

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
| `--add-devices` | off | Add newly discovered devices (not already onboarded) to LiveNX |
| `--preview-add` | off | Report which devices would be added and the request that would be sent; adds nothing |
| `--add-node-ip` / `--add-node-id` | the discovery node | Node to add the devices to (mutually exclusive; need `--add-devices` or `--preview-add`) |
| `--community` | LiveNX credentials store | SNMPv2c community string |
| `--snmp-port` | `161` | SNMP port, used with `--community` |
| `--poll-interval` | `3` | Seconds between job status polls |
| `--timeout` | `1800` | Give up waiting after this many seconds (the job keeps running on the server) |
| `--verify-tls` | off | Verify the server certificate |
| `--dry-run` | off | Print the request and exit |

### Adding new devices to LiveNX

With `--add-devices`, once the job finishes successfully the script:

1. Fetches the devices already onboarded (`GET /v1/devices`).
2. Treats a discovered device as **new** if neither its serial/result ID nor its primary IP
   matches an onboarded device. The rest are reported as `existing` and left untouched.
3. Adds the new ones with `POST /v1/devices`, carrying over the discovered site, tags, group,
   polling settings and interfaces.

The node the devices are added to is the node discovery ran from (`--node-ip`/`--node-id`, or
the local server node). Use `--add-node-ip` or `--add-node-id` to add them to a different
node. The node is validated before discovery starts, so a typo fails immediately.

```bash
# See what would be added, without changing LiveNX
./livenx_discover.py --host 10.4.205.50 --api-key '<key>' --preview-add 10.0.1.0/24

# Discover from the local node, but add the new devices to another node
./livenx_discover.py --host 10.4.205.50 --api-key '<key>' --add-devices --add-node-ip 10.4.205.51 10.0.1.0/24
```

Nothing is added if the job finishes with `ERROR` or `CANCELLED`. Only devices that are not
already onboarded are sent, so re-running the same command is safe.

### Output

Progress goes to stderr while the job runs, for example
`status=RUNNING attempted=40/256 discovered=3`. The CSV on stdout has these columns:

`serial, hostName, systemName, primaryIp, vendor, model, osVersion`

When `--add-devices` or `--preview-add` is used, an extra `addStatus` column is appended
(`new`, `existing` or `added`); the default output is unchanged.

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
