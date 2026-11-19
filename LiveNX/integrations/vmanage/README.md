# Cisco SD-WAN vManage to LiveNX Inventory Sync

Imports Cisco SD-WAN devices (vEdge/cEdge) from vManage into LiveNX as virtual devices.

## Overview

This tool logs in to vManage, reads the device list (`GET /dataservice/device`) and adds any device that
LiveNX doesn't already have. A device counts as already present when both hostname and address match.
It is add-only: nothing is ever removed from LiveNX. New devices are created on the LiveNX node whose
`ipAddress` equals `LIVENX_TARGET_IP`.

It runs as part of the main integration tool (`main.py`), not as a standalone script.

## Features

- **vManage Login**: Session login (`j_security_check`) plus XSRF token for 19.2+ releases, with logout when done
- **Device Filtering**: Import only selected `device-type` values (default `vedge`) and optionally only reachable devices
- **Differential Updates**: Only devices missing from LiveNX are sent
- **Site Mapping**: Devices land in `SDWAN-Site-<site-id>`, or in one site you choose
- **Interactive Prompts**: Confirms additions unless `--noprompt` is used
- **Continuous Mode**: Works with `--continuous` like the other syncs

## Prerequisites

- Python 3.x
- Access to the LiveNX API (token and `LIVENX_TARGET_IP` of a LiveNX node)
- Access to the vManage API (a user that can read `/dataservice/device`)
- Required Python packages (see requirements.txt)

## Installation

1. Clone the repository and navigate to the integrations directory:
```bash
cd LiveNX/integrations
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

All settings are environment variables.

### LiveNX
- `LIVENX_API_HOST`: LiveNX server host/IP
- `LIVENX_API_PORT`: LiveNX API port (e.g. 8093)
- `LIVENX_API_TOKEN`: LiveNX API token
- `LIVENX_TARGET_IP`: `ipAddress` of the LiveNX node that will own the new devices

### vManage
| Variable | Description | Default |
|----------|-------------|---------|
| `VMANAGE_API_HOST` | vManage host/IP | |
| `VMANAGE_API_PORT` | vManage port | 8443 |
| `VMANAGE_API_USER` | vManage username | |
| `VMANAGE_API_PASSWORD` | vManage password | |
| `VMANAGE_API_VERIFY_SSL` | Verify the vManage TLS certificate | false |
| `VMANAGE_DEVICE_TYPES` | Comma separated vManage `device-type` values to import | vedge |
| `VMANAGE_ONLY_REACHABLE` | Skip devices vManage reports unreachable | false |
| `VMANAGE_LIVENX_SITE` | Put all devices in this LiveNX site | `SDWAN-Site-<site-id>` |

## Usage

```bash
# Add vManage devices to LiveNX (prompts before adding)
python3 main.py --inventory --fromproduct vmanage --toproduct livenx

# Run continuously with no prompts
python3 main.py --inventory --fromproduct vmanage --toproduct livenx --continuous --noprompt
```

### Using Docker Run

```bash
docker run -e LIVENX_API_HOST=10.0.0.1 -e LIVENX_API_PORT=8093 -e LIVENX_API_TOKEN=your_token_here -e LIVENX_TARGET_IP=10.0.0.1 -e VMANAGE_API_HOST=10.10.10.1 -e VMANAGE_API_USER=admin -e VMANAGE_API_PASSWORD="password" liveaction/livenx-integrations --inventory --fromproduct vmanage --toproduct livenx --continuous --noprompt
```

### Using Docker Compose

Set the `VMANAGE_API_*` values in `docker-compose.yml`, change the `command` to the vManage arguments above, then:

```bash
docker compose up -d
```

## Field Mapping

| LiveWire Product | External Product | Attribute in LiveNX | Attribute in External Product |
| ---------------- | ---------------- | ------------------- | ----------------------------- |
| LiveNX | vManage | hostName / systemName | host-name (falls back to system-ip) |
| LiveNX | vManage | address | system-ip |
| LiveNX | vManage | systemDescription | device-model, version, board-serial |
| LiveNX | vManage | site | site-id (as `SDWAN-Site-<site-id>`) |
| LiveNX | vManage | interfaces[0].address | system-ip (single placeholder interface) |

## Notes

- The target LiveNX site may need to exist already; if device creation is rejected, set `VMANAGE_LIVENX_SITE` to an existing site.
- Only one placeholder interface (the system IP) is created per device; real interfaces are not imported.

## Testing

```bash
pytest test_vmanage.py
```

The tests are offline and don't need a vManage or LiveNX.
