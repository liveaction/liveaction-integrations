# NAT data from LiveNX and DHCP leases from Infoblox

Script to fetch NAT data from LiveNX and DHCP leases from Infoblox, then consolidate into a report.

## Overview

This tool fetch the device NAT data.

## Prerequisites

- Python 3.x
- Access to LiveNX API
- Access to Infoblox API

## Installation

1. Clone this repository

## Usage

### Basic Command
```bash
# Run monitor script 
python infoblox_script.py --livenx_host=<livenx.host> --livenx_token=<livenx-api-token> --report_id=<livenx-report-id> --device_serial=<livenx-device-serial> --infoblox_host=<inflox-host> --infoblox_username=<inflox-username> --infoblox_password=<inflox-password>
```

### Command Line Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `--livenx_host` | Livenx hostname/Ipadress | Yes |
| `--livenx_token` | Livenx api token | Yes |
| `--report_id` | Livenc Report ID to  | Yes |
| `--device_serial` | Livenc Device Serial | Yes |
| `--infoblox_host` | Infoblox host | Yes |
| `--infoblox_username` | Infoblox username | Yes |
| `--infoblox_password` | Infoblox password | Yes |