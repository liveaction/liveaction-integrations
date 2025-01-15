# Network Diagnostics Tool

This Python script is designed to perform various network diagnostic tasks such as SNMP walks, packet captures, API data collection from vManage, pings, and tracepaths. It automates these tasks using command-line arguments, making it suitable for network troubleshooting and diagnostics.

## Features

- **SNMP v2/v3 Walk**: Perform SNMP walks on target devices (v2c and v3 supported).
- **Packet Capture**: Capture network traffic on a specified interface for a given duration.
- **vManage API Interaction**: Retrieve device statistics and information from a Cisco vManage instance using REST API.
- **Ping**: Test network connectivity to a target IP address.
- **Tracepath**: Run tracepath to diagnose network routing issues.
- **System Logs**: Collect and save system logs.

## Prerequisites

- Python 3.x
- `snmpwalk` installed (for SNMP operations)
- `tcpdump` installed (for packet capture)
- `ping` installed (for pinging targets)
- `tracepath` installed (for tracing network paths)
- Root or sudo access (for packet capturing and some other commands)
- Access to a Cisco vManage instance (for API data collection)

## Installation

1. Clone this repository or copy the script to your local environment.
2. Install the necessary Python libraries:
   ```bash
   pip install requests argparse
   ```

3. Ensure the system has the required tools installed:
   - `snmpwalk`
   - `tcpdump`
   - `ping`
   - `tracepath`

## Usage

To run the diagnostics script, use the following command syntax:

```bash
python3 diag.py [OPTIONS]
```

### Options

| Option                   | Description                                                                 |
|---------------------------|-----------------------------------------------------------------------------|
| `--target_ip`             | The target IP address for SNMP, ping, and tracepath operations.              |
| `--vmanage_ip`            | The IP address of the vManage instance.                                      |
| `--vmanage_port`          | The port for vManage API interaction (default: 8443).                        |
| `--vmanage_username`      | The username for vManage API authentication.                                 |
| `--vmanage_password`      | The password for vManage API authentication.                                 |
| `--vmanage_mins`          | Number of minutes of vManage data to collect (default: 10).                  |
| `--vmanage_max_count`     | Maximum number of records to collect from vManage (default: 1000).           |
| `--capture`               | Capture packets on the default interface (eth0) for 60 seconds.              |
| `--logs`                  | Collect system logs using `journalctl`.                                      |
| `--ping`                  | Ping the target IP address.                                                  |
| `--trace`                 | Run tracepath to the target IP address.                                      |
| `--snmpv2walkcommunity`   | SNMP v2 community string for performing SNMP walk.                           |
| `--snmpv3walkuser`        | SNMP v3 username for performing SNMP walk.                                   |
| `--snmpv3authpassword`    | SNMP v3 authentication password.                                             |
| `--snmpv3walkpassphrase`  | SNMP v3 encryption passphrase.                                               |
| `--vmanage_use_token`     | Use token-based authentication for vManage.                                  |

### Example Commands

- **Run an SNMP v2 walk:**
  ```bash
  python3 diag.py --target_ip 192.168.1.1 --snmpv2walkcommunity public
  ```

- **Perform a packet capture for 60 seconds:**
  ```bash
  python3 diag.py --capture
  ```

- **Retrieve data from vManage:**
  ```bash
  python3 diag.py --vmanage_ip 10.10.10.1 --vmanage_username admin --vmanage_password password --vmanage_mins 10 --vmanage_max_count 100
  ```

- **Ping a target IP:**
  ```bash
  python3 diag.py --target_ip 8.8.8.8 --ping
  ```

- **Run tracepath to a target IP:**
  ```bash
  python3 diag.py --target_ip 8.8.8.8 --trace
  ```

- **Run healthcheck Testcases to a liveNX:**
  ```bash
  pytest test_diag.py --livenx_ip=<livenx ip> --livenx_port=<livenx port default 8093> --livenx_token=<livenx token>
  ```

## Output

- SNMP walk results are saved to `snmpv2_walk_output.txt` or `snmpv3_walk_output.txt`.
- Packet captures are saved as `.pcap` files (e.g., `packet_capture_YYYYMMDDHHMMSS.pcap`).
- vManage API data is logged to `vmanage_data_json`.
- System logs are saved as `system_logs_YYYYMMDDHHMMSS.log`.
- Tracepath results are saved to `tracepath_output.txt`.

## Troubleshooting

- Ensure that `snmpwalk`, `tcpdump`, `ping`, and `tracepath` are installed on the system and accessible via the command line.
- vManage operations require valid credentials and an active connection to the vManage server.

## License

This project is licensed under the MIT License.
