# LiveNX Log Monitor and Auto Device Registration

A Python utility that monitors log files for unknown device connections and automatically registers them in LiveNX.

## Overview

This tool scans log files for messages about unknown devices sending flow packets, extracts their IP addresses, and automatically registers them as virtual devices in LiveNX. It can run as a one-time operation or continuously monitor the log file.

## Prerequisites

- Python 3.x
- Access to LiveNX API
- Required environment variables:
  - `LIVENX_API_HOST`: LiveNX server hostname
  - `LIVENX_API_PORT`: LiveNX API port
  - `LIVENX_API_TOKEN`: Authentication token for LiveNX API
  - `LIVENX_TARGET_IP`: Target LiveNX node IP address

## Installation

1. Clone this repository
2. Set up the required environment variables:
```bash
export LIVENX_API_HOST="your.livenx.host"
export LIVENX_API_PORT="8093"
export LIVENX_API_TOKEN="your-api-token"
export LIVENX_TARGET_IP="your-target-node-ip"
```

## Usage

### Basic Command
```bash
# Run once
python3 script.py --logfile /path/to/your/logfile.log

# Run continuously
python3 script.py --logfile /path/to/your/logfile.log --continuous
```

### Command Line Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `--logfile` | Path to the log file to monitor | Yes |
| `--continuous` | Monitor the log file continuously | No |

## Features

### Log File Monitoring
- Parses log files for "Flow packet received from unknown device" messages
- Extracts IP addresses using regular expressions
- Can run as one-time scan or continuous monitor

### Device Registration
- Automatically creates virtual device entries in LiveNX
- Sets up basic interface configuration (ge0/0)
- Uses IP address as hostname
- Configures default network parameters

### API Integration
- Secure HTTPS communication with LiveNX API
- Bearer token authentication
- Automatic node discovery and selection
- SSL certificate verification bypass for internal networks

## Default Device Configuration

Registered devices will have the following default configuration:
- Interface: ge0/0
- Subnet Mask: 255.255.255.0
- Input/Output Capacity: 1000000
- Sample Ratio: 2
- Basic interface configuration without WAN or XCON settings

## Error Handling

- SSL certificate verification disabled for internal networks
- Robust error handling for file operations
- API communication error logging
- Input validation for command line arguments

## Logging

The program uses Python's logging module to provide detailed operation information, including:
- Command line arguments
- Discovered IP addresses
- API responses
- Error conditions

## Security Considerations

- SSL certificate verification is disabled by default
- API tokens should be kept secure
- Environment variables used for sensitive configuration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Known Limitations

- Only processes logs with specific message format
- Uses basic device configuration
- SSL certificate verification disabled
- Single interface configuration

## License

This project is licensed under the MIT License.