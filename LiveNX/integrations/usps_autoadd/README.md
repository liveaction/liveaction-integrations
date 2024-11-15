# Create/formalize Custom Application Upload/Sync Script (USPS)

A Python utility that Create/formalize Custom Application them in LiveNX.

## Overview

This tool scans Raw file registers them as custom application devices in LiveNX.

## Prerequisites

- Python 3.x
- Access to LiveNX API
- Required environment variables:
  - `LIVENX_API_HOST`: LiveNX server hostname
  - `LIVENX_API_PORT`: LiveNX API port
  - `LIVENX_API_TOKEN`: Authentication token for LiveNX API

## Installation

1. Clone this repository
2. Set up the required environment variables:
```bash
export LIVENX_API_HOST="your.livenx.host"
export LIVENX_API_PORT="8093"
export LIVENX_API_TOKEN="your-api-token"
```

## Usage

### Basic Command
```bash
# Run monitor script 
python3 adddevice.py --rawfile /path/to/your/rawfile.csv
```

### Command Line Arguments

| Argument | Description | Required | Default |
|----------|-------------|----------|----------|
| `--rawfile` | Path to the log file to monitor | Yes | Null |
| `--delimiter` | Monitor the log file continuously | No | ; |

## Features

### Raw File Access
- Parses raw files for List of IPs
- Extracts Raw id Address Type present

### Custom Application Registration
- Creates custom applications entries in LiveNX

### API Integration
- Secure HTTPS communication with LiveNX API
- Bearer token authentication
- Automatic node discovery and selection
- SSL certificate verification bypass for internal networks

## Error Handling

- SSL certificate verification disabled for internal networks
- Robust error handling for file operations
- API communication error logging
- Input validation for command line arguments

## Logging

The program uses Python's custom application module to provide detailed operation information, including:
- Command line arguments
- Discovered Valid Row addresses
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