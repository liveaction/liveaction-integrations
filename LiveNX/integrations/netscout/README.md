# Netscout CSV Custom Applications Import Script

A Python utility that imports CSV files exported from Netscout into LiveNX as custom applications.

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
# Run import script 
python3 import_applications.py --rawfile /path/to/your/rawfile.csv
```

### Command Line Arguments

| Argument | Description | Required | Default |
|----------|-------------|----------|----------|
| `--rawfile` | Path to the netscout application CSV file | Yes | Null |
| `--delimiter` | Column separator to access values | No | ; |

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
