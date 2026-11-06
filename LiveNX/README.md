# LiveNX Specific documentation, diagnostic and integration scripts

## docs
 
Documentation for LiveNX

## diagnostic
This repository is designed to perform various network diagnostic tasks such as SNMP walks, packet captures, API data collection from vManage, pings, and tracepaths. It automates these tasks using command-line arguments, making it suitable for network troubleshooting and diagnostics.

## integrations

This repository contains the integrations from LiveAction's LiveNX to third party platforms.

## device-discovery

Standard-library Python scripts that use the LiveNX API to discover network devices on IP addresses/ranges (`livenx_discover.py`) and to list the devices already onboarded to LiveNX (`livenx_devices_csv.py`), both as CSV. See [device-discovery/README.md](device-discovery/README.md).

## kafka

This repository contains support for streaming data from LiveAction's LiveNX to Apache Kafka.

## grafana

This repository contains Grafana Dashboards for the LiveNX product.

## configs

This repository contains recommended router configurations to be applied in order for provide the nescessary requirements for the LiveNX product.

## Features


## License

This project is licensed under the MIT License.