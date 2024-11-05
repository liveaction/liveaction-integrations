Here is a `README.md` file describing the functionality of the SQL file.

```markdown
# ClickHouse Kafka Table and Materialized View Creation Script

This script automates the creation of a Kafka table and a materialized view in a ClickHouse database. It uses Docker to execute SQL commands on a running `clickhouse-server` container.

## Overview

The script performs the following tasks:
1. Drops any existing tables named `livenx_flowdb.basic_entity_1m_stream` and `livenx_flowdb.basic_entity_1m_stream_mv`.
2. Creates a new Kafka-engine table `livenx_flowdb.basic_entity_1m_stream` that streams JSON messages from a specified Kafka topic.
3. Creates a materialized view `livenx_flowdb.basic_entity_1m_stream_mv` to materialize data from the Kafka stream table.

## Prerequisites

Ensure that:
- Docker is installed and running.
- A ClickHouse server is running in a Docker container named `clickhouse-server`.
- Kafka is set up and running with the specified broker, topic, and consumer group.

## Usage

Run the script with the following syntax:
```bash
./start_kafka_stream.sh <kafka_broker> <kafka_topic> <kafka_group>
```

### Arguments
- `<kafka_broker>`: Kafka broker list (e.g., `broker1:9092,broker2:9092`)
- `<kafka_topic>`: The Kafka topic name to stream from.
- `<kafka_group>`: Kafka consumer group name.

### Example
```bash
./start_kafka_stream.sh localhost:9092 my_topic my_consumer_group
```

## Table Schema

The Kafka table `livenx_flowdb.basic_entity_1m_stream` contains the following fields:

| Column               | Data Type                       | Description                                 |
|----------------------|---------------------------------|---------------------------------------------|
| `time`               | `DateTime`                      | Timestamp with compression                  |
| `FlowDirection`      | `UInt8`                         | Flow direction indicator                    |
| `DeviceSiteRegion`   | `LowCardinality(String)`        | Region of the device site                   |
| `DeviceSiteName`     | `LowCardinality(String)`        | Name of the device site                     |
| `DeviceSerial`       | `String`                        | Serial number of the device                 |
| `EgressIfWanType`    | `UInt8`                         | Type of WAN for egress interface            |
| `EgressSpName`       | `LowCardinality(String)`        | Egress service provider name                |
| `DeviceAndEgressIfTagSetId` | `UInt32`                | Identifier for device and egress tag set    |
| `EgressIfIndex`      | `UInt32` (with compression)     | Egress interface index                      |
| `EgressIfName`       | `String`                        | Egress interface name                       |
| `IngressIfWanType`   | `UInt8`                         | Type of WAN for ingress interface           |
| `IngressSpName`      | `LowCardinality(String)`        | Ingress service provider name               |
| `DeviceAndIngressIfTagSetId` | `UInt32`              | Identifier for device and ingress tag set   |
| `IngressIfIndex`     | `UInt32` (with compression)     | Ingress interface index                     |
| `IngressIfName`      | `String`                        | Ingress interface name                      |
| `SumFlowCount`       | `UInt64`                        | Sum of flow counts                          |
| `SumPackets`         | `Nullable(UInt64)`              | Sum of packets (nullable)                   |
| `SumOctets`          | `Nullable(UInt64)`              | Sum of octets (nullable)                    |
| `Sampled`            | `Bool`                          | Sampling indicator                          |

## Kafka Settings

The Kafka engine table uses the following settings:
- `kafka_broker_list`: Set to the provided `<kafka_broker>` argument.
- `kafka_topic_list`: Set to the provided `<kafka_topic>` argument.
- `kafka_group_name`: Set to the provided `<kafka_group>` argument.
- `kafka_format`: Uses `JSONEachRow` format for reading JSON messages.

## Notes

- **Materialized View**: The materialized view `livenx_flowdb.basic_entity_1m_stream_mv` continuously materializes data from the Kafka table.
- **Data Compression**: Several columns use ClickHouse compression codecs (e.g., `DoubleDelta`, `LZ4`, `T64`) for optimized storage.

## License

This script is open-source and can be modified as needed.
```

This `README.md` should help users understand how to use and what to expect from the script. Let me know if you need further customization!