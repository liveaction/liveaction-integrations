#!/bin/bash

# Enable strict error handling
set -e 

# Check if all required arguments are provided
if [ $# -ne 3 ]; then
    echo "Usage: $0 <kafka_broker> <kafka_topic> <kafka_group>"
    exit 1
fi

# Assign arguments to variables
KAFKA_BROKER=$1
KAFKA_TOPIC=$2
KAFKA_GROUP=$3

# Execute the ClickHouse commands
docker exec -i clickhouse-server clickhouse-client -n <<-EOSQL

DROP TABLE IF EXISTS livenx_flowdb.basic_entity_1m_stream;
DROP TABLE IF EXISTS livenx_flowdb.basic_entity_1m_stream_mv;

-- Create the Kafka engine table
CREATE TABLE IF NOT EXISTS livenx_flowdb.basic_entity_1m_stream
(
    time DateTime CODEC(DoubleDelta, LZ4),
    FlowDirection UInt8,
    DeviceSiteRegion LowCardinality(String),
    DeviceSiteName LowCardinality(String),
    DeviceSerial String,
    EgressIfWanType UInt8,
    EgressSpName LowCardinality(String),
    DeviceAndEgressIfTagSetId UInt32,
    EgressIfIndex UInt32 CODEC(T64, LZ4),
    EgressIfName String,
    IngressIfWanType UInt8,
    IngressSpName LowCardinality(String),
    DeviceAndIngressIfTagSetId UInt32,
    IngressIfIndex UInt32 CODEC(T64, LZ4),
    IngressIfName String,
    SumFlowCount UInt64,
    SumPackets Nullable(UInt64),
    SumOctets Nullable(UInt64),
    Sampled Bool
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = '$KAFKA_BROKER',
    kafka_topic_list = '$KAFKA_TOPIC',
    kafka_group_name = '$KAFKA_GROUP',
    kafka_format = 'JSON';

-- Create the materialized view
CREATE MATERIALIZED VIEW IF NOT EXISTS livenx_flowdb.basic_entity_1m_stream_mv
TO livenx_flowdb.basic_entity_1m_stream
AS
SELECT
    time,
    FlowDirection,
    DeviceSiteRegion,
    DeviceSiteName,
    DeviceSerial,
    EgressIfWanType,
    EgressSpName,
    DeviceAndEgressIfTagSetId,
    EgressIfIndex,
    EgressIfName,
    IngressIfWanType,
    IngressSpName,
    DeviceAndIngressIfTagSetId,
    IngressIfIndex,
    IngressIfName,
    SumFlowCount,
    SumPackets,
    SumOctets,
    Sampled
FROM livenx_flowdb.basic_entity_1m;

EOSQL
