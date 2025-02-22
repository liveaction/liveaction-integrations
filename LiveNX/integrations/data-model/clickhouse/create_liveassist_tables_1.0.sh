#!/bin/bash
set -e
docker exec -i clickhouse-server clickhouse-client -n <<-EOSQL

CREATE TABLE IF NOT EXISTS default.structured_events
(
    alert_id String CODEC(ZSTD(1)),
    alert_type String CODEC(ZSTD(1)),
    timestamp DateTime64(6) CODEC(Delta(8), ZSTD(1)),
    severity_text String CODEC(ZSTD(1)),
    severity_number UInt32 CODEC(ZSTD(1)),
    message String CODEC(ZSTD(1)),
    source_ip String CODEC(ZSTD(1)),
    source_type String CODEC(ZSTD(1)),
    investigative_url String CODEC(ZSTD(1)),
    source String CODEC(ZSTD(1)),
    site_display String CODEC(ZSTD(1)),
    site_name String CODEC(ZSTD(1)),
    device_display String CODEC(ZSTD(1)),
    device_name String CODEC(ZSTD(1)),
    device_serial String CODEC(ZSTD(1)),
    four_tuple_display String CODEC(ZSTD(1)),
    interface_name String CODEC(ZSTD(1)),
    title String CODEC(ZSTD(1)),
    resolution Bool,
    policy String CODEC(ZSTD(1)),
    errors String CODEC(ZSTD(1)),
    note String CODEC(ZSTD(1)),
    dscp String CODEC(ZSTD(1)),
    initial_jitter_avg Float64,
    latest_jitter_avg Float64,
    initial_average_application_flow_delay Float64,
    latest_average_application_flow_delay Float64,
    initial_average_network_flow_delay Float64,
    latest_average_network_flow_delay Float64,
    device_status String CODEC(ZSTD(1)),
    previous_device_status String CODEC(ZSTD(1)),
    class_names String CODEC(ZSTD(1)),
    application_name String CODEC(ZSTD(1)),
    interface_capacity String CODEC(ZSTD(1)),
    interface_direction String CODEC(ZSTD(1)),
    initial_drop_rate Float64,
    latest_drop_rate Float64,
    initial_utilization Float64,
    latest_utilization Float64,
    bandwidth String CODEC(ZSTD(1)),
    configured_threshold Float64,
    interface_tags String CODEC(ZSTD(1)),
    device_tags String CODEC(ZSTD(1)),
    site_tags String CODEC(ZSTD(1)),
    mitre_category String CODEC(ZSTD(1)),
    description String CODEC(ZSTD(1)),
    level2_topology String CODEC(ZSTD(1)),
    level2_applicationsflow String CODEC(ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toDate(timestamp)
ORDER BY (message, toUnixTimestamp(timestamp))
TTL toDateTime(timestamp) + toIntervalDay(30)
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS default.otel_logs
(
    Timestamp DateTime64(9) CODEC(Delta(8), ZSTD(1)),
    TimestampTime DateTime DEFAULT toDateTime(Timestamp),
    TraceId String CODEC(ZSTD(1)),
    SpanId String CODEC(ZSTD(1)),
    TraceFlags UInt8,
    SeverityText LowCardinality(String) CODEC(ZSTD(1)),
    SeverityNumber UInt8,
    ServiceName LowCardinality(String) CODEC(ZSTD(1)),
    Body String CODEC(ZSTD(1)),
    ResourceSchemaUrl LowCardinality(String) CODEC(ZSTD(1)),
    ResourceAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    ScopeSchemaUrl LowCardinality(String) CODEC(ZSTD(1)),
    ScopeName String CODEC(ZSTD(1)),
    ScopeVersion LowCardinality(String) CODEC(ZSTD(1)),
    ScopeAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    LogAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    INDEX idx_trace_id TraceId TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_res_attr_key mapKeys(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_res_attr_value mapValues(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_scope_attr_key mapKeys(ScopeAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_scope_attr_value mapValues(ScopeAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_log_attr_key mapKeys(LogAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_log_attr_value mapValues(LogAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_body Body TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 8
)
ENGINE = MergeTree
PARTITION BY toDate(TimestampTime)
PRIMARY KEY (ServiceName, TimestampTime)
ORDER BY (ServiceName, TimestampTime, Timestamp)
TTL TimestampTime + toIntervalDay(3)
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS default.otel_metrics_sum
(
    ResourceAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    ResourceSchemaUrl String CODEC(ZSTD(1)),
    ScopeName String CODEC(ZSTD(1)),
    ScopeVersion String CODEC(ZSTD(1)),
    ScopeAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    ScopeDroppedAttrCount UInt32 CODEC(ZSTD(1)),
    ScopeSchemaUrl String CODEC(ZSTD(1)),
    ServiceName LowCardinality(String) CODEC(ZSTD(1)),
    MetricName String CODEC(ZSTD(1)),
    MetricDescription String CODEC(ZSTD(1)),
    MetricUnit String CODEC(ZSTD(1)),
    Attributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    StartTimeUnix DateTime64(9) CODEC(Delta(8), ZSTD(1)),
    TimeUnix DateTime64(9) CODEC(Delta(8), ZSTD(1)),
    Value Float64 CODEC(ZSTD(1)),
    Flags UInt32 CODEC(ZSTD(1)),
    Exemplars Nested(
        FilteredAttributes Map(LowCardinality(String), String),
        TimeUnix DateTime64(9),
        Value Float64,
        SpanId String,
        TraceId String
    ) CODEC(ZSTD(1)),
    AggregationTemporality Int32 CODEC(ZSTD(1)),
    IsMonotonic Bool CODEC(Delta(1), ZSTD(1)),
    INDEX idx_res_attr_key mapKeys(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_res_attr_value mapValues(ResourceAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_scope_attr_key mapKeys(ScopeAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_scope_attr_value mapValues(ScopeAttributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_attr_key mapKeys(Attributes) TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_attr_value mapValues(Attributes) TYPE bloom_filter(0.01) GRANULARITY 1
)
ENGINE = MergeTree
PARTITION BY toDate(TimeUnix)
ORDER BY (ServiceName, MetricName, Attributes, toUnixTimestamp64Nano(TimeUnix))
TTL toDateTime(TimeUnix) + toIntervalDay(3)
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE MATERIALIZED VIEW IF NOT EXISTS default.structured_events_view TO default.structured_events
(
    alert_id String,
    alert_type String,
    timestamp DateTime64(9),
    severity_text String,
    severity_number UInt8,
    message String,
    source_ip String,
    source_type String,
    investigative_url String,
    source String,
    site_display String,
    site_name String,
    device_display String,
    device_name String,
    device_serial String,
    four_tuple_display String,
    interface_name String,
    title String,
    resolution UInt8,
    policy String,
    errors String,
    note String,
    dscp String,
    initial_jitter_avg String,
    latest_jitter_avg String,
    initial_average_application_flow_delay String,
    latest_average_application_flow_delay String,
    initial_average_network_flow_delay String,
    latest_average_network_flow_delay String,
    device_status String,
    previous_device_status String,
    class_names String,
    application_name String,
    interface_capacity String,
    interface_direction String,
    initial_drop_rate String,
    latest_drop_rate String,
    initial_utilization String,
    latest_utilization String,
    bandwidth String,
    configured_threshold String,
    interface_tags String,
    device_tags String,
    site_tags String,
    mitre_category String,
    description String,
    level2_topology String,
    level2_applicationsflow String
)
AS SELECT
    LogAttributes['alertId'] AS alert_id,
    LogAttributes['alertType'] AS alert_type,
    Timestamp AS timestamp,
    SeverityText AS severity_text,
    SeverityNumber AS severity_number,
    Body AS message,
    LogAttributes['host.ip'] AS source_ip,
    LogAttributes['host.type'] AS source_type,
    LogAttributes['host.login.url'] AS investigative_url,
    LogAttributes['log.type'] AS source,
    if(mapContains(LogAttributes, 'sinfo.SITE.displayValue'), LogAttributes['sinfo.SITE.displayValue'], '') AS site_display,
    if(mapContains(LogAttributes, 'sinfo.SITE.siteName'), LogAttributes['sinfo.SITE.siteName'], '') AS site_name,
    if(mapContains(LogAttributes, 'sinfo.DEVICE.displayValue'), LogAttributes['sinfo.DEVICE.displayValue'], '') AS device_display,
    if(mapContains(LogAttributes, 'sinfo.DEVICE.deviceName'), LogAttributes['sinfo.DEVICE.deviceName'], '') AS device_name,
    if(mapContains(LogAttributes, 'sinfo.DEVICE.deviceSerial'), LogAttributes['sinfo.DEVICE.deviceSerial'], '') AS device_serial,
    if(mapContains(LogAttributes, 'sinfo.FOUR_TUPLE.displayValue'), LogAttributes['sinfo.FOUR_TUPLE.displayValue'], '') AS four_tuple_display,
    if(mapContains(LogAttributes, 'desc.sinfo.interfaceName'), LogAttributes['desc.sinfo.interfaceName'], '') AS interface_name,
    LogAttributes['title'] AS title,
    multiIf((LogAttributes['userStatus']) = 'ACTIVE', 0, (LogAttributes['userStatus']) = 'RESOLVED', 1, 0) AS resolution,
    if(mapContains(LogAttributes, 'Policy'), LogAttributes['Policy'], '') AS policy,
    if(mapContains(LogAttributes, 'Errors'), LogAttributes['Errors'], '') AS errors,
    if(mapContains(LogAttributes, 'Note'), LogAttributes['Note'], '') AS note,
    if(mapContains(LogAttributes, 'DSCP'), LogAttributes['DSCP'], '') AS dscp,
    if(mapContains(LogAttributes, 'Initial Jitter Avg'), extract(LogAttributes['Initial Jitter Avg'], '[+-]?[0-9.]+'), '0.0') AS initial_jitter_avg,
    if(mapContains(LogAttributes, 'Latest Jitter Avg'), extract(LogAttributes['Latest Jitter Avg'], '[+-]?[0-9.]+'), '0.0') AS latest_jitter_avg,
    if(mapContains(LogAttributes, 'Initial Average Application Flow Delay'), extract(LogAttributes['Initial Average Application Flow Delay'], '[+-]?[0-9.]+'), '0.0') AS initial_average_application_flow_delay,
    if(mapContains(LogAttributes, 'Latest Average Application Flow Delay'), extract(LogAttributes['Latest Average Application Flow Delay'], '[+-]?[0-9.]+'), '0.0') AS latest_average_application_flow_delay,
    if(mapContains(LogAttributes, 'Initial Average Network Flow Delay'), extract(LogAttributes['Initial Average Network Flow Delay'], '[+-]?[0-9.]+'), '0.0') AS initial_average_network_flow_delay,
    if(mapContains(LogAttributes, 'Latest Average Network Flow Delay'), extract(LogAttributes['Latest Average Network Flow Delay'], '[+-]?[0-9.]+'), '0.0') AS latest_average_network_flow_delay,
    if(mapContains(LogAttributes, 'Device Status'), LogAttributes['Device Status'], '') AS device_status,
    if(mapContains(LogAttributes, 'Previous Device Status'), LogAttributes['Previous Device Status'], '') AS previous_device_status,
    if(mapContains(LogAttributes, 'Class Names'), LogAttributes['Class Names'], '') AS class_names,
    if(mapContains(LogAttributes, 'Application Name'), LogAttributes['Application Name'], if(mapContains(LogAttributes, 'Application'), LogAttributes['Application'], if(mapContains(LogAttributes, 'application'), LogAttributes['application'], ''))) AS application_name,
    if(mapContains(LogAttributes, 'Interface Capacity'), LogAttributes['Interface Capacity'], '') AS interface_capacity,
    if(mapContains(LogAttributes, 'Interface Direction'), LogAttributes['Interface Direction'], '') AS interface_direction,
    if((LogAttributes['alertType']) = 'MEDIA_PACKET_LOSS_PERCENT', extract(LogAttributes['Initial Packet Loss'], '[+-]?[0-9.]+'), if(mapContains(LogAttributes, 'Initial Drop Rate'), extract(LogAttributes['Initial Drop Rate'], '[+-]?[0-9.]+'), '0.0')) AS initial_drop_rate,
    if((LogAttributes['alertType']) = 'MEDIA_PACKET_LOSS_PERCENT', extract(LogAttributes['Latest Packet Loss'], '[+-]?[0-9.]+'), if(mapContains(LogAttributes, 'Latest Drop Rate'), extract(LogAttributes['Latest Drop Rate'], '[+-]?[0-9.]+'), '0.0')) AS latest_drop_rate,
    multiIf((LogAttributes['alertType']) = 'DEVICE_CPU', extract(LogAttributes['Initial CPU Percentage'], '[+-]?[0-9.]+'), (LogAttributes['alertType']) = 'DEVICE_MEM', extract(LogAttributes['Initial Memory Percentage'], '[+-]?[0-9.]+'), if(mapContains(LogAttributes, 'Initial Utilization'), extract(LogAttributes['Initial Utilization'], '[+-]?[0-9.]+'), '0.0')) AS initial_utilization,
    multiIf((LogAttributes['alertType']) = 'DEVICE_CPU', extract(LogAttributes['Latest CPU Percentage'], '[+-]?[0-9.]+'), (LogAttributes['alertType']) = 'DEVICE_MEM', extract(LogAttributes['Latest Memory Percentage'], '[+-]?[0-9.]+'), if(mapContains(LogAttributes, 'Latest Utilization'), extract(LogAttributes['Latest Utilization'], '[+-]?[0-9.]+'), '0.0')) AS latest_utilization,
    if(mapContains(LogAttributes, 'Bandwidth'), LogAttributes['Bandwidth'], '0.0') AS bandwidth,
    if(mapContains(LogAttributes, 'Configured Threshold'), extract(LogAttributes['Configured Threshold'], '[+-]?[0-9.]+'), '0.0') AS configured_threshold,
    if(mapContains(LogAttributes, concat('interfaceName.', LogAttributes['desc.sinfo.interfaceName'], '.tagValue')), LogAttributes[concat('interfaceName.', LogAttributes['desc.sinfo.interfaceName'], '.tagValue')], '') AS interface_tags,
    if(mapContains(LogAttributes, concat('deviceSerial.', LogAttributes['sinfo.DEVICE.deviceSerial'], '.tagValue')), LogAttributes[concat('deviceSerial.', LogAttributes['sinfo.DEVICE.deviceSerial'], '.tagValue')], '') AS device_tags,
    if(mapContains(LogAttributes, concat('siteName.', LogAttributes['sinfo.SITE.siteName'], '.tagValue')), LogAttributes[concat('siteName.', LogAttributes['sinfo.SITE.siteName'], '.tagValue')], '') AS site_tags,
    if(mapContains(LogAttributes, 'mitrecategory'), LogAttributes['mitrecategory'], '') AS mitre_category,
    if(mapContains(LogAttributes, 'description'), LogAttributes['description'], '') AS description,
    if(mapContains(LogAttributes, 'LevelTwoInformation_topologypath'), LogAttributes['LevelTwoInformation_topologypath'], if(mapContains(LogAttributes, 'LevelTwoInformation_4tupletopologypath'), LogAttributes['LevelTwoInformation_4tupletopologypath'], '')) AS level2_topology,
    if(mapContains(LogAttributes, 'LevelTwoInformation_topapplicationsflowcsv'), LogAttributes['LevelTwoInformation_topapplicationsflowcsv'], '') AS level2_applicationsflow
FROM default.otel_logs
WHERE ((LogAttributes['log.type']) = 'npm') AND ((LogAttributes['receiver_type']) = 'livenx');

CREATE MATERIALIZED VIEW IF NOT EXISTS default.SNMP_Inventory_MV
(
    ID String,
    Device_Name String,
    Device_Type String,
    Management_IP String,
    Site String,
    Vendor String,
    Model String,
    SNMP_Metrics Array(Tuple(String, String, Float64, String, DateTime64(9))),
    SNMP_Traps Array(String),
    SNMP_Interfaces Array(Tuple(String, UInt16, String, UInt64, UInt64, UInt32, DateTime64(9))),
    SNMP_Configuration Array(Tuple(String, String, String, String, String, String, DateTime64(9))),
    Polling_Configuration Array(Tuple(UInt32, UInt8, UInt16, DateTime64(9)))
)
ENGINE = ReplacingMergeTree
PRIMARY KEY ID
ORDER BY (ID, Device_Type)
SETTINGS index_granularity = 8192
AS WITH device_info AS
    (
        SELECT
            ResourceAttributes['device.id'] AS ID,
            ResourceAttributes['device.name'] AS Device_Name,
            ResourceAttributes['device.type'] AS Device_Type,
            ResourceAttributes['network.ip'] AS Management_IP,
            ResourceAttributes['location.site'] AS Site,
            ResourceAttributes['device.vendor'] AS Vendor,
            ResourceAttributes['device.model'] AS Model,
            ScopeName
        FROM default.otel_metrics_sum
        WHERE ((ResourceAttributes['device.id']) IS NOT NULL) AND (ScopeName = 'github.com/open-telemetry/opentelemetry-collector-contrib/receiver/snmpreceiver')
        GROUP BY
            ID,
            Device_Name,
            Device_Type,
            Management_IP,
            Site,
            Vendor,
            Model,
            ScopeName
    )
SELECT
    d.ID,
    d.Device_Name,
    d.Device_Type,
    d.Management_IP,
    d.Site,
    d.Vendor,
    d.Model,
    groupArray((coalesce(MetricName, ''), coalesce(toString(Attributes['snmp.oid']), ''), coalesce(Value, 0.), coalesce(MetricUnit, ''), coalesce(TimeUnix, toDateTime64('2000-01-01 00:00:00', 9)))) AS SNMP_Metrics,
    arrayFilter(x -> (x != ''), ['']) AS SNMP_Traps,
    groupArray((coalesce(toString(Attributes['interface.name']), ''), toUInt16OrZero(Attributes['interface.index']), coalesce(toString(Attributes['interface.status']), ''), coalesce(toUInt64(Value * if((Attributes['traffic.direction']) = 'in', 1, 0)), 0), coalesce(toUInt64(Value * if((Attributes['traffic.direction']) = 'out', 1, 0)), 0), toUInt32OrZero(Attributes['interface.errors']), coalesce(TimeUnix, toDateTime64('2000-01-01 00:00:00', 9)))) AS SNMP_Interfaces,
    groupArray((coalesce(toString(ResourceAttributes['snmp.community']), ''), coalesce(toString(ResourceAttributes['snmp.version']), ''), coalesce(toString(ResourceAttributes['snmp.security.level']), ''), coalesce(toString(ResourceAttributes['snmp.username']), ''), coalesce(toString(ResourceAttributes['snmp.auth.protocol']), ''), coalesce(toString(ResourceAttributes['snmp.priv.protocol']), ''), coalesce(TimeUnix, toDateTime64('2000-01-01 00:00:00', 9)))) AS SNMP_Configuration,
    groupArray((coalesce(toUInt32OrZero(ResourceAttributes['polling.interval']), 0), coalesce(toUInt8OrZero(ResourceAttributes['polling.retries']), 0), coalesce(toUInt16OrZero(ResourceAttributes['polling.timeout']), 0), coalesce(TimeUnix, toDateTime64('2000-01-01 00:00:00', 9)))) AS Polling_Configuration
FROM default.otel_metrics_sum AS o
INNER JOIN device_info AS d ON (d.ID = (o.ResourceAttributes['device.id'])) AND (o.ScopeName = d.ScopeName)
GROUP BY
    d.ID,
    d.Device_Name,
    d.Device_Type,
    d.Management_IP,
    d.Site,
    d.Vendor,
    d.Model;

EOSQL
