#!/usr/bin/env bash
set -euo pipefail

# create_arp_information_view.sh
#
# Creates or replaces the view:
#   liveassist.ARP_Information
#
# This script ONLY executes the single VIEW statement requested.
# If the 'liveassist' DB or 'livenx_snmpdb.device_metric_dist' table doesn't exist,
# ClickHouse will error.

usage() {
  cat <<'USAGE'
Usage: create_arp_information_view.sh [options]

Options:
  --docker-container NAME    Docker container running ClickHouse [default: clickhouse-server]
  --help|-h                  Show this help and exit
USAGE
}

DOCKER_CONTAINER="clickhouse-server"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker-container) DOCKER_CONTAINER="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "Error: 'docker' is required." >&2; exit 1; }
if ! docker ps --format '{{.Names}}' | grep -Fxq "$DOCKER_CONTAINER"; then
  echo "Error: Docker container '$DOCKER_CONTAINER' is not running (or not found)." >&2
  exit 1
fi

DOCKER_CMD=(docker exec -i "$DOCKER_CONTAINER" clickhouse-client -n)

# Execute exactly one statement via stdin. No interpolation thanks to single-quoted heredoc.
"${DOCKER_CMD[@]}" <<'SQL'
CREATE OR REPLACE VIEW liveassist.ARP_Information
(
    `time` DateTime,
    `DeviceId` LowCardinality(String),
    `DeviceTimeMillis` UInt64,
    `MetricName` LowCardinality(String),
    `MetricIndex` LowCardinality(String),
    `MetricType` LowCardinality(String),
    `MetricValue` Nullable(Float64),

    -- Flattened fields from Tags
    `arpEntryMacAddress` Nullable(String),
    `arpEntryIpAddress` Nullable(IPv4),
    `arpEntryIfIndex`   Nullable(UInt32),
    `arpEntryInterface` Nullable(String),
    `metricDescription` Nullable(String),
    `snmpType`          Nullable(String),
    `unit`              Nullable(String)
)
AS
SELECT
    time,
    DeviceId,
    DeviceTimeMillis,
    MetricName,
    MetricIndex,
    MetricType,
    MetricValue,

    Tags['arpEntryMacAddress']                      AS arpEntryMacAddress,
    toIPv4OrNull(Tags['arpEntryIpAddress'])         AS arpEntryIpAddress,
    toUInt32OrNull(Tags['arpEntryIfIndex'])         AS arpEntryIfIndex,
    Tags['arpEntryInterface']                       AS arpEntryInterface,
    Tags['metricDescription']                       AS metricDescription,
    Tags['snmpType']                                AS snmpType,
    Tags['unit']                                    AS unit
FROM livenx_snmpdb.device_metric_dist
WHERE MetricName ILIKE '%arp%';
SQL

echo "OK: Created/replaced view liveassist.ARP_Information."
exit 0
