#!/usr/bin/env bash
set -euo pipefail

# create_dns_dhcp_otel_view.sh
#
# Creates the view:
#   liveassist.DNS_DHCP_OpenTelemetry_Log_Data
# as:
#   SELECT * FROM default.otel_logs
#   WHERE LogAttributes['event_description'] ILIKE '%dns%'
#      OR LogAttributes['event_description'] ILIKE '%dhcp%'
#
# This script ONLY executes the single VIEW statement requested.
# If the 'liveassist' DB or 'default.otel_logs' doesn't exist, ClickHouse will error.

usage() {
  cat <<'USAGE'
Usage: create_dns_dhcp_otel_view.sh [options]

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

# Execute exactly one statement via stdin.
"${DOCKER_CMD[@]}" <<'SQL'
CREATE VIEW IF NOT EXISTS liveassist.DNS_DHCP_OpenTelemetry_Log_Data AS
SELECT *
FROM default.otel_logs
WHERE
  LogAttributes['event_description'] ILIKE '%dns%'
  OR LogAttributes['event_description'] ILIKE '%dhcp%';
SQL

echo "OK: Ensured view liveassist.DNS_DHCP_OpenTelemetry_Log_Data exists."
exit 0
