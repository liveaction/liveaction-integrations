#!/usr/bin/env bash
set -euo pipefail

# create_bluecat_ipam_view.sh
#
# Creates the view:
#   liveassist.BlueCat_IPAM_IP_Management_Address_Devices
# as SELECT * FROM netops.ipam_devices
#
# This script ONLY executes the single VIEW statement requested.
# If 'liveassist' DB or 'netops.ipam_devices' doesn't exist, ClickHouse will error.

usage() {
  cat <<'USAGE'
Usage: create_bluecat_ipam_view.sh [options]

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

readonly VIEW_SQL="CREATE VIEW IF NOT EXISTS liveassist.BlueCat_IPAM_IP_Management_Address_Devices AS SELECT * FROM netops.ipam_devices;"

DOCKER_CMD=(docker exec -i "$DOCKER_CONTAINER" clickhouse-client
)

DOCKER_CMD+=(--query "$VIEW_SQL")

"${DOCKER_CMD[@]}"

echo "OK: Ensured view liveassist.BlueCat_IPAM_IP_Management_Address_Devices exists."
exit 0