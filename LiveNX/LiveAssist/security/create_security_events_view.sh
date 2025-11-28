#!/usr/bin/env bash
set -euo pipefail

# create_security_events_view.sh
#
# Creates the following view inside ClickHouse via the running container:
#
#   CREATE VIEW liveassist.Security_Events
#     AS SELECT * FROM livenx_platformdb.si_findings_dist;
#
# NOTE: This is EXACTLY the statement requested (no IF NOT EXISTS).
#       If the view already exists, ClickHouse will error.
#
# This variant uses:
#   docker exec clickhouse-server clickhouse-client
# and executes exactly that one SQL statement.
#
# Preconditions:
# - Docker is installed and the container `clickhouse-server` is running.
# - The database `liveassist` already exists.
# - The source table `livenx_platformdb.si_findings_dist` exists and is readable by the default user.
#
# If you need auth, adapt the command at the bottom to include:
#   --user <user> --password <pass>

command -v docker >/dev/null 2>&1 || { echo "Error: 'docker' is required." >&2; exit 1; }
if ! docker ps --format '{{.Names}}' | grep -Fxq "clickhouse-server"; then
  echo "Error: Docker container 'clickhouse-server' is not running (or not found)." >&2
  exit 1
fi

readonly VIEW_SQL="CREATE VIEW liveassist.Security_Events AS SELECT * FROM livenx_platformdb.si_findings_dist;"

# Execute inside the container
docker exec clickhouse-server clickhouse-client --query \"$VIEW_SQL\"

echo \"OK: Created view liveassist.Security_Events.\"
