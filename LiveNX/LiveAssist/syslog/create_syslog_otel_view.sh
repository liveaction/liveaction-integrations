#!/usr/bin/env bash
set -euo pipefail

# create_syslog_otel_view.sh
#
# Creates the following view inside ClickHouse via the running container:
#
#   CREATE VIEW IF NOT EXISTS liveassist.SYSLOG_OpenTelemtry_Log_Data
#     AS SELECT * FROM default.otel_logs WHERE Body LIKE '%SYS-%';
#
# This variant uses:
#   docker exec clickhouse-server clickhouse-client
# and executes exactly that one SQL statement.
#
# Preconditions:
# - Docker is installed and the container `clickhouse-server` is running.
# - The database `liveassist` already exists.
# - The source table `default.otel_logs` exists and is readable by the default user.
#
# If you need auth, adapt the command at the bottom to include:
#   --user <user> --password <pass>

command -v docker >/dev/null 2>&1 || { echo "Error: 'docker' is required." >&2; exit 1; }
if ! docker ps --format '{{.Names}}' | grep -Fxq "clickhouse-server"; then
  echo "Error: Docker container 'clickhouse-server' is not running (or not found)." >&2
  exit 1
fi

readonly VIEW_SQL="CREATE VIEW IF NOT EXISTS liveassist.SYSLOG_OpenTelemtry_Log_Data AS SELECT * FROM default.otel_logs WHERE Body LIKE '%SYS-%';"

# Execute inside the container
docker exec clickhouse-server clickhouse-client --query \"$VIEW_SQL\"

echo \"OK: Ensured view liveassist.SYSLOG_OpenTelemtry_Log_Data exists.\"
