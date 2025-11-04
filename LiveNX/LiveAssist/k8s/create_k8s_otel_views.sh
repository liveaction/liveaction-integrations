#!/usr/bin/env bash
set -euo pipefail

# create_k8s_otel_views.sh
#
# Creates the following views inside ClickHouse via the running container:
#
#   CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_histogram
#     AS SELECT * FROM default.otel_metrics_histogram WHERE Attributes['k8s'] = 'k8s';
#
#   CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_sum
#     AS SELECT * FROM default.otel_metrics_sum WHERE Attributes['k8s'] = 'k8s';
#
#   CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_gauge
#     AS SELECT * FROM default.otel_metrics_gauge WHERE Attributes['k8s'] = 'k8s';
#
#   CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_logs
#     AS SELECT * FROM default.otel_logs WHERE LogAttributes['k8s'] = 'k8s';
#
# This variant uses:
#   docker exec clickhouse-server clickhouse-client --multiquery
# and executes exactly those four SQL statements.
#
# Preconditions:
# - Docker is installed and the container `clickhouse-server` is running.
# - The database `liveassist` already exists.
# - The source tables exist and are readable by the default user:
#     default.otel_metrics_histogram
#     default.otel_metrics_sum
#     default.otel_metrics_gauge
#     default.otel_logs
# - Attributes/LogAttributes maps contain the 'k8s' key for relevant rows.
#
# If you need auth, adapt the command at the bottom to include:
#   --user <user> --password <pass>

command -v docker >/dev/null 2>&1 || { echo "Error: 'docker' is required." >&2; exit 1; }
if ! docker ps --format '{{.Names}}' | grep -Fxq "clickhouse-server"; then
  echo "Error: Docker container 'clickhouse-server' is not running (or not found)." >&2
  exit 1
fi

read -r -d '' VIEW_SQL <<'SQL'
CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_histogram AS
  SELECT * FROM default.otel_metrics_histogram WHERE Attributes['k8s'] = 'k8s';
CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_sum AS
  SELECT * FROM default.otel_metrics_sum WHERE Attributes['k8s'] = 'k8s';
CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_metrics_gauge AS
  SELECT * FROM default.otel_metrics_gauge WHERE Attributes['k8s'] = 'k8s';
CREATE VIEW IF NOT EXISTS liveassist.Kubernetes_OpenTelemetry_otel_logs AS
  SELECT * FROM default.otel_logs WHERE LogAttributes['k8s'] = 'k8s';
SQL

# Execute inside the container
docker exec clickhouse-server clickhouse-client --multiquery --query "$VIEW_SQL"

echo "OK: Ensured Kubernetes OTEL views exist in 'liveassist'."
