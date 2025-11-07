#!/usr/bin/env bash
set -euo pipefail

# insert_config.sh
#
# Read a router config file and insert it as an OpenTelemetry-style log row
# into ClickHouse (JSONEachRow) by running clickhouse-client INSIDE a Docker container.
#
# Requirements: jq, docker, sha256sum|shasum
#
# Example:
#   ./insert_config.sh \
#     --file Branch1-LA-config.txt \
#     --router-name Branch1-LA \
#     --router-ip 10.255.255.30 \
#     --vendor cisco \
#     --severity info \
#     --database default \
#     --table otel_logs \
#     --docker-container clickhouse-server
#
# Matches table schema (capitalized fields):
#   Timestamp(DateTime64(9)), SeverityText, SeverityNumber, ServiceName, Body,
#   TraceId, SpanId, TraceFlags, ResourceAttributes(Map), LogAttributes(Map), ...
#
# Notes:
# - Timestamp formatted as "YYYY-MM-DD HH:MM:SS" (UTC). ClickHouse parses it into DateTime64(9).
# - Top-level ServiceName is hard-set to "routerconfig" so your view returns rows.
# - resource/service.name is also set to "routerconfig" for OTEL compatibility.

usage() {
  cat <<'USAGE'
Usage: insert_config.sh [options]

Required:
  --file PATH                Router config file to ingest

Optional metadata:
  --router-name NAME         host.name (resource attribute)
  --router-ip IP             net.host.ip (resource attribute)
  --vendor VENDOR            router.vendor (resource attribute)
  --severity LEVEL           trace|debug|info|warn|error|fatal [default: info]
  --trace-id HEX             32-hex chars (optional)
  --span-id HEX              16-hex chars (optional)
  --trace-flags N            UInt8 trace flags [default: 0]

ClickHouse (from inside the container):
  --ch-host HOST             [default: 127.0.0.1]
  --ch-port PORT             [default: 9000]
  --ch-user USER             [default: default]
  --ch-password PASS         [default: empty]
  --database DB              [default: default]
  --table TABLE              [default: otel_logs]

Docker:
  --docker-container NAME    [default: clickhouse-server]

Other:
  --help                     Show help and exit
USAGE
}

# Defaults
FILE=""
ROUTER_NAME="${ROUTER_NAME:-}"
ROUTER_IP="${ROUTER_IP:-}"
VENDOR="${VENDOR:-}"
SEVERITY="info"
TRACE_ID="${TRACE_ID:-}"
SPAN_ID="${SPAN_ID:-}"
TRACE_FLAGS="${TRACE_FLAGS:-0}"

CH_HOST="127.0.0.1"
CH_PORT="9000"
CH_USER="default"
CH_PASSWORD=""
DATABASE="default"
TABLE="otel_logs"

DOCKER_CONTAINER="clickhouse-server"

SERVICE_NAME="routerconfig"
# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --file) FILE="$2"; shift 2 ;;
    --router-name) ROUTER_NAME="$2"; shift 2 ;;
    --router-ip) ROUTER_IP="$2"; shift 2 ;;
    --vendor) VENDOR="$2"; shift 2 ;;
    --severity) SEVERITY="$(echo "$2" | tr '[:upper:]' '[:lower:]')"; shift 2 ;;
    --trace-id) TRACE_ID="$2"; shift 2 ;;
    --span-id) SPAN_ID="$2"; shift 2 ;;
    --trace-flags) TRACE_FLAGS="$2"; shift 2 ;;
    --ch-host) CH_HOST="$2"; shift 2 ;;
    --ch-port) CH_PORT="$2"; shift 2 ;;
    --ch-user) CH_USER="$2"; shift 2 ;;
    --ch-password) CH_PASSWORD="$2"; shift 2 ;;
    --database) DATABASE="$2"; shift 2 ;;
    --table) TABLE="$2"; shift 2 ;;
    --docker-container) DOCKER_CONTAINER="$2"; shift 2 ;;
    --service-name) SERVICE_NAME="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

# Validations
[[ -n "$FILE" ]] || { echo "Error: --file is required." >&2; usage; exit 1; }
[[ -f "$FILE" ]] || { echo "Error: file not found: $FILE" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || { echo "Error: 'jq' is required." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Error: 'docker' is required." >&2; exit 1; }

if ! docker ps --format '{{.Names}}' | grep -Fxq "$DOCKER_CONTAINER"; then
  echo "Error: Docker container '$DOCKER_CONTAINER' is not running (or not found)." >&2
  exit 1
fi

# Severity → numeric bucket (OpenTelemetry anchors)
sev_to_num() {
  case "$1" in
    trace) echo 1 ;;
    debug) echo 5 ;;
    info)  echo 9 ;;
    warn)  echo 13 ;;
    error) echo 17 ;;
    fatal) echo 21 ;;
    *)     echo 9 ;;
  esac
}
SEVERITY_NUMBER="$(sev_to_num "$SEVERITY")"

# Timestamp (UTC). Safe for DateTime64(9).
TIMESTAMP="$(date -u +"%Y-%m-%d %H:%M:%S")"

# File metadata
if command -v sha256sum >/dev/null 2>&1; then
  SHA256="$(sha256sum "$FILE" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  SHA256="$(shasum -a 256 "$FILE" | awk '{print $1}')"
else
  SHA256=""
fi
# Portable stat for size
SIZE_BYTES="$(stat -c%s "$FILE" 2>/dev/null || stat -f%z "$FILE")"
BASENAME="$(basename "$FILE")"

# Build one JSONEachRow record with capitalized keys matching your schema.
JSON_ROW="$(
  jq -n \
    --arg ts "$TIMESTAMP" \
    --arg severity_text "$SEVERITY" \
    --argjson severity_number "$SEVERITY_NUMBER" \
    --rawfile body "$FILE" \
    --arg filename "$BASENAME" \
    --arg sha256 "$SHA256" \
    --arg size_bytes "$SIZE_BYTES" \
    --arg router_name "$ROUTER_NAME" \
    --arg router_ip "$ROUTER_IP" \
    --arg vendor "$VENDOR" \
    --arg trace_id "$TRACE_ID" \
    --arg span_id "$SPAN_ID" \
    --arg service_name "$SERVICE_NAME" \
    --argjson trace_flags "${TRACE_FLAGS:-0}" \
  '{
      Timestamp: $ts,
      SeverityText: $severity_text,
      SeverityNumber: $severity_number,
      ServiceName: $service_name,
      Body: $body,
      TraceFlags: $trace_flags,
      LogAttributes: {
        "filename": $filename,
        "sha256": $sha256,
        "size_bytes": $size_bytes
      },
      ResourceAttributes: (
        {
          "service.name": $service_name
        }
        + (if $router_name != "" then {"host.name": $router_name} else {} end)
        + (if $router_ip   != "" then {"net.host.ip": $router_ip} else {} end)
        + (if $vendor      != "" then {"router.vendor": $vendor} else {} end)
      )
    }
    + (if $trace_id != "" then {TraceId: $trace_id} else {} end)
    + (if $span_id  != "" then {SpanId:  $span_id } else {} end)
  '
)"

# Sanity check JSON before insert
printf '%s\n' "$JSON_ROW" | jq -e . >/dev/null || {
  echo "Error: Generated JSON is invalid. Aborting." >&2
  exit 1
}

# Compose docker exec to run clickhouse-client (native protocol)
DOCKER_CMD=(docker exec -i "$DOCKER_CONTAINER" clickhouse-client)
if [[ -n "$CH_PASSWORD" ]]; then
  DOCKER_CMD+=(--password "$CH_PASSWORD")
fi
DOCKER_CMD+=(--query "INSERT INTO ${DATABASE}.${TABLE} FORMAT JSONEachRow")

# Insert
printf '%s\n' "$JSON_ROW" | "${DOCKER_CMD[@]}"

# ----- Added: ensure views exist -----
# Note: --multiquery lets us run multiple statements in one client call.
VIEW_SQL=$(cat <<'SQL'
CREATE DATABASE IF NOT EXISTS liveassist;
CREATE VIEW IF NOT EXISTS liveassist.Router_Config_OpenTelemetry_Log_Data AS
  SELECT * FROM default.otel_logs WHERE ServiceName = 'routerconfig';
CREATE VIEW IF NOT EXISTS liveassist.Recommended_Router_Config_For_LiveNX_OpenTelemetry_Log_Data AS
  SELECT * FROM default.otel_logs WHERE ServiceName = 'recommendrouterconfig';
SQL
)

docker exec -i "$DOCKER_CONTAINER" clickhouse-client \
  ${CH_PASSWORD:+--password "$CH_PASSWORD"} \
  --multiquery \
  --query "$VIEW_SQL"
# ----- end added block -----

echo "OK: Inserted ${BASENAME} into ${DATABASE}.${TABLE} via '${DOCKER_CONTAINER}' @ ${TIMESTAMP} (severity=${SEVERITY}); ensured views in 'liveassist'."
exit 0