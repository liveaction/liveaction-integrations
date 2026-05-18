#!/bin/bash
set -euo pipefail

SERVICE_NAME="livenx-infoblox"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="/etc/${SERVICE_NAME}/${SERVICE_NAME}.env"
INSTALL_DIR="/opt/${SERVICE_NAME}"
VENV_DIR="${INSTALL_DIR}/venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================"
echo " LiveNX Infoblox Integration - systemd Installer"
echo "============================================"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)."
    exit 1
fi

# Prompt for required configuration
echo "Enter configuration values (required fields marked with *):"
echo ""

read -rp "* LiveNX Host: " LIVENX_HOST
read -rp "* LiveNX API Token: " LIVENX_TOKEN
read -rp "* LiveNX Report ID: " REPORT_ID
read -rp "* Device Serial: " DEVICE_SERIAL
read -rp "* Infoblox Host: " INFOBLOX_HOST
read -rp "* Infoblox Username: " INFOBLOX_USERNAME
read -rsp "* Infoblox Password: " INFOBLOX_PASSWORD
echo ""
read -rp "  Poll Interval (seconds, default 60): " POLL_INTERVAL
POLL_INTERVAL=${POLL_INTERVAL:-60}

echo ""
echo "ClickHouse configuration (leave blank to skip):"
read -rp "  ClickHouse Host: " CH_HOST
read -rp "  ClickHouse Port (default 9440): " CH_PORT
CH_PORT=${CH_PORT:-9440}
read -rp "  ClickHouse Username: " CH_USERNAME
read -rsp "  ClickHouse Password: " CH_PASSWORD
echo ""
read -rp "  ClickHouse Database (default inventory_db): " CH_DATABASE
CH_DATABASE=${CH_DATABASE:-inventory_db}
read -rp "  ClickHouse Table (default infoblox_nat_dhcp): " CH_TABLE
CH_TABLE=${CH_TABLE:-infoblox_nat_dhcp}
read -rp "  ClickHouse CA Certs path: " CH_CACERTS
read -rp "  ClickHouse Cert file path: " CH_CERTFILE
read -rp "  ClickHouse Key file path: " CH_KEYFILE

# Install application files
echo ""
echo "Installing application to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
cp "${SCRIPT_DIR}/infoblox_script.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"

# Create virtual environment and install dependencies
echo "Setting up Python virtual environment..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip -q
"${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" -q

# Build command-line arguments
EXEC_ARGS="--livenx_host ${LIVENX_HOST} --livenx_token ${LIVENX_TOKEN} --report_id ${REPORT_ID} --device_serial ${DEVICE_SERIAL} --infoblox_host ${INFOBLOX_HOST} --infoblox_username ${INFOBLOX_USERNAME} --infoblox_password ${INFOBLOX_PASSWORD} --poll_interval_seconds ${POLL_INTERVAL}"

if [[ -n "${CH_HOST}" ]]; then
    EXEC_ARGS="${EXEC_ARGS} --clickhouse_host ${CH_HOST} --clickhouse_port ${CH_PORT} --clickhouse_username ${CH_USERNAME} --clickhouse_password ${CH_PASSWORD} --clickhouse_database ${CH_DATABASE} --clickhouse_table ${CH_TABLE}"
    [[ -n "${CH_CACERTS}" ]] && EXEC_ARGS="${EXEC_ARGS} --clickhouse_cacerts ${CH_CACERTS}"
    [[ -n "${CH_CERTFILE}" ]] && EXEC_ARGS="${EXEC_ARGS} --clickhouse_certfile ${CH_CERTFILE}"
    [[ -n "${CH_KEYFILE}" ]] && EXEC_ARGS="${EXEC_ARGS} --clickhouse_keyfile ${CH_KEYFILE}"
fi

# Create environment file directory
mkdir -p "$(dirname "${ENV_FILE}")"

# Write environment file (used to store the args securely)
cat > "${ENV_FILE}" <<EOF
# LiveNX Infoblox Integration Configuration
# Generated on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
INFOBLOX_ARGS=${EXEC_ARGS}
EOF
chmod 600 "${ENV_FILE}"

# Create systemd service unit
echo "Creating systemd service at ${SERVICE_FILE}..."
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=LiveNX Infoblox NAT/DHCP Integration Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python3 ${INSTALL_DIR}/infoblox_script.py \$INFOBLOX_ARGS
WorkingDirectory=${INSTALL_DIR}

Restart=on-failure
RestartSec=10
StartLimitIntervalSec=300
StartLimitBurst=5

StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable the service
echo "Enabling and starting service..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
systemctl start "${SERVICE_NAME}.service"

echo ""
echo "============================================"
echo " Installation Complete!"
echo "============================================"
echo ""
echo "Service status:  systemctl status ${SERVICE_NAME}"
echo "View logs:       journalctl -u ${SERVICE_NAME} -f"
echo "Restart:         systemctl restart ${SERVICE_NAME}"
echo "Stop:            systemctl stop ${SERVICE_NAME}"
echo "Uninstall:       systemctl stop ${SERVICE_NAME} && systemctl disable ${SERVICE_NAME} && rm ${SERVICE_FILE} && rm -rf ${INSTALL_DIR} && rm -rf $(dirname "${ENV_FILE}") && systemctl daemon-reload"
echo ""
echo "The service will automatically restart on failure (after 10s delay, max 5 retries per 5 minutes)."
