#!/bin/bash
# Install the BAM alerts forwarder as a systemd service on LiveNX. Run from this directory with sudo.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
install -d -m 755 /opt/bam-alerts /etc/bam-alerts
install -m 755 bam_alerts_to_otel.py /opt/bam-alerts/
if [ ! -f /etc/bam-alerts/bam_alerts.env ]; then
  install -m 600 -o admin bam_alerts.env.sample /etc/bam-alerts/bam_alerts.env
  echo "Created /etc/bam-alerts/bam_alerts.env -- edit BAM_BASE/BAM_USER/BAM_PASS before starting."
fi
install -m 644 bam-alerts-to-otel.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable bam-alerts-to-otel.service
echo "Then: sudo systemctl start bam-alerts-to-otel && journalctl -u bam-alerts-to-otel -f"
