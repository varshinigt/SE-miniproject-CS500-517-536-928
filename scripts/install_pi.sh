#!/usr/bin/env bash
# Install Pocket Packet Sniffer as systemd services on a Raspberry Pi (NFR-PORT-01).
# Usage (from the repository root):  sudo ./scripts/install_pi.sh
set -euo pipefail

INSTALL_DIR=/opt/pocket-packet-sniffer
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi

echo "Installing system packages"
apt-get update
apt-get install -y --no-install-recommends python3-venv libpcap-dev iw wireless-tools bluez

echo "Copying project to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR/data/pcaps"
cp -r "$REPO_DIR/src" "$REPO_DIR/requirements.txt" "$REPO_DIR/requirements-dashboard.txt" "$INSTALL_DIR/"

echo "Creating virtual environment"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -r "$INSTALL_DIR/requirements-dashboard.txt"

echo "Installing systemd units"
install -m 644 "$REPO_DIR/scripts/pocket-packet-sniffer.service" /etc/systemd/system/
install -m 644 "$REPO_DIR/scripts/pocket-packet-capture.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pocket-packet-sniffer.service pocket-packet-capture.service

IP_ADDR="$(hostname -I | awk '{print $1}')"
echo "Done. Dashboard: http://${IP_ADDR}:8000  (open it from a phone on the same network)"
echo "Capture logs: journalctl -u pocket-packet-capture -f"
