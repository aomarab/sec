#!/usr/bin/env bash
# Install the Threat Intel endpoint agent as a systemd service.
# Usage:  sudo ./install.sh        (run from the copied 'endpoint' tree)
set -euo pipefail

APP_DIR=/opt/sec-endpoint
CONF_DIR=/etc/sec-endpoint
UNIT=/etc/systemd/system/sec-endpoint-agent.service
# repo/source root that contains the 'endpoint' package (3 levels up from here)
SRC_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "Please run as root (sudo)."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required on the host."; exit 1; }
[ -f "$SRC_DIR/endpoint/agent.py" ] || { echo "Could not find the endpoint package next to this script."; exit 1; }

echo "Installing agent files to $APP_DIR ..."
install -d "$APP_DIR/endpoint" "$CONF_DIR"
cp "$SRC_DIR/endpoint/"*.py "$APP_DIR/endpoint/"

if [ ! -f "$CONF_DIR/agent.config.json" ]; then
  cp "$SRC_DIR/endpoint/agent.config.example.json" "$CONF_DIR/agent.config.json"
  chmod 600 "$CONF_DIR/agent.config.json"
  echo ">> Edit $CONF_DIR/agent.config.json and set 'server_url' and 'token'."
fi

cp "$SRC_DIR/endpoint/packaging/linux/secagent.service" "$UNIT"
systemctl daemon-reload
systemctl enable sec-endpoint-agent.service

echo
echo "Installed. Next:"
echo "  1) edit $CONF_DIR/agent.config.json   (server_url + enrollment token)"
echo "  2) sudo systemctl start sec-endpoint-agent.service"
echo "  3) journalctl -u sec-endpoint-agent -f   # watch logs"
echo
echo "Uninstall: sudo systemctl disable --now sec-endpoint-agent.service && sudo rm -f $UNIT && sudo rm -rf $APP_DIR"
