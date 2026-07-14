#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

info "Stopping SentinelX service ..."
if systemctl is-active --quiet sentinelx.service 2>/dev/null; then
    systemctl stop sentinelx.service
    info "Service stopped"
else
    warn "Service is not running"
fi

info "Disabling SentinelX service ..."
if systemctl is-enabled --quiet sentinelx.service 2>/dev/null; then
    systemctl disable sentinelx.service
    info "Service disabled"
fi

info "Removing binaries ..."
rm -f /usr/bin/sentinelx-backend
rm -f /usr/bin/sentinelx-cli
info "Binaries removed"

info "Removing systemd service ..."
rm -f /usr/lib/systemd/system/sentinelx.service
systemctl daemon-reload
info "Service unit removed"

info "Removing configuration ..."
rm -f /etc/sentinelx/sentinelx.conf
rm -f /etc/sentinelx/sentinelx.conf.new
rmdir /etc/sentinelx 2>/dev/null || true
info "Configuration removed"

read -rp "Remove data directory /var/lib/sentinelx (database will be lost)? [y/N] " answer
if [[ "${answer}" =~ ^[Yy]$ ]]; then
    rm -rf /var/lib/sentinelx
    info "Data directory removed"
else
    info "Data directory preserved at /var/lib/sentinelx"
fi

echo ""
info "Uninstallation complete!"
