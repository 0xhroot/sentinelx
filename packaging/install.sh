#!/usr/bin/env bash
set -euo pipefail

BINARY_DIR="${1:-.}"
CONFIG_FILE="packaging/sentinelx.conf"
SERVICE_FILE="packaging/sentinelx.service"

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

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${ID}"
    elif command -v lsb_release &>/dev/null; then
        lsb_release -is | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
info "Detected distribution: ${DISTRO}"

install_binaries() {
    info "Installing binaries to /usr/bin/ ..."
    install -Dm755 "${BINARY_DIR}/sentinelx-backend" /usr/bin/sentinelx-backend
    install -Dm755 "${BINARY_DIR}/sentinelx-cli" /usr/bin/sentinelx-cli
    info "Binaries installed"
}

install_config() {
    info "Installing configuration ..."
    mkdir -p /etc/sentinelx
    if [[ ! -f /etc/sentinelx/sentinelx.conf ]]; then
        install -Dm644 "${CONFIG_FILE}" /etc/sentinelx/sentinelx.conf
        info "Default config installed to /etc/sentinelx/sentinelx.conf"
    else
        warn "Config already exists, skipping (new config saved as .new)"
        install -Dm644 "${CONFIG_FILE}" /etc/sentinelx/sentinelx.conf.new
    fi
}

install_service() {
    info "Installing systemd service ..."
    install -Dm644 "${SERVICE_FILE}" /usr/lib/systemd/system/sentinelx.service
    systemctl daemon-reload
    info "Service unit installed"
}

create_directories() {
    info "Creating data directory ..."
    mkdir -p /var/lib/sentinelx
    info "Data directory ready at /var/lib/sentinelx"
}

enable_service() {
    info "Enabling and starting SentinelX service ..."
    systemctl enable sentinelx.service
    systemctl start sentinelx.service
    info "SentinelX is now running"
}

install_binaries
install_config
install_service
create_directories

echo ""
info "Installation complete!"
echo ""
info "Next steps:"
echo "  1. Edit /etc/sentinelx/sentinelx.conf to configure SentinelX"
echo "  2. systemctl start sentinelx   (to start the service)"
echo "  3. systemctl status sentinelx  (to check status)"
echo ""
read -rp "Enable and start the service now? [Y/n] " answer
if [[ "${answer:-Y}" =~ ^[Yy]?$ ]]; then
    enable_service
fi
