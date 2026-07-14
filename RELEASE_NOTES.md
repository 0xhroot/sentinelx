# SentinelX v1.0.0 Release Notes

**Release Date:** 2026-07-15
**Version:** 1.0.0
**License:** GPL-3.0-or-later

---

## Highlights

SentinelX v1.0.0 is the first stable release of an enterprise-grade Linux runtime integrity and rootkit detection platform. Built entirely in Rust, SentinelX provides real-time monitoring of kernel structures, processes, modules, network connections, memory regions, and persistence mechanisms to detect rootkits, hidden malware, and advanced threats.

Key capabilities:

- **Kernel Integrity Engine** — Monitors kernel text, read-only sections, sysctl hardening, and critical structures for tampering
- **eBPF Kernel Sensors** — Native kernel instrumentation via Aya for high-fidelity event detection with graceful degradation
- **Evidence-Driven Pipeline** — Multi-source evidence correlation eliminates false positives from single-source detection
- **Offline-First Threat Intelligence** — IoCs, MITRE ATT&CK mapping, YARA/Sigma rules, and CVE tracking without internet access
- **Automated Response** — Configurable actions (alert, kill, block, quarantine) triggered by severity thresholds
- **REST API and CLI** — Full management via Axum REST API or feature-rich command-line interface

## What's New

### Detection Engine
- Evidence-driven pipeline architecture with `DiscoveryProvider` / `MetadataCollector` / `ObjectAssessor` traits
- Central assessment engine with configurable numeric scoring (trust, integrity, risk, reputation)
- Correlation engine with TOML-configurable rules for multi-indicator attack pattern detection
- Incident and threat engines with MITRE ATT&CK mapping and weighted risk scoring

### Kernel Monitoring
- eBPF programs via Aya for syscall tracing, process lifecycle, and file access events
- fanotify integration for real-time file system monitoring
- Netlink sockets for network connection tracking
- Audit socket integration for system call auditing

### Threat Intelligence
- Behavioral profiling engine with 11 categories and 7-factor weighted scoring
- IoC database with hash, domain, IP, and URL matching
- MITRE ATT&CK technique and tactic mapping
- YARA and Sigma rule matching engines
- CVE tracking and vulnerability correlation

### Applications
- `sentinelx-cli` — Full CLI with scan, monitor, status, timeline, forensics, and export commands
- `sentinelx-backend` — Axum REST API with health, status, threats, scan, processes, modules, network, forensics, report, and timeline endpoints
- React TypeScript dashboard with dark theme (API-only in v1.0)

### Infrastructure
- Docker multi-stage build for optimized production images
- Systemd service unit for daemon management
- Arch Linux PKGBUILD packaging
- Automated install and uninstall scripts

### Fleet Management (Alpha)
- Agent-coordinator communication over secure transport
- Policy distribution and heartbeat monitoring
- Remote response capabilities across distributed hosts

## Breaking Changes

None — this is the first stable release.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/sentinelx/sentinelx.git
cd sentinelx

# Build
cargo build --release

# Run
sudo ./target/release/sentinelx-cli scan
```

### Via Docker

```bash
docker pull ghcr.io/sentinelx/sentinelx:1.0.0
docker run --privileged -v /var/lib/sentinelx:/var/lib/sentinelx ghcr.io/sentinelx/sentinelx:1.0.0
```

### Systemd Service

```bash
sudo cp target/release/sentinelx-backend /usr/bin/
sudo cp target/release/sentinelx-cli /usr/bin/
sudo cp packaging/sentinelx.service /etc/systemd/system/
sudo cp sentinelx.toml /etc/sentinelx/sentinelx.toml
sudo systemctl enable --now sentinelx
```

## System Requirements

- Linux kernel 5.8+ (eBPF features require 5.8+)
- Rust 1.75+ (for building from source)
- Root privileges for kernel-level monitoring
- SQLite 3 (included in most distributions)
- 150MB RAM maximum under normal operation

## Known Limitations

- Requires root privileges for kernel-level monitoring features
- Linux-only support (no macOS or Windows)
- SQLite only — no PostgreSQL or MySQL support yet
- Fleet management is alpha quality
- eBPF features require kernel 5.8 or later
- No web-based management UI yet
- Limited MITRE ATT&CK technique coverage (8 techniques)
- No automatic rule update mechanism

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for detailed information.

## Contributing

Contributions are welcome! Please see the project repository for guidelines.

- Report bugs via GitHub Issues
- Submit pull requests to the `main` branch
- Follow the existing code style (cargo fmt + cargo clippy)
- Add tests for new functionality
- Update documentation for user-facing changes

## License

SentinelX is licensed under the [GNU General Public License v3.0 or later](LICENSE).
