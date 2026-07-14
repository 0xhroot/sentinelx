# SentinelX Installation Guide

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Building from Source](#2-building-from-source)
3. [Running SentinelX](#3-running-sentinelx)
4. [Configuration](#4-configuration)
5. [Arch Linux (AUR/PKGBUILD)](#5-arch-linux)
6. [Debian/Ubuntu](#6-debianubuntu)
7. [Fedora/RHEL](#7-fedorarhel)
8. [Docker](#8-docker)

---

## 1. Prerequisites

### Required

| Dependency | Minimum Version | Purpose |
|------------|----------------|---------|
| **Rust** | 1.75+ | Compiler (edition 2021, workspace `rust-version = "1.75"`) |
| **Linux kernel** | 5.8+ | eBPF, fanotify, netlink, audit sockets |
| **SQLite** | 3.x | Persistent storage (via `sqlx` with WAL mode) |
| **Build essentials** | — | `gcc`, `make`, `pkg-config`, Linux headers |

Install on Debian/Ubuntu:
```bash
sudo apt update
sudo apt install build-essential pkg-config linux-headers-$(uname -r) libsqlite3-dev
```

Install on Fedora/RHEL:
```bash
sudo dnf groupinstall "Development Tools"
sudo dnf install kernel-devel pkg-config sqlite-devel
```

Install on Arch Linux:
```bash
sudo pacman -S base-devel linux-headers pkg-config sqlite
```

### Optional (for dashboard)

| Dependency | Version | Purpose |
|------------|---------|---------|
| **Node.js** | 18+ | Dashboard build (React + TypeScript + Vite) |
| **npm** | 9+ | Dashboard package manager |

### Optional (for eBPF sensor)

| Dependency | Purpose |
|------------|---------|
| `CAP_BPF` or `CAP_SYS_ADMIN` capability | eBPF program loading |
| `CAP_PERFMON` capability | Performance monitoring |
| BTF support (`/sys/kernel/btf/vmlinux`) | CO-RE eBPF programs |
| Aya 0.14 (Rust crate) | eBPF userspace framework (included) |

### Privileges

SentinelX requires **root privileges** (or equivalent capabilities) for:
- eBPF program loading and map access
- fanotify filesystem monitoring
- Netlink socket monitoring
- Audit subsystem access
- Reading `/proc` entries for all processes
- Process termination (response engine)

Run with `sudo` or configure Linux capabilities via systemd (see [Deployment](DEPLOYMENT.md)).

---

## 2. Building from Source

### Clone and build

```bash
git clone https://github.com/sentinelx/sentinelx.git
cd sentinelx

# Build all crates in release mode
cargo build --release
```

The release profile enables LTO, single codegen unit, strip, and panic=abort for optimal binary size and performance:

```toml
[profile.release]
lto = true
codegen-units = 1
opt-level = 3
strip = true
panic = "abort"
```

Release binaries are produced at:
- `target/release/sentinelx-backend` (~7.4 MB)
- `target/release/sentinelx-cli` (~2.3 MB)

### Build the dashboard (optional)

```bash
cd apps/dashboard
npm install
npm run build
```

The dashboard is a React SPA with TypeScript and Tailwind CSS. The built output is in `apps/dashboard/dist/`.

### Run tests

```bash
cargo test
```

### Lint and format check

```bash
cargo fmt --check
cargo clippy -- -D warnings
```

---

## 3. Running SentinelX

### Backend (REST API server)

```bash
# Run with default configuration
cargo run --release -p sentinelx-backend

# Or run the compiled binary directly
./target/release/sentinelx-backend

# Custom host/port/config
./target/release/sentinelx-backend --host 127.0.0.1 --port 9443 --config /etc/sentinelx/sentinelx.toml
```

The backend:
1. Loads configuration (or uses defaults)
2. Opens SQLite database at configured path (falls back to in-memory)
3. Registers HookDetector in the legacy `DetectionEngine`
4. Runs the evidence-driven pipeline (7 discovery providers, 7 metadata collectors, 7 assessors)
5. Initializes telemetry providers (eBPF, fanotify, netlink, audit)
6. Starts fleet manager with coordinator
7. Starts the Axum HTTP server on `0.0.0.0:8443` by default

### CLI

```bash
cargo run --release -p sentinelx-cli -- <COMMAND>
```

Or after building:
```bash
./target/release/sentinelx-cli <COMMAND>
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `scan` | Run a full detection scan across all detectors |
| `monitor --interval 60` | Run continuous monitoring with periodic scans |
| `status` | Show system status, metrics, and detector information |
| `timeline` | Display the threat event timeline |
| `integrity` | Show kernel and file integrity status |
| `modules` | List loaded kernel modules with trust assessment |
| `processes` | List running processes with suspicious indicators |
| `network` | List active network connections |
| `forensics` | Collect a comprehensive forensic snapshot |
| `export --format json --output report` | Export threats or reports to a file |
| `config` | Show current configuration |
| `assess --object-type process` | Run the central assessment engine |
| `incidents` | Show correlated security incidents |
| `threats` | Show threat decisions with risk scores |
| `graph` | Show the correlation graph and rules |
| `response` | Show response engine status and history |
| `workflows` | Show available workflows and policies |
| `audit` | Show response audit log |
| `telemetry` | Show real-time telemetry engine status and events |
| `events --count 20` | Show recent telemetry events |
| `providers` | Show registered telemetry providers |
| `monitor-live --interval 1` | Live monitoring of telemetry events |
| `behavior` | Show behavioral analysis engine status and rules |
| `behavior-profiles` | Show behavioral profiles |
| `behavior-stats` | Show behavioral statistics and scoring weights |
| `intel` | Show threat intelligence engine status |
| `mitre` | Show MITRE ATT&CK technique coverage |
| `iocs` | Show loaded Indicators of Compromise |
| `ioc-check hash <value>` | Check if an IoC is known malicious |
| `cves` | Show tracked CVE vulnerabilities |
| `yara` | Show loaded YARA rules |
| `sigma` | Show loaded Sigma detection rules |
| `ebpf` | Show eBPF kernel sensor status and capabilities |
| `providers-health` | Show telemetry provider health with diagnostics |
| `fleet` | Show fleet overview and agent management |
| `fleet-agents` | List all fleet agents |
| `fleet-agent <id>` | Show detailed info for a specific agent |
| `fleet-policies` | Show distributed fleet policies |
| `fleet-actions` | Show recent remote actions |

### CLI Global Options

```
--config <PATH>    Path to configuration file
```

---

## 4. Configuration

SentinelX uses a TOML configuration file. The default search path is determined by the `directories` crate (`~/.config/sentinelx/sentinelx.toml` on Linux), or you can specify a custom path with `--config`.

### Default configuration

Copy the provided `sentinelx.toml` to `/etc/sentinelx/sentinelx.toml`:

```bash
sudo mkdir -p /etc/sentinelx
sudo cp sentinelx.toml /etc/sentinelx/sentinelx.toml
sudo nano /etc/sentinelx/sentinelx.toml
```

### Configuration reference

```toml
[general]
hostname = ""                  # Auto-detected if empty
scan_interval_seconds = 60     # Scan interval for monitor mode
baseline_on_start = true       # Establish baseline on startup
max_memory_mb = 150            # Memory usage cap
max_cpu_percent = 3.0          # CPU usage cap

[detection]
enabled_detectors = [
    "kernel_integrity",
    "hidden_process",
    "hidden_module",
    "hidden_connection",
    "hook_detection",
    "memory_integrity",
    "persistence",
    "privilege_escalation",
]
severity_threshold = "low"     # Minimum severity to report
mitre_attack_mapping = true    # Map detections to MITRE ATT&CK
evidence_collection = true     # Collect evidence for detections

[monitoring]
process_monitoring = true
network_monitoring = true
module_monitoring = true
memory_monitoring = true
syscall_monitoring = true
file_integrity_monitoring = true

[storage]
database_path = "/var/lib/sentinelx/sentinelx.db"
evidence_path = "/var/lib/sentinelx/evidence"
log_path = "/var/log/sentinelx"
retention_days = 90            # Data retention period
max_events = 1000000           # Maximum events to retain

[api]
enabled = true
host = "127.0.0.1"
port = 8443
tls_enabled = false
cors_origins = ["http://localhost:3000"]

[logging]
level = "info"                 # trace, debug, info, warn, error
format = "pretty"              # pretty, compact, json
file_output = true
json_format = false

[ebpf]
enabled = true
map_size = 10240
perf_buffer_pages = 64
max_events_per_second = 10000
```

### Validation rules

- `scan_interval_seconds` must be > 0
- `max_memory_mb` must be between 1 and 1024
- `max_cpu_percent` must be between 0 and 100
- `api.port` cannot be 0
- `retention_days` must be > 0

---

## 5. Arch Linux

### Building an AUR package

Create a `PKGBUILD`:

```bash
mkdir -p ~/sentinelx-pkg && cd ~/sentinelx-pkg
```

```bash
# PKGBUILD
pkgname=sentinelx
pkgver=1.0.0
pkgrel=1
pkgdesc="Enterprise Linux Runtime Integrity & Rootkit Detection Platform"
arch=('x86_64')
url="https://github.com/sentinelx/sentinelx"
license=('GPL-3.0-or-later')
depends=('sqlite' 'gcc-libs' 'zlib')
makedepends=('cargo' 'linux-headers' 'pkg-config')
options=(!strip)
source=("$pkgname-$pkgver.tar.gz::https://github.com/sentinelx/sentinelx/archive/v$pkgver.tar.gz")

build() {
    cd "$srcdir/sentinelx-$pkgver"
    cargo build --release --frozen
}

package() {
    cd "$srcdir/sentinelx-$pkgver"
    install -Dm755 target/release/sentinelx-backend "$pkgdir/usr/bin/sentinelx-backend"
    install -Dm755 target/release/sentinelx-cli "$pkgdir/usr/bin/sentinelx-cli"
    install -Dm644 sentinelx.toml "$pkgdir/etc/sentinelx/sentinelx.toml"
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
```

Build and install:

```bash
makepkg -si
```

### Using an AUR helper (yay/paru)

```bash
yay -S sentinelx
# or
paru -S sentinelx
```

---

## 6. Debian/Ubuntu

### Build a .deb package

```bash
# Install build dependencies
sudo apt update
sudo apt install build-essential pkg-config libsqlite3-dev linux-headers-$(uname -r) \
    dpkg-dev fakeroot

# Build SentinelX
cargo build --release

# Create package structure
PKGDIR=$(mktemp -d)
mkdir -p "$PKGDIR/DEBIAN"
mkdir -p "$PKGDIR/usr/bin"
mkdir -p "$PKGDIR/etc/sentinelx"
mkdir -p "$PKGDIR/var/lib/sentinelx"
mkdir -p "$PKGDIR/var/log/sentinelx"
mkdir -p "$PKGDIR/usr/share/doc/sentinelx"

# Install binaries
cp target/release/sentinelx-backend "$PKGDIR/usr/bin/"
cp target/release/sentinelx-cli "$PKGDIR/usr/bin/"
chmod 755 "$PKGDIR/usr/bin/sentinelx-backend" "$PKGDIR/usr/bin/sentinelx-cli"

# Install configuration
cp sentinelx.toml "$PKGDIR/etc/sentinelx/"
cp LICENSE "$PKGDIR/usr/share/doc/sentinelx/"

# Create control file
cat > "$PKGDIR/DEBIAN/control" << EOF
Package: sentinelx
Version: 1.0.0
Section: security
Priority: optional
Architecture: amd64
Depends: libsqlite3-0
Maintainer: SentinelX Contributors <sentinelx@example.com>
Description: Enterprise Linux Runtime Integrity & Rootkit Detection Platform
 SentinelX detects kernel rootkits, hidden processes, hidden modules,
 hidden connections, syscall hooks, memory tampering, persistence
 mechanisms, and more on Linux systems.
EOF

# Build the .deb
fakeroot dpkg-deb --build "$PKGDIR" "sentinelx_1.0.0_amd64.deb"

# Install
sudo dpkg -i sentinelx_1.0.0_amd64.deb
sudo apt-get install -f  # Fix any missing dependencies
```

---

## 7. Fedora/RHEL

### Build an RPM package

```bash
# Install build dependencies
sudo dnf groupinstall "Development Tools"
sudo dnf install kernel-devel pkg-config sqlite-devel rpm-build

# Build SentinelX
cargo build --release

# Create RPM build tree
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create spec file
cat > ~/rpmbuild/SPECS/sentinelx.spec << 'EOF'
Name:           sentinelx
Version:        1.0.0
Release:        1%{?dist}
Summary:        Enterprise Linux Runtime Integrity & Rootkit Detection Platform
License:        GPL-3.0-or-later
URL:            https://github.com/sentinelx/sentinelx
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  cargo
BuildRequires:  kernel-devel
BuildRequires:  sqlite-devel

%description
SentinelX detects kernel rootkits, hidden processes, hidden modules,
hidden connections, syscall hooks, memory tampering, persistence
mechanisms, and more on Linux systems.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/sentinelx
mkdir -p %{buildroot}/var/lib/sentinelx
mkdir -p %{buildroot}/var/log/sentinelx
install -m 755 target/release/sentinelx-backend %{buildroot}/usr/bin/
install -m 755 target/release/sentinelx-cli %{buildroot}/usr/bin/
install -m 644 sentinelx.toml %{buildroot}/etc/sentinelx/

%files
/usr/bin/sentinelx-backend
/usr/bin/sentinelx-cli
%config(noreplace) /etc/sentinelx/sentinelx.toml
%dir /var/lib/sentinelx
%dir /var/log/sentinelx

%changelog
EOF

# Build the RPM
rpmbuild -ba ~/rpmbuild/SPECS/sentinelx.spec

# Install
sudo rpm -i ~/rpmbuild/RPMS/x86_64/sentinelx-1.0.0-1.*.rpm
```

---

## 8. Docker

### Dockerfile

```dockerfile
FROM rust:1.75-slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libsqlite3-dev linux-headers-amd64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libsqlite3-0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r sentinelx && useradd -r -g sentinelx sentinelx
RUN mkdir -p /var/lib/sentinelx /var/log/sentinelx /etc/sentinelx
RUN chown -R sentinelx:sentinelx /var/lib/sentinelx /var/log/sentinelx

COPY --from=builder /build/target/release/sentinelx-backend /usr/bin/
COPY --from=builder /build/target/release/sentinelx-cli /usr/bin/
COPY sentinelx.toml /etc/sentinelx/sentinelx.toml

EXPOSE 8443

ENTRYPOINT ["sentinelx-backend"]
CMD ["--host", "0.0.0.0", "--port", "8443"]
```

### Build and run

```bash
# Build the image
docker build -t sentinelx:latest .

# Run (note: requires --privileged or specific capabilities for eBPF)
docker run -d \
    --name sentinelx \
    --privileged \
    -p 8443:8443 \
    -v /var/lib/sentinelx:/var/lib/sentinelx \
    -v /var/log/sentinelx:/var/log/sentinelx \
    sentinelx:latest

# Run in dry-run mode without privileged
docker run -d \
    --name sentinelx \
    -p 8443:8443 \
    -v /var/lib/sentinelx:/var/lib/sentinelx \
    sentinelx:latest --host 127.0.0.1
```

### Docker Compose

```yaml
version: "3.8"
services:
  sentinelx:
    build: .
    container_name: sentinelx
    privileged: true
    ports:
      - "8443:8443"
    volumes:
      - sentinelx-data:/var/lib/sentinelx
      - sentinelx-logs:/var/log/sentinelx
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
    environment:
      - RUST_LOG=info

volumes:
  sentinelx-data:
  sentinelx-logs:
```

### Docker notes

- For full detection capabilities (eBPF, fanotify, netlink, audit), the container must run with `--privileged` or explicit capability grants: `--cap-add=CAP_BPF --cap-add=CAP_SYS_ADMIN --cap-add=CAP_PERFMON --cap-add=CAP_AUDIT_WRITE`
- The SQLite database should be persisted via a volume mount to `/var/lib/sentinelx/`
- Without privileged mode, SentinelX falls back gracefully: telemetry providers degrade to proc scanning, and the pipeline still functions
