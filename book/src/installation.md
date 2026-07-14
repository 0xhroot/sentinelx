# Installation Guide

## Prerequisites

### Required

| Dependency | Minimum Version | Purpose |
|------------|----------------|---------|
| **Rust** | 1.75+ | Compiler (edition 2021) |
| **Linux kernel** | 5.8+ | eBPF, fanotify, netlink, audit sockets |
| **SQLite** | 3.x | Persistent storage (WAL mode) |
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

### Optional (Dashboard)

| Dependency | Version | Purpose |
|------------|---------|---------|
| **Node.js** | 18+ | Dashboard build (React + TypeScript + Vite) |
| **npm** | 9+ | Dashboard package manager |

### Optional (eBPF Sensor)

| Dependency | Purpose |
|------------|---------|
| `CAP_BPF` or `CAP_SYS_ADMIN` capability | eBPF program loading |
| `CAP_PERFMON` capability | Performance monitoring |
| BTF support (`/sys/kernel/btf/vmlinux`) | CO-RE eBPF programs |

### Privileges

SentinelX requires **root privileges** (or equivalent capabilities) for:

- eBPF program loading and map access
- fanotify filesystem monitoring
- Netlink socket monitoring
- Audit subsystem access
- Reading `/proc` entries for all processes
- Process termination (response engine)

Run with `sudo` or configure Linux capabilities via systemd.

## Building from Source

```bash
git clone https://github.com/sentinelx/sentinelx.git
cd sentinelx

# Build all crates in release mode
cargo build --release
```

The release profile enables LTO, single codegen unit, strip, and panic=abort:

```toml
[profile.release]
lto = true
codegen-units = 1
opt-level = 3
strip = true
panic = "abort"
```

Release binaries:

| Binary | Size |
|--------|------|
| `target/release/sentinelx-backend` | ~7.4 MB |
| `target/release/sentinelx-cli` | ~2.3 MB |

### Build the Dashboard (Optional)

```bash
cd apps/dashboard
npm install
npm run build
```

### Run Tests

```bash
cargo test
```

### Lint and Format Check

```bash
cargo fmt --check
cargo clippy -- -D warnings
```

## Running SentinelX

### Backend (REST API)

```bash
# Default configuration
./target/release/sentinelx-backend

# Custom host/port/config
./target/release/sentinelx-backend --host 127.0.0.1 --port 9443 --config /etc/sentinelx/sentinelx.toml
```

### CLI

```bash
./target/release/sentinelx-cli scan
./target/release/sentinelx-cli monitor --interval 60
./target/release/sentinelx-cli status
```

## Distribution Packages

### Arch Linux (AUR)

```bash
makepkg -si
# or
yay -S sentinelx
```

### Debian/Ubuntu

```bash
sudo dpkg -i sentinelx_1.0.0_amd64.deb
```

### Fedora/RHEL

```bash
sudo rpm -i sentinelx-1.0.0-1.x86_64.rpm
```

### Docker

```bash
docker build -t sentinelx .
docker run --privileged --network host sentinelx
```

See [Deployment](deployment.md) for production setup details.
