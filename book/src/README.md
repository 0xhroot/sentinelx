# SentinelX Documentation

**Enterprise Linux Runtime Integrity & Rootkit Detection Platform**

SentinelX is an advanced open-source Linux security platform built in Rust, capable of detecting kernel rootkits, hidden processes, hidden modules, hidden connections, syscall hooks, memory tampering, persistence mechanisms, and more.

## Key Features

- **Kernel Integrity Engine** — Monitors kernel text, read-only sections, sysctl hardening, and critical structures
- **Hidden Process Detection** — Compares multiple sources (task_struct, /proc, scheduler queues) to find hidden processes
- **Hidden Module Detection** — Detects DKOM attacks by comparing /proc/modules, sysfs, and kallsyms
- **Hidden Connection Detection** — Finds connections not traceable to any process
- **Hook Detection** — Detects syscall table hooks, inline hooks, ftrace hooks, and kprobe abuse
- **Memory Integrity** — Monitors kernel memory sections, symbol tables, and process memory mappings
- **Persistence Scanner** — Scans systemd, cron, rc.local, ld.so.preload, bash profiles, init scripts
- **Correlation Engine** — Correlates multiple indicators to detect complex attacks
- **Forensics Engine** — Collects complete forensic snapshots
- **Response Engine** — Automated response with configurable actions (alert, kill, block, quarantine)
- **REST API** — Full REST API with OpenAPI support
- **React Dashboard** — Modern dark-theme security dashboard
- **CLI** — Full-featured command-line interface

## Architecture at a Glance

```
┌──────────────────────────────────────────────────────────────────┐
│                        SentinelX System                          │
├──────────────────────────────────────────────────────────────────┤
│  ┌────────────────── Kernel Space ────────────────────────────┐ │
│  │  eBPF Programs │ fanotify │ NETLINK_ROUTE │ NETLINK_AUDIT  │ │
│  └────────────────────────────┬───────────────────────────────┘ │
│  ┌────────────────── User Space ──────────────────────────────┐ │
│  │  Telemetry → Pipeline Coordinator → Analysis Engines       │ │
│  │  Response Engine → CLI / REST API / Dashboard              │ │
│  │  Fleet Management → SQLite Database (WAL mode)             │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

## Performance

| Metric | Value |
|--------|-------|
| CPU usage (idle) | < 2% |
| CPU usage (scanning) | < 3% |
| Memory usage (idle) | < 100 MB |
| Memory usage (scanning) | < 150 MB |
| Full scan latency | < 2 seconds |
| eBPF event latency | ~45 μs average |
| Telemetry bus throughput | 50,000 events/second |

## Quick Start

```bash
# Build
cargo build --release

# Run backend
./target/release/sentinelx-backend

# Run a scan
./target/release/sentinelx-cli scan
```

See the [Installation](installation.md) guide for detailed setup instructions.
