# Architecture Overview

SentinelX is an enterprise Linux runtime integrity and rootkit detection platform built in Rust. It consists of **34 crates**, a REST API backend, a CLI tool, and a React dashboard.

## System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          SentinelX System                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────── Kernel Space ──────────────────────────────┐  │
│  │  eBPF Programs  │  fanotify  │  NETLINK_ROUTE  │ NETLINK_AUDIT│  │
│  └──────────────────────────┬─────────────────────────────────────┘  │
│                              │                                        │
│  ┌──────────────────── User Space ────────────────────────────────┐  │
│  │  ┌──────────┐   ┌──────────────┐   ┌────────────────────────┐ │  │
│  │  │ Telemetry│──▶│   Pipeline   │──▶│   Analysis Engines     │ │  │
│  │  │  Engine   │   │ Coordinator  │   │ Correlation │ Incident │ │  │
│  │  └──────────┘   └──────────────┘   │ Threat      │ Behavior │ │  │
│  │                                     │ Intelligence│ Timeline │ │  │
│  │                                     └────────────────────────┘ │  │
│  │                              │                                  │  │
│  │  ┌───────────────────────────▼───────────────────────────────┐ │  │
│  │  │              Response Engine                              │ │  │
│  │  │  Alert │ Kill │ Block │ Quarantine │ Isolate │ Forensics  │ │  │
│  │  └──────────────────────────────────────────────────────────┘ │  │
│  │                              │                                  │  │
│  │  ┌───────────┐  ┌───────────▼──────────┐  ┌───────────────┐  │  │
│  │  │    CLI    │  │   REST API (Axum)     │  │   Dashboard   │  │  │
│  │  └───────────┘  └──────────────────────┘  └───────────────┘  │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐ │  │
│  │  │           SQLite Database (WAL mode)                     │ │  │
│  │  └──────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
```

## Core Pipeline

The evidence-driven detection pipeline is the heart of SentinelX. It decomposes detection into four discrete, composable stages:

```
Linux System → Discovery → Metadata → Assessment → Evidence
```

### Phase 1: Discovery

Seven `DiscoveryProvider` implementations observe the system:

- **Process** — Scans /proc, task_struct, scheduler queues
- **Module** — Scans /proc/modules, sysfs, kallsyms
- **Network** — Scans /proc/net, netlink, connection tables
- **Persistence** — Scans systemd, cron, init scripts, ld.so.preload
- **Kernel** — Monitors kernel text, sysctl, hooks
- **Memory** — Checks kallsyms, /proc/self/maps, W^X enforcement
- **Integrity** — Verifies hashes of critical system files

### Phase 2: Metadata Enrichment

Seven `MetadataCollector` implementations enrich discovered objects with properties, ownership, hashes, permissions, package info, and tags.

### Phase 3: Assessment

Seven `ObjectAssessor` implementations produce numeric scores:

| Dimension | Range | Description |
|-----------|-------|-------------|
| Trust | 0–100 | How trustworthy the object is |
| Integrity | 0–100 | Integrity of the object |
| Risk | 0–100 | Risk level posed by the object |
| Reputation | 0–100 | Known reputation |
| Confidence | 0.0–1.0 | Assessment confidence |

### Phase 4: Evidence Generation

Immutable `CoreEvidence` records are generated from assessment results and stored in the evidence store.

## Crate Inventory

| Crate | Purpose |
|-------|---------|
| `sentinelx-common` | Shared types, errors, traits |
| `sentinelx-config` | TOML configuration management |
| `sentinelx-core` | Pipeline interfaces |
| `sentinelx-assessment` | Numeric scoring engine (0–100) |
| `sentinelx-database` | SQLite storage (18 repositories) |
| `sentinelx-telemetry` | Metrics collector, bus, providers |
| `sentinelx-kernel` | Kernel integrity monitoring |
| `sentinelx-process` | Process scanning and assessment |
| `sentinelx-network` | Network connection scanning |
| `sentinelx-module` | Kernel module scanning, DKOM detection |
| `sentinelx-memory` | Memory integrity checks |
| `sentinelx-integrity` | File integrity monitoring |
| `sentinelx-persistence` | Persistence mechanism scanning |
| `sentinelx-forensics` | Forensic evidence collection |
| `sentinelx-correlation` | Relationship graph, TOML rules |
| `sentinelx-incident` | Security incident management |
| `sentinelx-threat` | Weighted risk scoring |
| `sentinelx-reporting` | Markdown/JSON reports with MITRE mapping |
| `sentinelx-response` | Automated response with safety controls |
| `sentinelx-rule-engine` | Custom user-defined detection rules |
| `sentinelx-behavior` | Behavioral profiling engine |
| `sentinelx-intelligence` | IoCs, MITRE ATT&CK, YARA, Sigma, CVE |
| `sentinelx-ebpf` | eBPF telemetry provider (Aya) |
| `sentinelx-fanotify` | fanotify filesystem monitoring |
| `sentinelx-netlink` | Netlink process/network monitoring |
| `sentinelx-audit` | Audit subsystem telemetry |
| `sentinelx-transport` | Secure message transport (TLS) |
| `sentinelx-agent` | Endpoint agent for fleet |
| `sentinelx-coordinator` | Central coordinator for fleet |
| `sentinelx-fleet` | Fleet orchestration |

## Binaries

| Binary | Description |
|--------|-------------|
| `sentinelx-backend` | Axum REST API server (~7.4 MB release) |
| `sentinelx-cli` | Command-line interface (~2.3 MB release) |

## Technology Stack

- **Language**: Rust (edition 2021, MSRV 1.75)
- **Async Runtime**: Tokio
- **Web Framework**: Axum 0.7
- **CLI Framework**: Clap 4
- **Database**: SQLite via sqlx 0.8 (WAL mode)
- **eBPF**: Aya framework
- **Frontend**: React + TypeScript + Tailwind CSS
- **Build**: Cargo with LTO release profile
