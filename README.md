<div align="center">

# SentinelX

**Enterprise Linux Runtime Integrity & Rootkit Detection Platform**

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![CI](https://github.com/sentinelx/sentinelx/actions/workflows/ci.yml/badge.svg)](https://github.com/sentinelx/sentinelx/actions/workflows/ci.yml)
[![Rust Version](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://www.kernel.org/)
[![Version](https://img.shields.io/badge/Version-1.0.0-green.svg)](VERSION)
[![Tests](https://img.shields.io/badge/Tests-696%20passing-brightgreen.svg)](#testing)
[![Security](https://img.shields.io/badge/Security-audit%20clean-yellow.svg)](SECURITY.md)
[![Docker](https://img.shields.io/badge/Docker-available-blue.svg)](#docker)

A memory-safe, high-performance Linux security platform built in Rust with real-time kernel-level telemetry via eBPF, fanotify, netlink, and audit sockets. SentinelX provides evidence-driven threat detection, automated incident response, and fleet management for enterprise environments.

[Quick Start](#quick-start) | [Installation](#installation) | [Architecture](#architecture-overview) | [CLI Reference](#cli-reference) | [API Reference](#rest-api) | [Documentation](#documentation)

</div>

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Key Features](#key-features)
- [Architecture Overview](#architecture-overview)
- [Complete Processing Pipeline](#complete-processing-pipeline)
- [Project Architecture](#project-architecture)
- [Core Concepts](#core-concepts)
- [Detection Methodology](#detection-methodology)
- [Threat Lifecycle](#threat-lifecycle)
- [Directory Structure](#directory-structure)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [REST API](#rest-api)
- [Dashboard](#dashboard)
- [Fleet Management](#fleet-management)
- [Security Model](#security-model)
- [Performance](#performance)
- [Testing](#testing)
- [Development Guide](#development-guide)
- [Plugin Architecture](#plugin-architecture)
- [Roadmap](#roadmap)
- [Comparison](#comparison-with-other-tools)
- [Screenshots](#screenshots)
- [FAQ](#frequently-asked-questions)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Executive Summary

### What SentinelX Is

SentinelX is an open-source, evidence-driven Linux runtime integrity monitoring and rootkit detection platform written entirely in Rust. It provides real-time kernel-level telemetry, multi-engine threat detection, automated incident response, and fleet-wide coordination for enterprise security operations.

### Why SentinelX Was Built

Existing Linux security tools force uncomfortable tradeoffs:

| Problem | Existing Tools | SentinelX |
|---------|---------------|-----------|
| **Kernel visibility** | eBPF-only tools lack filesystem/audit context | Unified telemetry across eBPF, fanotify, netlink, audit |
| **Detection accuracy** | Signature-based tools produce high false-positive rates | Evidence-driven pipeline with 5-dimension scoring |
| **Response capability** | Detection-only tools require manual intervention | Automated response with safety controls and rollback |
| **Fleet management** | Single-host tools lack multi-host coordination | Built-in fleet management with TLS transport |
| **Memory safety** | C/C++ tools are vulnerable to exploitation | Written in Rust with minimal unsafe (52 FFI blocks) |
| **Architecture** | Monolithic tools resist extension | 34-crate modular workspace |

### Design Philosophy

1. **Evidence is immutable.** Once created, `CoreEvidence` objects cannot be modified, ensuring forensic integrity.
2. **Graceful degradation.** Every subsystem has fallback paths. If eBPF is unavailable, fanotify is used. If fanotify fails, audit sockets take over.
3. **Safety by default.** The response engine defaults to dry-run mode, never kills PID 1, never unloads core kernel modules, and never quarantines system binaries.
4. **Pipeline-driven.** All data flows through a consistent 4-layer pipeline: Discovery, Metadata, Assessment, Evidence.
5. **Offline-first.** Threat intelligence, MITRE ATT&CK mappings, and detection rules work without network connectivity.

---

## Key Features

| Category | Feature | Description |
|----------|---------|-------------|
| **Architecture** | Evidence-driven pipeline | 4-layer processing: Discovery, Metadata, Assessment, Evidence |
| **Architecture** | 34-crate workspace | Modular Rust crates with clear separation of concerns |
| **Architecture** | Async runtime | Tokio-based async processing with bounded channels |
| **Detection** | Kernel integrity | Detects hooked syscalls, modified kernel structures, DKOM attacks |
| **Detection** | Process scanning | Hidden processes, suspicious forks, privilege escalation |
| **Detection** | Module scanning | Unsigned modules, hidden modules, DKOM detection |
| **Detection** | Network scanning | Hidden connections, reverse shells, suspicious sockets |
| **Detection** | Memory scanning | Memory tampering, injected code, process memory anomalies |
| **Detection** | File integrity | Critical file modification, permission changes, new executables |
| **Detection** | Persistence scanning | Systemd, cron, rc.local, LD_PRELOAD, init scripts |
| **Telemetry** | eBPF sensor | Real-time kernel events via Aya framework |
| **Telemetry** | fanotify | Filesystem-level event monitoring |
| **Telemetry** | Netlink | Network interface, route, and neighbor changes |
| **Telemetry** | Audit subsystem | Audit daemon integration via NETLINK_AUDIT |
| **Telemetry** | Provider fallback | Automatic degradation: eBPF, fanotify, netlink, audit, proc |
| **Analysis** | Correlation engine | Relationship graph, TOML-driven rules, multi-indicator detection |
| **Analysis** | Incident management | Lifecycle tracking: Open, Investigating, Contained, Resolved, Closed |
| **Analysis** | Threat scoring | 5-dimension risk assessment: Trust, Integrity, Risk, Reputation, Confidence |
| **Analysis** | Behavior profiling | Weighted scoring across 7 behavioral factors |
| **Analysis** | Threat intelligence | IoCs, MITRE ATT&CK, YARA, Sigma, CVE tracking |
| **Response** | Automated response | 22 response actions with safety controls and rollback |
| **Response** | Safety controls | Dry-run mode, PID 1 protection, core module protection |
| **Response** | Audit logging | Full response audit trail with rollback tracking |
| **Fleet** | Coordinator | Central coordination for multi-host deployments |
| **Fleet** | Agents | Endpoint agents with heartbeat monitoring |
| **Fleet** | TLS transport | rustls-based mTLS with gzip compression |
| **Fleet** | Policy distribution | Push policies to fleet agents |
| **Dashboard** | Web UI | React + TypeScript SPA with 10 monitoring pages |
| **API** | REST API | 86 endpoints covering all subsystems |
| **CLI** | 34 commands | Complete command-line interface for all operations |
| **Packaging** | Multi-format | PKGBUILD, DEB, RPM, Docker, systemd |
| **Performance** | Optimized build | LTO, single codegen unit, stripped binaries |
| **Security** | Memory safe | Rust with minimal unsafe; all unsafe blocks audited |

---

## Architecture Overview

SentinelX processes security data through a pipeline of specialized subsystems. Each subsystem is implemented as one or more Rust crates in the workspace.

### Subsystem Overview

```mermaid
graph TB
    subgraph "Kernel Space"
        eBPF[eBPF Probes]
        FA[fa:fa-folder fanotify]
        NL[fa:fa-network-wired Netlink]
        AU[fa:fa-shield-alt Audit]
    end

    subgraph "Telemetry Layer"
        PM[Provider Manager]
        TE[Telemetry Engine]
        TB[Telemetry Bus]
    end

    subgraph "Detection Pipeline"
        DP[Discovery Providers<br/>7 engines]
        MC[Metadata Collectors<br/>7 collectors]
        AE[Assessment Engine<br/>7 assessors]
        ES[Evidence Store]
    end

    subgraph "Analysis Layer"
        CE[Correlation Engine]
        IE[Incident Engine]
        TE2[Threat Engine]
        BE[Behavior Engine]
        TI[Threat Intelligence]
    end

    subgraph "Response Layer"
        RE[Response Engine]
        WE[Workflow Engine]
        PE[Policy Engine]
        AL[Audit Log]
    end

    subgraph "Fleet Layer"
        CO[Coordinator]
        AG[Agents]
        TM[Transport Manager]
    end

    subgraph "Interface Layer"
        CLI[CLI - 34 commands]
        API[REST API - 86 endpoints]
        DB[Dashboard - React SPA]
    end

    eBPF --> PM
    FA --> PM
    NL --> PM
    AU --> PM
    PM --> TE
    TE --> TB
    TB --> DP
    DP --> MC
    MC --> AE
    AE --> ES
    ES --> CE
    CE --> IE
    IE --> TE2
    TE2 --> BE
    BE --> TI
    TE2 --> RE
    RE --> WE
    WE --> PE
    PE --> AL
    CO <--> TM
    TM <--> AG
    ES --> CLI
    ES --> API
    API --> DB
```

### Subsystem Responsibilities

| Subsystem | Crate(s) | Responsibility |
|-----------|----------|---------------|
| **Discovery** | `process`, `module`, `network`, `kernel`, `memory`, `integrity`, `persistence` | Discover security-relevant objects (processes, modules, connections, files) |
| **Metadata** | Same as Discovery | Enrich discovered objects with additional context (hashes, permissions, parents) |
| **Assessment** | `assessment` | Score objects across 5 dimensions: Trust, Integrity, Risk, Reputation, Confidence |
| **Evidence** | `evidence`, `core` | Create immutable `CoreEvidence` objects with full provenance |
| **Correlation** | `correlation` | Identify multi-indicator attacks via relationship graph and TOML rules |
| **Incident** | `incident` | Track security incidents through their lifecycle |
| **Threat** | `threat` | Generate threat decisions with weighted risk scores |
| **Response** | `response`, `rule_engine` | Execute automated response actions with safety controls |
| **Telemetry** | `telemetry` | Real-time event processing via kernel providers |
| **Behavior** | `behavior` | Profile object behavior across 7 weighted factors |
| **Intelligence** | `intelligence` | IoCs, MITRE ATT&CK, YARA, Sigma, CVE tracking |
| **Fleet** | `fleet`, `coordinator`, `agent`, `transport` | Multi-host coordination, heartbeat, policy distribution |
| **Database** | `database` | SQLite persistence for all data |
| **Configuration** | `config` | TOML-based configuration management |

---

## Complete Processing Pipeline

Every piece of security data flows through SentinelX via this pipeline:

```mermaid
flowchart TD
    A[Linux Kernel] -->|eBPF events| B[Telemetry Engine]
    A -->|fanotify events| B
    A -->|netlink events| B
    A -->|audit events| B
    A -->|proc filesystem| B

    B -->|Events| C[Discovery Providers]

    C -->|SentinelObjects| D[Metadata Collectors]
    D -->|Enriched Objects| E[Assessment Engine]
    E -->|Scored Objects| F[Evidence Store]

    F -->|CoreEvidence| G[Correlation Engine]
    G -->|CorrelationResults| H[Incident Engine]
    H -->|Incidents| I[Threat Engine]
    I -->|ThreatDecisions| J[Response Engine]

    J -->|Actions| K[Alert / Kill / Block / Isolate]
    J -->|Audit Trail| L[Audit Log]

    F -->|Evidence| M[Timeline Engine]
    M -->|Attack Timeline| N[Dashboard / CLI / API]

    B -->|Events| O[Behavior Engine]
    O -->|BehaviorProfiles| P[Intelligence Engine]
```

### Pipeline Stages Explained

**Stage 1: Kernel Data Collection**

The telemetry layer collects raw events from four kernel subsystems simultaneously:

| Provider | Source | Events Captured |
|----------|--------|----------------|
| eBPF | Kernel probes via Aya | Process exec/exit/fork/clone/setuid, file open/write/delete, syscall tracing |
| fanotify | Filesystem notifications | File access, creation, deletion, permission changes |
| Netlink | AF_NETLINK socket | Interface changes, route updates, neighbor discovery |
| Audit | NETLINK_AUDIT socket | Syscall auditing, security events, access control |

**Stage 2: Discovery**

Seven discovery providers scan the system for security-relevant objects:

| Provider | Objects Discovered |
|----------|-------------------|
| `ProcessDiscoveryProvider` | Running processes, process trees, capabilities, open files |
| `ModuleDiscoveryProvider` | Loaded kernel modules, module signatures, module sources |
| `NetworkDiscoveryProvider` | Active connections, listening sockets, network interfaces |
| `KernelIntegrityProvider` | Kernel text integrity, syscall table, IDT/GDT |
| `MemoryIntegrityProvider` | Memory regions, injected code, process memory |
| `FileIntegrityProvider` | Critical file hashes, permission changes, new executables |
| `PersistenceDiscoveryProvider` | Systemd units, cron jobs, rc.local, LD_PRELOAD |

**Stage 3: Metadata Enrichment**

Each discovered object is enriched with additional context:

- Process: parent PID, command line, open files, capabilities, execution history
- Module: signature status, source (in-tree/out-of-tree), load address
- Network: connection state, remote endpoint, protocol, socket options
- File: SHA-256 hash, permissions, owner, modification time, SELinux context

**Stage 4: Assessment**

Seven assessors score each object across five dimensions:

| Dimension | Range | Description |
|-----------|-------|-------------|
| Trust | 0-100 | Based on signature verification, known-good status |
| Integrity | 0-100 | Based on hash comparison, tamper detection |
| Risk | 0-100 | Based on behavioral anomalies, suspicious patterns |
| Reputation | 0-100 | Based on threat intelligence, IoC matches |
| Confidence | 0.0-1.0 | Statistical confidence in the assessment |

**Stage 5: Evidence Generation**

Objects with non-None risk levels produce immutable `CoreEvidence` objects containing:

- Unique evidence ID
- Object reference and type
- All five assessment scores
- Collection timestamp
- Source detector name
- Raw metadata

**Stage 6: Correlation**

The correlation engine identifies multi-indicator attacks using:

- **In-memory graph** for relationship modeling
- **TOML-driven rules** with 6 default patterns
- **Time-window analysis** (300s and 600s windows)
- **Evidence clustering** across detectors

**Stage 7: Incident Creation**

Correlated evidence produces incidents with:

- Lifecycle status tracking (Open, Investigating, Contained, Resolved, Closed)
- Attack chain reconstruction
- MITRE ATT&CK mapping
- Severity escalation (only upward)

**Stage 8: Threat Decision**

The threat engine generates decisions with weighted risk scores:

```
Final Score = Trust(20%) + Integrity(20%) + Risk(25%) + Reputation(15%) + Evidence(10%) + Complexity(10%)
```

**Stage 9: Response Execution**

The response engine selects and executes actions based on:

- Severity thresholds (critical, high, medium, low)
- Confidence levels
- Threat type matching
- Safety controls (dry-run, PID protection, module protection)

---

## Project Architecture

### Workspace Structure

The workspace contains 40 crates organized into logical groups:

```
sentinelx/
├── crates/
│   ├── common/          # Shared types, errors, traits
│   ├── config/          # TOML configuration management
│   ├── core/            # Pipeline interfaces and coordinator
│   ├── database/        # SQLite storage via sqlx
│   ├── telemetry/       # Metrics, tracing, event bus, providers
│   ├── assessment/      # Central scoring engine (7 assessors)
│   ├── detector/        # Detection engine, event bus, scoring
│   ├── evidence/        # Indexed evidence store
│   ├── rule_engine/     # Custom user-defined detection rules
│   │
│   ├── process/         # Process discovery and metadata
│   ├── module/          # Kernel module scanning
│   ├── network/         # Network connection scanning
│   ├── kernel/          # Kernel integrity monitoring
│   ├── memory/          # Memory integrity monitoring
│   ├── integrity/       # File integrity monitoring
│   ├── persistence/     # Persistence mechanism scanning
│   ├── forensics/       # Forensic snapshot collection
│   │
│   ├── ebpf/            # eBPF kernel sensor (Aya)
│   ├── fanotify/        # Filesystem monitoring (fanotify)
│   ├── netlink/         # Network monitoring (AF_NETLINK)
│   ├── audit/           # Audit subsystem (NETLINK_AUDIT)
│   │
│   ├── correlation/     # Relationship graph, TOML rules
│   ├── incident/        # Incident lifecycle management
│   ├── threat/          # Threat decisions, risk scoring
│   ├── timeline/        # Attack timeline generation
│   ├── behavior/        # Behavioral profiling engine
│   ├── intelligence/    # IoCs, MITRE, YARA, Sigma, CVE
│   │
│   ├── response/        # Automated response, safety controls
│   │
│   ├── transport/       # TLS/mTLS message transport
│   ├── agent/           # Endpoint agent
│   ├── coordinator/     # Fleet coordinator
│   ├── fleet/           # Fleet management
│   │
│   ├── benchmarks/      # Criterion benchmarks (4 suites)
│   └── integration-tests/ # Reliability and failure mode tests
│
├── apps/
│   ├── cli/             # Clap-based CLI (34 commands)
│   └── dashboard/       # React + TypeScript SPA
│
├── backend/             # Axum REST API server (86 endpoints)
├── docs/                # Architecture and operations docs
├── examples/            # Configuration, API, CLI examples
├── fuzz/                # Fuzz testing targets (6 targets)
├── packaging/           # PKGBUILD, systemd, install scripts
├── book/                # mdBook documentation site
└── tests/               # Integration tests
```

### Crate Dependency Graph

```mermaid
graph TD
    common --> config
    common --> core
    common --> database
    common --> telemetry
    common --> assessment
    common --> detector
    common --> evidence
    common --> rule_engine

    core --> process
    core --> module
    core --> network
    core --> kernel
    core --> memory
    core --> integrity
    core --> persistence

    telemetry --> ebpf
    telemetry --> fanotify
    telemetry --> netlink
    telemetry --> audit

    evidence --> correlation
    correlation --> incident
    incident --> threat
    threat --> response

    behavior --> intelligence
    intelligence --> threat

    transport --> agent
    transport --> coordinator
    agent --> fleet
    coordinator --> fleet

    database --> backend
    backend --> cli
```

---

## Core Concepts

### Objects

A `SentinelObject` represents any security-relevant entity on the system:

| Object Type | Example | Canonical ID |
|-------------|---------|-------------|
| Process | sshd PID 1234 | `process:1234` |
| Kernel Module | nvidia | `module:nvidia` |
| Network Connection | TCP 10.0.0.1:22 | `network:10.0.0.1:22` |
| File | /etc/passwd | `file:/etc/passwd` |
| Kernel Symbol | sys_call_table | `kernel:sys_call_table` |

### Evidence

`CoreEvidence` is an immutable record of an assessment:

- **Immutable**: Created once, never modified
- **Attributed**: Linked to the source object and detector
- **Scored**: Contains all five assessment dimensions
- **Timestamped**: Records exact collection time
- **Auditable**: Full provenance chain

### Assessments

The assessment engine scores objects across five dimensions, each producing a 0-100 score:

| Dimension | Assessor | Weight |
|-----------|----------|--------|
| Trust | Signature verification, known-good database | 20% |
| Integrity | Hash comparison, tamper detection | 20% |
| Risk | Behavioral anomaly detection | 25% |
| Reputation | Threat intelligence, IoC matching | 15% |
| Confidence | Statistical confidence in all scores | 10% (0-1.0) |

### Incidents

A security incident represents a correlated set of evidence:

| Field | Description |
|-------|-------------|
| Status | Open, Investigating, Contained, Resolved, Closed |
| Severity | Info, Low, Medium, High, Critical |
| Attack Chain | Ordered steps of the attack |
| MITRE Mappings | ATT&CK technique IDs |
| Related Objects | Processes, files, modules involved |

### Threats

A `ThreatDecision` is the final output of the analysis pipeline:

- **Risk Score**: Composite score (0-100) from weighted dimensions
- **Priority**: Immediate, High, Normal, Low, Informational
- **Recommendation**: Suggested response actions
- **Response Plan**: Pre-defined response workflow

### Responses

The response engine executes actions with safety controls:

| Safety Control | Default | Description |
|---------------|---------|-------------|
| `dry_run` | `true` | Log actions without executing |
| `never_kill_init` | `true` | Never kill PID 1 |
| `never_unload_core_modules` | `true` | Protect vmlinux, core, nvidia, drm, kvm |
| `never_quarantine_system_binaries` | `true` | Protect /usr/bin, /bin, /sbin |
| `never_delete_files` | `true` | Never delete files, only quarantine |
| Protected PIDs | `[1]` | PIDs that cannot be killed |
| Protected Modules | `[vmlinux, core, nvidia, drm, kvm]` | Modules that cannot be unloaded |

---

## Detection Methodology

### Why Evidence Is Immutable

Evidence immutability ensures forensic integrity. Once a `CoreEvidence` object is created during the assessment phase, it cannot be modified by any subsequent engine. This means:

- Correlation results cannot alter the underlying evidence
- Incident creation cannot modify evidence scores
- Threat decisions cannot change evidence timestamps
- Response actions cannot delete evidence records

### Why Correlation Exists

Single-indicator detections produce high false-positive rates. The correlation engine addresses this by:

1. **Multi-indicator detection**: Requiring multiple related events within a time window
2. **Relationship modeling**: Building a graph of entities and their relationships
3. **Pattern matching**: Applying TOML-driven rules to identify known attack patterns
4. **Temporal analysis**: Using time windows (300s, 600s) to group related events

### Default Correlation Rules

| Rule | Conditions | Window | Description |
|------|-----------|--------|-------------|
| Multi-indicator | 3+ events | 300s | Multiple security events from same source |
| Privilege escalation chain | 2+ events | 600s | Sequential privilege escalation indicators |
| Rootkit indicators | 3+ events | 300s | Hook + hidden process + integrity violation |
| Process anomaly cluster | 3+ events | 600s | Multiple process-related anomalies |
| Cross-detector evidence | 2+ evidence | 300s | Evidence from multiple detectors |
| Severity escalation | 3+ events | 600s | Increasing severity over time |

### Why Incidents Exist

Incidents provide a higher-level view than individual threats. They:

- Group related threats into a single security event
- Track the lifecycle of a security issue
- Enable human investigation and response
- Support severity escalation (only upward)
- Map to MITRE ATT&CK techniques

---

## Threat Lifecycle

```mermaid
sequenceDiagram
    participant Kernel as Linux Kernel
    participant Tel as Telemetry Engine
    participant Disc as Discovery
    participant Assess as Assessment
    participant Corr as Correlation
    participant Inc as Incident Engine
    participant Threat as Threat Engine
    participant Resp as Response Engine
    participant Audit as Audit Log

    Kernel->>Tel: Raw event (eBPF/fanotify/netlink/audit)
    Tel->>Disc: TelemetryEvent
    Disc->>Disc: Discover SentinelObjects
    Disc->>Assess: Enriched Objects
    Assess->>Assess: Score (Trust, Integrity, Risk, Reputation, Confidence)
    Assess->>Corr: CoreEvidence (immutable)
    
    Corr->>Corr: Build relationship graph
    Corr->>Corr: Apply correlation rules
    Corr->>Inc: CorrelationResults
    
    Inc->>Inc: Create/update incidents
    Inc->>Inc: Reconstruct attack chain
    Inc->>Threat: Incidents with evidence
    
    Threat->>Threat: Calculate risk score
    Threat->>Threat: Generate threat decision
    Threat->>Resp: ThreatDecision
    
    Resp->>Resp: Match response policies
    Resp->>Resp: Check safety controls
    Resp->>Resp: Execute response actions
    Resp->>Audit: AuditRecord
    
    Note over Audit: Full audit trail with<br/>rollback tracking
```

---

## Directory Structure

```
sentinelx/
├── Cargo.toml              # Workspace root (40 members)
├── Cargo.lock              # Dependency lockfile
├── VERSION                 # 1.0.0
├── LICENSE                 # GPL-3.0-or-later
├── README.md               # This file
├── CHANGELOG.md            # Version history
├── CONTRIBUTING.md         # Contribution guide
├── SECURITY.md             # Security policy
├── CODE_OF_CONDUCT.md      # Code of conduct
├── RELEASE_NOTES.md        # v1.0.0 release notes
├── KNOWN_LIMITATIONS.md    # Known limitations
├── ROADMAP.md              # Future roadmap
├── deny.toml               # cargo-deny config
├── Makefile                # Build automation
├── Dockerfile              # Multi-stage Docker build
├── docker-compose.yml      # Docker Compose config
│
├── crates/                 # 34 Rust library crates
│   ├── common/             # Shared types and traits
│   ├── config/             # Configuration management
│   ├── core/               # Pipeline coordinator
│   ├── database/           # SQLite storage
│   ├── telemetry/          # Telemetry engine
│   ├── assessment/         # Assessment engine
│   ├── detector/           # Detection engine
│   ├── evidence/           # Evidence store
│   ├── rule_engine/        # Custom rules
│   ├── process/            # Process scanning
│   ├── module/             # Module scanning
│   ├── network/            # Network scanning
│   ├── kernel/             # Kernel integrity
│   ├── memory/             # Memory integrity
│   ├── integrity/          # File integrity
│   ├── persistence/        # Persistence scanning
│   ├── forensics/          # Forensic snapshots
│   ├── ebpf/               # eBPF sensor
│   ├── fanotify/           # fanotify monitoring
│   ├── netlink/            # Netlink monitoring
│   ├── audit/              # Audit subsystem
│   ├── correlation/        # Correlation engine
│   ├── incident/           # Incident management
│   ├── threat/             # Threat decisions
│   ├── timeline/           # Attack timeline
│   ├── behavior/           # Behavior profiling
│   ├── intelligence/       # Threat intelligence
│   ├── response/           # Response engine
│   ├── transport/          # TLS transport
│   ├── agent/              # Fleet agent
│   ├── coordinator/        # Fleet coordinator
│   ├── fleet/              # Fleet management
│   ├── benchmarks/         # Criterion benchmarks
│   └── integration-tests/  # Reliability tests
│
├── apps/
│   ├── cli/                # Command-line interface
│   └── dashboard/          # React web dashboard
│
├── backend/                # Axum REST API server
├── docs/                   # Documentation (14 files)
│   ├── diagrams/           # Mermaid diagrams (10 files)
│   ├── ARCHITECTURE_OVERVIEW.md
│   ├── INSTALL.md
│   ├── DEPLOYMENT.md
│   ├── OPERATIONS.md
│   ├── SECURITY.md
│   ├── PERFORMANCE.md
│   ├── BENCHMARKS.md
│   └── architecture-phase*.md
│
├── examples/               # Usage examples
│   ├── config/             # Sample configuration
│   ├── api/                # API usage scripts
│   ├── cli/                # CLI usage scripts
│   ├── docker/             # Docker examples
│   ├── fleet/              # Fleet deployment guide
│   └── response/           # Custom response workflows
│
├── fuzz/                   # Fuzz testing (6 targets)
├── book/                   # mdBook documentation site
├── packaging/              # Packaging files
│   ├── PKGBUILD            # Arch Linux
│   ├── sentinelx.spec      # RPM
│   ├── sentinelx.service   # systemd
│   ├── sentinelx.conf      # Default config (TOML)
│   ├── sentinelx.install   # Arch install script
│   ├── install.sh          # Universal installer
│   └── uninstall.sh        # Uninstaller
│
└── .github/
    ├── workflows/          # CI/CD (3 workflows)
    ├── ISSUE_TEMPLATE/     # Issue templates
    ├── PULL_REQUEST_TEMPLATE.md
    ├── CODEOWNERS
    ├── dependabot.yml
    └── FUNDING.yml
```

---

## Technology Stack

| Technology | Version | Purpose | Why Selected |
|-----------|---------|---------|-------------|
| **Rust** | 1.75+ | Primary language | Memory safety, zero-cost abstractions, Linux kernel compatibility |
| **Tokio** | 1.x | Async runtime | Industry-standard async Rust, excellent ecosystem |
| **Axum** | 0.7 | HTTP framework | Tower-based, ergonomic, production-ready |
| **SQLx** | 0.8 | Database | Async SQLite with compile-time query checks |
| **Serde** | 1.x | Serialization | De facto standard for Rust serialization |
| **Tracing** | 0.1 | Structured logging | Distributed tracing, structured events |
| **Clap** | 4.x | CLI framework | Derive-based, type-safe argument parsing |
| **Aya** | 0.14 | eBPF framework | Pure-Rust eBPF, no C dependencies |
| **rustls** | 0.23 | TLS | Memory-safe TLS, no OpenSSL dependency |
| **flate2** | 1.x | Compression | Gzip compression for transport |
| **React** | 18.x | Dashboard UI | Component-based, large ecosystem |
| **TypeScript** | 5.x | Dashboard types | Type safety for frontend |
| **Vite** | 5.x | Dashboard build | Fast HMR, optimized builds |
| **SQLite** | 3.x | Database | Zero-config, embedded, reliable |
| **Docker** | - | Containerization | Standard deployment format |
| **GitHub Actions** | - | CI/CD | Native GitHub integration |

### Why Rust Over C/C++

| Criterion | C/C++ | Rust |
|-----------|-------|------|
| Memory safety | Manual management | Compiler-enforced |
| Data races | Possible at runtime | Prevented at compile time |
| Unsafe code | Implicit everywhere | Explicit and auditable |
| Dependencies | System package manager | Cargo with lockfile |
| Testing | Multiple frameworks | Built-in `cargo test` |
| Documentation | Varies | `cargo doc` with doc comments |

---

## Installation

### System Requirements

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| OS | Linux 5.8+ | Linux 6.1+ |
| Architecture | x86_64, aarch64 | x86_64 |
| RAM | 256 MB | 512 MB |
| Disk | 100 MB | 500 MB |
| Rust | 1.75+ | Latest stable |
| Privileges | root (for kernel access) | root |

### Arch Linux

```bash
# From AUR
yay -S sentinelx

# Or build from source
git clone https://github.com/sentinelx/sentinelx
cd sentinelx
makepkg -si
```

### Debian / Ubuntu

```bash
# Install dependencies
sudo apt install build-essential libssl-dev pkg-config

# Build from source
git clone https://github.com/sentinelx/sentinelx
cd sentinelx
cargo build --release

# Install
sudo cp target/release/sentinelx-backend /usr/bin/
sudo cp target/release/sentinelx-cli /usr/bin/
sudo cp packaging/sentinelx.service /etc/systemd/system/
sudo cp packaging/sentinelx.conf /etc/sentinelx/sentinelx.toml
```

### Fedora / RHEL

```bash
# Install dependencies
sudo dnf install gcc openssl-devel sqlite-devel

# Build from source
git clone https://github.com/sentinelx/sentinelx
cd sentinelx
cargo build --release

# Install
sudo cp target/release/sentinelx-backend /usr/bin/
sudo cp target/release/sentinelx-cli /usr/bin/
```

### Docker

```bash
# Pull and run
docker pull ghcr.io/sentinelx/sentinelx:latest
docker run -d \
  --name sentinelx \
  --cap-add NET_ADMIN \
  --cap-add SYS_PTRACE \
  --cap-add AUDIT_CONTROL \
  --cap-add SYSLOG \
  -v sentinelx-data:/var/lib/sentinelx \
  -p 8443:8443 \
  ghcr.io/sentinelx/sentinelx:latest
```

### Docker Compose

```yaml
version: "3.8"
services:
  sentinelx:
    build: .
    cap_add:
      - NET_ADMIN
      - SYS_PTRACE
      - AUDIT_CONTROL
      - SYSLOG
    volumes:
      - sentinelx-data:/var/lib/sentinelx
      - ./sentinelx.toml:/etc/sentinelx/sentinelx.toml:ro
    ports:
      - "8443:8443"
    restart: unless-stopped
volumes:
  sentinelx-data:
```

### From Source

```bash
# Clone
git clone https://github.com/sentinelx/sentinelx
cd sentinelx

# Build (debug)
cargo build

# Build (release, optimized)
cargo build --release

# Run tests
cargo test --workspace

# Install
cargo install --path backend
cargo install --path apps/cli
```

---

## Quick Start

```bash
# 1. Clone and build
git clone https://github.com/sentinelx/sentinelx
cd sentinelx
cargo build --release

# 2. Start the backend server
sudo ./target/release/sentinelx-backend --host 0.0.0.0 --port 8443

# 3. In another terminal, run a scan
sudo ./target/release/sentinelx-cli scan

# 4. Check system status
sudo ./target/release/sentinelx-cli status

# 5. View the dashboard
# Open http://localhost:8443 in your browser

# 6. Check threats
sudo ./target/release/sentinelx-cli threats

# 7. View timeline
sudo ./target/release/sentinelx-cli timeline

# 8. Enable continuous monitoring
sudo ./target/release/sentinelx-cli monitor --interval 30
```

---

## Configuration

SentinelX uses TOML configuration. The default configuration file is located at `/etc/sentinelx/sentinelx.toml`.

### Complete Configuration Reference

```toml
[general]
# System hostname (auto-detected if empty)
hostname = ""
# Scan interval in seconds for continuous monitoring
scan_interval_seconds = 60
# Capture baseline on first start
baseline_on_start = true
# Maximum memory usage in MB
max_memory_mb = 150
# Maximum CPU usage percentage
max_cpu_percent = 3.0

[detection]
# Enable/disable specific detection engines
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
# Minimum severity threshold for alerts
severity_threshold = "low"
# Enable MITRE ATT&CK mapping
mitre_attack_mapping = true
# Enable evidence collection
evidence_collection = true

[monitoring]
# Enable/disable monitoring for each subsystem
process = true
network = true
module = true
memory = true
syscall = true
file_integrity = true

[storage]
# SQLite database path
database_path = "/var/lib/sentinelx/sentinelx.db"
# Evidence file storage path
evidence_path = "/var/lib/sentinelx/evidence"
# Log file path
log_path = "/var/log/sentinelx"
# Data retention in days
retention_days = 90
# Maximum events in database
max_events = 1000000

[api]
# Enable REST API
enabled = true
# API listen host
host = "127.0.0.1"
# API listen port
port = 8443
# Enable TLS
tls_enabled = false
# TLS certificate path
tls_cert_path = ""
# TLS key path
tls_key_path = ""
# CORS allowed origins
cors_origins = []

[logging]
# Log level: trace, debug, info, warn, error
level = "info"
# Log format: text, json
format = "text"
# Log to file (empty = stdout only)
file_output = ""
# Use JSON format for file output
json_format = false

[ebpf]
# Enable eBPF sensor
enabled = true
# eBPF map size
map_size = 10240
# Perf buffer pages
perf_buffer_pages = 64
# Maximum events per second
max_events_per_second = 10000
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Tracing log filter |
| `SENTINELX_CONFIG` | `/etc/sentinelx/sentinelx.toml` | Configuration file path |

---

## CLI Reference

SentinelX provides 34 CLI commands organized by category.

### Detection Commands

| Command | Description | Example |
|---------|-------------|---------|
| `scan` | Run full detection scan | `sentinelx-cli scan` |
| `monitor` | Continuous monitoring mode | `sentinelx-cli monitor --interval 30` |
| `status` | System status and metrics | `sentinelx-cli status` |
| `integrity` | Kernel and file integrity | `sentinelx-cli integrity` |
| `modules` | Kernel modules with trust | `sentinelx-cli modules` |
| `processes` | Running processes | `sentinelx-cli processes` |
| `network` | Active connections | `sentinelx-cli network` |

### Analysis Commands

| Command | Description | Example |
|---------|-------------|---------|
| `timeline` | Threat event timeline | `sentinelx-cli timeline` |
| `assess` | Run assessment engine | `sentinelx-cli assess --object-type process` |
| `incidents` | Security incidents | `sentinelx-cli incidents` |
| `threats` | Threat decisions | `sentinelx-cli threats` |
| `graph` | Correlation graph | `sentinelx-cli graph` |

### Forensics Commands

| Command | Description | Example |
|---------|-------------|---------|
| `forensics` | Forensic snapshot | `sentinelx-cli forensics` |
| `export` | Export to file | `sentinelx-cli export --format json --output ./export` |

### Response Commands

| Command | Description | Example |
|---------|-------------|---------|
| `response` | Response engine status | `sentinelx-cli response` |
| `workflows` | Response workflows | `sentinelx-cli workflows` |
| `audit` | Response audit log | `sentinelx-cli audit` |

### Telemetry Commands

| Command | Description | Example |
|---------|-------------|---------|
| `telemetry` | Telemetry engine status | `sentinelx-cli telemetry` |
| `events` | Recent telemetry events | `sentinelx-cli events --count 50` |
| `providers` | Registered providers | `sentinelx-cli providers` |
| `monitor-live` | Live telemetry feed | `sentinelx-cli monitor-live --interval 5` |
| `ebpf` | eBPF sensor status | `sentinelx-cli ebpf` |
| `providers-health` | Provider diagnostics | `sentinelx-cli providers-health` |

### Behavior Commands

| Command | Description | Example |
|---------|-------------|---------|
| `behavior` | Behavior engine status | `sentinelx-cli behavior` |
| `behavior-profiles` | Behavioral profiles | `sentinelx-cli behavior-profiles` |
| `behavior-stats` | Behavior statistics | `sentinelx-cli behavior-stats` |

### Intelligence Commands

| Command | Description | Example |
|---------|-------------|---------|
| `intel` | Intelligence engine status | `sentinelx-cli intel` |
| `mitre` | MITRE ATT&CK coverage | `sentinelx-cli mitre` |
| `iocs` | Loaded IoCs | `sentinelx-cli iocs` |
| `ioc-check` | Check IoC reputation | `sentinelx-cli ioc-check --type hash --value abc123` |
| `cves` | Tracked CVEs | `sentinelx-cli cves` |
| `yara` | YARA rules | `sentinelx-cli yara` |
| `sigma` | Sigma rules | `sentinelx-cli sigma` |

### Fleet Commands

| Command | Description | Example |
|---------|-------------|---------|
| `fleet` | Fleet overview | `sentinelx-cli fleet` |
| `fleet-agents` | List agents | `sentinelx-cli fleet-agents` |
| `fleet-agent` | Agent detail | `sentinelx-cli fleet-agent --agent-id agent-001` |
| `fleet-policies` | Fleet policies | `sentinelx-cli fleet-policies` |
| `fleet-actions` | Remote actions | `sentinelx-cli fleet-actions` |

### Config Commands

| Command | Description | Example |
|---------|-------------|---------|
| `config` | Show configuration | `sentinelx-cli config` |

---

## REST API

SentinelX exposes 86 REST API endpoints organized by category.

### Base URL

```
http://localhost:8443/api
```

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/status` | System status |
| `POST` | `/api/scan` | Run full scan |
| `POST` | `/api/scan/{detector}` | Run specific detector |
| `GET` | `/api/detectors` | List detectors |

### Threat Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/threats` | List threats |
| `GET` | `/api/threats/stats` | Threat statistics |
| `GET` | `/api/threats/{id}` | Get threat |
| `POST` | `/api/threats/{id}/acknowledge` | Acknowledge threat |
| `POST` | `/api/threats/{id}/resolve` | Resolve threat |

### Detection Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/processes` | List processes |
| `GET` | `/api/modules` | List modules |
| `GET` | `/api/network` | List connections |
| `GET` | `/api/kernel/integrity` | Kernel integrity |
| `GET` | `/api/memory/integrity` | Memory integrity |

### Evidence Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/evidence` | List evidence |
| `POST` | `/api/evidence/collect` | Collect evidence |
| `GET` | `/api/evidence/stats` | Evidence statistics |

### Incident Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/incidents` | List incidents |
| `GET` | `/api/incidents/{id}` | Get incident |
| `POST` | `/api/incidents/{id}/status` | Update status |

### Response Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/responses` | List responses |
| `GET` | `/api/responses/audit` | Response audit log |
| `GET` | `/api/workflows` | List workflows |

### Telemetry Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/telemetry` | Telemetry events |
| `GET` | `/api/telemetry/live` | Live event stream |
| `GET` | `/api/telemetry/providers` | List providers |
| `GET` | `/api/telemetry/providers/health` | Provider health |
| `GET` | `/api/telemetry/stats` | Telemetry statistics |

### Intelligence Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/intelligence/iocs` | List IoCs |
| `POST` | `/api/intelligence/iocs` | Add IoC |
| `GET` | `/api/intelligence/mitre` | MITRE techniques |
| `GET` | `/api/intelligence/yara` | YARA rules |
| `GET` | `/api/intelligence/sigma` | Sigma rules |
| `GET` | `/api/intelligence/cves` | CVE entries |

### Fleet Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/fleet` | Fleet overview |
| `GET` | `/api/fleet/agents` | List agents |
| `GET` | `/api/fleet/agents/{id}` | Agent detail |
| `POST` | `/api/fleet/heartbeat` | Agent heartbeat |
| `GET` | `/api/fleet/policies` | Fleet policies |
| `POST` | `/api/fleet/policies` | Distribute policy |
| `GET` | `/api/fleet/actions` | Remote actions |

### Example: curl

```bash
# Health check
curl http://localhost:8443/api/health

# Run a scan
curl -X POST http://localhost:8443/api/scan

# List threats
curl http://localhost:8443/api/threats

# Get threat statistics
curl http://localhost:8443/api/threats/stats

# List incidents
curl http://localhost:8443/api/incidents

# Get telemetry events
curl http://localhost:8443/api/telemetry?count=10

# Live telemetry stream (SSE)
curl -N http://localhost:8443/api/telemetry/live

# Add an IoC
curl -X POST http://localhost:8443/api/intelligence/iocs \
  -H "Content-Type: application/json" \
  -d '{"type": "hash", "value": "abc123", "source": "manual"}'

# Fleet overview
curl http://localhost:8443/api/fleet
```

---

## Dashboard

SentinelX includes a React + TypeScript web dashboard with 10 monitoring pages.

### Pages

| Page | Description |
|------|-------------|
| **Overview** | System health, key metrics, recent alerts |
| **Threats** | Active threats with severity, confidence, MITRE mapping |
| **Incidents** | Security incidents with lifecycle tracking |
| **Evidence** | Collected evidence with assessment scores |
| **Telemetry** | Real-time telemetry event feed |
| **Processes** | Running processes with suspicious indicators |
| **Modules** | Kernel modules with trust assessment |
| **Network** | Active connections with anomaly detection |
| **Kernel Integrity** | Kernel memory and structure integrity |
| **Settings** | Configuration management |

### Building the Dashboard

```bash
cd apps/dashboard
npm install
npm run dev      # Development server (port 5173)
npm run build    # Production build to dist/
```

---

## Fleet Management

SentinelX supports multi-host security monitoring through its fleet management system.

### Architecture

```mermaid
graph TB
    subgraph "Coordinator Host"
        CO[Coordinator Engine]
        TM[Transport Manager<br/>TLS/mTLS]
        DB[(SQLite)]
    end

    subgraph "Agent Host 1"
        AG1[Agent Engine]
        TP1[Telemetry Provider]
    end

    subgraph "Agent Host 2"
        AG2[Agent Engine]
        TP2[Telemetry Provider]
    end

    subgraph "Agent Host N"
        AGN[Agent Engine]
        TPN[Telemetry Provider]
    end

    CO <-->|TLS| AG1
    CO <-->|TLS| AG2
    CO <-->|TLS| AGN

    AG1 --> TP1
    AG2 --> TP2
    AGN --> TPN

    CO --> DB
```

### Components

| Component | Role |
|-----------|------|
| **Coordinator** | Central coordination, policy distribution, action dispatch |
| **Agent** | Endpoint agent, telemetry collection, action execution |
| **Transport** | TLS/mTLS with gzip compression, message framing |
| **FleetManager** | High-level fleet operations, health tracking |

### Message Types

| Message | Direction | Purpose |
|---------|-----------|---------|
| `Registration` | Agent -> Coordinator | Register new agent |
| `RegistrationAck` | Coordinator -> Agent | Confirm registration |
| `Heartbeat` | Agent -> Coordinator | Periodic health check |
| `HeartbeatAck` | Coordinator -> Agent | Confirm heartbeat |
| `Telemetry` | Agent -> Coordinator | Telemetry events |
| `Incident` | Agent -> Coordinator | Security incidents |
| `Threat` | Agent -> Coordinator | Threat decisions |
| `Policy` | Coordinator -> Agent | Distribute policies |
| `PolicyAck` | Agent -> Coordinator | Confirm policy receipt |
| `RemoteAction` | Coordinator -> Agent | Execute remote action |
| `RemoteActionResult` | Agent -> Coordinator | Action result |

---

## Security Model

### Trust Model

SentinelX operates with the following trust assumptions:

1. **Root privileges required**: Kernel-level monitoring requires root or specific capabilities
2. **Trusted bootloader**: The system bootloader and kernel are trusted
3. **Trusted SentinelX binary**: The SentinelX binary itself is not tampered with
4. **Trusted configuration**: The configuration file is not modified by an attacker

### Least Privilege

The systemd service uses minimal capabilities:

```
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_AUDIT_CONTROL CAP_SYSLOG
```

| Capability | Purpose |
|-----------|---------|
| `CAP_NET_ADMIN` | Network monitoring, interface inspection |
| `CAP_SYS_PTRACE` | Process inspection, /proc access |
| `CAP_AUDIT_CONTROL` | Audit subsystem access |
| `CAP_SYSLOG` | Kernel log access |

### Response Safety

The response engine implements multiple safety layers:

| Safety Control | Description |
|---------------|-------------|
| Dry-run by default | All response actions are logged but not executed unless explicitly enabled |
| PID 1 protection | Never kills the init process |
| Core module protection | Never unloads vmlinux, core, nvidia, drm, or kvm modules |
| System binary protection | Never quarantines files in /usr/bin, /bin, /sbin |
| No file deletion | Files are quarantined, never deleted |
| Protected paths | /, /etc, /usr, /boot, /proc, /sys, /dev, /var/run, /run, /tmp |
| Audit logging | All actions are logged with full context |

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Rootkit detection | eBPF-based kernel integrity monitoring |
| Hidden processes | Process enumeration comparison (procfs vs kernel) |
| Hidden modules | Module list comparison with load tracking |
| Hook detection | Syscall table, IDT, kernel function integrity |
| Memory tampering | Process memory integrity scanning |
| Persistence | Systemd, cron, rc.local, LD_PRELOAD monitoring |
| Privilege escalation | Capability change detection, setuid monitoring |
| Network exfiltration | Connection monitoring, hidden socket detection |

---

## Performance

### Benchmark Results

| Benchmark | Median | p95 |
|-----------|--------|-----|
| Kernel integrity scan | ~50ms | ~80ms |
| Hook detection scan | ~30ms | ~50ms |
| Memory integrity scan | ~100ms | ~150ms |
| File integrity scan | ~200ms | ~300ms |
| Process scan | ~20ms | ~35ms |
| Network scan | ~15ms | ~25ms |
| Module trust scan | ~25ms | ~40ms |
| Full sequential scan | ~500ms | ~750ms |
| Full concurrent scan | ~200ms | ~350ms |
| Scan-to-timeline | ~600ms | ~900ms |
| Telemetry bus publish | ~1us | ~2us |
| Telemetry bus throughput | ~500K events/s | ~700K events/s |

### Resource Usage

| Resource | Idle | Active Scan | Continuous Monitoring |
|----------|------|-------------|----------------------|
| CPU | < 1% | < 3% | < 2% |
| Memory | ~30 MB | ~80 MB | ~50 MB |
| Disk I/O | Minimal | ~10 MB/s | ~1 MB/s |
| Network | None | None | None (unless fleet) |

### Optimization

The release build uses maximum optimization:

```toml
[profile.release]
lto = true              # Link-Time Optimization
codegen-units = 1       # Single codegen unit
opt-level = 3           # Maximum optimization
strip = true            # Strip debug symbols
panic = "abort"         # No unwinding overhead
```

---

## Testing

SentinelX has **696 tests** across all crates.

### Test Categories

| Category | Count | Description |
|----------|-------|-------------|
| Unit tests | ~600 | Per-crate tests for individual functions |
| Integration tests | 10 | Reliability and failure mode tests |
| Doc tests | ~86 | Documentation examples |

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p sentinelx-telemetry

# Run with output
cargo test --workspace -- --nocapture

# Run specific test
cargo test test_database_corruption
```

### Integration Test Coverage

The integration tests (`crates/integration-tests/`) cover:

1. Database corruption handling
2. Network disconnection recovery
3. Agent state transitions
4. Telemetry engine restart
5. Panic recovery (task isolation)
6. Response dry-run execution
7. Concurrent stress testing
8. Channel backpressure
9. Configuration reload
10. Graceful shutdown

### Fuzz Testing

Six fuzz targets in `fuzz/`:

| Target | Focus |
|--------|-------|
| `fuzz_telemetry_event` | Telemetry event parsing |
| `fuzz_api_request` | API request handling |
| `fuzz_rule_parser` | TOML rule parsing |
| `fuzz_database_query` | SQL query construction |
| `fuzz_message_transport` | Message deserialization |
| `fuzz_response_policy` | Policy evaluation |

### Benchmarks

```bash
# Run all benchmarks
cargo bench --workspace

# Run specific benchmark suite
cargo bench --bench detector_scan
cargo bench --bench full_scan
cargo bench --bench analysis_pipeline
cargo bench --bench telemetry_throughput
```

### CI Pipeline

Every push runs:

1. `cargo fmt --check` - Formatting
2. `cargo clippy -- -D warnings` - Linting
3. `cargo test --workspace` - All 696 tests
4. `cargo build --release` - Release build
5. `cargo audit` - Security audit

---

## Development Guide

### Adding a New Detector

1. Create a crate in `crates/` implementing `DiscoveryProvider`, `MetadataCollector`, and `ObjectAssessor`
2. Register the provider in `backend/src/main.rs`
3. Add the crate to `Cargo.toml` workspace members
4. Write tests in `#[cfg(test)]` module
5. Add CLI commands in `apps/cli/src/commands/`

### Adding a New Assessment Dimension

1. Add a new assessor in `crates/assessment/src/`
2. Implement the `ObjectAssessor` trait
3. Register in `create_all_assessors()`
4. Add scoring configuration in `ScoringConfig`

### Adding a New Correlation Rule

1. Define the rule in TOML format
2. Add to `DEFAULT_RULES` in `crates/correlation/src/lib.rs`
3. Implement the correlation logic
4. Write tests

### Adding a New Response Action

1. Add variant to `ResponseAction` enum in `crates/response/src/types.rs`
2. Implement the action in `crates/response/src/engine.rs`
3. Add safety checks
4. Write tests

### Adding a New Telemetry Provider

1. Create a struct implementing `TelemetryProvider` trait
2. Register in `TelemetryEngine::register_provider()`
3. Add to `ProviderManager` with capability detection
4. Implement fallback logic

### Adding a New API Endpoint

1. Add handler function in `backend/src/routes.rs`
2. Register route in the `router()` function
3. Add request/response types
4. Write tests

### Adding a New CLI Command

1. Add command variant to the `Commands` enum in `apps/cli/src/main.rs`
2. Implement the command handler
3. Add help text and options
4. Write tests

---

## Plugin Architecture

SentinelX uses a trait-based extension model:

| Extension Point | Trait | Crate |
|----------------|-------|-------|
| Detection | `DiscoveryProvider`, `MetadataCollector`, `ObjectAssessor` | `core` |
| Assessment | `ObjectAssessor` | `assessment` |
| Correlation | `CorrelationRule` (TOML-driven) | `correlation` |
| Response | `ResponseAction` (enum-based) | `response` |
| Telemetry | `TelemetryProvider` | `telemetry` |
| Rules | `RuleCondition` (TOML-driven) | `rule_engine` |

### Future Plugin System

Planned for v2.0:

- WASM-based plugin runtime
- Dynamic loading of detection plugins
- User-defined telemetry providers
- Custom response action plugins
- API for external integrations

---

## Roadmap

### v1.0.0 (Current)

- Evidence-driven pipeline
- 7 detection engines
- 4 telemetry providers
- Correlation and incident management
- Automated response with safety controls
- Fleet management
- REST API (86 endpoints)
- CLI (34 commands)
- React dashboard

### v1.1.0

- PostgreSQL support
- Web-based management UI
- Automatic rule updates
- Enhanced MITRE ATT&CK coverage
- Performance improvements

### v1.2.0

- macOS support
- Windows support (limited)
- Container runtime monitoring
- Kubernetes integration

### v1.3.0

- Machine learning detection
- Cloud deployment support
- Multi-tenant architecture
- Advanced behavioral analysis

### v2.0.0

- Plugin system (WASM)
- API v2 with gRPC
- Distributed telemetry
- Advanced threat hunting
- Integration marketplace

---

## Comparison With Other Tools

| Feature | SentinelX | Falco | Wazuh | Velociraptor | Osquery |
|---------|-----------|-------|-------|--------------|---------|
| **Language** | Rust | C++ | C | Go | C++ |
| **Memory Safety** | Yes | Partial | No | Yes | No |
| **Kernel Monitoring** | eBPF + fanotify + netlink + audit | eBPF + syscall | Syscall audit | OS queries | OS queries |
| **Detection Method** | Evidence-driven pipeline | Rules | Rules + ML | Artifacts | Queries |
| **Response** | Built-in automated | Via sidekick | Built-in | Built-in | None |
| **Fleet Management** | Built-in | Via Falco sidekick | Built-in | Built-in | Via osqueryi |
| **Deployment** | Single binary + systemd | DaemonSet | Agent + manager | Single binary | Agent |
| **Configuration** | TOML | YAML | XML | YAML | SQL-like |
| **Database** | SQLite | None | MySQL/PostgreSQL | SQLite | None |
| **Dashboard** | Built-in React | Via Kibana | Built-in | None | None |
| **License** | GPL-3.0 | Apache-2.0 | GPL-2.0 | Apache-2.0 | Apache-2.0 |

> **Note**: This comparison focuses on architecture and deployment model. Each tool has specific strengths for different use cases. SentinelX differentiates through its evidence-driven pipeline, built-in response engine, and memory-safe implementation.

---

## Screenshots

<!-- Screenshots will be added after the first public release -->

| Screenshot | Description |
|-----------|-------------|
| Dashboard Overview | System health, key metrics, recent alerts |
| Threats View | Active threats with severity and MITRE mapping |
| Telemetry Feed | Real-time kernel events |
| Fleet Management | Multi-host agent status |
| CLI Output | Terminal-based detection results |

---

## Frequently Asked Questions

### General

**Q: What is SentinelX?**
A: SentinelX is an open-source Linux runtime integrity monitoring and rootkit detection platform. It provides real-time kernel-level telemetry, multi-engine threat detection, automated incident response, and fleet management.

**Q: Why is it written in Rust?**
A: Rust provides memory safety without garbage collection, zero-cost abstractions for performance, and prevents data races at compile time. For a security tool that operates at the kernel level, these properties are critical.

**Q: Is SentinelX production-ready?**
A: SentinelX v1.0.0 is the first stable release. It has 696 tests, comprehensive documentation, and has been hardened through security auditing. It is suitable for production deployment with appropriate testing.

### Installation

**Q: What Linux versions are supported?**
A: Linux kernel 5.8 or later is required for eBPF support. Tested on Ubuntu 20.04+, Debian 11+, Fedora 36+, Arch Linux, and RHEL 9+.

**Q: Can I run SentinelX without root?**
A: Root privileges are required for kernel-level monitoring (eBPF, fanotify, netlink, audit). Some features can run without root, but full detection capability requires root.

**Q: How much disk space does SentinelX need?**
A: The binary is approximately 10 MB. The database grows based on events; typical usage is 100-500 MB for 90-day retention.

### Detection

**Q: What does SentinelX detect?**
A: Rootkits, hidden processes, hidden kernel modules, hook detection, memory tampering, file integrity violations, persistence mechanisms, privilege escalation, hidden network connections, and suspicious syscalls.

**Q: How does SentinelX differ from signature-based tools?**
A: SentinelX uses an evidence-driven pipeline that correlates multiple indicators over time, reducing false positives. It scores objects across five dimensions rather than matching signatures.

**Q: Does SentinelX support custom detection rules?**
A: Yes. The `rule_engine` crate supports TOML-defined rules with conditions (Equals, GreaterThan, Regex, And, Or).

### Performance

**Q: What is the performance impact?**
A: Less than 3% CPU and 150 MB memory during active scanning. Idle usage is under 1% CPU and 30 MB memory.

**Q: Can SentinelX run continuously?**
A: Yes. Use `sentinelx-cli monitor --interval 30` for continuous monitoring. The telemetry engine runs in the background with configurable intervals.

### Fleet

**Q: How does fleet management work?**
A: A central coordinator communicates with endpoint agents via TLS-encrypted connections. Agents send heartbeats, telemetry, and incidents. The coordinator distributes policies and remote actions.

**Q: Is fleet communication encrypted?**
A: Yes. All fleet communication uses rustls-based TLS with optional mutual TLS (mTLS) certificate verification.

### Security

**Q: Is SentinelX itself secure?**
A: SentinelX is written in Rust with minimal unsafe code (52 FFI blocks, all audited). It uses parameterized SQL queries, input validation, and follows security best practices.

**Q: Can an attacker disable SentinelX?**
A: The systemd service uses `ProtectSystem=strict`, capability bounding, and system call filtering. An attacker would need root privileges to disable the service.

### Development

**Q: How can I contribute?**
A: See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Areas for contribution include: new detection engines, additional MITRE ATT&CK techniques, documentation, tests, and packaging.

**Q: How do I add a new detection engine?**
A: Implement the `DiscoveryProvider`, `MetadataCollector`, and `ObjectAssessor` traits, then register the provider in `backend/src/main.rs`. See the [Development Guide](#development-guide).

---

## Contributing

We welcome contributions from the community. See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Quick Start

```bash
# Fork and clone
git clone https://github.com/your-username/sentinelx
cd sentinelx

# Create a branch
git checkout -b feature/my-feature

# Make changes and test
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# Commit and push
git commit -m "feat: add new detection engine"
git push origin feature/my-feature

# Create a Pull Request
```

### Areas for Contribution

- New detection engines
- Additional MITRE ATT&CK technique coverage
- Documentation improvements
- Test coverage
- Packaging for additional distributions
- Dashboard improvements
- Performance optimizations
- Bug fixes

---

## License

SentinelX is licensed under the [GNU General Public License v3.0 or later](LICENSE).

This means you can:
- Use SentinelX for any purpose
- Study and modify the source code
- Distribute copies
- Distribute modified versions

Under the terms of the GPL-3.0, you must:
- Include the license and copyright notice
- State changes you made
- License your modifications under GPL-3.0
- Make source code available

For more information, see [https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html).

---

## Acknowledgements

### Libraries

- [Tokio](https://tokio.rs/) - Async runtime
- [Axum](https://github.com/tokio-rs/axum) - HTTP framework
- [SQLx](https://github.com/launchbadge/sqlx) - Async SQLite
- [Serde](https://serde.rs/) - Serialization
- [Clap](https://github.com/clap-rs/clap) - CLI framework
- [Aya](https://aya-rs.dev/) - eBPF framework
- [rustls](https://github.com/rustls/rustls) - TLS implementation
- [Tracing](https://github.com/tokio-rs/tracing) - Structured logging
- [Chrono](https://github.com/chronotope/chrono) - Date/time handling
- [UUID](https://github.com/uuid-rs/uuid) - UUID generation

### Projects

- [Falco](https://falco.org/) - Cloud-native runtime security
- [Wazuh](https://wazuh.com/) - Open-source security monitoring
- [Velociraptor](https://docs.velociraptor.app/) - Endpoint visibility
- [Osquery](https://osquery.io/) - SQL-powered OS instrumentation

### Community

- The Rust community for an incredible ecosystem
- Linux kernel developers for eBPF, fanotify, and netlink
- Open-source security researchers for threat detection methodologies
- Contributors to the MITRE ATT&CK framework

---

<div align="center">

**SentinelX v1.0.0** | [Documentation](docs/) | [API Reference](examples/api/openapi.yaml) | [Contributing](CONTRIBUTING.md) | [Security Policy](SECURITY.md)

Built with Rust. Designed for Linux. Secured by evidence.

</div>
