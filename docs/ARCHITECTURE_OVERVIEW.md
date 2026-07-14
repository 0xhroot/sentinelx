# SentinelX Architecture Overview

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Core Pipeline](#2-core-pipeline)
3. [Detection Engines](#3-detection-engines)
4. [Telemetry System](#4-telemetry-system)
5. [Correlation and Incident Management](#5-correlation-and-incident-management)
6. [Response Engine](#6-response-engine)
7. [Fleet Management](#7-fleet-management)
8. [Data Flow Diagrams](#8-data-flow-diagrams)
9. [Technology Stack](#9-technology-stack)

---

## 1. System Overview

SentinelX is an enterprise Linux runtime integrity and rootkit detection platform built in Rust. It consists of **34 crates**, a REST API backend, a CLI tool, and a React dashboard.

### High-level architecture

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
│  │                                                                  │  │
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
│  │  │           │  │   + OpenAPI + CORS     │  │   (React SPA) │  │  │
│  │  └───────────┘  └──────────────────────┘  └───────────────┘  │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐ │  │
│  │  │               Fleet Management                           │ │  │
│  │  │  Transport (TLS) │ Agent │ Coordinator │ Fleet Manager  │ │  │
│  │  └──────────────────────────────────────────────────────────┘ │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐ │  │
│  │  │           SQLite Database (WAL mode)                     │ │  │
│  │  │  18 tables │ Evidence │ Incidents │ Telemetry │ Fleet    │ │  │
│  │  └──────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
```

### Crate inventory (34 crates)

| Crate | Path | Purpose |
|-------|------|---------|
| `sentinelx-common` | `crates/common` | Shared types, errors, traits (Detector, Scanner), Severity |
| `sentinelx-config` | `crates/config` | Configuration management (TOML settings) |
| `sentinelx-core` | `crates/core` | Pipeline interfaces: Discovery, Metadata, Assessment, Evidence |
| `sentinelx-assessment` | `crates/assessment` | Central assessment engine with numeric scoring (0–100) |
| `sentinelx-database` | `crates/database` | SQLite storage with 18 repository implementations |
| `sentinelx-telemetry` | `crates/telemetry` | Metrics collector, telemetry engine, bus, provider manager |
| `sentinelx-detector` | `crates/detector` | Legacy detection engine, registry, event bus, scoring, trust |
| `sentinelx-kernel` | `crates/kernel` | Kernel integrity monitoring, hook detection, module discovery |
| `sentinelx-process` | `crates/process` | Process scanning, discovery, metadata, assessment |
| `sentinelx-network` | `crates/network` | Network connection scanning, discovery, metadata, assessment |
| `sentinelx-module` | `crates/module` | Kernel module scanning, DKOM detection, trust scoring |
| `sentinelx-memory` | `crates/memory` | Memory integrity checks (kallsyms, /proc/self/maps) |
| `sentinelx-integrity` | `crates/integrity` | File integrity monitoring for critical system files |
| `sentinelx-persistence` | `crates/persistence` | Persistence mechanism scanning (systemd, cron, init, etc.) |
| `sentinelx-forensics` | `crates/forensics` | Forensic evidence collection (process trees, network, modules) |
| `sentinelx-evidence` | `crates/evidence` | Evidence storage and indexing |
| `sentinelx-timeline` | `crates/timeline` | Chronological event reconstruction |
| `sentinelx-correlation` | `crates/correlation` | Relationship graph, TOML rules, evidence correlation |
| `sentinelx-incident` | `crates/incident` | Security incident management with status/severity tracking |
| `sentinelx-threat` | `crates/threat` | Threat engine with weighted risk scoring |
| `sentinelx-reporting` | `crates/reporting` | Report generation (Markdown, JSON) with MITRE ATT&CK mapping |
| `sentinelx-response` | `crates/response` | Automated response with safety controls (dry-run, rate limiting) |
| `sentinelx-rule-engine` | `crates/rule_engine` | Custom user-defined detection rules |
| `sentinelx-behavior` | `crates/behavior` | Behavioral profiling engine with TOML rules |
| `sentinelx-intelligence` | `crates/intelligence` | Threat intelligence: IoCs, MITRE ATT&CK, YARA, Sigma, CVE |
| `sentinelx-ebpf` | `crates/ebpf` | eBPF telemetry provider (Aya framework) |
| `sentinelx-fanotify` | `crates/fanotify` | fanotify filesystem monitoring provider |
| `sentinelx-netlink` | `crates/netlink` | Netlink process/network monitoring provider |
| `sentinelx-audit` | `crates/audit` | Audit subsystem telemetry provider |
| `sentinelx-transport` | `crates/transport` | Secure message transport (TLS, compression, framing) |
| `sentinelx-agent` | `crates/agent` | Endpoint agent for fleet deployment |
| `sentinelx-coordinator` | `crates/coordinator` | Central coordinator for fleet management |
| `sentinelx-fleet` | `crates/fleet` | High-level fleet orchestration and management |
| `sentinelx-benchmarks` | `crates/benchmarks` | Criterion benchmarks for telemetry throughput |

### Binaries

| Binary | Source | Description |
|--------|--------|-------------|
| `sentinelx-backend` | `backend/` | Axum REST API server with all engines |
| `sentinelx-cli` | `apps/cli/` | Command-line interface with 35+ subcommands |

### Frontend

| Application | Source | Description |
|------------|--------|-------------|
| Dashboard | `apps/dashboard/` | React + TypeScript + Tailwind CSS SPA |

---

## 2. Core Pipeline

The evidence-driven detection pipeline is the heart of SentinelX. It decomposes detection into four discrete, composable stages.

### Pipeline flow

```
Linux System
    │
    │  /proc, /sys, eBPF, netlink, audit, fanotify
    │
    ▼
┌─────────────────────────────────────────────────────┐
│              Phase 1: Discovery                     │
│  DiscoveryProvider::discover() → SentinelObjects    │
│  7 providers: process, module, network, persistence,│
│  kernel, memory, integrity                          │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│              Phase 2: Metadata Enrichment            │
│  MetadataCollector::enrich() → Enriched Objects     │
│  7 collectors: properties, ownership, hashes,       │
│  permissions, package_info, tags                    │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│              Phase 3: Assessment                     │
│  ObjectAssessor::assess() → AssessmentResult        │
│  7 assessors from sentinelx-assessment crate        │
│  Numeric scoring: trust/integrity/risk/reputation   │
│  (0–100) + confidence (0.0–1.0)                    │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│              Phase 4: Evidence Generation            │
│  CoreEvidence from assessment results               │
│  Immutable records with metadata + assessment       │
│  snapshot; stored in evidence_store                 │
└─────────────────────────────────────────────────────┘
```

### Key types

#### SentinelObject

The central domain entity. Everything the system observes is a `SentinelObject`.

```rust
pub struct SentinelObject {
    pub id: String,                           // "process:1234", "file:/etc/passwd"
    pub object_type: ObjectType,              // Process, KernelModule, NetworkConnection, etc.
    pub metadata: ObjectMetadata,             // Properties, ownership, hashes, tags
    pub relationships: Vec<ObjectRelationship>, // Links to other objects
    pub created_at: DateTime<Utc>,
    pub source: String,                       // Which provider discovered it
    pub assessments: Vec<AssessmentResult>,   // Accumulated assessments
    pub evidence_refs: Vec<Uuid>,             // Links to CoreEvidence
}
```

#### ObjectAssessment (numeric scoring)

```rust
pub struct ObjectAssessment {
    pub object_id: String,
    pub trust: u32,        // 0–100
    pub integrity: u32,    // 0–100
    pub risk: u32,         // 0–100
    pub reputation: u32,   // 0–100
    pub confidence: f64,   // 0.0–1.0
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
}
```

#### CoreEvidence (immutable)

```rust
pub struct CoreEvidence {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub object_id: String,
    pub evidence_type: CoreEvidenceType,
    pub source: String,
    pub confidence: f64,
    pub severity: CoreSeverity,
    pub metadata_snapshot: HashMap<String, Value>,
    pub assessment_snapshot: Option<AssessmentResult>,
    pub related_evidence: Vec<Uuid>,
    pub data: HashMap<String, Value>,
}
```

### Pipeline coordinator

```rust
pub struct PipelineCoordinator {
    discovery: DiscoveryEngine,      // Runs all DiscoveryProviders
    metadata: MetadataEngine,        // Runs all MetadataCollectors
    assessment: AssessmentEngine,    // Runs all ObjectAssessors
    evidence_store: Arc<RwLock<Vec<CoreEvidence>>>,
}
```

Execution: `pipeline.run()` → `PipelineResult { objects_discovered, objects_enriched, objects_assessed, evidence_count, duration_ms }`

### Object types

| ObjectType | Canonical ID format | Example |
|-----------|---------------------|---------|
| Process | `process:{pid}` | `process:1234` |
| KernelModule | `kernel_module:{name}` | `kernel_module:nvidia` |
| NetworkConnection | `network_connection:{proto}:{local}:{remote}` | `network_connection:tcp:127.0.0.1:8080:10.0.0.1:443` |
| File | `file:{path}` | `file:/etc/passwd` |
| MemoryRegion | `memory_region:{pid}:{address}` | `memory_region:1234:0x7fff12340000` |
| Service | `service:{name}` | `service:nginx` |

### Relationship graph

```rust
pub struct ObjectRelationship {
    pub relationship_type: RelationshipType,
    pub target_id: String,
}

pub enum RelationshipType {
    Parent, Child, DependsOn, ConnectsTo, Loads,
    Executes, Modifies, Owns, Inherits,
}
```

---

## 3. Detection Engines

### Process detection

| Component | Source | Function |
|-----------|--------|----------|
| `ProcessDiscoveryProvider` | `crates/process/src/discovery.rs` | Scans `/proc` via `ProcessScanner` |
| `ProcessMetadataCollector` | `crates/process/src/metadata.rs` | Enriches with package info, thread count, FD count |
| `ProcessAssessor` | `crates/process/src/assessment.rs` | Evaluates hidden status (DKOM, PID hide) |

Detection techniques: DKOM process hiding, PID manipulation, orphaned processes, hidden threads.

### Kernel module detection

| Component | Source | Function |
|-----------|--------|----------|
| `ModuleDiscoveryProvider` | `crates/module/src/discovery.rs` | Scans `/proc/modules` via `ModuleScanner` |
| `ModuleMetadataCollector` | `crates/module/src/metadata.rs` | Cross-references sysfs/kallsyms, DKOM detection, builtin list |
| `ModuleAssessor` | `crates/module/src/assessment.rs` | Trust (builtin=Trusted, invalid sig=Blacklisted), risk scoring |

Detection techniques: Module hiding via DKOM, unsigned modules, modified module lists, kallsyms tampering.

### Network detection

| Component | Source | Function |
|-----------|--------|----------|
| `NetworkDiscoveryProvider` | `crates/network/src/discovery.rs` | Scans `/proc/net` via `NetworkScanner` |
| `NetworkMetadataCollector` | `crates/network/src/metadata.rs` | Compares with process objects, detects hidden/orphaned connections |
| `NetworkAssessor` | `crates/network/src/assessment.rs` | hidden=High, orphaned=Medium, normal=None |

Detection techniques: Hidden connections, orphaned sockets, reverse shells, C2 channels.

### Kernel integrity detection

| Component | Source | Function |
|-----------|--------|----------|
| `KernelDiscoveryProvider` | `crates/kernel/src/discovery.rs` | Scans hardening checks (kptr_restrict, dmesg_restrict, etc.) |
| `KernelMetadataCollector` | `crates/kernel/src/metadata.rs` | Marks critical findings |
| `KernelAssessor` | `crates/kernel/src/assessment.rs` | hook=Critical, integrity violation=Critical |

Additionally, `HookDetector` (stateful) maintains a baseline of known hooks and detects new ones by diffing across scans.

Detection techniques: Syscall table hooks, inline hooks, ftrace hooks, kprobe abuse, sysctl hardening violations.

### Memory integrity detection

| Component | Source | Function |
|-----------|--------|----------|
| `MemoryDiscoveryProvider` | `crates/memory/src/discovery.rs` | Discovers kallsyms/self-maps integrity checks |
| `MemoryMetadataCollector` | `crates/memory/src/metadata.rs` | Hashes `/proc/kallsyms` and `/proc/self/maps` |
| `MemoryAssessor` | `crates/memory/src/assessment.rs` | modified=Critical, risk_score>0.7=Medium |

Detection techniques: Kernel memory section modification, symbol table tampering, process memory mapping anomalies.

### File integrity detection

| Component | Source | Function |
|-----------|--------|----------|
| `IntegrityDiscoveryProvider` | `crates/integrity/src/discovery.rs` | Discovers critical system files |
| `IntegrityMetadataCollector` | `crates/integrity/src/metadata.rs` | Hashes files, populates current hash and readability |
| `IntegrityAssessor` | `crates/integrity/src/assessment.rs` | modified=Critical, unreadable=High |

Monitoring targets: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`.

### Persistence detection

| Component | Source | Function |
|-----------|--------|----------|
| `PersistenceDiscoveryProvider` | `crates/persistence/src/discovery.rs` | Scans systemd, cron, rc.local, ld.so.preload, profiles, init |
| `PersistenceMetadataCollector` | `crates/persistence/src/metadata.rs` | Classifies as TrustedOS/TrustedPackage/Unknown/Suspicious |
| `PersistenceAssessor` | `crates/persistence/src/assessment.rs` | Evaluation based on classification |

Scanning targets: systemd units, cron jobs, rc.local, ld.so.preload, bash profiles, init scripts, SUID binaries.

---

## 4. Telemetry System

### Architecture

```
Linux Kernel
    │
    ├── eBPF (Aya) ────────┐
    ├── fanotify ───────────┤
    ├── NETLINK_ROUTE ──────┤
    ├── NETLINK_AUDIT ──────┤
    └── /proc scanning ─────┤
                             │
                    ┌────────▼────────┐
                    │ TelemetryEngine │
                    │ (providers +    │
                    │  normalizer)    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  TelemetryBus   │
                    │ (broadcast +    │
                    │  mpsc + buffer) │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │    Pipeline     │
                    │ (Discovery →    │
                    │  Evidence)      │
                    └─────────────────┘
```

### TelemetryProvider trait

```rust
#[async_trait]
pub trait TelemetryProvider: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn status(&self) -> ProviderStatus;
    async fn initialize(&mut self, event_tx: mpsc::Sender<TelemetryEvent>) -> Result<()>;
    async fn shutdown(&mut self) -> Result<()>;
    fn info(&self) -> ProviderInfo;
}
```

### TelemetryEvent (immutable, 34 event types)

```rust
pub struct TelemetryEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub provider: String,
    pub category: TelemetryCategory,      // Process | Filesystem | Network | Kernel | Persistence
    pub event_type: TelemetryEventType,   // 34 variants
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub namespace: Option<String>,
    pub container: Option<String>,
    pub object_id: Option<String>,
    pub metadata: serde_json::Value,
}
```

### Event categories

| Category | Event Types |
|----------|------------|
| Process | Create, Fork, Clone, Exec, Exit, Setuid, Setgid, Ptrace, CapChange |
| Filesystem | Open, Close, Read, Write, Rename, Delete, Execute, PermChange, OwnChange, Mount, Unmount |
| Network | Connect, Accept, Bind, Listen, Close, DnsLookup |
| Kernel | ModuleLoad, ModuleUnload, BpfLoad, ParamChange |
| Persistence | ServiceCreate, CronModify, RcLocalModify, LdPreloadModify |

### Provider implementations

#### eBPF provider (`crates/ebpf/`)

- **Technology**: Aya 0.14 userspace eBPF framework
- **Program types**: Tracepoints (sched_process_exec/exit/fork), Kprobes (setuid/setgid/bpf_load), XDP (network)
- **Data flow**: eBPF ring buffer → BpfRawEvent (repr(C)) → TelemetryEvent
- **Graceful degradation**: Falls back to tracepoint-only if no BTF; marks as Degraded if no CAP_BPF

#### fanotify provider (`crates/fanotify/`)

- **Technology**: Linux fanotify syscalls via libc
- **Events**: FAN_ACCESS, FAN_OPEN, FAN_MODIFY, FAN_CLOSE_WRITE, FAN_DELETE, FAN_OPEN_PERM, FAN_ATTRIB
- **Default paths**: `/etc`, `/usr`, `/boot`
- **Threading**: Blocking read loop on OS thread via `tokio::task::spawn_blocking`

#### Netlink provider (`crates/netlink/`)

- **Technology**: AF_NETLINK socket with NETLINK_ROUTE
- **Subscribed groups**: RTMGRP_LINK, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_ROUTE, RTMGRP_NEIGH
- **Parsing**: NlMsgHdr → Ifinfomsg → NlAttr TLV (Type-Length-Value)

#### Audit provider (`crates/audit/`)

- **Technology**: NETLINK_AUDIT socket
- **Record types**: SYSCALL, EXECVE, CRED, PATH
- **Syscall mapping**: Maps x86_64 syscall numbers to TelemetryEventType

### ProviderManager

Handles capability detection and provider selection:

```
Capability Detection → Provider Selection → Fallback
```

| Capability | Detection method |
|-----------|-----------------|
| eBPF | `/sys/kernel/btf/vmlinux` + CAP_BPF/CAP_SYS_ADMIN |
| fanotify | CAP_SYS_ADMIN |
| netlink | Always available (AF_NETLINK unrestricted) |
| audit | CAP_AUDIT_WRITE/CAP_AUDIT_CONTROL |
| proc connector | Always available (/proc filesystem) |

### TelemetryBus

- **Ingestion**: `mpsc::channel` for provider → bus
- **Fan-out**: `tokio::sync::broadcast` for bus → subscribers
- **Buffer**: `VecDeque` with configurable capacity (default 50K)
- **Rate limiting**: Default 50K events/second max
- **Backpressure**: mpsc channels prevent unbounded memory growth
- **Eviction**: When buffer full, oldest events dropped

---

## 5. Correlation and Incident Management

### Correlation engine (`sentinelx-correlation`)

Builds a relationship graph from evidence and applies configurable TOML rules:

#### InMemoryGraph

```rust
pub struct GraphNode { id: String, label: String, node_type: NodeType, properties: HashMap }
pub struct GraphEdge { source: String, target: String, edge_type: EdgeType, properties: HashMap }
```

Node types: Process, File, Module, Network, Service, Memory, User
Edge types: Spawned, Opened, Connected, Loaded, Modified, Created, Deleted, Executes, Owns, Inherits

#### Correlation rules (TOML)

```toml
[[rules]]
name = "kernel_rootkit"
description = "Rootkit indicators"
requires = ["kernel_module", "process"]
min_evidence = 2
min_confidence = 0.7
time_window_seconds = 300
severity = "critical"
mitre_techniques = ["T1014"]
recommended_response = "Isolate host and dump memory"
```

7 default rules: kernel_rootkit, privilege_escalation_chain, network_exfiltration, file_tampering, memory_manipulation, multi_indicator_anomaly, suspicious_persistence.

#### EvidenceCorrelator

Consumes `EvidenceNode` structs, builds relationships in the graph, applies TOML rules, produces `CorrelatedEvidence` results.

### Incident engine (`sentinelx-incident`)

Manages security incidents with lifecycle tracking:

```rust
pub struct Incident {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub status: IncidentStatus,      // Open → Investigating → Contained → Resolved → Closed
    pub severity: IncidentSeverity,  // Info, Low, Medium, High, Critical
    pub confidence: f64,
    pub evidence_ids: Vec<String>,
    pub attack_chain: Vec<AttackChainStep>,
    pub mitre_mappings: Vec<MitreMapping>,
    pub recommended_response: Option<String>,
}
```

### Threat engine (`sentinelx-threat`)

Evaluates incidents using weighted risk scoring:

```rust
pub struct RiskScore {
    pub trust_score: f64,          // Weight: 0.15
    pub integrity_score: f64,      // Weight: 0.20
    pub risk_score: f64,           // Weight: 0.25
    pub reputation_score: f64,     // Weight: 0.10
    pub evidence_count: usize,     // Weight: 0.10
    pub incident_complexity: usize, // Weight: 0.10
    pub rule_confidence: f64,      // Weight: 0.10
    pub final_score: f64,          // 0–100
}
```

Score mapping: 0–20 = Info, 21–40 = Low, 41–60 = Medium, 61–80 = High, 81–100 = Critical

Produces `ThreatDecision` with severity, priority (Immediate/High/Normal/Low/Informational), and response recommendations.

### Behavior engine (`sentinelx-behavior`)

Builds per-object behavioral profiles from telemetry events:

- **11 behavior categories**: ProcessAncestry, ExecFrequency, NetworkActivity, PrivilegeEscalation, etc.
- **BehaviorScore**: 7 weighted factors → severity
- **6 default TOML rules**: repeated_privilege_escalation, unsigned_executable_persistence, network_exfiltration_pattern, etc.

### Intelligence engine (`sentinelx-intelligence`)

Offline-first threat intelligence:

- **IoCs**: 8 types (Hash, IpAddress, Domain, Filename, ProcessName, ModuleName, Url, Email)
- **MITRE ATT&CK**: 16 default techniques with tactic mapping
- **YARA rules**: Rule storage and evaluation stubs
- **Sigma rules**: Sigma detection rules with logsource and detection config
- **CVE tracking**: CVE entries with CVSS scores and affected products
- **Reputation scoring**: Per-object reputation with malicious flag

---

## 6. Response Engine

### Architecture

```
Threat Decision
    │
    ▼
┌─────────────────────┐
│   Policy Engine     │  Evaluates policies against threat severity
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Workflow Engine    │  Manages response workflow execution
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Response Actions   │  Execute configured responses
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│    Audit Log        │  Record all response actions
└─────────────────────┘
```

### Response actions

| Action | Description | Safety |
|--------|-------------|--------|
| `Alert` | Generate alert notification | Always safe |
| `LogEvent` | Record event to database | Always safe |
| `CollectForensics` | Capture forensic snapshot | Always safe |
| `KillProcess` | Terminate a process | Requires validation |
| `BlockIP` | Block network connection | Requires validation |
| `QuarantineFile` | Move file to quarantine | Requires validation |
| `IsolateHost` | Isolate host from network | Requires validation |
| `UnloadModule` | Unload kernel module | Requires validation |

### Safety controls

```rust
ResponseConfig {
    dry_run: true,                    // Default: don't execute destructive actions
    max_severity: Severity::High,     // Only respond to High+ threats
    cooldown_seconds: 10,             // Minimum time between responses
    max_responses_per_minute: 60,     // Rate limit
}
```

**Built-in protections:**
- `dry_run=true` by default — all destructive actions are simulated
- `never_kill_init=true` — PID 1 is always protected
- `never_unload_core_modules=true` — critical kernel modules protected
- Protected PIDs: [1]
- Protected modules: [vmlinux, core, nvidia, drm, kvm]
- All response actions logged to audit trail
- Rate limiting prevents cascading responses

---

## 7. Fleet Management

### Architecture

```
┌──────────────────────────────────────────────┐
│              Fleet Dashboard                  │
│  Overview │ Agents │ Policies │ Actions      │
└─────────────────────┬────────────────────────┘
                      │ REST API
┌─────────────────────▼────────────────────────┐
│              Fleet Manager                    │
│  Agent Registration │ Policy Distribution     │
│  Heartbeat Tracking │ Remote Action Queue     │
│  Health Monitoring  │ Event Broadcast         │
└─────────────────────┬────────────────────────┘
                      │
┌─────────────────────▼────────────────────────┐
│           Coordinator Engine                  │
│  Agent Records │ Heartbeat History            │
│  Policy Records│ Incident Aggregation         │
│  Stats Collection│ Stale Agent Detection      │
└─────────────────────┬────────────────────────┘
                      │ mTLS Transport
         ┌────────────┼────────────┐
         │            │            │
    ┌────▼────┐  ┌────▼────┐  ┌────▼────┐
    │ Agent A │  │ Agent B │  │ Agent C │
    │ (Host)  │  │ (Host)  │  │ (Host)  │
    │Pipeline │  │Pipeline │  │Pipeline │
    │Telemetry│  │Telemetry│  │Telemetry│
    └─────────┘  └─────────┘  └─────────┘
```

### Transport layer (`crates/transport/`)

- **Wire format**: `[4 bytes LE length][JSON payload]`
- **TLS**: Optional via `tokio-rustls` + `rustls`
- **Compression**: Gzip for payloads > 1 KB
- **Protocol version**: Negotiated on connect
- **Message acknowledgement**: Critical messages (Registration, Policy, RemoteAction) require ack
- **Reconnection**: Background task with configurable retry

### Message types

| Type | Direction | Purpose |
|------|-----------|---------|
| Registration / RegistrationAck | Agent ↔ Coordinator | Agent lifecycle |
| Heartbeat / HeartbeatAck | Agent → Coordinator | Health reporting |
| Policy / PolicyAck | Coordinator → Agent | Policy distribution |
| RemoteAction / RemoteActionResult | Coordinator ↔ Agent | Remote command execution |
| Incident / Threat | Agent → Coordinator | Event reporting |
| VersionNegotiation | Both | Protocol compatibility |
| Ping / Pong | Both | Connectivity check |

### Agent engine (`crates/agent/`)

Runs on each monitored host:
- Sends heartbeats every 30 seconds with system health (CPU, memory, disk, load), telemetry status, and detection stats
- Receives and applies distributed policies
- Executes remote actions (kill process, run scan, collect forensics, quarantine file)
- Detects system info: hostname, kernel, distribution, architecture

### Coordinator engine (`crates/coordinator/`)

Central coordination point:
- Agent registration and metadata tracking
- Heartbeat processing and stale agent detection
- Health status: Healthy (within timeout), Degraded (1–3x timeout), Offline (>3x timeout)
- Policy creation and distribution
- Incident aggregation from agents
- Broadcast events via `tokio::sync::broadcast`

### Fleet manager (`crates/fleet/`)

High-level orchestration:
- Wraps `CoordinatorEngine` with extended agent tracking
- Remote action lifecycle management (create → pending → completed/failed)
- Fleet overview aggregation
- Event system for UI updates

---

## 8. Data Flow Diagrams

### Complete data flow (detection to response)

```
Linux Kernel
    │
    │  [eBPF, fanotify, netlink, audit, /proc]
    │
    ▼
TelemetryEvent (34 types)
    │
    ▼
TelemetryBus (broadcast channel)
    │
    ├──▶ PipelineCoordinator
    │       │
    │       ├── Discovery (7 providers) → Vec<SentinelObject>
    │       ├── Metadata (7 collectors) → Enriched objects
    │       ├── Assessment (7 assessors) → Vec<AssessmentResult>
    │       └── Evidence generation → Vec<CoreEvidence>
    │
    ├──▶ CorrelationEngine
    │       │
    │       ├── Build relationship graph
    │       ├── Apply TOML rules
    │       └── Produce CorrelatedEvidence
    │
    ├──▶ IncidentEngine
    │       │
    │       ├── Create/update incidents
    │       ├── Attack chain reconstruction
    │       └── MITRE ATT&CK mapping
    │
    ├──▶ ThreatEngine
    │       │
    │       ├── Weighted risk scoring (0–100)
    │       ├── Severity classification
    │       └── Produce ThreatDecision
    │
    ├──▶ BehaviorEngine
    │       │
    │       ├── Per-object profiling
    │       ├── Behavioral rule evaluation
    │       └── Behavior scores
    │
    └──▶ ResponseEngine
            │
            ├── Policy evaluation
            ├── Workflow execution
            ├── Safety controls (dry-run, rate limit, protected PIDs)
            └── Audit logging
```

### Fleet data flow

```
Agent Host                          Coordinator
    │                                   │
    │  Registration                     │
    │──────────────────────────────────▶│
    │                                   │
    │  Heartbeat (30s)                  │
    │  {cpu, memory, disk, load,        │
    │   providers, threats, incidents}  │
    │──────────────────────────────────▶│
    │                                   │
    │  RegistrationAck                  │
    │◀──────────────────────────────────│
    │                                   │
    │  Policy Distribution              │
    │◀──────────────────────────────────│
    │  PolicyAck                        │
    │──────────────────────────────────▶│
    │                                   │
    │  Remote Action                    │
    │◀──────────────────────────────────│
    │  RemoteActionResult               │
    │──────────────────────────────────▶│
    │                                   │
    │  Incident Report                  │
    │──────────────────────────────────▶│
    │                                   │
    │  Threat Report                    │
    │──────────────────────────────────▶│
    │                                   │
    │◀─────── TCP (optional mTLS) ─────▶│
```

### Pipeline state transitions

```
SentinelObject lifecycle:

[Discovery]          [Metadata]           [Assessment]         [Evidence]
Created with      →  Enriched with     →  AssessmentResult  → CoreEvidence
canonical ID,        properties,           added per assessor  created from
object_type,         ownership, hashes,    (trust, integrity,  assessment +
source               permissions,          risk, reputation,   metadata snapshot
                     package_info, tags    confidence)
```

---

## 9. Technology Stack

### Core dependencies

| Component | Technology | Version |
|-----------|-----------|---------|
| Language | Rust | 1.75+ (edition 2021) |
| Async runtime | Tokio | 1.x (full features) |
| HTTP framework | Axum | 0.7 |
| Database | SQLite via sqlx | 0.8 |
| Serialization | serde + serde_json | 1.x |
| Configuration | toml | 0.8 |
| CLI | clap | 4.x |
| TLS | rustls + tokio-rustls | latest |
| Compression | flate2 (gzip) | latest |
| eBPF | Aya | 0.14 |
| Hashing | sha2 | 0.10 |
| Tracing | tracing + tracing-subscriber | 0.1 / 0.3 |
| Time | chrono | 0.4 |
| UUID | uuid (v4) | 1.x |
| Async traits | async-trait | 0.1 |
| Error handling | thiserror | 1.x |
| Filesystem walking | walkdir | 2.x |
| C FFI | libc | 0.2 |
| Linux API | nix | 0.29 |

### Frontend stack

| Component | Technology |
|-----------|-----------|
| Framework | React 18 |
| Language | TypeScript |
| Styling | Tailwind CSS |
| Build tool | Vite |
| Package manager | npm |

### Build configuration

```toml
[profile.release]
lto = true              # Link-time optimization
codegen-units = 1       # Single codegen unit (deterministic builds)
opt-level = 3           # Maximum optimization
strip = true            # Strip debug symbols
panic = "abort"         # No unwind tables
```

### Release binaries

| Binary | Size |
|--------|------|
| `sentinelx-backend` | ~7.4 MB |
| `sentinelx-cli` | ~2.3 MB |
| **Total** | **~9.7 MB** |

### Test coverage

| Metric | Count |
|--------|-------|
| Total test cases | 535+ |
| Crates with tests | All 34 |
| Integration tests | `tests/` directory |
| Benchmarks | Criterion (telemetry throughput) |
