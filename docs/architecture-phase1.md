# SentinelX Architecture: Evidence-Driven Pipeline

## Table of Contents

1. [Executive Overview](#1-executive-overview)
2. [Old Architecture: Detector-Driven Pipeline](#2-old-architecture-detector-driven-pipeline)
3. [New Architecture: Evidence-Driven Pipeline](#3-new-architecture-evidence-driven-pipeline)
4. [Object Model](#4-object-model)
5. [Adapter Layer](#5-adapter-layer)
6. [Pipeline Coordinator](#6-pipeline-coordinator)
7. [Evidence Flow](#7-evidence-flow)
8. [Sequence Diagrams](#8-sequence-diagrams)
9. [Design Decisions](#9-design-decisions)
10. [Future Roadmap](#10-future-roadmap)
11. [Developer Guide](#11-developer-guide)
12. [Known Limitations](#12-known-limitations)

---

## 1. Executive Overview

### 1.1 Purpose

SentinelX is a real-time Linux endpoint detection and response (EDR) system. It monitors processes, kernel modules, network connections, file integrity, memory regions, and persistence mechanisms to detect rootkits, malware, and advanced threats on Linux systems.

### 1.2 Design Philosophy

SentinelX follows these core principles:

- **Evidence-first**: Every detection must produce structured, auditable evidence. No silent alerts.
- **Object-centric**: All system entities (processes, files, connections) are modeled as first-class objects with unified metadata, assessment, and lifecycle.
- **Composable pipeline**: Detection is decomposed into discrete, independent stages (Discovery, Metadata, Assessment, Evidence) that can be extended independently.
- **Backward compatible**: New architecture wraps existing detectors via adapters. Zero breakage during migration.
- **Defense in depth**: Multiple independent assessors evaluate each object from different angles (trust, integrity, reputation, risk).

### 1.3 High-Level Architecture

```
                         ┌─────────────────────────────────────────────┐
                         │              SentinelX System               │
                         ├─────────────────────────────────────────────┤
                         │                                             │
   ┌─────────┐     ┌─────▼──────┐     ┌──────────┐     ┌────────────┐ │
   │  Linux   │────▶│  Discovery │────▶│ Metadata  │────▶│ Assessment │ │
   │  System  │     │   Layer    │     │  Layer    │     │   Layer    │ │
   └─────────┘     └────────────┘     └──────────┘     └─────┬──────┘ │
                                                              │        │
                                                              ▼        │
   ┌──────────────────────────────────────────────────────────────┐    │
   │                     Evidence Layer                           │    │
   │  CoreEvidence ──▶ Evidence Store ──▶ Correlation ──▶ Threats │    │
   └──────────────────────────────────────────────────────────────┘    │
                         │                                             │
                         ▼                                             │
   ┌──────────────┐  ┌──────────┐  ┌───────────┐  ┌───────────────┐  │
   │   Timeline   │  │  Scoring │  │  Response  │  │   Reporting   │  │
   └──────────────┘  └──────────┘  └───────────┘  └───────────────┘  │
                         │                                             │
                         ▼                                             │
                   ┌───────────┐  ┌───────────┐                       │
                   │   REST    │  │ Dashboard │                       │
                   │   API     │  │    (SPA)  │                       │
                   └───────────┘  └───────────┘                       │
                                                                      │
                   ┌───────────┐                                       │
                   │    CLI    │                                       │
                   └───────────┘                                       │
                         └─────────────────────────────────────────────┘
```

### 1.4 Why the Migration Was Necessary

The original detector-driven architecture had several structural problems:

1. **Monolithic output**: Detectors produced `ThreatEvent` objects that mixed detection results, evidence, and response triggers into a single type. There was no way to separate "what was found" from "what it means."

2. **No object identity**: Detections described threats but not the objects they affected. A hidden process detector would emit a `ThreatEvent` about a threat, but there was no canonical representation of the process itself that other subsystems could reference.

3. **Tight coupling**: The `DetectionEngine` directly orchestrated detectors, scoring, correlation, and evidence collection in a single flow. Adding a new analysis stage required modifying the engine.

4. **Limited evidence model**: The legacy `Evidence` type lacked assessment context (trust, integrity, reputation). Evidence was a flat bag of key-value data with no connection to the object that produced it.

5. **No composability**: Detectors were black boxes. You could run all of them or none. There was no way to compose a pipeline where one detector's output feeds another's input, or where metadata enrichment happens between discovery and assessment.

---

## 2. Old Architecture: Detector-Driven Pipeline

### 2.1 Components

| Component | Crate | Responsibility |
|-----------|-------|---------------|
| `DetectorRegistry` | `sentinelx-detector` | Stores detectors in `Arc<RwLock<HashMap>>`, runs all on demand |
| `DetectionEngine` | `sentinelx-detector` | Orchestrates scan, scoring, correlation, evidence, trust |
| `ThreatScorer` | `sentinelx-detector` | Assigns numeric scores to threats based on confidence, severity, rules |
| `TrustEngine` | `sentinelx-detector` | Tracks detector reliability over time |
| `EventBus` | `sentinelx-detector` | In-process pub/sub for `Event` objects |
| `EvidenceStore` | `sentinelx-evidence` | Indexed in-memory evidence storage |
| `CorrelationEngine` | `sentinelx-correlation` | Pattern matching across threat events |
| `RuleEngine` | `sentinelx-rule-engine` | Custom user-defined detection rules |
| `TimelineEngine` | `sentinelx-timeline` | Chronological event reconstruction |

### 2.2 Data Flow

```
Detectors
    │
    ▼
DetectorRegistry::run_all()
    │
    ▼
Vec<ThreatEvent> ──────────────────────────────────────────────────┐
    │                                                               │
    ├──────────────────────────────┐                                │
    │                              │                                │
    ▼                              ▼                                ▼
ThreatScorer                  CorrelationEngine              EventBus
    │                              │                                │
    ▼                              ▼                                ▼
Vec<ThreatScore>           Vec<CorrelationResult>            Event history
    │                              │
    └──────────────┬───────────────┘
                   │
                   ▼
         Response Engine (evaluate + execute)
```

### 2.3 The ThreatEvent Type

The `ThreatEvent` was the sole output of all detectors:

```rust
pub struct ThreatEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub category: ThreatCategory,
    pub title: String,
    pub description: String,
    pub evidence: Vec<Evidence>,         // inline evidence
    pub mitre_attack: Vec<MitreAttackMapping>,
    pub source_detector: String,
    pub process: Option<ProcessInfo>,    // optional context
    pub network: Option<NetworkConnection>,
    pub hash: Option<HashValue>,
    pub tags: Vec<String>,
}
```

This single type was responsible for:
- Representing a detection (title, description, category)
- Carrying severity and MITRE mappings
- Holding inline evidence
- Optionally carrying process/network/hash context
- Serving as input to correlation, scoring, timeline, and response

### 2.4 Limitations

| Problem | Impact |
|---------|--------|
| **No object identity** | Two detectors finding the same process produce unrelated `ThreatEvent`s. No deduplication, no cross-reference. |
| **Evidence is inline** | `ThreatEvent.evidence` is a `Vec<Evidence>` baked into the event. Evidence lifecycle is coupled to event lifecycle. |
| **No assessment context** | No concept of "this process is untrusted" or "this file has tampered integrity." These judgments were implicit in the threat severity. |
| **Black-box detectors** | Each detector returns `Vec<ThreatEvent>`. No intermediate metadata enrichment. No way to add cross-cutting concerns (e.g., "enrich all process objects with package info"). |
| **Single output type** | Detectors can only emit threats. There's no way to emit "I found a process, but I'm not sure if it's bad yet." Discovery is conflated with judgment. |
| **Coupled pipeline** | `DetectionEngine::run_scan()` calls `registry.run_all()` directly. Can't insert stages between discovery and scoring without modifying the engine. |

### 2.5 False-Positive Issues

The old architecture had no mechanism for:

1. **Reputation tracking**: A process detected as suspicious today can't easily carry that context into tomorrow's scan.
2. **Trust decay**: The `TrustEngine` tracked detector reliability, but not object-level trust.
3. **Assessment accumulation**: If three detectors each find a process suspicious, their individual `ThreatEvent`s don't compound into a unified risk assessment.
4. **Evidence provenance**: Evidence was a flat `HashMap<String, Value>` with no connection to the assessment that produced it.

---

## 3. New Architecture: Evidence-Driven Pipeline

### 3.1 Layer-by-Layer Design

The new architecture decomposes detection into five distinct layers with clear responsibilities:

```
┌─────────────────────────────────────────────────────────────────┐
│                       Pipeline Layer                             │
│  PipelineCoordinator orchestrates: Discover → Enrich → Assess   │
├─────────┬──────────┬────────────┬──────────────┬───────────────┤
│Discover │ Metadata │ Assessment │  Evidence    │   Pipeline    │
│  Layer  │  Layer   │   Layer    │   Layer      │  Coordinator  │
├─────────┼──────────┼────────────┼──────────────┼───────────────┤
│Discovery│ Metadata │  Object    │ CoreEvidence │ Pipeline      │
│Provider │ Collector│  Assessor  │              │ Coordinator   │
│  trait  │  trait   │   trait    │   immutable  │               │
├─────────┼──────────┼────────────┼──────────────┼───────────────┤
│Discover │ Metadata │ Assessment │  Evidence    │ Pipeline      │
│ Engine  │  Engine  │   Engine   │  Store       │  Result       │
└─────────┴──────────┴────────────┴──────────────┴───────────────┘
```

### 3.2 Layer Responsibilities

#### Discovery Layer

**Purpose**: Find objects in the system.

The Discovery layer answers: "What exists on this system right now?"

- `DiscoveryProvider` trait: Any component that can find system objects
- `DiscoveryEngine`: Runs all registered providers, collects results, handles failures gracefully

Providers return `Vec<SentinelObject>` — objects with type, identity, and raw metadata. They do NOT judge whether an object is malicious. Discovery is observation, not assessment.

#### Metadata Layer

**Purpose**: Enrich objects with contextual information.

The Metadata layer answers: "What else do we know about this object?"

- `MetadataCollector` trait: Any component that can add metadata to objects
- `MetadataEngine`: Runs all collectors against discovered objects

Collectors mutate objects in-place, adding properties, ownership info, permissions, hashes, package info, and tags. They run on the full set of discovered objects, allowing cross-object enrichment (e.g., "this file belongs to package X, which is installed from the official repository").

#### Assessment Layer

**Purpose**: Evaluate objects from multiple independent perspectives.

The Assessment layer answers: "What is our judgment about this object?"

- `ObjectAssessor` trait: Any component that can evaluate an object
- `AssessmentEngine`: Runs all matching assessors against objects

Each assessor produces an `AssessmentResult` with five independent dimensions:

| Dimension | Values | Meaning |
|-----------|--------|---------|
| **Trust** | Trusted, Untrusted, Unknown | Is this object from a known-good source? |
| **Integrity** | Intact, Tampered, Unknown | Has this object been modified? |
| **Risk** | None, Low, Medium, High, Critical | Overall risk level |
| **Reputation** | Known, Suspicious, Malicious, Unknown | Is this object known to be bad? |
| **Confidence** | 0.0 - 1.0 | How confident is this assessor? |

Multiple assessors can evaluate the same object. Results accumulate in `SentinelObject.assessments`.

#### Evidence Layer

**Purpose**: Create immutable, auditable records of assessments.

The Evidence layer answers: "What happened and why?"

- `CoreEvidence`: Immutable evidence record created from assessment results
- Bidirectional conversion methods bridge old and new evidence types

Evidence is generated automatically by the pipeline when an assessment has `risk != None`. Each evidence record captures a point-in-time snapshot of the object's metadata and assessment, creating a complete audit trail.

#### Pipeline Coordinator

**Purpose**: Orchestrate the four layers in sequence.

The Pipeline Coordinator answers: "Run the full detection pipeline."

- `PipelineCoordinator`: Owns Discovery, Metadata, Assessment engines and an evidence store
- `run()`: Executes all four phases sequentially, returns `PipelineResult`

### 3.3 Separation of Concerns

| Concern | Old Architecture | New Architecture |
|---------|-----------------|-----------------|
| Finding things | `Detector::detect()` → `ThreatEvent` | `DiscoveryProvider::discover()` → `SentinelObject` |
| Context enrichment | Inline in detector | `MetadataCollector::enrich()` |
| Judgment | Implicit in severity | `ObjectAssessor::assess()` → `AssessmentResult` |
| Evidence creation | `Evidence` inside `ThreatEvent` | `CoreEvidence` generated from assessments |
| Deduplication | None | Objects have canonical IDs (`"process:1234"`) |
| Cross-referencing | None | `ObjectRelationship` graph |

---

## 4. Object Model

### 4.1 SentinelObject

The `SentinelObject` is the central domain entity in the new architecture. Everything the system observes is represented as a `SentinelObject`.

```rust
pub struct SentinelObject {
    pub id: String,                           // "process:1234", "file:/etc/passwd"
    pub object_type: ObjectType,              // What kind of object
    pub metadata: ObjectMetadata,             // Enriched metadata
    pub relationships: Vec<ObjectRelationship>, // Links to other objects
    pub created_at: DateTime<Utc>,            // When discovered
    pub source: String,                       // Which provider found it
    pub assessments: Vec<AssessmentResult>,   // Accumulated assessments
    pub evidence_refs: Vec<Uuid>,             // Links to CoreEvidence
}
```

#### Object Types

```rust
pub enum ObjectType {
    Process,              // Running processes (/proc/[pid])
    KernelModule,         // Loaded kernel modules (/proc/modules)
    NetworkConnection,    // Active network connections (/proc/net/tcp)
    Service,              // Systemd services
    Socket,               // Unix/network sockets
    File,                 // Files on disk
    MemoryRegion,         // Mapped memory regions
    User,                 // System users
    Namespace,            // Linux namespaces
    Container,            // Containerized processes
}
```

#### Canonical IDs

Object IDs are composed as `"{type}:{identifier}"`:

| Object Type | ID Format | Example |
|-------------|-----------|---------|
| Process | `process:{pid}` | `process:1234` |
| KernelModule | `kernel_module:{name}` | `kernel_module:nvidia` |
| NetworkConnection | `network_connection:{proto}:{local}:{remote}` | `network_connection:tcp:127.0.0.1:8080:10.0.0.1:443` |
| File | `file:{path}` | `file:/etc/passwd` |
| MemoryRegion | `memory_region:{pid}:{address}` | `memory_region:1234:0x7fff12340000` |
| Service | `service:{name}` | `service:nginx` |

Canonical IDs ensure that two detectors finding the same object produce `SentinelObject`s with the same ID, enabling deduplication and cross-referencing.

### 4.2 Metadata

```rust
pub struct ObjectMetadata {
    pub properties: HashMap<String, serde_json::Value>,  // Arbitrary key-value
    pub ownership: Option<OwnershipInfo>,                 // uid/gid/user/group
    pub permissions: Option<PermissionInfo>,              // mode, setuid, etc.
    pub hashes: HashMap<String, String>,                  // sha256, md5, etc.
    pub package_info: Option<PackageInfo>,                // Package manager info
    pub tags: Vec<String>,                                // Freeform tags
}
```

Metadata is designed to be open-ended. The `properties` map accepts any JSON value, allowing detectors to embed arbitrary structured data. The typed fields (`ownership`, `permissions`, `hashes`, `package_info`) provide structured access to the most common metadata patterns.

### 4.3 Assessment

```rust
pub struct AssessmentResult {
    pub object_id: String,
    pub trust: TrustLevel,         // Trusted | Untrusted | Unknown
    pub integrity: IntegrityLevel, // Intact | Tampered | Unknown
    pub confidence: f64,           // 0.0 - 1.0
    pub risk: RiskLevel,           // None | Low | Medium | High | Critical
    pub reputation: ReputationLevel, // Known | Suspicious | Malicious | Unknown
    pub assessed_at: DateTime<Utc>,
    pub assessor: String,          // Which assessor produced this
}
```

Key properties:

- **Multiple assessments per object**: A process might be assessed by a trust assessor (Untrusted), an integrity assessor (Intact), and a reputation assessor (Suspicious). All three results accumulate.
- **Assessor attribution**: Each result records which assessor produced it, enabling audit trails and trust tracking.
- **Risk ordering**: `RiskLevel` derives `PartialOrd, Ord`, enabling comparison: `None < Low < Medium < High < Critical`.
- **Confidence clamping**: Confidence is always clamped to 0.0..=1.0 at construction time.

### 4.4 Evidence

```rust
pub struct CoreEvidence {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub object_id: String,
    pub evidence_type: CoreEvidenceType,
    pub source: String,
    pub confidence: f64,
    pub severity: CoreSeverity,
    pub metadata_snapshot: HashMap<String, serde_json::Value>,
    pub assessment_snapshot: Option<AssessmentResult>,
    pub related_evidence: Vec<Uuid>,
    pub data: HashMap<String, serde_json::Value>,
}
```

CoreEvidence is **immutable after construction**. There are no `&mut self` methods. All fields are set via the builder pattern at construction time:

```rust
let evidence = CoreEvidence::new("process:1234", CoreEvidenceType::ProcessIntegrity, CoreSeverity::High, "kernel-integrity")
    .with_confidence(0.95)
    .with_assessment(assessment_result)
    .with_data("hook_address", json!("0xffffffff81234567"))
    .with_tag("rootkit");
```

The `metadata_snapshot` and `assessment_snapshot` fields capture the object's state at the moment evidence was created, providing a complete point-in-time record.

### 4.5 Relationships

```rust
pub struct ObjectRelationship {
    pub relationship_type: RelationshipType,
    pub target_id: String,  // ID of the related SentinelObject
}

pub enum RelationshipType {
    Parent,     // process -> parent process
    Child,      // process -> child process
    DependsOn,  // service -> library
    ConnectsTo, // process -> remote endpoint
    Loads,      // process -> kernel module
    Executes,   // process -> binary file
    Modifies,   // process -> file
    Owns,       // user -> file/process
}
```

Relationships form a graph that enables cross-object analysis. For example, if a process loads a suspicious kernel module, the relationship graph connects them:

```
process:1234 --[Loads]--> kernel_module:nvidia
process:1234 --[Executes]--> file:/usr/bin/app
process:1234 --[ConnectsTo]--> network_connection:tcp:...
```

### 4.6 Object Lifecycle

```
Discovery                    Metadata                  Assessment                Evidence
──────────────────────────── ────────────────────────── ───────────────────────── ──────────────
SentinelObject created       properties enriched         AssessmentResult added    CoreEvidence
  - id (canonical)             ownership filled           appended to object        created from
  - object_type                permissions set            (one per assessor)        assessment
  - source                     hashes computed                                    stored in
  - metadata (empty)           tags added                                         evidence_store
  - relationships set          package_info resolved
```

---

## 5. Adapter Layer

### 5.1 Purpose

The adapter layer enables existing detectors (which implement the old `Detector` trait and produce `ThreatEvent`s) to participate in the new evidence-driven pipeline **without any modification**.

### 5.2 LegacyDetectorAdapter

Wraps `Box<dyn Detector>` and implements `DiscoveryProvider`:

```
┌─────────────────────────┐         ┌─────────────────────────────┐
│   LegacyDetectorAdapter │         │    DiscoveryProvider trait   │
├─────────────────────────┤         ├─────────────────────────────┤
│  detector: Box<dyn      │────────▶│  name()                     │
│    Detector>            │         │  description()              │
│                         │         │  supported_object_types()   │
│  new(detector)          │         │  discover() -> SentinelObj  │
│  detector_name()        │         └─────────────────────────────┘
└─────────────────────────┘
```

The `discover()` method:

1. Calls `self.detector.detect()` (old API)
2. For each returned `ThreatEvent`:
   - Maps `ThreatCategory` → `ObjectType`
   - Creates a `SentinelObject` with canonical ID
   - Serializes all threat fields into `ObjectMetadata.properties`
   - Sets `OwnershipInfo` from `ProcessInfo` if present
3. Returns `Vec<SentinelObject>`

#### Category-to-Object Mapping

| ThreatCategory | ObjectType |
|---------------|-----------|
| HiddenProcess, DkomAttack | Process |
| HiddenModule, HookDetected | KernelModule |
| HiddenConnection, ReverseShell | NetworkConnection |
| IntegrityViolation, MemoryTampering | File |
| PersistenceMechanism | Service |
| PrivilegeEscalation | Process |
| ContainerEscape | Container |
| SuspiciousSyscall | Process |
| (all others) | Process (default) |

### 5.3 LegacyEvidenceAdapter

Wraps `Box<dyn EvidenceCollector>` and produces `Vec<CoreEvidence>`:

1. Calls `self.collector.collect_evidence()` (old API)
2. For each returned `Evidence`: calls `CoreEvidence::from_legacy_evidence()`
3. Returns `Vec<CoreEvidence>`

### 5.4 Bidirectional Evidence Conversion

`CoreEvidence` provides four conversion methods for full interoperability:

```
                     CoreEvidence
                    /      |      \
                   /       |       \
    from_threat_event   from_legacy   to_threat_event
                   \       |       /
                    \      |      /
         ThreatEvent  or  Evidence  (legacy types)
```

| Method | Direction | Purpose |
|--------|-----------|---------|
| `from_threat_event()` | ThreatEvent → CoreEvidence | Convert detector output to new format |
| `to_threat_event()` | CoreEvidence → ThreatEvent | Convert back for backward compatibility |
| `from_legacy_evidence()` | Evidence → CoreEvidence | Convert old evidence to new format |
| `into_legacy_evidence()` | CoreEvidence → Evidence | Convert new evidence to old format |

### 5.5 Compatibility Guarantees

- All 8 existing detectors continue working unchanged
- The old `DetectionEngine` flow is untouched
- REST API endpoints continue using the existing engine
- Dashboard displays the same data
- CLI commands function identically
- The new pipeline runs alongside the old system as an additional analysis pass

---

## 6. Pipeline Coordinator

### 6.1 Structure

```rust
pub struct PipelineCoordinator {
    discovery: DiscoveryEngine,      // Runs all DiscoveryProviders
    metadata: MetadataEngine,        // Runs all MetadataCollectors
    assessment: AssessmentEngine,    // Runs all ObjectAssessors
    evidence_store: Arc<RwLock<Vec<CoreEvidence>>>,
}
```

### 6.2 Execution Order

```
pipeline.run()
    │
    ├── Phase 1: Discovery
    │   discovery.discover_all()
    │   → Vec<DiscoveryResult> → flatten → Vec<SentinelObject>
    │
    ├── Phase 2: Metadata Enrichment
    │   metadata.enrich_all(&mut objects)
    │   → Objects now have populated metadata
    │
    ├── Phase 3: Assessment
    │   assessment.assess_all(&mut objects)
    │   → Each object now has Vec<AssessmentResult>
    │
    ├── Phase 4: Evidence Generation
    │   For each object with risk != None:
    │     Create CoreEvidence from assessment + metadata snapshot
    │   Store in evidence_store
    │
    └── Return PipelineResult
```

### 6.3 Data Flow

```
DiscoveryEngine                    MetadataEngine
      │                                  │
      ▼                                  ▼
DiscoveryResult[]                  Enriched objects
      │                                  │
      └──────────┬───────────────────────┘
                 │
                 ▼
         AssessmentEngine
                 │
                 ▼
         Objects with assessments
                 │
                 ▼
    ┌────────────────────────┐
    │  Evidence Generation   │
    │  (risk != None only)   │
    └────────────────────────┘
                 │
                 ▼
         PipelineResult
         ├── objects_discovered: usize
         ├── objects_enriched: usize
         ├── objects_assessed: usize
         ├── evidence_count: usize
         ├── duration_ms: u64
         ├── objects: Vec<SentinelObject>
         └── evidence: Vec<CoreEvidence>
```

### 6.4 Error Handling

The pipeline is designed to be **fault-tolerant at every stage**:

- **Discovery**: Individual provider failures are logged. Other providers continue. Partial results are returned.
- **Metadata**: Individual collector failures are logged. Other collectors continue. Objects are still assessed.
- **Assessment**: Individual assessor failures are logged. Other assessors continue. Objects still get evidence.
- **Evidence generation**: Only runs for objects with `risk != Objects with `risk != None`. No failure possible (pure data transformation).

No single provider, collector, or assessor failure can halt the pipeline.

### 6.5 Concurrency Model

- **Within a phase**: Providers/collectors/assessors run **sequentially** (simplicity over parallelism at this stage).
- **Across phases**: Phases run **strictly sequentially** (each phase depends on the previous).
- **Evidence store**: Protected by `Arc<RwLock<Vec<CoreEvidence>>>` for concurrent read access from the API layer.
- **Future optimization**: `discover_all()` can be parallelized with `tokio::join!` or `futures::join_all` since providers are independent.

---

## 7. Evidence Flow

The complete evidence flow from system observation to response:

```
 Linux System
      │
      │  /proc, /sys, eBPF, netlink, ...
      │
      ▼
 ┌───────────────────────────────────────────┐
 │              Discovery Layer              │
 │  DiscoveryProvider::discover()            │
 │  Output: Vec<SentinelObject>              │
 │  (raw objects with identity, no judgment) │
 └───────────────────────────────────────────┘
      │
      ▼
 ┌───────────────────────────────────────────┐
 │              Metadata Layer               │
 │  MetadataCollector::enrich()              │
 │  Mutates: properties, ownership, hashes,  │
 │           permissions, package_info, tags  │
 └───────────────────────────────────────────┘
      │
      ▼
 ┌───────────────────────────────────────────┐
 │             Assessment Layer              │
 │  ObjectAssessor::assess()                 │
 │  Output: AssessmentResult per assessor    │
 │  Dimensions: trust, integrity, risk,      │
 │              reputation, confidence       │
 └───────────────────────────────────────────┘
      │
      ▼
 ┌───────────────────────────────────────────┐
 │             Evidence Layer                │
 │  CoreEvidence::new() from assessments     │
 │  Immutable snapshot of object + judgment  │
 │  Stored in evidence_store                 │
 └───────────────────────────────────────────┘
      │
      ▼
 ┌───────────────────────────────────────────┐
 │           Evidence Store (DB)             │
 │  EvidenceRepository::insert_batch()       │
 │  Persistent, queryable, auditable         │
 └───────────────────────────────────────────┘
      │
      ▼
 ┌───────────────────────────────────────────┐
 │          Correlation Engine               │
 │  Pattern matching across evidence items   │
 │  Co-occurrence, entity clustering,        │
 │  severity escalation, time windows        │
 └───────────────────────────────────────────┘
      │
      ▼
 ┌───────────────────────────────────────────┐
 │           Threat Generation              │
 │  Correlated evidence → high-confidence    │
 │  threat identification                    │
 └───────────────────────────────────────────┘
      │
      ▼
 ┌───────────────────────────────────────────┐
 │           Timeline Engine                 │
 │  Chronological event reconstruction       │
 │  Attack narrative generation              │
 └───────────────────────────────────────────┘
      │
      ▼
 ┌───────────────────────────────────────────┐
 │            Response Engine                │
 │  Automated response: kill process,        │
 │  quarantine file, isolate host            │
 └───────────────────────────────────────────┘
```

---

## 8. Sequence Diagrams

### 8.1 CLI Scan

```
CLI                    Backend                 PipelineCoordinator
 │                        │                          │
 │  sentinelx scan        │                          │
 │───────────────────────▶│                          │
 │                        │  run_scan()              │
 │                        │─────────────────────────▶│
 │                        │                          │
 │                        │     ┌─ discover_all() ───┤
 │                        │     │   8 providers       │
 │                        │     │   → SentinelObjects │
 │                        │     │                     │
 │                        │     ├─ enrich_all() ─────┤
 │                        │     │   metadata enriched │
 │                        │     │                     │
 │                        │     ├─ assess_all() ─────┤
 │                        │     │   assessments added │
 │                        │     │                     │
 │                        │     └─ evidence gen ─────┤
 │                        │        evidence stored    │
 │                        │                          │
 │                        │  PipelineResult          │
 │                        │◀─────────────────────────│
 │                        │                          │
 │  threats + evidence    │                          │
 │◀───────────────────────│                          │
```

### 8.2 Backend Startup

```
main()                DetectionEngine        PipelineCoordinator
  │                        │                         │
  │  new(settings)         │                         │
  │───────────────────────▶│                         │
  │                        │                         │
  │  register 8 detectors  │                         │
  │───────────────────────▶│                         │
  │                        │                         │
  │  engine.start()        │                         │
  │───────────────────────▶│                         │
  │                        │                         │
  │  engine.run_scan()     │                         │
  │───────────────────────▶│  registry.run_all()     │
  │                        │  → Vec<ThreatEvent>     │
  │                        │  persist to DB          │
  │                        │                         │
  │  engine.run_evidence_collection()                │
  │───────────────────────▶│  evidence → DB          │
  │                        │                         │
  │  NEW: create PipelineCoordinator                 │
  │────────────────────────────────────────────────▶│
  │                        │                         │
  │  NEW: register 8 LegacyDetectorAdapters          │
  │────────────────────────────────────────────────▶│
  │                        │                         │
  │  NEW: pipeline.run()   │                         │
  │────────────────────────────────────────────────▶│
  │                        │       discover → enrich │
  │                        │       → assess → evidence│
  │                        │                         │
  │  log pipeline results  │                         │
  │◀────────────────────────────────────────────────│
  │                        │                         │
  │  start HTTP server     │                         │
  │────┐                   │                         │
  │    │ serve routes      │                         │
```

### 8.3 Detector Registration

```
main()          LegacyDetectorAdapter     DiscoveryEngine
  │                    │                      │
  │  new(HiddenModule  │                      │
  │    Detector)       │                      │
  │───────────────────▶│                      │
  │                    │                      │
  │  Arc::new(Box::new │                      │
  │    adapter)        │                      │
  │───────────────────▶│                      │
  │                    │                      │
  │  discovery.register│                      │
  │    (adapter)       │                      │
  │──────────────────────────────────────────▶│
  │                    │     providers.push()  │
  │                    │◀─────────────────────│
  │                    │                      │
  │  (repeat for 7 more detectors)           │
```

### 8.4 Evidence Generation

```
PipelineCoordinator     AssessmentEngine     Evidence Generation
        │                      │                      │
        │  assess_all()        │                      │
        │─────────────────────▶│                      │
        │                      │                      │
        │  For each object:    │                      │
        │  For each assessor:  │                      │
        │    assess(object)    │                      │
        │    → AssessmentResult│                      │
        │    push to obj.assessments                  │
        │                      │                      │
        │  objects assessed     │                      │
        │◀─────────────────────│                      │
        │                      │                      │
        │  For each object:    │                      │
        │    if risk != None:  │                      │
        │      CoreEvidence::  │                      │
        │        new(...)      │                      │
        │      .with_metadata  │                      │
        │      .with_assessment│                      │
        │      .with_data(...) │                      │
        │──────────────────────────────────────────▶│
        │                      │    evidence_store    │
        │                      │      .push(evidence) │
        │                      │◀─────────────────────│
        │                      │                      │
        │  PipelineResult      │                      │
        │  { evidence_count: N }                      │
```

---

## 9. Design Decisions

### 9.1 Why an Object Model?

**Decision**: Introduce `SentinelObject` as a universal domain entity.

**Rationale**: The old `ThreatEvent` conflated detection output with object representation. Two detectors finding the same process created two unrelated threat events with no way to connect them. The object model provides:
- **Canonical identity**: `process:1234` is always `process:1234`
- **Accumulation**: Multiple assessments accumulate on one object
- **Cross-referencing**: Relationships connect objects into a graph
- **Separation**: Discovery produces objects; assessment judges them

### 9.2 Why Immutable Evidence?

**Decision**: `CoreEvidence` has no `&mut self` methods after construction.

**Rationale**: Evidence is a legal/forensic record. It must be tamper-proof once created. Mutable evidence creates audit trail issues:
- Who changed it? When? Why?
- Does the stored evidence still match what was originally observed?
- Can an attacker modify evidence to hide their tracks?

Immutable evidence guarantees that what was observed is what was recorded.

### 9.3 Why Five Assessment Dimensions?

**Decision**: Trust, Integrity, Risk, Reputation, Confidence as separate dimensions.

**Rationale**: These dimensions measure fundamentally different things:

- **Trust** = "Where did this come from?" (supply chain)
- **Integrity** = "Has this been modified?" (file/process state)
- **Risk** = "How dangerous is this?" (combined judgment)
- **Reputation** = "Is this known to be bad?" (threat intelligence)
- **Confidence** = "How sure are we?" (evidence quality)

Collapsing these into a single severity score loses information. A system library with high integrity but unknown trust is very different from a known-malicious binary with tampered integrity.

### 9.4 Why a Pipeline Instead of a Monolith?

**Decision**: Sequential stages (Discover → Enrich → Assess → Evidence) instead of a single `detect()` call.

**Rationale**:
- **Composability**: New stages can be inserted without modifying existing ones
- **Testability**: Each stage can be tested independently
- **Extensibility**: New providers/collectors/assessors can be added without touching the pipeline
- **Observability**: Each stage's timing and output can be measured independently
- **Fault isolation**: A failing metadata collector doesn't prevent discovery

### 9.5 Why Adapters Instead of Rewriting Detectors?

**Decision**: Wrap existing detectors in adapters instead of rewriting them.

**Rationale**:
- **Zero breakage**: All 8 detectors continue working unchanged
- **Incremental migration**: Detectors can be migrated one at a time in Phase 2
- **Reduced risk**: No changes to battle-tested detection logic
- **Parallel operation**: Old and new systems run simultaneously
- **Team velocity**: No blocking dependency between architecture work and detector improvements

### 9.6 Why Separate CoreEvidence and Evidence?

**Decision**: New `CoreEvidence` type alongside legacy `Evidence` type, with bidirectional conversion.

**Rationale**: The legacy `Evidence` type lacks:
- Assessment context (trust, integrity, reputation)
- Metadata snapshots
- Object association
- Immutability guarantees

Creating a new type rather than extending the old one ensures:
- Clean interface design without legacy baggage
- No breaking changes to existing consumers
- Full bidirectional compatibility during migration
- Clear migration endpoint (remove `Evidence` when migration completes)

---

## 10. Future Roadmap

### Phase 1 (Current): Core Interfaces + Adapters

**Status**: COMPLETE

- Created `sentinelx-core` crate with all pipeline interfaces
- Implemented `LegacyDetectorAdapter` for backward compatibility
- Wired `PipelineCoordinator` into backend alongside existing system
- All 258 tests passing, zero warnings

### Phase 2: Native Detector Migration

**Goal**: Convert detectors from old `Detector` trait to new `DiscoveryProvider` trait.

**Planned work**:

1. Create native `DiscoveryProvider` implementations for each detector:
   - `ProcessDiscovery` (replaces `HiddenProcessDetector`)
   - `KernelModuleDiscovery` (replaces `HiddenModuleDetector`, `HookDetector`, `KernelIntegrityDetector`)
   - `NetworkDiscovery` (replaces `HiddenConnectionDetector`)
   - `FileIntegrityDiscovery` (replaces `IntegrityChecker`)
   - `MemoryDiscovery` (replaces `MemoryIntegrityChecker`)
   - `PersistenceDiscovery` (replaces `PersistenceScanner`)

2. Create native `ObjectAssessor` implementations:
   - `TrustAssessor` (evaluates source trust)
   - `IntegrityAssessor` (checks file/process integrity)
   - `ReputationAssessor` (checks against threat intelligence)
   - `RiskAssessor` (combines signals into risk level)

3. Create native `MetadataCollector` implementations:
   - `ProcessMetadataCollector` (enriches with /proc data)
   - `FileMetadataCollector` (enriches with stat, hashes, package info)
   - `NetworkMetadataCollector` (enriches with DNS, GeoIP)

4. Remove `LegacyDetectorAdapter` and `LegacyEvidenceAdapter`

5. Remove old `DetectionEngine` orchestration flow

### Phase 3: Native eBPF Telemetry

**Goal**: Real-time event-driven detection using eBPF.

**Planned work**:

1. eBPF programs for:
   - Process execution tracing
   - File access monitoring
   - Network connection tracking
   - Kernel module loading
   - Privilege escalation detection
   - Memory mapping changes

2. Event-driven pipeline:
   - eBPF ring buffer → event channel → pipeline
   - Instead of polling, react to system events in real-time
   - Sub-millisecond detection latency

3. Behavior graph:
   - Build a real-time process/file/network relationship graph
   - Detect anomalous graph patterns (new edges, unusual parents, etc.)
   - Entity-centric detection instead of event-centric

### Phase 4: Advanced Analytics

**Goal**: Graph-based correlation, threat intelligence integration, plugin ecosystem.

**Planned work**:

1. **Graph correlation**:
   - Full object relationship graph as first-class entity
   - Graph neural network for anomaly detection
   - Temporal graph analysis (evolution over time)

2. **Threat intelligence**:
   - STIX/TAXII feed integration
   - IOC matching against discovered objects
   - Reputation scoring from external feeds
   - YARA rule scanning of discovered files

3. **Plugin ecosystem**:
   - WASM plugin runtime for third-party detectors
   - Plugin marketplace
   - Sandboxed execution environment
   - Plugin API versioning

---

## 11. Developer Guide

### 11.1 Creating a New Discovery Provider

```rust
use sentinelx_core::discovery::DiscoveryProvider;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject, ObjectMetadata};

pub struct MyDiscoveryProvider;

#[async_trait::async_trait]
impl DiscoveryProvider for MyDiscoveryProvider {
    fn name(&self) -> &str {
        "my-discovery"
    }

    fn description(&self) -> &str {
        "Discovers custom system objects"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::Process, ObjectType::File]
    }

    async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError> {
        let mut objects = Vec::new();

        // Discover processes
        // ...

        // Create objects with canonical IDs
        let obj = SentinelObject::new(
            ObjectType::Process,
            "my-discovery",
            "1234",  // PID
        )
        .with_metadata(
            ObjectMetadata::new()
                .with_property("command_line", json!(["/usr/bin/app"]))
                .with_ownership(OwnershipInfo {
                    uid: 1000,
                    gid: 1000,
                    user: "alice".into(),
                    group: "alice".into(),
                })
        );

        objects.push(obj);
        Ok(objects)
    }
}
```

Register it in the pipeline:

```rust
pipeline.discovery().register(Arc::new(Box::new(MyDiscoveryProvider)));
```

### 11.2 Creating a New Metadata Collector

```rust
use sentinelx_core::metadata::MetadataCollector;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::SentinelObject;

pub struct PackageMetadataCollector;

#[async_trait::async_trait]
impl MetadataCollector for PackageMetadataCollector {
    fn name(&self) -> &str {
        "package-metadata"
    }

    fn description(&self) -> &str {
        "Enriches file objects with package manager information"
    }

    async fn enrich(&self, objects: &mut [SentinelObject]) -> Result<(), CoreError> {
        for object in objects.iter_mut() {
            if let sentinelx_core::object::ObjectType::File = object.object_type {
                // Look up which package owns this file
                if let Some(pkg) = self.lookup_package(object) {
                    object.metadata.package_info = Some(pkg);
                }
            }
        }
        Ok(())
    }
}
```

Register it:

```rust
pipeline.metadata().register(Arc::new(PackageMetadataCollector));
```

### 11.3 Creating a New Object Assessor

```rust
use sentinelx_core::assessment::*;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

pub struct TrustAssessor;

#[async_trait::async_trait]
impl ObjectAssessor for TrustAssessor {
    fn name(&self) -> &str {
        "trust-assessor"
    }

    fn description(&self) -> &str {
        "Evaluates object trust based on source and signature"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![] // empty = all types
    }

    async fn assess(&self, object: &SentinelObject) -> Result<AssessmentResult, CoreError> {
        let trust = if self.is_signed_and_known(object) {
            TrustLevel::Trusted
        } else if self.is_suspicious_source(object) {
            TrustLevel::Untrusted
        } else {
            TrustLevel::Unknown
        };

        Ok(AssessmentResult::new(&object.id, "trust-assessor")
            .with_trust(trust)
            .with_confidence(0.8))
    }
}
```

Register it:

```rust
pipeline.assessment().register(Arc::new(TrustAssessor));
```

### 11.4 Coding Standards

- **All traits are `Send + Sync`**: Required for async runtime and shared ownership.
- **Error types use `thiserror`**: Each layer has its own error type in `CoreError`.
- **Builder pattern for domain objects**: `SentinelObject::new(...).with_metadata(...).with_relationship(...)`.
- **Evidence is immutable**: No `&mut self` methods on `CoreEvidence`.
- **Fail gracefully**: Provider/collector/assessor failures are logged, not fatal.
- **Canonical IDs**: Always use `ObjectType::as_str()` + identifier for object IDs.
- **No comments in code**: Code should be self-documenting through naming.
- **Tests for every public API**: Each module has a `tests` submodule with comprehensive tests.

---

## 12. Known Limitations

### 12.1 Temporary Compatibility Layers

| Item | Status | Planned Removal |
|------|--------|----------------|
| `LegacyDetectorAdapter` | Active | Phase 2 (after native migration) |
| `LegacyEvidenceAdapter` | Active | Phase 2 |
| `CoreEvidence::from_threat_event()` | Active | Phase 2 |
| `CoreEvidence::to_threat_event()` | Active | Phase 2 |
| `CoreEvidence::from_legacy_evidence()` | Active | Phase 2 |
| `CoreEvidence::into_legacy_evidence()` | Active | Phase 2 |
| `CoreEvidenceType` ↔ `ThreatCategory` mapping | Active | Phase 2 |

### 12.2 Legacy APIs Still in Use

| API | Used By | Replacement Plan |
|-----|---------|-----------------|
| `Detector::detect()` → `Vec<ThreatEvent>` | All 8 detectors | Native `DiscoveryProvider` in Phase 2 |
| `EvidenceCollector::collect_evidence()` | All 8 detectors | Native metadata collectors in Phase 2 |
| `DetectionEngine::run_scan()` | Backend main, CLI | `PipelineCoordinator::run()` in Phase 2 |
| `CorrelationEngine` (operates on `ThreatEvent`) | DetectionEngine | Will accept `CoreEvidence` in Phase 2 |

### 12.3 Planned Removals

| Item | Condition for Removal |
|------|----------------------|
| `LegacyDetectorAdapter` | All detectors have native `DiscoveryProvider` impls |
| `LegacyEvidenceAdapter` | All detectors produce evidence natively |
| `ThreatEvent` as primary output | Evidence-driven pipeline is sole output |
| `DetectionEngine` monolithic flow | All functionality migrated to pipeline |
| Bidirectional conversion methods | No legacy consumers remain |

### 12.4 Current Pipeline Limitations

- **Sequential execution**: Providers, collectors, and assessors run sequentially. Parallel execution is planned.
- **No streaming**: Pipeline runs as a batch. Real-time streaming from eBPF is Phase 3.
- **In-memory evidence store**: `PipelineCoordinator` evidence store is in-memory. Persistence happens through the old `DetectionEngine` flow.
- **No native metadata/assessment**: All current providers are legacy adapters. Native implementations are Phase 2.
- **No cross-pipeline correlation**: The `CorrelationEngine` operates on old `ThreatEvent` data, not on `CoreEvidence`. Full integration is Phase 2.

---

## Appendix A: Workspace Structure

```
sentinelx/
├── Cargo.toml                          # Workspace root (24 members)
├── apps/
│   ├── cli/                            # Command-line interface
│   └── dashboard/                      # React SPA (Vite + TypeScript)
├── backend/
│   ├── Cargo.toml                      # Axum HTTP server
│   └── src/
│       ├── main.rs                     # Startup, detector registration, pipeline wiring
│       ├── routes.rs                   # REST API endpoints
│       └── error.rs                    # API error types
├── crates/
│   ├── benchmarks/                     # Criterion benchmarks
│   ├── common/                         # Shared types, traits, errors
│   │   └── src/
│   │       ├── traits.rs              # Detector, Scanner, EventProducer/Consumer
│   │       ├── types.rs               # ThreatEvent, ThreatCategory, ProcessInfo, etc.
│   │       ├── severity.rs            # Severity enum
│   │       └── ...
│   ├── config/                         # Settings, defaults, file loading
│   ├── core/                           # NEW: Evidence-driven pipeline interfaces
│   │   └── src/
│   │       ├── lib.rs                 # Module exports
│   │       ├── error.rs               # CoreError
│   │       ├── object.rs              # SentinelObject, ObjectType, metadata
│   │       ├── discovery.rs           # DiscoveryProvider, DiscoveryEngine
│   │       ├── metadata.rs            # MetadataCollector, MetadataEngine
│   │       ├── assessment.rs          # ObjectAssessor, AssessmentResult, AssessmentEngine
│   │       ├── evidence.rs            # CoreEvidence, bidirectional conversions
│   │       ├── adapter.rs             # LegacyDetectorAdapter, LegacyEvidenceAdapter
│   │       └── pipeline.rs            # PipelineCoordinator, PipelineResult
│   ├── correlation/                    # Pattern matching across threats
│   ├── database/                       # SQLite persistence (sqlx)
│   ├── detector/                       # DetectionEngine, DetectorRegistry, scoring, trust
│   ├── ebpf/                           # eBPF program management
│   ├── evidence/                       # Evidence, EvidenceCollector, EvidenceStore
│   ├── forensics/                      # System snapshot collection
│   ├── integrity/                      # File integrity checking
│   ├── kernel/                         # Kernel hook detection, symbol analysis
│   ├── memory/                         # Memory integrity verification
│   ├── module/                         # Hidden kernel module detection
│   ├── network/                        # Hidden connection detection
│   ├── persistence/                    # Persistence mechanism scanning
│   ├── process/                        # Hidden process detection
│   ├── reporting/                      # Markdown/JSON report generation
│   ├── response/                       # Automated response actions
│   ├── rule_engine/                    # Custom detection rules
│   ├── telemetry/                      # Metrics collection
│   └── timeline/                       # Event timeline and narrative
└── docs/
    └── architecture-phase1.md          # This document
```

## Appendix B: Dependency Graph

```
sentinelx-core
├── sentinelx-common        (ThreatEvent, Severity, Detector trait)
└── sentinelx-evidence      (Evidence, EvidenceCollector for conversions)

sentinelx-backend
├── sentinelx-core          (PipelineCoordinator, LegacyDetectorAdapter)
├── sentinelx-config
├── sentinelx-database
├── sentinelx-detector      (DetectionEngine, EventBus)
├── sentinelx-integrity
├── sentinelx-kernel
├── sentinelx-memory
├── sentinelx-module
├── sentinelx-network
├── sentinelx-persistence
├── sentinelx-process
├── sentinelx-telemetry
└── sentinelx-timeline
```

## Appendix C: Test Summary

| Crate | Tests | Description |
|-------|-------|-------------|
| sentinelx-core | 44 | Object model, discovery, metadata, assessment, evidence, adapters, pipeline |
| sentinelx-detector | 46 | Event bus, scoring, trust, plugins, behavior graph |
| sentinelx-persistence | 36 | File analysis, package detection, trust scoring, scanner |
| sentinelx-forensics | 23 | System info, process tree, network state, IOCs |
| sentinelx-response | 19 | Response actions, dry run, rate limiting, history |
| sentinelx-correlation | 12 | Co-occurrence, entity cluster, severity escalation |
| sentinelx-timeline | 8 | Event sorting, narrative generation |
| sentinelx-reporting | 8 | Markdown/JSON report generation |
| sentinelx-ebpf | 14 | Engine lifecycle, config, stats |
| sentinelx-integrity | 6 | Baseline, permission, modification detection |
| sentinelx-kernel | 7 | Symbol diff, hook detection |
| sentinelx-module | 6 | Module scanning, trust scoring |
| sentinelx-database | 7 | Event, threat, evidence CRUD |
| sentinelx-network | 5 | Connection scanning |
| sentinelx-process | 4 | Process scanning |
| sentinelx-rule_engine | 5 | Rule evaluation |
| sentinelx-config | 4 | Settings load/save |
| sentinelx-memory | 2 | Memory integrity |
| sentinelx-telemetry | 2 | Metrics collection |
| **Total** | **258** | |
