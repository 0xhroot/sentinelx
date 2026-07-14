# SentinelX Architecture — Phase 4+5: Correlation, Incident & Threat Engines

**Date:** 2026-07-13
**Status:** Complete

---

## 1. Overview

Phase 4+5 introduces three new engines that complete the evidence-driven security pipeline:

- **Correlation Engine** — Builds a relationship graph from evidence and applies configurable TOML rules to detect multi-indicator attack patterns
- **Incident Engine** — Manages security incidents with status tracking, severity, evidence attachment, attack chains, and MITRE ATT&CK mappings
- **Threat Engine** — Evaluates incidents using a weighted risk scoring algorithm, produces threat decisions with severity, priority, and response recommendations

These engines run as the final stages of the security pipeline, after evidence has been collected and assessed.

## 2. New Crates

### 2.1 `sentinelx-correlation` (Extended)

**Path:** `crates/correlation/`

#### 2.1.1 Module Structure

```
crates/correlation/src/
├── lib.rs                  — Exports all modules
├── engine.rs               — Original CorrelationEngine (ThreatEvent-based)
├── graph.rs                — InMemoryGraph (new: evidence-based relationship graph)
├── rules.rs                — CorrelationRuleConfig (new: TOML-driven rules)
├── evidence_correlator.rs  — EvidenceCorrelator (new: evidence correlation)
└── tests/                  — 28 tests
```

#### 2.1.2 InMemoryGraph

A directed graph data structure for modeling relationships between security objects:

- **GraphNode**: `id` (String), `label` (String), `node_type` (NodeType), `properties` (HashMap)
- **GraphEdge**: `source` (String), `target` (String), `edge_type` (EdgeType), `properties` (HashMap)
- **NodeType**: `Process`, `File`, `Module`, `Network`, `Service`, `Memory`, `User`
- **EdgeType**: `Spawned`, `Opened`, `Connected`, `Loaded`, `Modified`, `Created`, `Deleted`, `Executes`, `Owns`, `Inherits`
- **GraphPath**: `nodes` (Vec<String>), `edges` (Vec<(String, EdgeType, String)>)

Key operations: `add_node`, `add_edge`, `get_node`, `get_neighbors`, `find_paths` (BFS with max_depth), `node_count`, `edge_count`, `clear`

#### 2.1.3 CorrelationRuleConfig

TOML-driven correlation rule configuration:

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

7 default rules: `kernel_rootkit`, `privilege_escalation_chain`, `network_exfiltration`, `file_tampering`, `memory_manipulation`, `multi_indicator_anomaly`, `suspicious_persistence`

#### 2.1.4 EvidenceCorrelator

Consumes `EvidenceNode` structs, builds relationships in the graph, applies TOML rules, produces `CorrelatedEvidence` results:

```rust
pub struct EvidenceNode {
    pub evidence_id: String,
    pub evidence_type: String,    // "process", "file", "network", etc.
    pub object_id: String,
    pub severity: String,
    pub confidence: f64,
    pub metadata: HashMap<String, String>,
}

pub struct CorrelatedEvidence {
    pub cluster_id: String,
    pub evidence_ids: Vec<String>,
    pub rule_name: String,
    pub severity: String,
    pub description: String,
    pub confidence: f64,
    pub mitre_techniques: Vec<String>,
    pub recommended_response: Option<String>,
}
```

### 2.2 `sentinelx-incident`

**Path:** `crates/incident/`

#### 2.2.1 Module Structure

```
crates/incident/src/
├── lib.rs      — Exports engine + types
├── types.rs    — Incident, IncidentStatus, IncidentSeverity, MitreMapping, AttackChainStep
├── engine.rs   — IncidentEngine (async, RwLock-protected HashMap)
└── tests/      — 16 tests
```

#### 2.2.2 Types

```rust
pub struct Incident {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub status: IncidentStatus,      // Open, Investigating, Contained, Resolved, Closed
    pub severity: IncidentSeverity,  // Info, Low, Medium, High, Critical
    pub confidence: f64,             // 0.0–1.0
    pub evidence_ids: Vec<String>,
    pub object_ids: Vec<String>,
    pub related_processes: Vec<String>,
    pub related_files: Vec<String>,
    pub related_modules: Vec<String>,
    pub attack_chain: Vec<AttackChainStep>,
    pub mitre_mappings: Vec<MitreMapping>,
    pub recommended_response: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct MitreMapping {
    pub technique_id: String,    // e.g., "T1014"
    pub technique_name: String,  // e.g., "Rootkit"
    pub tactic: String,          // e.g., "Defense Evasion"
}

pub struct AttackChainStep {
    pub order: usize,
    pub evidence_id: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
}
```

#### 2.2.3 IncidentEngine API

- `create_incident(title, description, severity, confidence)` → `Incident`
- `get_incident(id)` → `Option<Incident>`
- `update_status(id, status)` → `bool`
- `escalate(id, new_severity)` → `bool`
- `add_evidence(id, evidence_id)` → `bool`
- `active_incidents()` → `Vec<Incident>`
- `list_incidents()` → `Vec<Incident>`
- `merge_incidents(ids, new_title)` → `Option<Incident>`
- `prune_closed(older_than_days)` → `usize`
- `count()` → `usize`
- `count_by_status()` → `HashMap<String, usize>`
- `count_by_severity()` → `HashMap<String, usize>`

### 2.3 `sentinelx-threat`

**Path:** `crates/threat/`

#### 2.3.1 Module Structure

```
crates/threat/src/
├── lib.rs      — Exports engine + types
├── types.rs    — ThreatDecision, ThreatSeverity, ThreatPriority, RiskScore, MitreMapping
├── engine.rs   — ThreatEngine (async, RwLock-protected)
└── tests/      — 14 tests
```

#### 2.3.2 Types

```rust
pub struct ThreatDecision {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub severity: ThreatSeverity,  // Info, Low, Medium, High, Critical
    pub risk_score: RiskScore,
    pub confidence: f64,
    pub priority: ThreatPriority,  // Immediate, High, Normal, Low, Informational
    pub mitre_mappings: Vec<MitreMapping>,
    pub description: String,
    pub recommendation: String,
    pub response_plan: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
}

pub struct RiskScore {
    pub trust_score: f64,
    pub integrity_score: f64,
    pub risk_score: f64,
    pub reputation_score: f64,
    pub evidence_count: usize,
    pub incident_complexity: usize,
    pub rule_confidence: f64,
    pub final_score: f64,  // 0–100
}
```

#### 2.3.3 Risk Scoring Algorithm

Configurable weighted scoring with defaults:

```rust
pub struct RiskWeights {
    pub trust: f64,           // 0.15
    pub integrity: f64,       // 0.20
    pub risk: f64,            // 0.25
    pub reputation: f64,      // 0.10
    pub evidence_count: f64,  // 0.10
    pub incident_complexity: f64, // 0.10
    pub rule_confidence: f64, // 0.10
}
```

Score mapping: 0–20 = Info, 21–40 = Low, 41–60 = Medium, 61–80 = High, 81–100 = Critical

#### 2.3.4 ThreatEngine API

- `evaluate_incident(incident)` → `ThreatDecision`
- `evaluate_and_store(incident)` → `ThreatDecision` (stores internally)
- `calculate_risk_score(incident)` → `RiskScore`
- `get_decision(id)` → `Option<ThreatDecision>`
- `list_decisions()` → `Vec<ThreatDecision>`
- `count()` → `usize`
- `count_by_severity()` → `HashMap<String, usize>`

## 3. Database Schema

### 3.1 New Tables

```sql
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL DEFAULT 'medium',
    confidence REAL NOT NULL DEFAULT 0.5,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    evidence_ids TEXT DEFAULT '[]',
    object_ids TEXT DEFAULT '[]',
    attack_chain TEXT DEFAULT '[]',
    mitre_mappings TEXT DEFAULT '[]',
    recommended_response TEXT,
    tags TEXT DEFAULT '[]',
    metadata TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS threat_decisions (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    risk_score_trust REAL DEFAULT 0.0,
    risk_score_integrity REAL DEFAULT 0.0,
    risk_score_risk REAL DEFAULT 0.0,
    risk_score_reputation REAL DEFAULT 0.0,
    risk_score_evidence_count INTEGER DEFAULT 0,
    risk_score_incident_complexity INTEGER DEFAULT 0,
    risk_score_rule_confidence REAL DEFAULT 0.0,
    risk_score_final REAL DEFAULT 0.0,
    confidence REAL NOT NULL DEFAULT 0.5,
    priority TEXT NOT NULL DEFAULT 'normal',
    mitre_mappings TEXT DEFAULT '[]',
    description TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    response_plan TEXT,
    tags TEXT DEFAULT '[]',
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS correlation_graph (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    properties TEXT DEFAULT '{}'
);
```

## 4. Backend Integration

### 4.1 AppState

```rust
pub struct AppState {
    pub store: SqlitePool,
    pub engine: Arc<Engine>,
    pub metrics: Arc<RwLock<MetricsCollector>>,
    pub timeline: Arc<RwLock<TimelineEngine>>,
    pub incident_engine: Arc<IncidentEngine>,   // NEW
    pub threat_engine: Arc<ThreatEngine>,       // NEW
}
```

### 4.2 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/incidents` | List all incidents |
| GET | `/api/incidents/:id` | Get incident by ID |
| PUT | `/api/incidents/:id/status` | Update incident status |
| GET | `/api/threat-decisions` | List all threat decisions |
| GET | `/api/threat-decisions/:id` | Get threat decision by ID |
| GET | `/api/graph` | Get correlation graph summary |
| GET | `/api/graph/:node_id` | Get graph node details |

### 4.3 Database Repositories

- `IncidentRepository`: insert, find_by_id, find_all, find_by_status, update_status, count, count_by_status, count_by_severity
- `ThreatDecisionRepository`: insert, find_by_id, find_all, find_by_severity, find_by_incident_id, count, count_by_severity
- `CorrelationGraphRepository`: insert_edge, find_by_source, find_by_target, find_all, count, clear

## 5. CLI Commands

| Command | Description |
|---------|-------------|
| `sentinelx incidents` | Show incidents by status/severity with MITRE mappings |
| `sentinelx threats` | Show threat decisions with risk scores |
| `sentinelx graph` | Show correlation graph status and rules |

## 6. Test Results

| Crate | Tests |
|-------|-------|
| sentinelx-correlation | 28 (6 graph + 7 rules + 5 evidence_correlator + 10 engine) |
| sentinelx-incident | 16 (8 types + 8 engine) |
| sentinelx-threat | 14 (6 types + 8 engine) |
| **Total new** | **58** |
| **Total workspace** | **398** |

## 7. Evidence-Only Constraint

These engines operate on **evidence only**, not on raw detections or predictions. The Threat Engine is the sole component authorized to classify attacks. Evidence flows through:

1. Discovery → 2. Metadata → 3. Assessment → 4. Evidence Store → 5. Correlation → 6. Incident → 7. Threat → 8. Response
