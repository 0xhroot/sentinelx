# SentinelX Architecture — Phase 3: Central Assessment Engine

**Date:** 2026-07-13
**Status:** Complete

---

## 1. Overview

Phase 3 introduces a **central Assessment Engine** that replaces per-detector assessor implementations with a unified, numeric-score-based assessment system. The engine provides configurable scoring (0–100 trust/integrity/risk/reputation, 0.0–1.0 confidence) and is wired into the existing pipeline through an adapter layer.

## 2. New Crate: `sentinelx-assessment`

**Path:** `crates/assessment/`

### 2.1 Module Structure

```
crates/assessment/src/
├── lib.rs              — Crate root, adapter, create_all_assessors()
├── types.rs            — ObjectAssessment (immutable, builder pattern)
├── config.rs           — ScoringConfig (TOML-driven, factor-based scoring)
├── store.rs            — AssessmentStore (in-memory, async RwLock)
├── error.rs            — AssessmentError, Result<T>
└── assessors/
    ├── mod.rs          — Assessor trait definition
    ├── process.rs      — ProcessAssessor
    ├── module.rs       — ModuleAssessor
    ├── network.rs      — NetworkAssessor
    ├── service.rs      — ServiceAssessor
    ├── file.rs         — FileAssessor
    ├── memory.rs       — MemoryAssessor
    └── kernel.rs       — KernelAssessor
```

### 2.2 Key Types

#### `ObjectAssessment`
Immutable assessment result with numeric scores (0–100). Built via builder pattern:
```rust
ObjectAssessment::new("process:1234")
    .with_trust(80)
    .with_integrity(90)
    .with_risk(20)
    .with_reputation(70)
    .with_confidence(0.85)
    .with_reason("Package verified")
    .with_warning("Running as root")
```

#### `ScoringConfig`
TOML-driven scoring configuration with factor-based score computation. Loaded from embedded defaults or custom file:
```rust
let config = ScoringConfig::load_default();
let trust = config.compute_trust(&["official_package", "correct_permissions"]);
// 50 (base) + 25 + 10 = 85
```

#### `Assessor` trait
```rust
#[async_trait]
pub trait Assessor: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn supported_object_types(&self) -> Vec<ObjectType>;
    async fn assess(&self, object: &SentinelObject, config: &ScoringConfig)
        -> Result<ObjectAssessment, CoreError>;
}
```

### 2.3 Assessor Implementations

| Assessor | Object Type | Key Factors |
|---|---|---|
| ProcessAssessor | Process | Package info, ownership (uid=0), permissions, DKOM hidden, orphaned |
| ModuleAssessor | KernelModule | Builtin, signature valid, DKOM suspected, trust_score |
| NetworkAssessor | NetworkConnection | Hidden connections, orphaned, PID association |
| ServiceAssessor | Service | Classification, symlink persistence, ownership |
| FileAssessor | File | Modified status, SUID/SGID, world-writable, package ownership |
| MemoryAssessor | MemoryRegion | Modified, executable, W^X violations, kernel regions |
| KernelAssessor | KernelModule | Hook detection, integrity violation, hardening checks |

### 2.4 AssessmentStore

In-memory store with `RwLock<HashMap<String, Vec<ObjectAssessment>>>`:
- `store()`, `store_batch()`, `get_latest()`, `get_history()`, `get_by_id()`
- `get_all_latest()`, `search()`, `expire_old()`, `count()`, `object_count()`

## 3. Adapter Layer

`AssessorAdapter` bridges the new `Assessor` trait (with `ScoringConfig`) to the existing `ObjectAssessor` trait (core pipeline interface):

```rust
pub struct AssessorAdapter {
    inner: Arc<dyn Assessor>,
    config: ScoringConfig,
}
```

The adapter converts numeric scores (0–100) to categorical levels (Trusted/Untrusted/Unknown, Intact/Tampered/Unknown, etc.) for backward compatibility with the pipeline's evidence generation.

`create_all_assessors()` returns all 7 assessors as `Vec<Arc<dyn ObjectAssessor>>` for easy registration.

## 4. Database Schema

New `assessment_results` table in SQLite:

```sql
CREATE TABLE IF NOT EXISTS assessment_results (
    id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    trust INTEGER NOT NULL,
    integrity INTEGER NOT NULL,
    risk INTEGER NOT NULL,
    reputation INTEGER NOT NULL,
    confidence REAL NOT NULL,
    reasons TEXT NOT NULL DEFAULT '[]',
    warnings TEXT NOT NULL DEFAULT '[]',
    metadata_references TEXT NOT NULL DEFAULT '[]',
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

`AssessmentRepository` provides CRUD operations, high-risk queries, and cleanup.

## 5. CoreEvidence Update

`CoreEvidence` now includes `assessment_id: Option<Uuid>` field, enabling evidence to reference specific assessment results instead of embedding full assessment snapshots.

## 6. Pipeline Enforcement

The pipeline now enforces **mandatory assessment**: evidence is only generated for objects that have at least one assessment. Objects without assessments are logged at debug level and skipped.

## 7. Backend Wiring

The backend's evidence-driven pipeline now registers assessors through the centralized adapter:

```rust
for assessor in sentinelx_assessment::create_all_assessors() {
    pipeline.assessment().register(assessor);
}
```

Discovery and metadata providers remain registered per-crate (unchanged from Phase 2).

## 8. CLI

New `sentinelx assess` subcommand:
- Lists loaded assessors and their supported object types
- Shows scoring configuration (base values)
- Supports `--object-type` filter

## 9. Reporting

`ReportGenerator` gains `generate_assessment_section()` method that produces:
- Risk distribution (Critical/High, Medium, Low, None)
- Score averages (Trust, Integrity, Confidence)
- Warning and reason counts

## 10. Verification Results

| Check | Result |
|---|---|
| `cargo fmt --all` | Clean |
| `cargo clippy -- -D warnings` | Clean (0 warnings) |
| `cargo test` | 340 passed, 0 failed |
| `cargo build --release` | Success |

## 11. Files Modified/Created

### Created
- `crates/assessment/` — New crate (11 source files)
- `apps/cli/src/commands/assess.rs` — CLI assess command
- `docs/architecture-phase3.md` — This document

### Deleted (old assessor dead code)
- `crates/process/src/assessment.rs` — Old ProcessAssessor (5 tests)
- `crates/module/src/assessment.rs` — Old ModuleAssessor (8 tests)
- `crates/network/src/assessment.rs` — Old NetworkAssessor (5 tests)
- `crates/persistence/src/assessment.rs` — Old PersistenceAssessor (5 tests)
- `crates/kernel/src/assessment.rs` — Old KernelAssessor (5 tests)
- `crates/memory/src/assessment.rs` — Old MemoryAssessor (4 tests)
- `crates/integrity/src/assessment.rs` — Old IntegrityAssessor (5 tests)

### Modified
- `Cargo.toml` — Added `sentinelx-assessment` to workspace deps
- `crates/core/src/evidence.rs` — Added `assessment_id: Option<Uuid>` field
- `crates/core/src/pipeline.rs` — Mandatory assessment enforcement
- `crates/database/src/store.rs` — `assessment_results` table migration
- `crates/database/src/repository.rs` — `AssessmentRepository`
- `crates/database/Cargo.toml` — Added `sentinelx-assessment` dependency
- `crates/reporting/src/report.rs` — Assessment section in reports
- `crates/reporting/Cargo.toml` — Added `sentinelx-assessment` dependency
- `backend/src/main.rs` — Centralized assessor registration
- `backend/Cargo.toml` — Added `sentinelx-assessment` dependency
- `apps/cli/src/main.rs` — Added `Assess` subcommand
- `apps/cli/src/commands/mod.rs` — Added assess module
- `apps/cli/Cargo.toml` — Added `sentinelx-assessment`, `sentinelx-core` dependencies
- `crates/process/src/lib.rs` — Removed `pub mod assessment` + `pub use assessment::*`
- `crates/module/src/lib.rs` — Removed `pub mod assessment` + `pub use assessment::*`
- `crates/network/src/lib.rs` — Removed `pub mod assessment` + `pub use assessment::*`
- `crates/persistence/src/lib.rs` — Removed `pub mod assessment` + `pub use assessment::*`
- `crates/kernel/src/lib.rs` — Removed `pub mod assessment` + `pub use assessment::*`
- `crates/memory/src/lib.rs` — Removed `pub mod assessment` + `pub use assessment::*`
- `crates/integrity/src/lib.rs` — Removed `pub mod assessment` + `pub use assessment::*`

## 12. Remaining Legacy (Phase 4 candidates)

- Core `AssessmentResult` (categorical) kept alongside new `ObjectAssessment` (numeric) for backward compatibility via adapter
- Discovery and metadata providers still registered per-crate (Phase 4 could centralize these)
