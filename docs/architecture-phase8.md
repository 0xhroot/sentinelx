# Architecture Phase 8: Behavior Engine + Threat Intelligence + Dashboard v2

## Overview

Phase 8 adds behavioral profiling, comprehensive threat intelligence (IoCs, MITRE ATT&CK, YARA, Sigma, CVE), and expanded dashboard/CLI/APIs to SentinelX. All intelligence is **offline-first** — no internet required.

## New Crates

### `sentinelx-behavior`
Behavioral profiling engine that builds per-object profiles from telemetry events.

**Key Types:**
- `BehaviorCategory` — 11 categories (ProcessAncestry, ExecFrequency, NetworkActivity, PrivilegeEscalation, etc.)
- `BehaviorProfile` — per-object profile with counters, risk/confidence trends, event history
- `BehaviorEvent` — timestamped category event with risk level
- `BehaviorScore` — 7 weighted factors (frequency 15%, recurrence 20%, escalation 25%, novelty 10%, persistence 15%, correlation 5%, assessment 10%) → severity
- `BehaviorRule` / `BehaviorRuleConfig` — TOML-configurable rules (6 defaults)
- `BehaviorEngine` — async engine with RwLock profiles, rule evaluation, scoring

**Default Rules:**
1. `repeated_privilege_escalation` — critical (privilege_changes ≥ 3)
2. `unsigned_executable_persistence` — high (persistence ≥ 1, integrity ≥ 1)
3. `network_exfiltration_pattern` — high (connections ≥ 100, privilege ≥ 1)
4. `suspicious_process_behavior` — medium (executions ≥ 50, integrity ≥ 1)
5. `kernel_module_anomaly` — high (executions ≥ 5)
6. `low_risk_baseline` — info (executions < 10)

### `sentinelx-intelligence`
Threat intelligence engine with offline-first IoCs, MITRE ATT&CK, YARA, Sigma, and CVE tracking.

**Key Types:**
- `IoCType` — 8 variants (Hash, IpAddress, Domain, Filename, ProcessName, ModuleName, Url, Email)
- `IoC` — indicator with severity, confidence, source, tags, expiry
- `MitreTechnique` / `MitreMatrix` — 16 default techniques with tactic mapping
- `YaraRule` — YARA rule stub (name, content, severity, tags)
- `SigmaRule` — Sigma detection rule with logsource and detection config
- `CveEntry` — CVE with CVSS score, affected products, references
- `ReputationScore` — per-object reputation with malicious flag
- `IntelligenceEngine` — async engine with RwLock stores, add/get/list/remove for all types

## Database Schema Additions

| Table | Purpose |
|---|---|
| `behavior_profiles` | Persisted behavioral profiles (14 columns, 2 indexes) |
| `iocs` | IoCs with type/value compound key (12 columns, 3 indexes) |
| `yara_rules` | YARA rule storage (8 columns, 1 index) |
| `sigma_rules` | Sigma rule storage (13 columns, 2 indexes) |
| `cves` | CVE tracking (7 columns, 1 index) |

## Repository Layer

5 new repositories in `sentinelx-database`:
- `BehaviorProfileRepository` — insert/find_by_object_id/find_all/count
- `IoCRepository` — insert/find_by_type/find_by_value/find_all/count/count_by_type/delete
- `YaraRuleRepository` — insert/find_all/find_by_name/count/delete
- `SigmaRuleRepository` — insert/find_all/find_by_name/count/delete
- `CveRepository` — insert/find_by_id/find_all/count

## Backend API Routes

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/behavior/profiles` | List all behavioral profiles |
| GET | `/api/behavior/profiles/{object_id}` | Get profile for specific object |
| POST | `/api/behavior/record` | Record a behavioral event |
| GET | `/api/behavior/stats` | Behavioral statistics |
| GET | `/api/intelligence/stats` | Intelligence engine summary |
| GET | `/api/intelligence/iocs` | List all IoCs |
| POST | `/api/intelligence/iocs` | Add new IoC |
| GET | `/api/intelligence/iocs/{type}/{value}` | Check if IoC exists |
| DELETE | `/api/intelligence/iocs/{type}/{value}` | Remove IoC |
| GET | `/api/intelligence/mitre` | List MITRE techniques |
| GET | `/api/intelligence/mitre/{id}` | Get specific technique |
| GET | `/api/intelligence/yara` | List YARA rules |
| POST | `/api/intelligence/yara` | Add YARA rule |
| GET | `/api/intelligence/yara/{name}` | Get specific rule |
| GET | `/api/intelligence/sigma` | List Sigma rules |
| POST | `/api/intelligence/sigma` | Add Sigma rule |
| GET | `/api/intelligence/sigma/{name}` | Get specific rule |
| GET | `/api/intelligence/cves` | List CVEs |
| POST | `/api/intelligence/cves` | Add CVE |
| GET | `/api/intelligence/cves/{id}` | Get specific CVE |
| GET | `/api/intelligence/reputation` | Get global reputation |

## CLI Commands

| Command | Description |
|---|---|
| `sentinelx behavior` | Show behavioral engine status, rules, categories |
| `sentinelx behavior-profiles` | Show behavioral profiles with scores |
| `sentinelx behavior-stats` | Show scoring weights and statistics |
| `sentinelx intel` | Show intelligence engine summary |
| `sentinelx mitre` | Show MITRE ATT&CK matrix by tactic |
| `sentinelx iocs` | Show loaded IoCs |
| `sentinelx ioc-check <type> <value>` | Check if an IoC is known malicious |
| `sentinelx cves` | Show tracked CVEs |
| `sentinelx yara` | Show loaded YARA rules |
| `sentinelx sigma` | Show loaded Sigma rules |

## AppState Changes

```rust
pub struct AppState {
    // ... existing fields ...
    pub behavior_engine: Arc<BehaviorEngine>,
    pub intelligence_engine: Arc<IntelligenceEngine>,
}
```

## Test Results

- **sentinelx-behavior**: 21 tests (13 types + 8 engine)
- **sentinelx-intelligence**: 22 tests (9 types + 13 engine)
- **sentinelx-database**: 24 tests (8 new repository tests)
- **Total project**: 535 tests passing
