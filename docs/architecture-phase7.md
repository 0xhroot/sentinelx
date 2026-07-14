# SentinelX Phase 7 – Real-Time Telemetry Engine

## Overview

Phase 7 transforms SentinelX from a polling-based detection system to an event-driven real-time telemetry engine. All detectors now react to events from kernel-level telemetry sources instead of continuously reading /proc.

## Architecture

```
Linux Kernel
    ↓
Telemetry Sources (eBPF, tracepoints, fanotify, auditd, netlink, proc)
    ↓
TelemetryProvider implementations
    ↓
EventNormalizer → TelemetryEvent (unified internal format)
    ↓
TelemetryBus (tokio channels, broadcast, backpressure)
    ↓
┌─────────────────────────────────────────────────┐
│  Existing Pipeline (unchanged)                  │
│  Discovery → Metadata → Assessment → Evidence   │
│  → Correlation → Incident → Threat → Response   │
└─────────────────────────────────────────────────┘
```

## New Crates

| Crate | Purpose |
|-------|---------|
| `crates/telemetry` | Core telemetry engine: types, provider trait, normalizer, bus, proc connector fallback |
| `crates/ebpf` | eBPF telemetry provider (Aya stub) |
| `crates/fanotify` | fanotify filesystem monitoring provider (stub) |
| `crates/audit` | auditd telemetry provider (stub) |
| `crates/netlink` | Netlink process/network provider (stub) |

## Key Types

### TelemetryEvent (immutable)

```rust
pub struct TelemetryEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub provider: String,
    pub category: TelemetryCategory,      // Process|Filesystem|Network|Kernel|Persistence
    pub event_type: TelemetryEventType,   // 34 variants
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub namespace: Option<String>,
    pub container: Option<String>,
    pub object_id: Option<String>,
    pub metadata: serde_json::Value,
}
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

### TelemetryBus

- Tokio broadcast channel for fan-out to subscribers
- VecDeque buffer with configurable capacity (default 50k)
- Rate limiting (default 50k/s max)
- Backpressure via mpsc channels
- Event eviction when buffer full

## Event Categories (34 event types)

| Category | Event Types |
|----------|-------------|
| Process | Create, Fork, Clone, Exec, Exit, Setuid, Setgid, Ptrace, CapChange |
| Filesystem | Open, Close, Read, Write, Rename, Delete, Execute, PermChange, OwnChange, Mount, Unmount |
| Network | Connect, Accept, Bind, Listen, Close, DnsLookup |
| Kernel | ModuleLoad, ModuleUnload, BpfLoad, ParamChange |
| Persistence | ServiceCreate, CronModify, RcLocalModify, LdPreloadModify |

## Provider Fallback Strategy

Priority order:
1. Aya eBPF (preferred)
2. Tracepoints
3. fanotify
4. auditd
5. Proc scanning (fallback)

Each provider is tried in order. If unavailable, the next is used. Startup never fails — at minimum, proc scanning provides events.

## Performance Targets

| Metric | Target |
|--------|--------|
| CPU usage | <2% idle |
| Memory usage | <100MB idle |
| Event latency | Non-blocking, async |
| Rate limit | 50k events/second |
| Buffer capacity | 50k events |

## Database Schema

```sql
CREATE TABLE telemetry_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    provider TEXT NOT NULL,
    category TEXT NOT NULL,
    event_type TEXT NOT NULL,
    pid INTEGER,
    uid INTEGER,
    namespace TEXT,
    container TEXT,
    object_id TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- Indexes: timestamp, pid, provider, category, event_type, object_id
```

## Backend API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/telemetry` | GET | List stored telemetry events |
| `/api/telemetry/live` | GET | Recent in-memory events (bus buffer) |
| `/api/telemetry/providers` | GET | List registered providers and status |
| `/api/telemetry/stats` | GET | Bus statistics |
| `/api/events/live` | GET | Live event stream |

## CLI Commands

| Command | Description |
|---------|-------------|
| `sentinelx telemetry` | Show telemetry engine status and config |
| `sentinelx events --count N` | Show recent telemetry events |
| `sentinelx providers` | Show registered providers |
| `sentinelx monitor-live --interval N` | Live monitoring of telemetry events |

## Integration

The telemetry engine is wired into `AppState` in `backend/src/main.rs`:

```rust
let telemetry_engine = Arc::new(TelemetryEngine::with_default_config());
telemetry_engine.initialize_default_providers().await;
```

On shutdown:
```rust
state.telemetry_engine.shutdown_all().await;
```

## Developer Guide: Adding a New Provider

1. Create a new crate under `crates/`
2. Add `sentinelx-telemetry` as a dependency
3. Implement the `TelemetryProvider` trait
4. In `initialize()`, spawn a tokio task that sends `TelemetryEvent`s through the `event_tx` channel
5. Register with `TelemetryEngine::register_provider()`
6. Events are automatically normalized and published to the bus

## Backward Compatibility

- Existing scan mode (polling) remains available as fallback
- All Phase 1-6 APIs unchanged
- `MetricsCollector` and `init_tracing` still exported from `sentinelx-telemetry`
- Existing `EbpfEngine` API preserved
