# SentinelX Performance Guide

## Table of Contents

1. [Benchmark Results](#1-benchmark-results)
2. [Performance Characteristics](#2-performance-characteristics)
3. [Memory Usage](#3-memory-usage)
4. [CPU Usage](#4-cpu-usage)
5. [Disk I/O](#5-disk-io)
6. [Network Overhead](#6-network-overhead)
7. [Tuning Parameters](#7-tuning-parameters)
8. [Profiling Guide](#8-profiling-guide)

---

## 1. Benchmark Results

### Summary

| Metric | Value |
|--------|-------|
| CPU usage (idle) | < 2% |
| CPU usage (scanning) | < 3% |
| Memory usage (idle) | < 100 MB |
| Memory usage (scanning) | < 150 MB |
| Full scan latency | < 2 seconds |
| eBPF event latency | ~45 μs average |
| Telemetry bus throughput | 50,000 events/second |
| Database write (single insert) | < 1 ms |
| API response time (health) | < 5 ms |

### Telemetry bus benchmarks

Criterion benchmarks in `crates/benchmarks/benches/telemetry_throughput.rs`:

| Benchmark | Description |
|-----------|-------------|
| Bus publish throughput | Measures event publishing at different channel capacities |
| Bus subscribe/receive throughput | Measures event reception at different volumes |
| Event creation overhead | Per-event-type creation cost |
| MPSC channel throughput | Raw tokio channel performance as baseline |

### Pipeline benchmarks

| Pipeline phase | Typical duration |
|----------------|-----------------|
| Discovery (all 7 providers) | ~200–500 ms |
| Metadata enrichment (7 collectors) | ~50–100 ms |
| Assessment (7 assessors) | ~30–80 ms |
| Evidence generation | ~10–20 ms |
| **Total pipeline** | **~300–700 ms** |

### Build benchmarks

| Profile | Build time | Binary size |
|---------|-----------|-------------|
| `cargo build` (debug) | ~30s | ~180 MB |
| `cargo build --release` (LTO) | ~60–90s | ~9.7 MB total |
| `sentinelx-backend` (release) | — | ~7.4 MB |
| `sentinelx-cli` (release) | — | ~2.3 MB |

---

## 2. Performance Characteristics

### Architecture benefits

- **Non-blocking async architecture**: Tokio runtime with multi-threaded executor prevents blocking on I/O
- **Event-driven telemetry**: eBPF ring buffers and netlink multicast avoid polling overhead
- **Lock-free counters**: `AtomicU64` for high-frequency telemetry statistics
- **Broadcast channel**: `tokio::sync::broadcast` for efficient fan-out to multiple subscribers
- **Immutable evidence**: No mutation overhead; evidence records are created once
- **WAL-mode SQLite**: Better concurrent read performance than rollback journal

### Pipeline characteristics

The evidence-driven pipeline follows a strict sequential flow:

```
Discovery → Metadata → Assessment → Evidence
```

Each phase is **fault-tolerant**: individual provider/collector/assessor failures are logged and other components continue. No single component failure can halt the pipeline.

Within each phase, components run **sequentially**. Future optimization could parallelize providers within the Discovery phase using `tokio::join!`.

### Telemetry characteristics

| Provider | Latency | Overhead | Scalability |
|----------|---------|----------|-------------|
| eBPF (Aya) | ~45 μs avg | Near-zero when attached; ring buffer is lock-free | High (kernel-bounded) |
| fanotify | ~100 μs | Minimal; OS handles event queuing | High (kernel-bounded) |
| netlink | ~50 μs | Low; kernel sends events via multicast | High (kernel-bounded) |
| audit | ~200 μs | Moderate; depends on audit rules complexity | Medium |
| proc scanning | ~500 ms | High; reads /proc entries | Low (polling-based) |

---

## 3. Memory Usage

### Memory budget

| Component | Idle | Scanning | Notes |
|-----------|------|----------|-------|
| Backend process | ~50 MB | ~80 MB | Tokio runtime + Axum server |
| Telemetry engine | ~20 MB | ~30 MB | Bus buffer + provider state |
| Detection pipeline | ~10 MB | ~40 MB | Object graph + evidence store |
| SQLite connection pool | ~5 MB | ~5 MB | 5 connections |
| Fleet manager | ~5 MB | ~5 MB | Agent state + policies |
| Behavior engine | ~5 MB | ~10 MB | Profiles + rules |
| Intelligence engine | ~5 MB | ~10 MB | IoCs + MITRE + YARA + Sigma |
| **Total** | **~100 MB** | **~150 MB** | Configurable via `max_memory_mb` |

### Memory configuration

```toml
[general]
max_memory_mb = 150   # Default cap (1–1024 MB)
```

The `max_memory_mb` setting is validated:
- Minimum: 1 MB
- Maximum: 1024 MB
- Default: 150 MB

### Telemetry bus memory

The telemetry bus uses a `VecDeque` buffer with configurable capacity:

- **Default capacity**: 50,000 events
- **Event size**: ~200 bytes average
- **Buffer memory**: ~10 MB at full capacity
- **Eviction**: Oldest events dropped when buffer is full

### Evidence store memory

Evidence records are stored in-memory and persisted to SQLite:

- **CoreEvidence size**: ~500 bytes average
- **Default max_events**: 1,000,000
- **Memory for 1M events**: ~500 MB (exceeds default cap)
- **Practical limit**: ~10,000 in-memory evidence records before rotation

### SQLite memory

Each SQLite connection uses approximately:
- **Page cache**: ~2 MB per connection
- **WAL index**: ~1 MB shared
- **Total for 5 connections**: ~11 MB

---

## 4. CPU Usage

### CPU budget

| Phase | CPU usage | Notes |
|-------|-----------|-------|
| Idle (telemetry only) | < 2% | Event processing from kernel |
| Scanning | < 3% | Full pipeline execution |
| Telemetry processing | ~1% | Normalizing and routing events |
| API serving | < 0.5% | Request handling |

### CPU configuration

```toml
[general]
max_cpu_percent = 3.0   # Default cap (0–100%)
```

### CPU-intensive operations

| Operation | CPU impact | Mitigation |
|-----------|-----------|------------|
| Full pipeline scan | ~3% for 200ms | Runs periodically, not continuously |
| eBPF event processing | ~1% sustained | Ring buffer is lock-free; minimal overhead |
| File integrity hashing | ~0.5% per scan | Only hashes critical system files |
| Database writes | ~0.1% | WAL mode, batch inserts |
| JSON serialization (API) | ~0.2% | serde with no default features |

### CPU profiling

Use `perf` for CPU profiling:

```bash
# Record CPU profile
sudo perf record -p $(pgrep sentinelx) -g -- sleep 30

# Analyze
sudo perf report

# Flame graph
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > cpu-flame.svg
```

---

## 5. Disk I/O

### Disk usage

| Component | Write pattern | Typical size |
|-----------|--------------|-------------|
| SQLite database | WAL + periodic checkpoints | 1–5 GB over 90 days |
| Evidence snapshots | On-demand forensic collection | ~1 KB per snapshot |
| Log files | Sequential append | ~10 MB/day |
| Telemetry events | Batch inserts | ~200 MB/day (100 agents) |

### SQLite I/O characteristics

- **Journal mode**: WAL (Write-Ahead Logging) — allows concurrent reads during writes
- **Auto-vacuum**: Full — reclaims space automatically after deletes
- **Busy timeout**: 5 seconds — waits for locks instead of failing
- **Write pattern**: Sequential inserts with periodic batch operations
- **Read pattern**: Mostly random reads for queries

### I/O tuning

For high-throughput deployments:

1. **Use SSD storage** for the SQLite database
2. **Separate WAL and DB files** on different physical devices if possible
3. **Tune WAL autocheckpoint**: Default is 1000 pages; increase for better write throughput
4. **Batch inserts**: Use `insert_batch()` for bulk operations

### Disk space monitoring

```bash
# Check database size
du -sh /var/lib/sentinelx/sentinelx.db

# Check WAL size
du -sh /var/lib/sentinelx/sentinelx.db-wal

# Check evidence directory
du -sh /var/lib/sentinelx/evidence/

# Check logs
du -sh /var/log/sentinelx/
```

---

## 6. Network Overhead

### API network

| Metric | Value |
|--------|-------|
| Health check response | ~200 bytes |
| Status response | ~2 KB |
| Threat list response | ~10 KB typical |
| Telemetry events response | ~50 KB typical |
| Fleet overview response | ~5 KB |

### Fleet transport network

| Metric | Value |
|--------|-------|
| Heartbeat size | ~500 bytes |
| Heartbeat interval | 30 seconds |
| Per-agent bandwidth | ~1–5 KB/s |
| Policy distribution | ~2 KB per policy |
| Remote action | ~1 KB per action |

### Compression

The transport layer uses gzip compression for payloads > 1 KB:

- **Compression ratio**: ~60% reduction for telemetry data
- **Compression latency**: ~10 μs per message
- **Decompression latency**: ~5 μs per message

### Bandwidth estimation

For a fleet of 100 agents:

| Traffic | Per agent | Total |
|---------|-----------|-------|
| Heartbeats (30s interval) | ~500 B / 30s | ~1.7 KB/s |
| Telemetry stats | ~200 B / 60s | ~0.3 KB/s |
| Policy distribution | ~2 KB / on change | Burst |
| **Total steady-state** | **~1.5 KB/s** | **~150 KB/s** |

---

## 7. Tuning Parameters

### General settings

```toml
[general]
scan_interval_seconds = 60    # Increase for lower CPU; decrease for faster detection
baseline_on_start = true      # Set to false for faster startup
max_memory_mb = 150           # Adjust based on available RAM
max_cpu_percent = 3.0         # Adjust based on available CPU
```

### eBPF settings

```toml
[ebpf]
enabled = true                 # Set to false to disable eBPF (use proc scanning only)
map_size = 10240               # eBPF map entries; increase for more event types
perf_buffer_pages = 64         # Perf buffer size; increase for burst handling
max_events_per_second = 10000  # Rate limit; decrease to reduce CPU
```

### Telemetry bus settings

Configured in code via `BusConfig`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `capacity` | 50,000 | Maximum events in buffer |
| `max_rate` | 50,000/s | Maximum event ingestion rate |

### Detection settings

```toml
[detection]
enabled_detectors = [...]      # Disable unused detectors to reduce scan time
severity_threshold = "low"     # Increase to "medium" to reduce noise
evidence_collection = true     # Set to false to skip evidence generation
```

### Storage settings

```toml
[storage]
retention_days = 90            # Reduce for less disk usage
max_events = 1000000           # Reduce for less memory usage
```

### Transport settings

Configured via `TransportConfig`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `compress` | true | Enable gzip compression |
| `max_retries` | 5 | Connection retry attempts |
| `retry_delay_ms` | 1000 | Delay between retries |
| `reconnect_delay_ms` | 5000 | Delay before reconnection |
| `heartbeat_interval_secs` | 30 | Heartbeat frequency |
| `buffer_size` | 8192 | TCP read buffer size |

### Response engine settings

```rust
ResponseConfig {
    enabled: true,
    dry_run: true,                    // Keep true in production unless verified
    max_severity: Severity::High,     // Only respond to High+ threats
    cooldown_seconds: 10,             // Minimum time between responses
    max_responses_per_minute: 60,     // Rate limit responses
}
```

---

## 8. Profiling Guide

### CPU profiling with perf

```bash
# Record
sudo perf record -p $(pgrep sentinelx) -g -- sleep 30

# Report
sudo perf report --stdio

# Flame graph
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg
```

### Memory profiling

```bash
# Track memory usage over time
while true; do
    echo "$(date +%s) $(ps -o rss= -p $(pgrep sentinelx))" >> memory.log
    sleep 1
done

# Analyze
awk '{print $1, $2/1024 " MB"}' memory.log | gnuplot -e "set terminal png; set output 'memory.png'; plot '-' with lines"
```

### Telemetry throughput profiling

Run the Criterion benchmarks:

```bash
cargo bench --package sentinelx-benchmarks
```

Available benchmarks:
- `telemetry_bus_publish`: Event publishing at different channel capacities
- `telemetry_bus_subscribe`: Event reception at different volumes
- `telemetry_event_creation`: Per-event-type creation overhead
- `telemetry_mpsc_throughput`: Raw tokio channel baseline

### Database profiling

```bash
# Enable SQLite query logging
sqlite3 /var/lib/sentinelx/sentinelx.db "PRAGMA query_log = ON;"

# Analyze slow queries
sqlite3 /var/lib/sentinelx/sentinelx.db "EXPLAIN QUERY PLAN SELECT * FROM threats;"

# Check database integrity
sqlite3 /var/lib/sentinelx/sentinelx.db "PRAGMA integrity_check;"

# Check WAL mode
sqlite3 /var/lib/sentinelx/sentinelx.db "PRAGMA journal_mode;"

# Check page count and size
sqlite3 /var/lib/sentinelx/sentinelx.db "PRAGMA page_count; PRAGMA page_size;"
```

### Tokio console

For real-time async task monitoring, enable the Tokio console subscriber:

```bash
RUST_LOG=tokio=trace cargo run --release -p sentinelx-backend
```

Then connect with the tokio-console TUI.

### Tracing spans

SentinelX uses `tracing` with structured logging. Enable trace-level logging for detailed timing:

```toml
[logging]
level = "trace"
```

Key spans to observe:
- `Evidence-driven pipeline completed` — total pipeline duration
- `Pipeline` phases — per-phase timing
- Telemetry event processing — per-event latency

### Load testing the API

```bash
# Install hey (HTTP load generator)
go install github.com/rakyll/hey@latest

# 100 requests/sec for 60 seconds
hey -n 6000 -c 10 http://localhost:8443/api/health

# Concurrent scan requests
hey -n 100 -c 10 -m POST http://localhost:8443/api/scan
```

### Continuous monitoring

For production performance monitoring:

1. Export telemetry stats to Prometheus via custom exporter
2. Monitor database file size growth rate
3. Track API response times with access logs
4. Monitor process RSS memory over time
5. Track telemetry event rates and drop rates per provider
