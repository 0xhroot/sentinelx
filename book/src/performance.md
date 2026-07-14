# Performance Guide

## Benchmark Results

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

### Pipeline Benchmarks

| Pipeline phase | Typical duration |
|----------------|-----------------|
| Discovery (all 7 providers) | ~200–500 ms |
| Metadata enrichment (7 collectors) | ~50–100 ms |
| Assessment (7 assessors) | ~30–80 ms |
| Evidence generation | ~10–20 ms |
| **Total pipeline** | **~300–700 ms** |

### Build Benchmarks

| Profile | Build time | Binary size |
|---------|-----------|-------------|
| `cargo build` (debug) | ~30s | ~180 MB |
| `cargo build --release` (LTO) | ~60–90s | ~9.7 MB total |
| `sentinelx-backend` (release) | — | ~7.4 MB |
| `sentinelx-cli` (release) | — | ~2.3 MB |

## Performance Characteristics

### Architecture Benefits

- **Non-blocking async architecture**: Tokio runtime with multi-threaded executor
- **Event-driven telemetry**: eBPF ring buffers and netlink multicast avoid polling
- **Lock-free counters**: `AtomicU64` for high-frequency telemetry statistics
- **Broadcast channel**: `tokio::sync::broadcast` for efficient fan-out
- **Immutable evidence**: No mutation overhead
- **WAL-mode SQLite**: Better concurrent read performance

### Telemetry Characteristics

| Provider | Latency | Overhead | Scalability |
|----------|---------|----------|-------------|
| eBPF (Aya) | ~45 μs avg | Near-zero | High (kernel-bounded) |
| fanotify | ~100 μs | Minimal | High (kernel-bounded) |
| netlink | ~50 μs | Low | High (kernel-bounded) |
| audit | ~200 μs | Moderate | Medium |
| proc scanning | ~500 ms | High | Low (polling-based) |

## Memory Usage

### Memory Budget

| Component | Idle | Scanning | Notes |
|-----------|------|----------|-------|
| Backend process | ~50 MB | ~80 MB | Tokio runtime + Axum |
| Telemetry engine | ~20 MB | ~30 MB | Bus buffer + providers |
| Detection pipeline | ~10 MB | ~40 MB | Object graph + evidence |
| SQLite connection pool | ~5 MB | ~5 MB | 5 connections |
| Fleet manager | ~5 MB | ~5 MB | Agent state + policies |
| Behavior engine | ~5 MB | ~10 MB | Profiles + rules |
| Intelligence engine | ~5 MB | ~10 MB | IoCs + MITRE + YARA |
| **Total** | **~100 MB** | **~150 MB** | Configurable |

### Telemetry Bus Memory

- **Default capacity**: 50,000 events
- **Event size**: ~200 bytes average
- **Buffer memory**: ~10 MB at full capacity
- **Eviction**: Oldest events dropped when full

### SQLite Memory

- **Page cache**: ~2 MB per connection
- **WAL index**: ~1 MB shared
- **Total for 5 connections**: ~11 MB

## CPU Usage

### CPU Budget

| Phase | CPU usage | Notes |
|-------|-----------|-------|
| Idle (telemetry only) | < 2% | Event processing from kernel |
| Scanning | < 3% | Full pipeline execution |
| Telemetry processing | ~1% | Normalizing and routing |
| API serving | < 0.5% | Request handling |

### CPU Profiling

```bash
# Record CPU profile
sudo perf record -p $(pgrep sentinelx) -g -- sleep 30

# Analyze
sudo perf report

# Flame graph
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > cpu-flame.svg
```

## Disk I/O

### Disk Usage

| Component | Write pattern | Typical size |
|-----------|--------------|-------------|
| SQLite database | WAL + checkpoints | 1–5 GB over 90 days |
| Evidence snapshots | On-demand | ~1 KB per snapshot |
| Log files | Sequential append | ~10 MB/day |
| Telemetry events | Batch inserts | ~200 MB/day (100 agents) |

### I/O Tuning

For high-throughput deployments:

1. Use **SSD storage** for the SQLite database
2. Separate WAL and DB files on different physical devices
3. Tune WAL autocheckpoint for better write throughput
4. Use `insert_batch()` for bulk operations

## Network Overhead

### API Network

| Metric | Value |
|--------|-------|
| Health check response | ~200 bytes |
| Status response | ~2 KB |
| Threat list response | ~10 KB typical |
| Fleet overview response | ~5 KB |

### Fleet Transport

| Metric | Value |
|--------|-------|
| Heartbeat size | ~500 bytes |
| Heartbeat interval | 30 seconds |
| Per-agent bandwidth | ~1–5 KB/s |
| Policy distribution | ~2 KB per policy |

### Bandwidth Estimation (100 agents)

| Traffic | Per agent | Total |
|---------|-----------|-------|
| Heartbeats | ~500 B / 30s | ~1.7 KB/s |
| Telemetry stats | ~200 B / 60s | ~0.3 KB/s |
| **Total steady-state** | **~1.5 KB/s** | **~150 KB/s** |

## Tuning Parameters

### General Settings

```toml
[general]
scan_interval_seconds = 60    # Increase for lower CPU
baseline_on_start = true      # Set to false for faster startup
max_memory_mb = 150           # Adjust based on available RAM
max_cpu_percent = 3.0         # Adjust based on available CPU
```

### eBPF Settings

```toml
[ebpf]
enabled = true
map_size = 10240              # Increase for more concurrent events
perf_buffer_pages = 64        # Increase for higher throughput
max_events_per_second = 10000 # Rate limit to prevent CPU spikes
```

### SQLite Settings

- WAL journal mode (default)
- Auto-vacuum: Full (default)
- Busy timeout: 5 seconds (default)
- Max connections: 5 (default)
- Acquire timeout: 10 seconds (default)

## Profiling Guide

### Memory Profiling

```bash
# RSS memory
ps -o pid,rss,comm -p $(pgrep sentinelx)

# Detailed memory map
pmap -x $(pgrep sentinelx)
```

### I/O Profiling

```bash
# Disk I/O
sudo iotop -p $(pgrep sentinelx)

# System call tracing
sudo strace -p $(pgrep sentinelx) -c
```
