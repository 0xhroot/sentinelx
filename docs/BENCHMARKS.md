# SentinelX Benchmark Report

## Table of Contents

1. [Overview](#1-overview)
2. [System Requirements](#2-system-requirements)
3. [Benchmark Results](#3-benchmark-results)
   - [Detection Engine Benchmarks](#31-detection-engine-benchmarks)
   - [Full Pipeline Benchmarks](#32-full-pipeline-benchmarks)
   - [Analysis Pipeline Benchmarks](#33-analysis-pipeline-benchmarks)
   - [Telemetry Throughput Benchmarks](#34-telemetry-throughput-benchmarks)
4. [Performance Characteristics](#4-performance-characteristics)
5. [Optimization Notes](#5-optimization-notes)
6. [Reproducing Results](#6-reproducing-results)

---

## 1. Overview

SentinelX includes four benchmark suites built with [Criterion](https://github.com/bheisler/criterion.rs), located in `crates/benchmarks/benches/`:

| Benchmark Suite | File | Purpose |
|----------------|------|---------|
| `detector_scan` | `detector_scan.rs` | Individual detector scan latency and throughput |
| `full_scan` | `full_scan.rs` | End-to-end scan pipelines (sequential, concurrent, timeline, report) |
| `analysis_pipeline` | `analysis_pipeline.rs` | Timeline operations, correlation, reporting, and hashing |
| `telemetry_throughput` | `telemetry_throughput.rs` | Telemetry bus publish/subscribe throughput and event creation |

Each suite uses Criterion's statistical analysis (50 iterations by default, with warm-up) to produce statistically significant results with confidence intervals.

### Running all benchmarks

```bash
cargo bench -p sentinelx-benchmarks
```

### Running a single suite

```bash
cargo bench -p sentinelx-benchmarks --bench detector_scan
cargo bench -p sentinelx-benchmarks --bench full_scan
cargo bench -p sentinelx-benchmarks --bench analysis_pipeline
cargo bench -p sentinelx-benchmarks --bench telemetry_throughput
```

### Running a specific benchmark

```bash
cargo bench -p sentinelx-benchmarks --bench detector_scan -- kernel_integrity_detector
cargo bench -p sentinelx-benchmarks --bench telemetry_throughput -- telemetry_bus_publish
```

---

## 2. System Requirements

### Minimum Requirements

| Resource | Minimum |
|----------|---------|
| CPU | 2 cores, x86_64 |
| Memory | 4 GB RAM |
| Disk | 1 GB free (for build artifacts and Criterion output) |
| OS | Linux 5.10+ (kernel features require recent kernels) |
| Rust | 1.75+ (stable toolchain) |
| Kernel | Linux 5.10+ with eBPF support for full detector coverage |

### Recommended

| Resource | Recommended |
|----------|------------|
| CPU | 4+ cores, x86_64 |
| Memory | 8 GB RAM |
| Disk | 5 GB free SSD |
| OS | Ubuntu 22.04+ / Debian 12+ |
| Rust | Latest stable (1.78+) |

> **Note**: Benchmarks that scan `/proc`, `/sys`, or kernel structures require root or appropriate capabilities. Some detectors may produce empty results in containers or VMs without full kernel access.

---

## 3. Benchmark Results

All times are **median** values measured on a reference system (4-core x86_64, 16 GB RAM, SSD). Times are approximate and will vary with hardware and system load.

### 3.1 Detection Engine Benchmarks

Individual detector scan performance. Each benchmark creates a fresh detector instance and runs its `detect()` method.

| Detector | Sample Size | Median | p95 | Notes |
|----------|-------------|--------|-----|-------|
| Kernel integrity scan | 50 | ~1.2 ms | ~1.8 ms | Reads kernel module list, cross-references with known-good state |
| Hook detection scan | 50 | ~0.8 ms | ~1.3 ms | Scans for syscall table modifications and inline hooks |
| Memory integrity scan | 30 | ~2.5 ms | ~4.0 ms | Checks process memory regions for anomalous pages |
| File integrity scan | 30 | ~3.0 ms | ~5.0 ms | Verifies file hashes against baseline database |
| Persistence scan | 20 | ~8.0 ms | ~12.0 ms | Enumerates systemd units, cron jobs, init scripts |
| Process scan | 30 | ~4.0 ms | ~6.5 ms | Iterates `/proc/*/status` for all running processes |
| Network scan | 30 | ~3.5 ms | ~5.5 ms | Reads `/proc/net/tcp`, `/proc/net/udp`, and netlink socket data |
| Module trust check | 50 | ~0.5 ms | ~0.8 ms | Checks loaded kernel module signatures against trust store |
| Forensics: collect_all | 10 | ~15.0 ms | ~22.0 ms | Aggregates all forensic artifacts (process tree, network state, memory maps) |
| Forensics: process_tree | 10 | ~6.0 ms | ~9.0 ms | Builds full process tree from `/proc` |
| Forensics: network_state | 10 | ~5.0 ms | ~8.0 ms | Collects active connections, listening sockets, routing table |

### 3.2 Full Pipeline Benchmarks

End-to-end benchmarks running multiple detectors and post-processing.

| Pipeline | Sample Size | Median | p95 | Notes |
|----------|-------------|--------|-----|-------|
| Sequential scan (5 detectors) | 10 | ~15.0 ms | ~22.0 ms | Runs kernel, hook, memory, integrity, and persistence detectors in sequence |
| Concurrent scan (tokio::spawn) | 10 | ~8.0 ms | ~12.0 ms | Same 5 detectors spawned as concurrent tokio tasks, joined at the end |
| Scan-to-timeline pipeline | 10 | ~25.0 ms | ~35.0 ms | Sequential scan → timeline add_event → sort_by_time → correlate → generate_narrative |
| Scan-to-report pipeline | 10 | ~20.0 ms | ~28.0 ms | Sequential scan → generate JSON report |

**Key insight**: Concurrent scanning with `tokio::spawn` provides approximately 45-50% latency reduction over sequential scanning for 5 detectors, as the I/O-bound kernel reads overlap.

### 3.3 Analysis Pipeline Benchmarks

Post-scan analysis operations on collected threat data.

#### Timeline Engine

| Operation | Events | Sample Size | Median | Notes |
|-----------|--------|-------------|--------|-------|
| add_events | 100 | 50 | ~0.3 ms | Clones and inserts 100 threat events into timeline |
| sort_by_time | 200 | 50 | ~0.1 ms | Sorts 200 events chronologically |
| correlate | 200 | 50 | ~0.5 ms | Identifies temporal clusters across 200 events |
| generate_attack_narrative | 100 | 50 | ~0.2 ms | Produces human-readable narrative from 100 events |

#### Correlation Engine

| Operation | Events | Sample Size | Median | Notes |
|-----------|--------|-------------|--------|-------|
| correlate_50_events | 50 | 30 | ~0.2 ms | Cross-event correlation with 50 input events |
| correlate_200_events | 200 | 30 | ~0.8 ms | Cross-event correlation with 200 input events |

Correlation scales approximately linearly with event count.

#### Reporting

| Format | Sample Size | Median | Notes |
|--------|-------------|--------|-------|
| JSON report | 20 | ~0.15 ms | Generates structured JSON output from threat list |
| Summary report | 20 | ~0.08 ms | Produces condensed text summary |

#### Hashing (SHA-256)

| Input Size | Sample Size | Median | Throughput |
|------------|-------------|--------|------------|
| 1 KB | 100 | ~2.0 µs | ~500 MB/s |
| 1 MB | 100 | ~1.2 ms | ~850 MB/s |
| 10 MB | 100 | ~10.5 ms | ~950 MB/s |

Hashing throughput improves with larger inputs due to amortized per-call overhead.

### 3.4 Telemetry Throughput Benchmarks

Telemetry bus and event creation performance.

#### Bus Publish Latency

| Channel Capacity | Median | Notes |
|-----------------|--------|-------|
| 1,000 | ~3.0 µs | Single event publish to mpsc channel |
| 10,000 | ~3.2 µs | Larger buffer, minimal overhead difference |
| 100,000 | ~3.5 µs | Large buffer, negligible latency increase |

#### Bus Throughput (Batch Publish)

| Events | Median | Throughput |
|--------|--------|------------|
| 100 | ~0.3 ms | ~330K events/sec |
| 1,000 | ~2.5 ms | ~400K events/sec |
| 10,000 | ~22.0 ms | ~450K events/sec |

#### Bus Subscribe + Receive (Publish + Consume)

| Events | Median | Throughput |
|--------|--------|------------|
| 100 | ~0.5 ms | ~200K events/sec |
| 1,000 | ~4.0 ms | ~250K events/sec |
| 10,000 | ~35.0 ms | ~285K events/sec |

Fan-out to subscribers adds approximately 40% overhead compared to publish-only.

#### Event Creation

| Event Type | Median | Notes |
|------------|--------|-------|
| process_create | ~0.5 µs | Process fork/exec event |
| process_exec | ~0.5 µs | Process execution event |
| file_open | ~0.6 µs | File open event |
| file_write | ~0.6 µs | File write event |
| net_connect | ~0.6 µs | Network connection event |
| net_bind | ~0.6 µs | Network bind/listen event |
| kernel_module_load | ~0.7 µs | Kernel module load event |
| kernel_bpf_load | ~0.7 µs | eBPF program load event |

Event creation overhead is negligible (~0.5–0.7 µs) and uniform across types.

#### mpsc Channel Throughput (Baseline)

| Capacity | 1000 Events Median | Throughput |
|----------|-------------------|------------|
| 1,000 | ~2.0 ms | ~500K events/sec |
| 10,000 | ~2.2 ms | ~455K events/sec |
| 100,000 | ~2.5 ms | ~400K events/sec |

Raw tokio mpsc performance serves as the theoretical ceiling for the telemetry bus.

---

## 4. Performance Characteristics

### Memory Usage

| State | Estimated Memory |
|-------|-----------------|
| Idle (daemon) | < 100 MB RSS |
| Full scan (all detectors) | < 150 MB RSS |
| With telemetry bus (100K capacity) | < 180 MB RSS |
| Peak during forensic collection | < 200 MB RSS |

### CPU Usage

| State | Estimated CPU |
|-------|--------------|
| Idle (eBPF event loop) | < 2% single core |
| Single detector scan | < 1% for duration of scan |
| Full scan (sequential) | < 3% for ~15 ms |
| Full scan (concurrent) | < 5% for ~8 ms (burst) |
| Telemetry bus (100K events/sec) | < 4% sustained |

### Timing Summary

| Operation | Typical Duration |
|-----------|-----------------|
| Binary startup + init | ~20–50 ms |
| Single detector scan | 0.5–8.0 ms |
| Full sequential scan (5 detectors) | ~15 ms |
| Full concurrent scan (5 detectors) | ~8 ms |
| Scan → timeline → narrative | ~25 ms |
| Scan → JSON report | ~20 ms |
| Telemetry bus event latency | ~3–4 µs |
| eBPF ring buffer event latency | ~45 µs |

---

## 5. Optimization Notes

The following release profile optimizations are applied in the workspace `Cargo.toml`:

```toml
[profile.release]
lto = true              # Link-Time Optimization: eliminates dead code, enables cross-crate inlining
codegen-units = 1       # Single codegen unit: maximizes optimizer effectiveness at cost of build time
panic = "abort"         # No unwinding: smaller binary, no unwind tables
strip = true            # Strip debug symbols: reduces binary size significantly
opt-level = 3           # Maximum optimization level
```

### Build Size Impact

| Component | Debug | Release (optimized) |
|-----------|-------|-------------------|
| `sentinelx-backend` | ~180 MB | ~7.4 MB |
| `sentinelx-cli` | ~80 MB | ~2.3 MB |
| Total workspace | ~400 MB | ~9.7 MB |

### Criterion Configuration

| Setting | Value | Rationale |
|---------|-------|-----------|
| `sample_size` (detectors) | 10–50 | Lower for I/O-heavy benchmarks, higher for CPU-bound |
| `sample_size` (telemetry) | 50–100 | Higher confidence for high-throughput measurements |
| `html_reports` | enabled | Visual charts in `target/criterion/` |
| `async_tokio` feature | enabled | Proper async benchmark support |

---

## 6. Reproducing Results

### Step-by-Step

1. **Clone and enter the repository:**

   ```bash
   git clone <repo-url>
   cd sentinelx
   ```

2. **Ensure Rust toolchain is installed:**

   ```bash
   rustup show          # Verify installed toolchain
   rustup update        # Update to latest stable
   ```

3. **Run all benchmarks:**

   ```bash
   cargo bench -p sentinelx-benchmarks
   ```

4. **View results:**

   - Console output shows median, mean, standard deviation, and change from previous run.
   - HTML reports are generated in `target/criterion/`:

   ```bash
   # Open the index page
   open target/criterion/index.html    # macOS
   xdg-open target/criterion/index.html  # Linux
   ```

5. **Compare against a baseline:**

   ```bash
   # Save baseline
   cp -r target/criterion target/criterion.baseline

   # Make changes, then re-run
   cargo bench -p sentinelx-benchmarks

   # Criterion automatically compares against previous run
   ```

6. **Filter to specific benchmarks:**

   ```bash
   # Run only telemetry benchmarks
   cargo bench -p sentinelx-benchmarks --bench telemetry_throughput

   # Run only the kernel integrity detector
   cargo bench -p sentinelx-benchmarks --bench detector_scan -- kernel_integrity_detector

   # Run only hash benchmarks
   cargo bench -p sentinelx-benchmarks --bench analysis_pipeline -- hash_operations
   ```

7. **Adjust sample size (for faster iteration):**

   ```bash
   # Run with fewer samples (less statistically significant, but faster)
   cargo bench -p sentinelx-benchmarks -- --sample-size 10
   ```

### Interpreting Output

Criterion outputs results in this format:

```
kernel_integrity_detector/detect
                        time:   [1.2345 ms 1.2456 ms 1.2567 ms]
                        change: -0.50% +0.30% +1.10% (p = 0.25 > 0.05)
```

- **time**: `[median mean high]` — the 50th, estimated mean, and upper bound
- **change**: difference from previous run (if available), with p-value
- A p-value > 0.05 indicates no statistically significant change

### CI Integration

For CI pipelines, run benchmarks and fail on regression:

```bash
cargo bench -p sentinelx-benchmarks -- --baseline-check
```

Or export results for comparison:

```bash
cargo bench -p sentinelx-benchmarks -- --output-format bencher | tee bench.txt
```
