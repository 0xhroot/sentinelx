# Developer Guide

## Building from Source

### Prerequisites

- Rust 1.75+
- Node.js 18+ (for dashboard)
- Linux kernel 5.8+ (for eBPF features)
- Build essentials (`gcc`, `make`, `pkg-config`, Linux headers, SQLite dev)

### Build

```bash
git clone https://github.com/sentinelx/sentinelx.git
cd sentinelx

# Build all Rust crates
cargo build --release

# Build the dashboard
cd apps/dashboard
npm install
npm run build
```

### Release Profile

```toml
[profile.release]
lto = true
codegen-units = 1
opt-level = 3
strip = true
panic = "abort"
```

## Project Structure

```
sentinelx/
├── crates/              # Core Rust libraries (34 crates)
│   ├── common/          # Shared types, errors, traits
│   ├── config/          # Configuration management
│   ├── core/            # Pipeline interfaces
│   ├── assessment/      # Numeric scoring engine
│   ├── database/        # SQLite storage
│   ├── telemetry/       # Metrics and tracing
│   ├── kernel/          # Kernel integrity monitoring
│   ├── process/         # Process scanning
│   ├── network/         # Network connection scanning
│   ├── module/          # Kernel module detection
│   ├── memory/          # Memory integrity
│   ├── integrity/       # File integrity monitoring
│   ├── persistence/     # Persistence mechanism scanning
│   ├── forensics/       # Forensic evidence collection
│   ├── correlation/     # Relationship graph
│   ├── incident/        # Security incident management
│   ├── threat/          # Threat engine
│   ├── reporting/       # Report generation
│   ├── response/        # Automated response
│   ├── rule-engine/     # Custom detection rules
│   ├── behavior/        # Behavioral profiling
│   ├── intelligence/    # Threat intelligence
│   ├── ebpf/            # eBPF telemetry provider
│   ├── fanotify/        # fanotify filesystem monitoring
│   ├── netlink/         # Netlink monitoring
│   ├── audit/           # Audit subsystem telemetry
│   ├── transport/       # Secure message transport
│   ├── agent/           # Fleet endpoint agent
│   ├── coordinator/     # Fleet coordinator
│   ├── fleet/           # Fleet orchestration
│   └── benchmarks/      # Criterion benchmarks
├── backend/             # Axum REST API server
├── apps/
│   ├── cli/             # Command-line interface
│   └── dashboard/       # React + TypeScript frontend
├── tests/               # Integration tests
├── docs/                # Documentation
└── scripts/             # Build and deployment scripts
```

## Testing

### Run All Tests

```bash
cargo test
```

### Run Specific Crate Tests

```bash
cargo test -p sentinelx-assessment
cargo test -p sentinelx-correlation
```

### Integration Tests

```bash
cargo test --test integration
```

### Benchmarks

```bash
cargo bench -p sentinelx-benchmarks
```

Criterion benchmarks cover:

- Bus publish throughput at different channel capacities
- Bus subscribe/receive throughput
- Event creation overhead per event type
- MPSC channel throughput as baseline

## Linting and Formatting

```bash
# Check formatting
cargo fmt --check

# Apply formatting
cargo fmt

# Run clippy
cargo clippy -- -D warnings
```

## Code Conventions

### Rust Style

- Edition 2021 with MSRV 1.75
- Use `#[tokio::main]` for async entry points
- Prefer `Arc<T>` for shared state
- Use `async RwLock` for concurrent access
- Structured logging via `tracing` crate
- Errors via `thiserror` with `anyhow` in binaries

### Pipeline Conventions

- Implement `DiscoveryProvider` for new discovery sources
- Implement `MetadataCollector` for new enrichment stages
- Implement `ObjectAssessor` for new assessment dimensions
- All providers/collectors/assessors are fault-tolerant (logged and skipped on failure)

### Configuration

- TOML-based configuration via `sentinelx-config`
- All settings have sensible defaults
- Validation via serde deserialize

### Database

- SQLite via sqlx with compile-time checked queries
- WAL journal mode
- 18 repository implementations for different data types
- Parameterized queries only (no string interpolation)

## Architecture Patterns

### Evidence-Driven Pipeline

```
Discovery → Metadata → Assessment → Evidence
```

Each phase is fault-tolerant: individual component failures are logged and do not halt the pipeline.

### Telemetry Event Flow

```
Kernel → Provider (eBPF/fanotify/netlink/audit) → EventBus → Normalizer → Pipeline
```

### Response Safety

All response actions support:

- **Dry-run mode**: Log actions without executing
- **Rate limiting**: Prevent runaway response loops
- **Audit logging**: Every action recorded
- **Severity thresholds**: Only respond to threats above configured severity

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Run `cargo fmt` and `cargo clippy -- -D warnings`
5. Submit a pull request

### Commit Messages

Follow conventional commit format:

```
feat: add new persistence detection for snap packages
fix: resolve race condition in concurrent process scanning
docs: update API reference for new endpoints
```
