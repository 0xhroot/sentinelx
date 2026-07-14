# Changelog

All notable changes to SentinelX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-15

### Added

- **Phase 1 — Evidence-Driven Pipeline Architecture**
  - New evidence-first architecture replacing detector-driven pipeline
  - `DiscoveryProvider`, `MetadataCollector`, and `ObjectAssessor` trait system
  - Unified pipeline coordinator with structured evidence flow
  - Core domain objects for processes, modules, network connections, and memory regions
  - `sentinelx-common` crate with shared types, errors, and traits
  - `sentinelx-config` crate with TOML-based configuration management
  - `sentinelx-database` crate with SQLite storage engine
  - `sentinelx-telemetry` crate for metrics and structured tracing
  - `sentinelx-core` crate orchestrating the full detection pipeline

- **Phase 2 — Native Detector Migration**
  - Migrated all 7 adaptable detectors to native provider implementations
  - Kernel integrity monitoring via `sentinelx-kernel`
  - Hidden process detection via `sentinelx-process`
  - Hidden module detection via `sentinelx-module`
  - Hidden connection detection via `sentinelx-network`
  - Memory integrity monitoring via `sentinelx-memory`
  - File integrity monitoring via `sentinelx-integrity`
  - Persistence mechanism scanning via `sentinelx-persistence`
  - Removed legacy adapter subsystem and all old detector code

- **Phase 3 — Central Assessment Engine**
  - `sentinelx-assessment` crate with unified numeric-score assessment
  - Configurable scoring with trust, integrity, risk, and reputation dimensions (0–100)
  - Confidence scoring (0.0–1.0) for all assessments
  - TOML-driven scoring configuration with factor-based weights
  - In-memory assessment store with async RwLock
  - Assessor implementations for processes, modules, network, and services

- **Phase 4 — Correlation Engine**
  - `sentinelx-correlation` crate with relationship graph from evidence
  - Configurable TOML rules for multi-indicator attack pattern detection
  - In-memory graph engine for evidence correlation

- **Phase 5 — Incident and Threat Engines**
  - `sentinelx-incident` crate for security incident lifecycle management
  - Status tracking, severity levels, evidence attachment, and attack chain recording
  - MITRE ATT&CK technique mapping for incidents
  - `sentinelx-threat` crate with weighted risk scoring algorithm
  - Threat decisions with severity, priority, and response recommendations

- **Phase 6 — Automated Response Engine**
  - `sentinelx-response` crate with configurable response actions
  - Actions: alert, kill process, block connection, quarantine file
  - Rule-based response triggers with severity thresholds
  - `sentinelx-evidence` crate for structured evidence collection and storage
  - `sentinelx-rule-engine` crate for configurable detection rules

- **Phase 7 — Real-Time Telemetry Engine**
  - Event-driven architecture replacing polling-based detection
  - `TelemetryProvider` trait system for kernel-level event sources
  - `EventNormalizer` for unified internal event format
  - `TelemetryBus` with tokio channels, broadcast, and backpressure
  - Async pipeline integration with existing discovery and assessment stages

- **Phase 8 — Behavior Engine and Threat Intelligence**
  - `sentinelx-behavior` crate for per-object behavioral profiling
  - 11 behavior categories including process ancestry, exec frequency, and network activity
  - 7-factor weighted behavior scoring with configurable rules
  - 6 default behavior detection rules
  - `sentinelx-intelligence` crate with offline-first threat intelligence
  - IoC (Indicator of Compromise) database and matching
  - MITRE ATT&CK technique and tactic mapping
  - YARA rule matching engine
  - Sigma rule support
  - CVE tracking and vulnerability matching

- **Phase 9 — Native eBPF Kernel Sensor Architecture**
  - `sentinelx-ebpf` crate with Aya-based eBPF program management
  - Kernel-level instrumentation replacing stub telemetry providers
  - `sentinelx-fanotify` crate for file access monitoring
  - `sentinelx-netlink` crate for network event monitoring
  - `sentinelx-audit` crate for audit socket integration
  - Graceful degradation when eBPF is unavailable
  - High-fidelity event detection with minimal performance impact

- **Phase 10 — Fleet Management**
  - `sentinelx-transport` crate for agent-coordinator communication
  - `sentinelx-agent` crate for distributed agent management
  - `sentinelx-coordinator` crate for central fleet coordination
  - `sentinelx-fleet` crate for multi-host security platform
  - Policy distribution and heartbeat monitoring
  - Remote response capabilities across fleet

- **Phase 11 — Applications, API, and Packaging**
  - `sentinelx-cli` command-line interface with full scan, monitor, and forensic commands
  - `sentinelx-backend` Axum REST API with OpenAPI documentation
  - React TypeScript dashboard with dark theme
  - Docker multi-stage build with optimized runtime image
  - Systemd service unit for daemon management
  - Arch Linux PKGBUILD and install/uninstall scripts
  - Configuration file with sensible defaults
  - Integration test framework

### Changed

- Migrated from detector-driven to evidence-driven pipeline architecture
- Replaced all legacy detector implementations with native provider triples
- Unified assessment scoring across all object types
- Converted from synchronous polling to async event-driven telemetry
- Upgraded to Rust 2021 edition with MSRV 1.75
- Migrated database layer to sqlx 0.8 with SQLite backend
- Upgraded web framework to Axum 0.7 with tower-http middleware
- Upgraded CLI framework to clap 4 with derive macros

### Fixed

- Eliminated false positives from single-source detection by requiring multi-source evidence
- Resolved race conditions in concurrent process scanning with async RwLock
- Fixed memory leak in long-running telemetry event bus
- Corrected MITRE ATT&CK technique mapping for persistence mechanisms
- Fixed kernel module signature verification edge cases

### Security

- All kernel-level operations use minimal unsafe Rust
- Input validation on all external data sources
- No panics in production code paths
- Graceful error handling throughout the pipeline
- Least privilege principle for all system calls
- SQL injection prevention via sqlx parameterized queries
- TLS support for API endpoints (configurable)
- CORS restrictions on API access

### Known Issues

- Requires root privileges for kernel-level monitoring features
- Linux-only support (no macOS or Windows)
- SQLite only — no PostgreSQL or MySQL support yet
- Single-node telemetry (fleet management is alpha quality)
- eBPF features require kernel 5.8 or later
- No web-based management UI yet (dashboard is API-only)
- Limited MITRE ATT&CK technique coverage (8 techniques in v1.0)
- No automatic rule update mechanism
