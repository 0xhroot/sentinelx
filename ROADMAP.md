# Roadmap

This document outlines the planned development direction for SentinelX.

## v1.1 — Database, Web UI, and Automatic Updates

**Target:** Q4 2026

### PostgreSQL Support
- Full PostgreSQL backend via sqlx
- Connection pooling with configurable pool sizes
- Migration system for schema upgrades
- SQLite-to-PostgreSQL data migration tool
- Dual-mode support (SQLite for single-node, PostgreSQL for fleet)

### Web-Based Management UI
- React-based management dashboard with authentication
- Real-time alert dashboard with filtering and search
- Host fleet visualization with health status
- Configuration management via browser
- User and role management (RBAC)
- Audit log viewer

### Automatic Rule Updates
- Built-in rule update mechanism with configurable intervals
- Update sources: local files, HTTP endpoints, Git repositories
- Version tracking for all rule types (detection rules, IoCs, YARA, Sigma, CVE)
- Rollback support for failed updates
- Notification system for available updates

### MITRE ATT&CK Expansion
- Expand coverage to 20+ techniques
- T1003 (Credential Dumping) detection
- T1053 (Scheduled Task/Job) detection
- T1070 (Indicator Removal) detection
- T1078 (Valid Accounts) detection
- T1105 (Ingress Tool Transfer) detection

## v1.2 — macOS and Windows Support

**Target:** Q2 2027

### macOS Support
- Endpoint Security Framework integration
- System Integrity Protection (SIP) compatibility
- Kernel extension replacement with EndpointSecurity
- Process and file monitoring via ES events
- Network monitoring via Network Extension framework
- Homebrew formula for distribution

### Windows Support
- Windows Event Log integration
- ETW (Event Tracing for Windows) kernel sensors
- Process and file monitoring via Minifilter
- Network monitoring via WFP (Windows Filtering Platform)
- Windows Service deployment model
- Chocolatey and winget packages

### Cross-Platform Abstraction
- Platform-agnostic detection trait system
- Unified CLI across all platforms
- Platform-specific backends with shared frontend
- Cross-compilation support in CI for all platforms

## v1.3 — Machine Learning and Cloud Deployment

**Target:** Q4 2027

### Machine Learning Detection
- Anomaly detection models trained on system behavior baselines
- Supervised classification for known malware patterns
- Unsupervised clustering for zero-day detection
- Feature extraction from telemetry events
- Model versioning and A/B testing framework
- Offline inference (no cloud dependency required)

### Cloud Deployment
- Kubernetes Helm chart for cloud deployment
- Managed cloud service offering (SentinelX Cloud)
- Multi-tenant architecture with tenant isolation
- Cloud-native storage backends (S3, GCS)
- Centralized management plane for cloud fleets
- Integration with cloud security posture management (CSPM)

### Advanced Analytics
- Attack graph visualization
- Kill chain reconstruction
- Lateral movement detection
- Data exfiltration pattern analysis
- Compromised credential detection

## v2.0 — Multi-Tenant, API v2, and Plugin System

**Target:** Q2 2028

### Multi-Tenant Architecture
- Full tenant isolation with separate databases
- Tenant-scoped policies and detection rules
- Resource quotas and rate limiting per tenant
- Cross-tenant threat intelligence sharing
- Tenant administration portal

### API v2
- gRPC API alongside REST
- WebSocket support for real-time event streaming
- Streaming API for large result sets
- GraphQL query interface
- API versioning with deprecation policy
- SDK generation for Go, Python, and JavaScript

### Plugin System
- Dynamic plugin loading (shared libraries)
- Plugin marketplace for community contributions
- Sandboxed plugin execution
- Plugin API for detection, response, and telemetry
- Custom detector plugin interface
- Custom response action plugin interface

### Community Features
- Public rule repository with contribution workflow
- Community detection rule sharing
- Threat intelligence sharing federation
- Plugin developer documentation and tooling
- Certification program for detection rules
