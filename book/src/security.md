# Security Documentation

## Threat Model

### Assets Protected

| Asset | Sensitivity | Description |
|-------|------------|-------------|
| Kernel integrity | Critical | Kernel text, sysctl, modules, hooks |
| Process table | Critical | Running process visibility and integrity |
| File system | High | Critical system files, binaries, configurations |
| Network state | High | Active connections, routing, DNS |
| Memory regions | Critical | Kernel and process memory integrity |
| Persistence mechanisms | High | Systemd, cron, init scripts, ld.so.preload |
| Telemetry data | Medium | Security events and system telemetry |
| Database | High | Threats, evidence, incidents, assessments |
| Configuration | High | Detection policies, response actions |
| Fleet communication | High | Agent-coordinator messages |

### Adversary Model

| Capability | Mitigation |
|-----------|-----------|
| **Kernel rootkit** | Kernel integrity engine, hook detection, module trust scoring |
| **DKOM** | Multi-source comparison: /proc vs kallsyms vs sysfs vs scheduler |
| **Process hiding** | Process discovery via multiple sources, task_struct walking |
| **Connection hiding** | Network discovery via multiple sources |
| **Persistence** | Persistence scanner covers all standard mechanisms |
| **Privilege escalation** | Capability monitoring, setuid/setgid detection |
| **Memory tampering** | Memory integrity checks, W^X enforcement |
| **File tampering** | File integrity monitoring, hash comparison |

### What SentinelX Does NOT Protect Against

- Physical access attacks
- Hardware-level implants (firmware, BMC)
- Side-channel attacks (Spectre, Meltdown)
- Denial-of-service against SentinelX itself
- Compromise of the SentinelX binary before deployment
- Attacks that compromise the system before SentinelX starts

## Privileged Operations

### Required Capabilities

| Capability | Required for | Provider |
|-----------|-------------|----------|
| `CAP_BPF` | eBPF program loading and map access | eBPF telemetry |
| `CAP_SYS_ADMIN` | fanotify, eBPF, mount operations | fanotify, eBPF |
| `CAP_PERFMON` | Performance monitoring, perf events | eBPF perf buffer |
| `CAP_AUDIT_WRITE` | Writing audit records | Audit telemetry |
| `CAP_AUDIT_CONTROL` | Configuring audit subsystem | Audit subsystem |
| `CAP_KILL` | Sending signals to processes | Response engine |
| `CAP_NET_ADMIN` | Network configuration queries | Netlink monitoring |
| `CAP_SYS_PTRACE` | Reading /proc for other processes | Process scanner |

### Graceful Degradation

| Missing capability | Degraded behavior |
|-------------------|-------------------|
| `CAP_BPF` | eBPF provider: `Degraded` status, tracepoint-only mode |
| `CAP_SYS_ADMIN` | fanotify provider: `Error` status; falls back to proc scanning |
| `CAP_AUDIT_WRITE` | Audit provider: `Error` status; no audit events |
| `CAP_PERFMON` | eBPF perf events: unavailable; kprobe programs still work |
| All capabilities | CLI mode only; no real-time telemetry; pipeline runs with /proc access |

The pipeline can run with only read access to `/proc` and `/sys`. Telemetry providers require additional capabilities for real-time event streaming.

### systemd Capability Configuration

```ini
[Service]
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_PERFMON CAP_AUDIT_WRITE CAP_AUDIT_CONTROL CAP_KILL CAP_NET_ADMIN
```

## unsafe Code Audit Summary

SentinelX minimizes unsafe Rust usage. All unsafe blocks are:

- Audited and documented
- Contained in well-defined boundaries (eBPF, /proc parsing, raw pointers)
- Verified with Miri where possible
- Subject to code review for every change

## TLS Configuration

### API TLS

```toml
[api]
tls_enabled = true
```

### Fleet Transport TLS

- TLS via `tokio-rustls` and `rustls`
- Protocol version negotiation on connect
- Gzip compression for payloads > 1KB
- Message acknowledgement for critical message types

## Database Security

- SQL injection prevention via sqlx parameterized queries
- WAL journal mode for data integrity
- File permissions: `640` on database file
- Owner: `sentinelx:sentinelx` system user
- Encryption at rest recommended via filesystem-level encryption (LUKS/dm-crypt)

## Network Security

- API bind address configurable (default `127.0.0.1`)
- CORS restrictions on API access
- Fleet transport uses mTLS for mutual authentication
- Firewall rules recommended for ports 8443 and 8543

## Reporting Vulnerabilities

Report security vulnerabilities to security@sentinelx.dev. Do not open public GitHub issues for security vulnerabilities.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

## Security Update Policy

- Critical vulnerabilities: Patched within 48 hours
- High severity: Patched within 1 week
- Medium severity: Patched in next release
- Low severity: Addressed as time permits
