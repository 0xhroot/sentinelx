# SentinelX Security Policy

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Privileged Operations](#2-privileged-operations)
3. [unsafe Code Audit Summary](#3-unsafe-code-audit-summary)
4. [TLS Configuration](#4-tls-configuration)
5. [Certificate Management](#5-certificate-management)
6. [Database Security](#6-database-security)
7. [Network Security](#7-network-security)
8. [Reporting Vulnerabilities](#8-reporting-vulnerabilities)
9. [Security Update Policy](#9-security-update-policy)

---

## 1. Threat Model

### Assets protected

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

### Adversary model

SentinelX assumes the following adversary capabilities:

| Capability | Description | Mitigation |
|-----------|-------------|-----------|
| **Kernel rootkit** | Load malicious kernel modules, hook syscalls, modify kernel data structures | Kernel integrity engine, hook detection, module trust scoring |
| **DKOM (Direct Kernel Object Manipulation)** | Hide processes/modules by unlinking from kernel lists | Multi-source comparison: /proc vs kallsyms vs sysfs vs scheduler |
| **Process hiding** | Remove processes from /proc visibility | Process discovery via multiple sources, task_struct walking |
| **Connection hiding** | Remove network connections from /proc/net | Network discovery via multiple sources |
| **Persistence** | Establish boot persistence via systemd, cron, init scripts | Persistence scanner covers all standard mechanisms |
| **Privilege escalation** | Exploit vulnerabilities to gain root | Capability monitoring, setuid/setgid detection |
| **Memory tampering** | Modify process or kernel memory | Memory integrity checks, W^X enforcement |
| **File tampering** | Modify critical system binaries | File integrity monitoring, hash comparison |
| **Evasion** | Modify SentinelX itself or its data | Immutable evidence, audit logging |

### What SentinelX does NOT protect against

- Physical access attacks
- Hardware-level implants (firmware, BMC)
- Side-channel attacks (Spectre, Meltdown)
- Denial-of-service against SentinelX itself
- Compromise of the SentinelX binary before deployment
- Attacks that compromise the system before SentinelX starts

---

## 2. Privileged Operations

SentinelX requires root privileges or specific Linux capabilities for its core functionality.

### Required capabilities

| Capability | Required for | Provider |
|-----------|-------------|----------|
| `CAP_BPF` | eBPF program loading and map access | eBPF telemetry provider |
| `CAP_SYS_ADMIN` | fanotify filesystem monitoring, eBPF, mount operations | fanotify provider, eBPF |
| `CAP_PERFMON` | Performance monitoring, perf events | eBPF perf buffer |
| `CAP_AUDIT_WRITE` | Writing audit records | Audit telemetry provider |
| `CAP_AUDIT_CONTROL` | Configuring audit subsystem | Audit subsystem control |
| `CAP_KILL` | Sending signals to processes | Response engine (kill process) |
| `CAP_NET_ADMIN` | Network configuration queries | Netlink monitoring |
| `CAP_SYS_PTRACE` | Reading /proc entries for other processes | Process scanner |

### Running without full privileges

SentinelX is designed for graceful degradation:

| Missing capability | Degraded behavior |
|-------------------|-------------------|
| `CAP_BPF` | eBPF provider: `Degraded` status, tracepoint-only mode |
| `CAP_SYS_ADMIN` | fanotify provider: `Error` status; falls back to proc scanning |
| `CAP_AUDIT_WRITE` | Audit provider: `Error` status; no audit events |
| `CAP_PERFMON` | eBPF perf events: unavailable; kprobe programs still work |
| All capabilities | CLI mode only; no real-time telemetry; pipeline runs with /proc access |

The pipeline (Discovery → Metadata → Assessment → Evidence) can run with only read access to `/proc` and `/sys`. Telemetry providers require additional capabilities for real-time event streaming.

### systemd capability configuration

```ini
[Service]
# Grant only the capabilities SentinelX needs
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_PERFMON CAP_AUDIT_WRITE CAP_AUDIT_CONTROL CAP_KILL CAP_NET_ADMIN
```

---

## 3. unsafe Code Audit Summary

### Overview

SentinelX contains **52 `unsafe` code blocks** across the codebase. All are confined to Linux FFI (Foreign Function Interface) crates that interact directly with kernel interfaces.

### Distribution by crate

| Crate | unsafe blocks | Purpose |
|-------|--------------|---------|
| `sentinelx-netlink` | 20 | AF_NETLINK socket operations, NLA parsing, Ifinfomsg/Rtmsg parsing |
| `sentinelx-audit` | 18 | NETLINK_AUDIT socket, audit record parsing, uname() |
| `sentinelx-fanotify` | 8 | fanotify_init/mark syscalls, file descriptor operations, read() |
| `sentinelx-ebpf` | 5 | eBPF event parsing, capability detection (capget), uname() |
| `sentinelx-telemetry` | 1 | Capability detection (capget syscall) |
| `sentinelx-process` | 1 | /proc file operations |

**Total: 52 unsafe blocks, 0 in application logic crates**

### Categories of unsafe usage

| Category | Count | Safety measure |
|----------|-------|---------------|
| **Syscall wrappers** (socket, bind, connect, read, recv) | 18 | Return values checked; errno set |
| **Memory reads** (ptr::read_unaligned, zeroed) | 14 | Size verified; alignment guaranteed by repr(C) structs |
| **File descriptor operations** (fcntl, close) | 6 | Non-blocking mode set; error codes checked |
| **Socket address initialization** (sockaddr_nl, sockaddr_in) | 8 | Zeroed before use; size validated |
| **uname()** for kernel version detection | 4 | Standard libc call; output buffer zeroed |
| **eBPF raw event parsing** | 2 | Size validated; repr(C) struct alignment |

### Safety guarantees

1. **All unsafe blocks are in Linux FFI crates** — no unsafe in application logic, pipeline, assessment, correlation, or response code
2. **Every unsafe block has a safety comment** explaining the invariant
3. **All system call return values are checked** — errors propagated as `Result`
4. **repr(C) structs** ensure correct memory layout for kernel data structures
5. **Buffer sizes are validated** before reading from sockets and files
6. **File descriptors are set to O_NONBLOCK** to prevent blocking the Tokio runtime
7. **No raw pointer arithmetic** — only `ptr::read_unaligned` for fixed-size struct reads

### Audit process

- All unsafe blocks should be reviewed during code changes
- `cargo clippy -- -D warnings` catches common unsafe misuse patterns
- The `unsafe` keyword is searched during CI to ensure no new unsafe blocks are added without review
- No unsafe code exists in the following crates: `common`, `config`, `core`, `assessment`, `database`, `detector`, `correlation`, `incident`, `threat`, `reporting`, `response`, `behavior`, `intelligence`, `fleet`, `backend`, `cli`, `evidence`, `rule_engine`, `timeline`, `forensics`

---

## 4. TLS Configuration

### API TLS

Enable TLS for the REST API in `sentinelx.toml`:

```toml
[api]
tls_enabled = true
```

When enabled, the API server uses `tokio-rustls` with `rustls` for TLS termination.

### Fleet transport TLS

The fleet transport layer supports optional TLS via `rustls`:

```rust
TransportConfig {
    tls: Some(TlsConfig {
        cert_path: "/etc/sentinelx/certs/server.pem".into(),
        key_path: "/etc/sentinelx/certs/server-key.pem".into(),
        ca_cert_path: "/etc/sentinelx/certs/ca.pem".into(),
    }),
    // ...
}
```

### TLS features

- **Library**: `rustls` (memory-safe TLS implementation, no OpenSSL dependency)
- **Certificate loading**: `rustls-pemfile` for PEM certificate and key parsing
- **Self-signed CA support**: Full CA chain verification
- **Protocol negotiation**: Version negotiation on connect
- **Wire format**: Length-prefixed framing with JSON payload

### TLS disabled (default)

TLS is disabled by default for development convenience. In production:

1. Enable API TLS if the API is exposed beyond localhost
2. Enable transport TLS for fleet communication over untrusted networks
3. Never transmit security-sensitive data (threats, evidence, telemetry) over unencrypted connections in production

---

## 5. Certificate Management

### Generating certificates

See [Deployment Guide - TLS/mTLS Configuration](DEPLOYMENT.md#3-tlsmtls-configuration) for certificate generation commands.

### Certificate file permissions

```bash
# Private keys: readable only by sentinelx user
sudo chmod 600 /etc/sentinelx/certs/*-key.pem
sudo chown sentinelx:sentinelx /etc/sentinelx/certs/*-key.pem

# Certificates: readable by sentinelx user
sudo chmod 644 /etc/sentinelx/certs/*.pem
sudo chown sentinelx:sentinelx /etc/sentinelx/certs/*.pem
```

### Certificate rotation

SentinelX loads certificates at startup. To rotate:

1. Generate new certificate and key
2. Replace files in `/etc/sentinelx/certs/`
3. Restart the SentinelX service

```bash
sudo systemctl restart sentinelx
```

### mTLS (mutual TLS)

For mTLS, configure the server to request client certificates:

```rust
ServerConfig::builder()
    .with_client_cert_verifier(AllowAnyAuthenticatedClient::new(root_store))
    .with_single_cert(certs, key)?
```

This ensures only agents with valid client certificates can connect to the coordinator.

---

## 6. Database Security

### SQLite security features

- **WAL journal mode**: Write-ahead logging for crash recovery
- **Auto-vacuum (Full)**: Automatically reclaims space from deleted records
- **Busy timeout (5s)**: Prevents concurrent access errors
- **Connection pool (5 max)**: Limits concurrent connections

### File permissions

```bash
# Database directory
sudo chown sentinelx:sentinelx /var/lib/sentinelx
sudo chmod 700 /var/lib/sentinelx

# Database file
sudo chmod 600 /var/lib/sentinelx/sentinelx.db
sudo chown sentinelx:sentinelx /var/lib/sentinelx/sentinelx.db
```

### Encryption at rest

SentinelX does not provide built-in database encryption. For encrypted storage:

- Use LUKS full-disk encryption on the host
- Use an encrypted filesystem for `/var/lib/sentinelx/`
- Consider SQLCipher integration as a future enhancement

### Data classification

| Table | Sensitivity | Contents |
|-------|------------|----------|
| `threats` | High | Detected threats with evidence |
| `evidence` | High | Forensic evidence records |
| `incidents` | High | Security incidents |
| `threat_decisions` | High | Threat engine decisions |
| `assessment_results` | Medium | Object assessment scores |
| `telemetry_events` | Medium | System telemetry |
| `behavior_profiles` | Medium | Behavioral profiles |
| `fleet_agents` | Medium | Agent metadata |
| `remote_actions` | High | Remote action audit trail |
| `events` | Medium | Security events |

### Data retention

Configure automatic cleanup:

```toml
[storage]
retention_days = 90
max_events = 1000000
```

Records older than `retention_days` are cleaned up by the `expire_old()` method on repositories.

---

## 7. Network Security

### API network

- Default binding: `127.0.0.1:8443` (localhost only)
- For fleet deployment: `0.0.0.0:8443` with firewall rules restricting source IPs
- CORS origins configurable in `sentinelx.toml`

### Fleet transport network

- Default: TCP without encryption (development only)
- Production: TLS via `tokio-rustls`
- Length-prefixed framing with JSON payload
- Maximum message size: 16 MB
- Gzip compression for payloads > 1 KB

### Telemetry network

All telemetry providers use local kernel interfaces only:

| Provider | Interface | Requires network? |
|----------|-----------|-------------------|
| eBPF | Kernel maps, ring buffers | No |
| fanotify | Filesystem monitoring | No |
| netlink | AF_NETLINK (local) | No |
| audit | NETLINK_AUDIT (local) | No |
| proc scanner | /proc filesystem | No |

No telemetry data is transmitted over the network by default. Fleet communication transmits aggregated telemetry stats, not raw events.

### Message protocol security

| Feature | Implementation |
|---------|---------------|
| **Framing** | 4-byte LE length prefix + JSON payload |
| **Version negotiation** | Protocol version checked on connect |
| **Message acknowledgement** | Critical messages (Registration, Policy, RemoteAction) require ack |
| **Replay protection** | Timestamp-based message validation |
| **Rate limiting** | Configurable max agents and heartbeat intervals |
| **Compression** | Gzip for payloads > 1 KB (optional) |

---

## 8. Reporting Vulnerabilities

### Reporting process

If you discover a security vulnerability in SentinelX:

1. **Do not** open a public GitHub issue
2. **Do not** discuss the vulnerability in public forums
3. Email security reports to: `security@sentinelx.example.com`
4. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### Response timeline

| Phase | Timeline |
|-------|---------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 1 week |
| Fix development | Within 2 weeks (critical) / 30 days (other) |
| Public disclosure | After fix is released |

### Scope

The following are in scope for security reports:

- Remote code execution
- Privilege escalation beyond intended capabilities
- Bypass of detection mechanisms
- Data leakage of security-sensitive information
- Authentication/authorization bypass in fleet communication
- unsafe code misuse leading to memory corruption
- Denial of service against the detection pipeline

The following are out of scope:

- Physical attacks
- Social engineering
- Issues in upstream dependencies (report to the dependency)
- Issues requiring pre-existing root access

### Recognition

Security researchers who report valid vulnerabilities will be credited in the release notes (unless they prefer to remain anonymous).

---

## 9. Security Update Policy

### Update frequency

- **Critical security fixes**: Released as soon as ready (within 1–2 weeks)
- **High-severity fixes**: Included in the next regular release
- **Medium/Low-severity fixes**: Included in the next major release

### Update mechanism

```bash
# Rebuild from source
cd sentinelx
git pull
cargo build --release

# Replace binaries
sudo cp target/release/sentinelx-backend /usr/local/bin/
sudo cp target/release/sentinelx-cli /usr/local/bin/

# Restart
sudo systemctl restart sentinelx
```

### Security changelog

Security-relevant changes are tagged with `[SECURITY]` in the changelog:

```
## [0.1.1] - 2026-07-20

### Security

- [SECURITY] Fixed potential buffer overflow in netlink message parsing
- [SECURITY] Updated rustls to address CVE-2026-XXXX
```

### Dependency updates

SentinelX uses `cargo audit` to check for known vulnerabilities in dependencies:

```bash
cargo install cargo-audit
cargo audit
```

### Supply chain security

- **LTO enabled**: Reduces attack surface by eliminating dead code
- **Single codegen unit**: Deterministic builds
- **Stripped binaries**: Removes debug symbols from release builds
- **Panic = abort**: Eliminates unwind tables (reduces binary size and attack surface)
- **Minimal unsafe**: All unsafe code confined to Linux FFI crates with documented safety invariants
