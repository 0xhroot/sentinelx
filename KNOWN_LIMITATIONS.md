# Known Limitations

This document describes the known limitations of SentinelX v1.0.0.

## Root Privileges Required

SentinelX requires root privileges (or `CAP_SYS_ADMIN` / `CAP_NET_ADMIN` capabilities) for kernel-level monitoring features including:

- eBPF program loading and management
- Kernel memory inspection
- fanotify file system monitoring
- Netlink socket network monitoring
- Audit socket system call monitoring
- `/proc` and `/sys` deep inspection

Running without root limits SentinelX to userspace-only detection, which significantly reduces detection coverage.

## Linux-Only Support

SentinelX is designed exclusively for Linux systems. There is no support for:

- macOS (no eBPF/Aya support, different kernel interfaces)
- Windows (no compatible kernel APIs)

The entire kernel monitoring stack (eBPF, fanotify, netlink, audit sockets) is Linux-specific.

## SQLite Only

SentinelX currently uses SQLite as its sole database backend via sqlx. There is no support for:

- PostgreSQL
- MySQL / MariaDB
- Other relational databases

SQLite is suitable for single-node deployments but has limitations for high-throughput logging and multi-node fleet scenarios. See the [ROADMAP](ROADMAP.md) for planned database support.

## Single-Node Telemetry (Fleet is Alpha)

The fleet management system is in alpha status. Current limitations:

- Agent-coordinator communication is experimental
- Policy distribution may not propagate to all agents reliably
- Heartbeat monitoring has limited timeout configuration
- Remote response actions are best-effort, not guaranteed
- No TLS for inter-node communication yet
- No mutual authentication between agents and coordinator

For production multi-host deployments, fleet features should be considered unstable.

## eBPF Requires Kernel 5.8+

SentinelX's eBPF-based kernel sensors require Linux kernel 5.8 or later for:

- BPF ring buffer support
- eBPF LSM (Linux Security Module) hooks
- Sufficient BPF helper functions

On kernels older than 5.8, SentinelX degrades gracefully to userspace-only detection using `/proc` parsing, sysctl inspection, and file integrity checks. This significantly reduces detection fidelity.

## No Web-Based Management UI

The React dashboard included in the repository is currently API-only and does not provide:

- A web-based management interface for configuring SentinelX
- User authentication or role-based access control
- Real-time alert dashboards
- Host fleet visualization

All management is performed via the CLI (`sentinelx-cli`) or REST API (`sentinelx-backend`).

## Limited MITRE ATT&CK Coverage

SentinelX v1.0.0 maps detections to 8 MITRE ATT&CK techniques:

| Technique | Name |
|-----------|------|
| T1014 | Rootkit (kernel text, hidden processes, hidden modules, hooks) |
| T1055 | Memory Tampering |
| T1543 | Persistence (systemd, cron, init scripts) |
| T1068 | Privilege Escalation (capability abuse) |
| T1571 | Network C2 (hidden connections) |

Many ATT&CK techniques are not yet covered, including:

- T1003 (Credential Dumping)
- T1005 (Data from Local System)
- T1021 (Remote Services)
- T1053 (Scheduled Task/Job)
- T1057 (Process Discovery)
- T1070 (Indicator Removal)
- T1078 (Valid Accounts)
- T1105 (Ingress Tool Transfer)
- T1484 (Domain Policy Modification)

See the [ROADMAP](ROADMAP.md) for planned ATT&CK coverage expansion.

## No Automatic Rule Updates

SentinelX does not currently support automatic updates for:

- Detection rules
- IoC databases
- YARA rules
- Sigma rules
- CVE databases
- Behavioral profiles

All rule updates require manual intervention:

1. Pull updated rules from a repository
2. Restart SentinelX or reload configuration
3. Verify rule versions

This means threat intelligence may become stale between manual updates.

## Performance Considerations

- Full eBPF telemetry may increase CPU usage under heavy system load
- Fleet management adds network overhead proportional to agent count
- SQLite write performance may bottleneck under extreme event rates (>10,000 events/sec)
- Memory usage may increase with large IoC databases
