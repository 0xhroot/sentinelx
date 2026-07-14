# Frequently Asked Questions

## General

### What is SentinelX?

SentinelX is an enterprise Linux runtime integrity and rootkit detection platform built in Rust. It detects kernel rootkits, hidden processes, hidden modules, hidden connections, syscall hooks, memory tampering, and persistence mechanisms.

### What operating systems are supported?

SentinelX supports **Linux only**. It requires Linux kernel 5.8+ for full eBPF features. There is no support for macOS or Windows.

### Is SentinelX free?

Yes. SentinelX is open-source under the GPL-3.0-or-later license.

### What are the minimum hardware requirements?

- 1 CPU core (2+ recommended)
- 128 MB RAM (256 MB recommended)
- 100 MB disk (1 GB+ recommended)

## Installation and Configuration

### Do I need root privileges?

Yes, for full functionality. SentinelX requires root or specific Linux capabilities (`CAP_BPF`, `CAP_SYS_ADMIN`, etc.) for kernel-level monitoring. Running without root limits detection to userspace-only mode.

### Can I run SentinelX without eBPF?

Yes. SentinelX degrades gracefully without eBPF. It falls back to `/proc` parsing, sysctl inspection, and file integrity checks. Detection fidelity is reduced but core functionality remains.

### Where is the configuration file?

The default path is `~/.config/sentinelx/sentinelx.toml`. Specify a custom path with `--config /path/to/sentinelx.toml`. For system-wide deployment, use `/etc/sentinelx/sentinelx.toml`.

### How do I enable TLS?

Set `tls_enabled = true` in the `[api]` section and provide certificate files. See [Deployment](deployment.md) for certificate generation instructions.

## Scanning and Detection

### How often should I scan?

The default scan interval is 60 seconds. For high-security environments, reduce to 30 seconds. For lower resource usage, increase to 120+ seconds.

### What does a full scan detect?

A full scan runs all 7 discovery providers and checks for: kernel integrity violations, hidden processes, hidden modules, hidden connections, syscall hooks, memory tampering, file integrity issues, and persistence mechanisms.

### What is the detection accuracy?

SentinelX uses multi-source evidence correlation to minimize false positives. Each detection is assessed with trust, integrity, risk, and reputation scores (0–100) with confidence levels (0.0–1.0).

### Does SentinelX support MITRE ATT&CK mapping?

Yes. SentinelX maps detections to MITRE ATT&CK techniques including T1014 (Rootkit), T1055 (Memory Tampering), T1543 (Persistence), T1068 (Privilege Escalation), and T1571 (Network C2).

## Performance

### How much CPU does SentinelX use?

Less than 3% under normal operation. Idle usage is under 2%. The telemetry bus handles up to 50,000 events/second.

### How much memory does SentinelX use?

Under 100 MB idle, under 150 MB during scanning. Configurable via `max_memory_mb` setting.

### How long does a full scan take?

Under 2 seconds for the complete pipeline (discovery, metadata, assessment, evidence).

## Fleet Management

### What is fleet management?

Fleet management allows central coordination of multiple SentinelX agents across different hosts. A coordinator manages agent registration, policy distribution, health monitoring, and remote actions.

### Is fleet management production-ready?

Fleet management is currently in **alpha** status. It is recommended for testing and evaluation, not production multi-host deployments.

### How do agents communicate with the coordinator?

Agents communicate via TCP with optional TLS encryption. The transport layer uses length-prefixed framing, gzip compression, and message acknowledgement for reliability.

## Troubleshooting

### SentinelX won't start

Check that:
1. You're running as root or with appropriate capabilities
2. SQLite database directory is writable
3. Configuration file is valid TOML
4. Required kernel features are available (`uname -r` shows 5.8+)

### eBPF provider shows "Degraded"

This means eBPF features are partially unavailable. Common causes:
- Missing `CAP_BPF` capability
- Kernel older than 5.8
- BTF not available (`/sys/kernel/btf/vmlinux` missing)

### High CPU usage

- Increase `scan_interval_seconds`
- Reduce `max_events_per_second` in `[ebpf]`
- Check for too many telemetry providers running

### Database is growing too large

- Reduce `retention_days` in `[storage]`
- Reduce `max_events` in `[storage]`
- Run `PRAGMA wal_checkpoint(TRUNCATE)` to reclaim space

### API returns CORS errors

Update `cors_origins` in the `[api]` section to include your dashboard URL:

```toml
[api]
cors_origins = ["http://localhost:3000", "https://sentinelx.example.com"]
```
