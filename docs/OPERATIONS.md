# SentinelX Operations Manual

## Table of Contents

1. [Day-to-Day Operations](#1-day-to-day-operations)
2. [Monitoring and Alerting](#2-monitoring-and-alerting)
3. [Log Management](#3-log-management)
4. [Backup and Recovery](#4-backup-and-recovery)
5. [Performance Tuning](#5-performance-tuning)
6. [Capacity Planning](#6-capacity-planning)
7. [Troubleshooting Guide](#7-troubleshooting-guide)
8. [Common Issues and Solutions](#8-common-issues-and-solutions)

---

## 1. Day-to-Day Operations

### Health checks

```bash
# API health endpoint
curl -s http://localhost:8443/api/health | jq .

# System status
curl -s http://localhost:8443/api/status | jq .

# Telemetry provider status
curl -s http://localhost:8443/api/telemetry/providers | jq .

# Telemetry bus statistics
curl -s http://localhost:8443/api/telemetry/stats | jq .

# Provider health (detailed with uptime and drop rates)
curl -s http://localhost:8443/api/telemetry/providers/health | jq .

# Provider kernel latency
curl -s http://localhost:8443/api/telemetry/providers/latency | jq .

# Fleet overview
curl -s http://localhost:8443/api/fleet | jq .
```

### CLI health checks

```bash
sentinelx-cli status            # System status, metrics, detector info
sentinelx-cli telemetry         # Telemetry engine status and config
sentinelx-cli providers         # Registered telemetry providers
sentinelx-cli providers-health  # Detailed provider health diagnostics
sentinelx-cli ebpf              # eBPF kernel sensor status and capabilities
sentinelx-cli fleet             # Fleet overview with agent counts
```

### Running scans

```bash
# One-shot full scan
sentinelx-cli scan

# Continuous monitoring (default 60s interval)
sentinelx-cli monitor --interval 60

# Live telemetry stream
sentinelx-cli monitor-live --interval 1
```

### Checking threats

```bash
sentinelx-cli incidents        # Security incidents with MITRE mappings
sentinelx-cli threats          # Threat decisions with risk scores
sentinelx-cli timeline         # Chronological event timeline
sentinelx-cli graph            # Correlation graph and rules
```

### Checking detections

```bash
sentinelx-cli integrity        # Kernel and file integrity status
sentinelx-cli modules          # Kernel modules with trust assessment
sentinelx-cli processes        # Processes with suspicious indicators
sentinelx-cli network          # Active network connections
```

### Intelligence

```bash
sentinelx-cli intel            # Intelligence engine summary
sentinelx-cli mitre            # MITRE ATT&CK technique coverage
sentinelx-cli iocs             # Loaded Indicators of Compromise
sentinelx-cli ioc-check hash <value>  # Check IoC
sentinelx-cli cves             # Tracked CVEs
sentinelx-cli yara             # Loaded YARA rules
sentinelx-cli sigma            # Loaded Sigma rules
```

### Behavioral analysis

```bash
sentinelx-cli behavior         # Behavioral engine status and rules
sentinelx-cli behavior-profiles  # Behavioral profiles
sentinelx-cli behavior-stats   # Scoring weights and statistics
```

### Forensics

```bash
# Collect a forensic snapshot (process trees, network state, modules, IOCs)
sentinelx-cli forensics

# Export report
sentinelx-cli export --format json --output /var/lib/sentinelx/reports
sentinelx-cli export --format markdown --output /var/lib/sentinelx/reports
```

### Response engine

```bash
sentinelx-cli response         # Response engine status and history
sentinelx-cli workflows        # Available workflows and policies
sentinelx-cli audit            # Response audit log
```

---

## 2. Monitoring and Alerting

### Key metrics to monitor

| Metric | Source | Warning threshold | Critical threshold |
|--------|--------|-------------------|-------------------|
| Backend process alive | `systemctl status sentinelx` | Any restart | Not running |
| API health | `GET /api/health` | Degraded response | No response |
| Telemetry events/sec | `GET /api/telemetry/stats` | > 80% of max rate | Provider stopped |
| Events dropped | `GET /api/telemetry/providers/health` | > 0.1% drop rate | > 1% drop rate |
| Database size | Filesystem | > 1 GB | > 5 GB |
| Memory usage | `ps aux \| grep sentinelx` | > 150 MB | > 256 MB |
| CPU usage | `top -p $(pgrep sentinelx)` | > 3% sustained | > 10% sustained |
| Fleet agents offline | `GET /api/fleet` | Any offline | > 50% offline |
| Active incidents | `GET /api/incidents` | > 0 High | > 0 Critical |

### Telemetry provider health

The `GET /api/telemetry/providers/health` endpoint returns:

```json
{
  "providers": [
    {
      "name": "ebpf",
      "status": "running",
      "events_received": 12345,
      "events_dropped": 0,
      "started_at": "2026-01-15T10:30:00Z",
      "uptime_seconds": 3600,
      "drop_rate_percent": 0.0
    }
  ],
  "summary": {
    "total": 5,
    "running": 4,
    "degraded": 1,
    "stopped": 0
  }
}
```

### Provider latency monitoring

```json
{
  "providers": [
    {
      "name": "ebpf",
      "avg_latency_us": 45,
      "max_latency_us": 320
    }
  ]
}
```

### Telemetry rate monitoring

```json
{
  "providers": [
    {
      "name": "netlink",
      "events_received": 5000,
      "events_dropped": 2
    }
  ]
}
```

### Monitoring with external tools

SentinelX exposes a REST API. You can monitor it with:

- **Prometheus**: Write a custom exporter that scrapes the API endpoints
- **Grafana**: Dashboard panels for fleet overview, telemetry stats, threat trends
- **Nagios/Zabbix**: Check `/api/health` endpoint for service status
- **Custom scripts**: Poll endpoints and alert on thresholds

Example monitoring script:

```bash
#!/bin/bash
HEALTH=$(curl -sf http://localhost:8443/api/health)
if [ $? -ne 0 ]; then
    echo "CRITICAL: SentinelX backend unreachable" >&2
    exit 2
fi

RUNNING=$(echo "$HEALTH" | jq -r '.providers.summary.running // 0')
TOTAL=$(echo "$HEALTH" | jq -r '.providers.summary.total // 0')

if [ "$RUNNING" -eq 0 ]; then
    echo "CRITICAL: No telemetry providers running"
    exit 2
elif [ "$RUNNING" -lt "$TOTAL" ]; then
    echo "WARNING: $RUNNING/$TOTAL providers running"
    exit 1
fi

echo "OK: $RUNNING/$TOTAL providers running"
exit 0
```

---

## 3. Log Management

### Log configuration

```toml
[logging]
level = "info"         # trace, debug, info, warn, error
format = "pretty"      # pretty, compact, json
file_output = true
json_format = false
```

### Log levels

| Level | Use case |
|-------|----------|
| `trace` | Extremely verbose, internal state |
| `debug` | Detailed diagnostic information |
| `info` | Normal operational messages |
| `warn` | Unexpected conditions that don't stop execution |
| `error` | Failures that require attention |

### Log format

- **pretty**: Human-readable format with timestamps and spans
- **compact**: Single-line format
- **json**: Structured JSON (recommended for production with log aggregators)

### Viewing logs

```bash
# systemd journal
sudo journalctl -u sentinelx -f
sudo journalctl -u sentinelx --since "1 hour ago"

# JSON format for log aggregation
# Set in sentinelx.toml:
# [logging]
# json_format = true
# format = "compact"
```

### Log rotation

If using file-based logging, configure logrotate:

```
/var/log/sentinelx/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 sentinelx sentinelx
    postrotate
        systemctl reload sentinelx 2>/dev/null || true
    endscript
}
```

### Structured logging fields

SentinelX uses `tracing` with structured fields. Key fields to search for:

| Field | Description |
|-------|-------------|
| `objects_discovered` | Pipeline discovery count |
| `objects_enriched` | Pipeline metadata enrichment count |
| `objects_assessed` | Pipeline assessment count |
| `evidence_count` | Evidence records generated |
| `duration_ms` | Operation duration in milliseconds |
| `events_received` | Telemetry events received |
| `events_dropped` | Telemetry events dropped |

---

## 4. Backup and Recovery

### Backup strategy

| Component | Backup method | Frequency | Retention |
|-----------|--------------|-----------|-----------|
| SQLite database | File copy (after WAL checkpoint) | Daily | 30 days |
| Configuration | File copy | On change | Indefinite |
| Evidence snapshots | File copy | Daily | 90 days |
| Logs | Log aggregation | Real-time | 90 days |

### Backup procedure

```bash
#!/bin/bash
BACKUP_DIR="/var/backups/sentinelx"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop writes (optional, for consistent backup)
sudo -u sentinelx sqlite3 /var/lib/sentinelx/sentinelx.db \
    "PRAGMA wal_checkpoint(TRUNCATE);"

# Backup database
sudo cp /var/lib/sentinelx/sentinelx.db "$BACKUP_DIR/sentinelx-$DATE.db"

# Backup configuration
sudo cp /etc/sentinelx/sentinelx.toml "$BACKUP_DIR/sentinelx.toml-$DATE"

# Backup evidence
sudo tar czf "$BACKUP_DIR/evidence-$DATE.tar.gz" /var/lib/sentinelx/evidence/

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.db" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

### Recovery procedure

```bash
# Stop the service
sudo systemctl stop sentinelx

# Restore database
sudo cp /var/backups/sentinelx/sentinelx-20260715.db /var/lib/sentinelx/sentinelx.db
sudo chown sentinelx:sentinelx /var/lib/sentinelx/sentinelx.db

# Restore configuration
sudo cp /var/backups/sentinelx/sentinelx.toml-20260715 /etc/sentinelx/sentinelx.toml

# Restore evidence
sudo tar xzf /var/backups/sentinelx/evidence-20260715.tar.gz -C /

# Start the service
sudo systemctl start sentinelx
```

### Disaster recovery

If the database is corrupted:

1. Stop the service
2. Remove the corrupted database
3. Start the service (it will create a new database automatically)
4. Re-import any available evidence from backups

```bash
sudo systemctl stop sentinelx
sudo rm /var/lib/sentinelx/sentinelx.db /var/lib/sentinelx/sentinelx.db-wal /var/lib/sentinelx/sentinelx.db-shm
sudo systemctl start sentinelx
```

---

## 5. Performance Tuning

### Resource limits

Configure resource caps in `sentinelx.toml`:

```toml
[general]
max_memory_mb = 150      # Memory usage cap (1–1024 MB)
max_cpu_percent = 3.0     # CPU usage cap (0–100%)
```

### eBPF tuning

```toml
[ebpf]
enabled = true
map_size = 10240                # eBPF map entries
perf_buffer_pages = 64          # Perf buffer size (pages)
max_events_per_second = 10000   # Event rate limit
```

### Telemetry bus tuning

The telemetry bus uses a Tokio broadcast channel with configurable parameters:

- **Buffer capacity**: 50,000 events (default)
- **Rate limit**: 50,000 events/second (default)
- **Backpressure**: mpsc channels for flow control
- **Event eviction**: When buffer is full, oldest events are dropped

### SQLite tuning

The database is configured with:
- **WAL journal mode**: Better concurrent read performance
- **Auto-vacuum (Full)**: Automatic space reclamation
- **Busy timeout (5s)**: Waits for locks instead of failing immediately
- **Max connections (5)**: Connection pool size
- **Acquire timeout (10s)**: Maximum time to wait for a connection

For high-throughput deployments, consider:
- Placing the SQLite database on SSD storage
- Using `PRAGMA synchronous=NORMAL` for better write performance
- Monitoring database file size and adjusting `retention_days`

### Scan interval

Adjust the scan interval based on workload:

```toml
[general]
scan_interval_seconds = 60    # Default: 60 seconds
```

Shorter intervals increase CPU usage but detect threats faster. Longer intervals reduce resource consumption.

### Tokio runtime

SentinelX uses Tokio with `#[tokio::main]` which defaults to a multi-threaded runtime. The number of worker threads defaults to the number of CPU cores.

---

## 6. Capacity Planning

### Single-host

| Resource | Minimum | Recommended | Notes |
|----------|---------|-------------|-------|
| CPU cores | 1 | 2+ | eBPF event processing is CPU-bound |
| RAM | 128 MB | 256 MB | Pipeline + telemetry bus + evidence store |
| Disk | 100 MB | 1 GB+ | Database + evidence + logs |
| Network | 1 Mbps | 10 Mbps | API + fleet communication |

### Per-agent (fleet)

| Resource | Usage |
|----------|-------|
| RAM | ~50–100 MB per agent |
| CPU | ~1–3% during normal operation |
| Network | ~1–5 KB/s heartbeat + telemetry |
| Disk | ~10–50 MB/day for database |

### Fleet sizing

| Fleet size | Coordinator requirements |
|-----------|------------------------|
| 1–10 agents | 2 CPU cores, 256 MB RAM |
| 10–100 agents | 4 CPU cores, 512 MB RAM |
| 100–1000 agents | 8 CPU cores, 1 GB RAM |

### Database growth

| Data type | Size per record | Daily volume (100 agents) | Daily growth |
|-----------|----------------|--------------------------|-------------|
| Telemetry events | ~200 bytes | ~1M events | ~200 MB |
| Evidence records | ~500 bytes | ~10K records | ~5 MB |
| Assessment results | ~300 bytes | ~100K records | ~30 MB |
| Incidents | ~1 KB | ~100 records | ~100 KB |
| Heartbeats | ~400 bytes | ~300K records | ~120 MB |

With `retention_days = 90` and `max_events = 1000000`, expect:
- ~5–10 GB database size for a 100-agent fleet
- Configure `retention_days = 30` to reduce storage requirements

---

## 7. Troubleshooting Guide

### Service won't start

```bash
# Check logs
sudo journalctl -u sentinelx --no-pager -n 50

# Check if port is in use
sudo ss -tlnp | grep 8443

# Check permissions
ls -la /var/lib/sentinelx/
ls -la /etc/sentinelx/

# Check capabilities (for eBPF/fanotify)
cat /proc/$(pgrep sentinelx)/status | grep Cap

# Try running directly
sudo /usr/local/bin/sentinelx-backend --host 127.0.0.1 --port 8443 --config /etc/sentinelx/sentinelx.toml
```

### eBPF provider not working

```bash
# Check BTF support
ls -la /sys/kernel/btf/vmlinux

# Check capabilities
sudo capsh --print | grep -i bpf

# Check kernel version (need 5.8+)
uname -r

# Check dmesg for eBPF errors
sudo dmesg | grep -i bpf

# Check sentinelx ebpf status
sentinelx-cli ebpf
```

### fanotify provider degraded

```bash
# Check CAP_SYS_ADMIN
sudo capsh --print | grep -i sys_admin

# Check if fanotify is available
grep -i fanotify /proc/kallsyms

# SentinelX will degrade to proc scanning if fanotify is unavailable
sentinelx-cli providers-health
```

### High memory usage

```bash
# Check current usage
ps aux | grep sentinelx

# Check telemetry bus stats
curl -s http://localhost:8443/api/telemetry/stats | jq .

# Reduce telemetry rate
# In sentinelx.toml:
# [ebpf]
# max_events_per_second = 5000

# Reduce max memory
# [general]
# max_memory_mb = 100
```

### Database locked errors

```bash
# Check WAL mode
sqlite3 /var/lib/sentinelx/sentinelx.db "PRAGMA journal_mode;"

# Check for long-running queries
sudo lsof /var/lib/sentinelx/sentinelx.db

# Force WAL checkpoint
sudo -u sentinelx sqlite3 /var/lib/sentinelx/sentinelx.db \
    "PRAGMA wal_checkpoint(TRUNCATE);"

# If persistent, increase busy timeout
# In Settings: busy_timeout is set to 5 seconds
```

### Fleet agents not connecting

```bash
# Check coordinator is running
curl -s http://localhost:8443/api/fleet | jq .

# Check network connectivity from agent
telnet coordinator-host 8443

# Check firewall rules
sudo ufw status

# Check agent logs
sudo journalctl -u sentinelx-agent --no-pager -n 50
```

### CLI not finding detectors

```bash
# List available detectors
sentinelx-cli status

# Check which detectors are enabled in config
sentinelx-cli config

# Ensure running as root for /proc access
sudo sentinelx-cli scan
```

---

## 8. Common Issues and Solutions

### Issue: "Failed to open database, using in-memory"

**Cause**: SQLite database path is not writable or directory doesn't exist.

**Solution**:
```bash
sudo mkdir -p /var/lib/sentinelx
sudo chown sentinelx:sentinelx /var/lib/sentinelx
```

### Issue: "Permission denied" on /proc entries

**Cause**: Not running as root or without CAP_SYS_PTRACE.

**Solution**: Run with `sudo` or configure systemd capabilities:
```ini
AmbientCapabilities=CAP_SYS_PTRACE CAP_BPF CAP_SYS_ADMIN
```

### Issue: eBPF programs fail to load

**Cause**: Missing kernel BTF, insufficient capabilities, or kernel version too old.

**Solution**:
1. Verify kernel >= 5.8: `uname -r`
2. Verify BTF: `ls /sys/kernel/btf/vmlinux`
3. Verify capabilities: `capsh --print | grep -i bpf`
4. If BTF unavailable, SentinelX falls back to tracepoint-only mode automatically

### Issue: High CPU usage during scans

**Cause**: Short scan interval or many processes on the system.

**Solution**:
```toml
[general]
scan_interval_seconds = 120  # Increase from 60
max_cpu_percent = 2.0         # Lower cap
```

### Issue: Telemetry events being dropped

**Cause**: Event rate exceeds bus capacity or consumer is slow.

**Solution**:
1. Check drop rate: `curl -s http://localhost:8443/api/telemetry/providers/health | jq`
2. Reduce event rate: `[ebpf] max_events_per_second = 5000`
3. Increase bus capacity (requires code change in `TelemetryBus`)

### Issue: "Connection refused" on API

**Cause**: Backend not running or wrong host/port.

**Solution**:
```bash
# Check if running
pgrep -a sentinelx

# Check listening ports
sudo ss -tlnp | grep sentinelx

# Check firewall
sudo ufw status | grep 8443
```

### Issue: Stale fleet agents showing as offline

**Cause**: Heartbeat timeout exceeded (agent crashed or network partition).

**Solution**:
```bash
# List offline agents
curl -s http://localhost:8443/api/fleet/agents | jq '.[] | select(.status == "offline")'

# Deregister stale agent
curl -X POST http://localhost:8443/api/fleet/agents/<agent-id>/deregister

# Restart agent on remote host
sudo systemctl restart sentinelx
```

### Issue: Evidence not being generated

**Cause**: Response engine in dry-run mode (default).

**Solution**: The response engine defaults to `dry_run: true`. This is a safety feature. To enable actual response actions, modify the `ResponseConfig`:

```rust
ResponseConfig {
    dry_run: false,
    // ...
}
```

Warning: Only disable dry-run after thorough testing. The response engine can kill processes and isolate hosts.

### Issue: Dashboard cannot reach API

**Cause**: CORS or network configuration.

**Solution**:
```toml
[api]
cors_origins = ["http://localhost:3000", "https://dashboard.example.com"]
```

### Issue: Build fails with "linux/audit.h not found"

**Cause**: Missing audit development headers.

**Solution**:
```bash
# Debian/Ubuntu
sudo apt install libaudit-dev

# Fedora/RHEL
sudo dnf install audit-libs-devel

# Arch Linux
sudo pacman -S audit
```
