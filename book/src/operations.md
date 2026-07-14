# Operations Manual

## Day-to-Day Operations

### Health Checks

```bash
# API health endpoint
curl -s http://localhost:8443/api/health | jq .

# System status
curl -s http://localhost:8443/api/status | jq .

# Telemetry provider status
curl -s http://localhost:8443/api/telemetry/providers | jq .

# Provider health (detailed with uptime and drop rates)
curl -s http://localhost:8443/api/telemetry/providers/health | jq .

# Fleet overview
curl -s http://localhost:8443/api/fleet | jq .
```

### CLI Health Checks

```bash
sentinelx-cli status            # System status, metrics, detector info
sentinelx-cli telemetry         # Telemetry engine status and config
sentinelx-cli providers         # Registered telemetry providers
sentinelx-cli providers-health  # Detailed provider health diagnostics
sentinelx-cli ebpf              # eBPF kernel sensor status and capabilities
sentinelx-cli fleet             # Fleet overview with agent counts
```

### Running Scans

```bash
sentinelx-cli scan                          # One-shot full scan
sentinelx-cli monitor --interval 60         # Continuous monitoring
sentinelx-cli monitor-live --interval 1     # Live telemetry stream
```

### Checking Threats

```bash
sentinelx-cli incidents        # Security incidents with MITRE mappings
sentinelx-cli threats          # Threat decisions with risk scores
sentinelx-cli timeline         # Chronological event timeline
sentinelx-cli graph            # Correlation graph and rules
```

### Intelligence

```bash
sentinelx-cli intel            # Intelligence engine summary
sentinelx-cli mitre            # MITRE ATT&CK technique coverage
sentinelx-cli iocs             # Loaded Indicators of Compromise
sentinelx-cli ioc-check hash <value>  # Check IoC
sentinelx-cli yara             # Loaded YARA rules
sentinelx-cli sigma            # Loaded Sigma rules
```

### Forensics

```bash
sentinelx-cli forensics
sentinelx-cli export --format json --output /var/lib/sentinelx/reports
sentinelx-cli export --format markdown --output /var/lib/sentinelx/reports
```

## Monitoring and Alerting

### Key Metrics

| Metric | Source | Warning | Critical |
|--------|--------|---------|----------|
| Backend process alive | `systemctl status sentinelx` | Any restart | Not running |
| API health | `GET /api/health` | Degraded | No response |
| Telemetry events/sec | `GET /api/telemetry/stats` | > 80% max rate | Provider stopped |
| Events dropped | `GET /api/telemetry/providers/health` | > 0.1% | > 1% |
| Database size | Filesystem | > 1 GB | > 5 GB |
| Memory usage | `ps aux \| grep sentinelx` | > 150 MB | > 256 MB |
| CPU usage | `top -p $(pgrep sentinelx)` | > 3% | > 10% |
| Fleet agents offline | `GET /api/fleet` | Any offline | > 50% offline |
| Active incidents | `GET /api/incidents` | > 0 High | > 0 Critical |

### Monitoring Script

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

### External Tools

SentinelX REST API integrates with:

- **Prometheus**: Custom exporter scraping API endpoints
- **Grafana**: Dashboard panels for fleet, telemetry, threats
- **Nagios/Zabbix**: Check `/api/health` for service status
- **Custom scripts**: Poll endpoints and alert on thresholds

## Log Management

### Configuration

```toml
[logging]
level = "info"         # trace, debug, info, warn, error
format = "pretty"      # pretty, compact, json
file_output = true
json_format = false
```

### Log Levels

| Level | Use case |
|-------|----------|
| `trace` | Extremely verbose, internal state |
| `debug` | Detailed diagnostic information |
| `info` | Normal operational messages |
| `warn` | Unexpected conditions |
| `error` | Failures requiring attention |

### Viewing Logs

```bash
sudo journalctl -u sentinelx -f
sudo journalctl -u sentinelx --since "1 hour ago"
```

### Log Rotation

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

## Backup and Recovery

### Backup Strategy

| Component | Method | Frequency | Retention |
|-----------|--------|-----------|-----------|
| SQLite database | File copy | Daily | 30 days |
| Configuration | File copy | On change | Indefinite |
| Evidence snapshots | File copy | Daily | 90 days |
| Logs | Log aggregation | Real-time | 90 days |

### Backup Script

```bash
#!/bin/bash
BACKUP_DIR="/var/backups/sentinelx"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

# Checkpoint WAL
sudo -u sentinelx sqlite3 /var/lib/sentinelx/sentinelx.db \
    "PRAGMA wal_checkpoint(TRUNCATE);"

# Backup
sudo cp /var/lib/sentinelx/sentinelx.db "$BACKUP_DIR/sentinelx-$DATE.db"
sudo cp /etc/sentinelx/sentinelx.toml "$BACKUP_DIR/sentinelx.toml-$DATE"
sudo tar czf "$BACKUP_DIR/evidence-$DATE.tar.gz" /var/lib/sentinelx/evidence/

# Cleanup old backups
find "$BACKUP_DIR" -name "*.db" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
```

### Recovery

```bash
sudo systemctl stop sentinelx
sudo cp /var/backups/sentinelx/sentinelx-20260715.db /var/lib/sentinelx/sentinelx.db
sudo chown sentinelx:sentinelx /var/lib/sentinelx/sentinelx.db
sudo systemctl start sentinelx
```

### Disaster Recovery

If the database is corrupted:

```bash
sudo systemctl stop sentinelx
sudo rm /var/lib/sentinelx/sentinelx.db /var/lib/sentinelx/sentinelx.db-wal /var/lib/sentinelx/sentinelx.db-shm
sudo systemctl start sentinelx
```

The database is recreated automatically on first run.

## Performance Tuning

### Resource Limits

```toml
[general]
max_memory_mb = 150      # Memory usage cap (1–1024 MB)
max_cpu_percent = 3.0     # CPU usage cap (0–100%)
```

### eBPF Tuning

```toml
[ebpf]
enabled = true
map_size = 10240
perf_buffer_pages = 64
max_events_per_second = 10000
```

### Scan Interval

```toml
[general]
scan_interval_seconds = 60    # Shorter = faster detection, more CPU
```

## Capacity Planning

### Single-Host

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU cores | 1 | 2+ |
| RAM | 128 MB | 256 MB |
| Disk | 100 MB | 1 GB+ |
| Network | 1 Mbps | 10 Mbps |

### Per-Agent (Fleet)

| Resource | Usage |
|----------|-------|
| RAM | ~50–100 MB |
| CPU | ~1–3% |
| Network | ~1–5 KB/s |
| Disk | ~10–50 MB/day |

### Fleet Sizing

| Fleet Size | Coordinator Requirements |
|-----------|------------------------|
| 1–10 agents | 2 CPU cores, 256 MB RAM |
| 10–100 agents | 4 CPU cores, 512 MB RAM |
| 100–1000 agents | 8 CPU cores, 1 GB RAM |
