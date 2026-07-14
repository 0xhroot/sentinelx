# Troubleshooting Guide

## 1. Service Won't Start

### Symptoms

`sentinelx-backend` exits immediately or fails to bind to the port.

### Diagnosis

```bash
# Check logs
sudo journalctl -u sentinelx --no-pager -n 50

# Check if port is in use
ss -tlnp | grep 8443

# Verify configuration
sentinelx-cli config

# Check file permissions
ls -la /etc/sentinelx/sentinelx.toml
ls -la /var/lib/sentinelx/
```

### Solutions

- **Port in use**: Change the port in `sentinelx.toml` or stop the conflicting service
- **Permission denied**: Ensure the `sentinelx` user owns `/var/lib/sentinelx/` and `/var/log/sentinelx/`
- **Invalid config**: Validate TOML syntax; check for missing required fields
- **SQLite locked**: Remove stale WAL/SHM files: `rm /var/lib/sentinelx/sentinelx.db-wal /var/lib/sentinelx/sentinelx.db-shm`

## 2. eBPF Provider Degraded

### Symptoms

`sentinelx-cli ebpf` shows `Degraded` or `Error` status.

### Diagnosis

```bash
sentinelx-cli ebpf
sentinelx-cli providers-health

# Check kernel version
uname -r

# Check BTF support
ls -la /sys/kernel/btf/vmlinux

# Check capabilities
capsh --print | grep Current
```

### Solutions

- **Kernel < 5.8**: Upgrade kernel or accept degraded userspace-only mode
- **Missing BTF**: Install `linux-headers-$(uname -r)` package
- **Missing capabilities**: Add `CAP_BPF` and `CAP_SYS_ADMIN` to systemd unit

## 3. High CPU Usage

### Symptoms

`top` shows sentinelx using > 10% CPU.

### Diagnosis

```bash
# Check current settings
sentinelx-cli status

# Profile CPU
sudo perf record -p $(pgrep sentinelx) -g -- sleep 10
sudo perf report
```

### Solutions

- Increase `scan_interval_seconds` (e.g., 60 → 120)
- Reduce `max_events_per_second` in `[ebpf]` section
- Disable unused telemetry providers
- Check for external tools polling the API too frequently

## 4. Memory Usage Growing

### Symptoms

RSS memory increasing over time.

### Diagnosis

```bash
# Check memory
ps -o pid,rss,comm -p $(pgrep sentinelx)
pmap -x $(pgrep sentinelx)

# Check database size
du -sh /var/lib/sentinelx/sentinelx.db
```

### Solutions

- Reduce `max_events` in `[storage]` to limit in-memory evidence
- Reduce `retention_days` to trigger more frequent cleanup
- Restart the service if a memory leak is suspected (report as bug)

## 5. Database Locked Errors

### Symptoms

Logs show `database is locked` errors.

### Diagnosis

```bash
# Check WAL mode
sqlite3 /var/lib/sentinelx/sentinelx.db "PRAGMA journal_mode;"

# Check busy timeout
sqlite3 /var/lib/sentinelx/sentinelx.db "PRAGMA busy_timeout;"
```

### Solutions

- Ensure WAL journal mode is active
- Move database to SSD storage
- Reduce concurrent API requests during scanning
- Increase busy timeout if needed

## 6. Fleet Agent Offline

### Symptoms

`sentinelx-cli fleet-agents` shows agent as Offline.

### Diagnosis

```bash
# Check agent connectivity
nc -zv <agent-ip> 8543

# Check agent logs
ssh <agent-host> sudo journalctl -u sentinelx --since "5 minutes ago"

# Check coordinator logs
sudo journalctl -u sentinelx --since "5 minutes ago" | grep fleet
```

### Solutions

- **Network issue**: Verify firewall allows port 8543 between agent and coordinator
- **Agent crash**: Restart the agent service
- **Heartbeat timeout**: Check `heartbeat_interval_secs` in transport config
- **TLS mismatch**: Verify certificates are valid and CA is trusted on both sides

## 7. API CORS Errors

### Symptoms

Browser console shows CORS policy errors.

### Solution

Update `cors_origins` in `sentinelx.toml`:

```toml
[api]
cors_origins = ["http://localhost:3000", "https://sentinelx.example.com"]
```

Restart the backend after configuration changes.

## 8. Dashboard Not Loading

### Symptoms

Browser shows blank page or 404 for the dashboard.

### Diagnosis

```bash
# Check if dashboard is built
ls -la apps/dashboard/dist/

# Check API health
curl -s http://localhost:8443/api/health
```

### Solutions

- Rebuild dashboard: `cd apps/dashboard && npm install && npm run build`
- Ensure nginx/Caddy is serving from the `dist/` directory
- Check that `try_files $uri $uri/ /index.html` is configured for SPA routing

## 9. Scan Takes Too Long

### Symptoms

`sentinelx-cli scan` takes > 10 seconds.

### Diagnosis

```bash
# Check system load
uptime
top -bn1 | head -20

# Check disk I/O
iostat -x 1 5
```

### Solutions

- Reduce number of enabled detectors in `[detection]`
- Disable file integrity monitoring if not needed
- Move database to faster storage
- Check for heavy disk I/O from other processes

## 10. No Telemetry Events

### Symptoms

`sentinelx-cli events` shows no events.

### Diagnosis

```bash
sentinelx-cli telemetry
sentinelx-cli providers
sentinelx-cli providers-health
```

### Solutions

- Verify telemetry providers are `Running` (not `Stopped` or `Error`)
- Check eBPF provider has required capabilities
- Ensure audit rules are configured if using audit provider
- Check that `/proc` and `/sys` are readable

## 11. Forensic Snapshot Incomplete

### Symptoms

Forensic data is missing process trees or network connections.

### Solutions

- Ensure running as root for full `/proc` access
- Check that process monitoring is enabled in config
- Verify network monitoring is not blocked by firewall

## 12. Report Generation Fails

### Symptoms

`sentinelx-cli export` fails or produces empty reports.

### Diagnosis

```bash
# Check output directory permissions
ls -la /var/lib/sentinelx/reports/

# Check disk space
df -h /var/lib/sentinelx/
```

### Solutions

- Ensure output directory exists and is writable
- Check available disk space
- Verify database is not corrupted
