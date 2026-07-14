# Configuration Reference

SentinelX uses a TOML configuration file. The default search path is `~/.config/sentinelx/sentinelx.toml`, or specify a custom path with `--config`.

## Default Configuration

```bash
sudo mkdir -p /etc/sentinelx
sudo cp sentinelx.toml /etc/sentinelx/sentinelx.toml
```

## Complete Reference

```toml
[general]
hostname = ""                  # Auto-detected if empty
scan_interval_seconds = 60     # Scan interval for monitor mode
baseline_on_start = true       # Establish baseline on startup
max_memory_mb = 150            # Memory usage cap (1–1024 MB)
max_cpu_percent = 3.0          # CPU usage cap (0–100%)

[detection]
enabled_detectors = [
    "kernel_integrity",
    "hidden_process",
    "hidden_module",
    "hidden_connection",
    "hook_detection",
    "memory_integrity",
    "persistence",
    "privilege_escalation",
]
severity_threshold = "low"     # Minimum severity to report
mitre_attack_mapping = true    # Map detections to MITRE ATT&CK
evidence_collection = true     # Collect evidence for detections

[monitoring]
process_monitoring = true
network_monitoring = true
module_monitoring = true
memory_monitoring = true
syscall_monitoring = true
file_integrity_monitoring = true

[storage]
database_path = "/var/lib/sentinelx/sentinelx.db"
evidence_path = "/var/lib/sentinelx/evidence"
log_path = "/var/log/sentinelx"
retention_days = 90            # Data retention period
max_events = 1000000           # Maximum events to retain

[api]
enabled = true
host = "127.0.0.1"
port = 8443
tls_enabled = false
cors_origins = ["http://localhost:3000"]

[logging]
level = "info"                 # trace, debug, info, warn, error
format = "pretty"              # pretty, compact, json
file_output = true
json_format = false

[ebpf]
enabled = true
map_size = 10240               # eBPF map entries
perf_buffer_pages = 64         # Perf buffer size (pages)
max_events_per_second = 10000  # Event rate limit
```

## Section Reference

### [general]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hostname` | string | `""` | Host identifier (auto-detected if empty) |
| `scan_interval_seconds` | integer | `60` | Interval between scans in monitor mode |
| `baseline_on_start` | bool | `true` | Establish behavior baseline on startup |
| `max_memory_mb` | integer | `150` | Memory usage cap in MB (1–1024) |
| `max_cpu_percent` | float | `3.0` | CPU usage cap as percentage (0–100) |

### [detection]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled_detectors` | list | all | List of active detector names |
| `severity_threshold` | string | `"low"` | Minimum severity: `low`, `medium`, `high`, `critical` |
| `mitre_attack_mapping` | bool | `true` | Enable MITRE ATT&CK technique mapping |
| `evidence_collection` | bool | `true` | Enable evidence collection for detections |

### [monitoring]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `process_monitoring` | bool | `true` | Monitor running processes |
| `network_monitoring` | bool | `true` | Monitor network connections |
| `module_monitoring` | bool | `true` | Monitor kernel modules |
| `memory_monitoring` | bool | `true` | Monitor memory regions |
| `syscall_monitoring` | bool | `true` | Monitor syscall activity |
| `file_integrity_monitoring` | bool | `true` | Monitor file integrity |

### [storage]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `database_path` | string | `/var/lib/sentinelx/sentinelx.db` | SQLite database path |
| `evidence_path` | string | `/var/lib/sentinelx/evidence` | Forensic evidence storage path |
| `log_path` | string | `/var/log/sentinelx` | Log file directory |
| `retention_days` | integer | `90` | Data retention period in days |
| `max_events` | integer | `1000000` | Maximum events to retain in memory |

### [api]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable REST API server |
| `host` | string | `"127.0.0.1"` | Bind address |
| `port` | integer | `8443` | Listen port |
| `tls_enabled` | bool | `false` | Enable TLS for API |
| `cors_origins` | list | `["http://localhost:3000"]` | Allowed CORS origins |

### [logging]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | string | `"info"` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `format` | string | `"pretty"` | Log format: `pretty`, `compact`, `json` |
| `file_output` | bool | `true` | Write logs to file |
| `json_format` | bool | `false` | Use JSON log format |

### [ebpf]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable eBPF telemetry provider |
| `map_size` | integer | `10240` | Number of eBPF map entries |
| `perf_buffer_pages` | integer | `64` | Perf buffer size in pages |
| `max_events_per_second` | integer | `10000` | Maximum eBPF event rate |

## Validation Rules

- `scan_interval_seconds` must be > 0
- `max_memory_mb` must be between 1 and 1024
- `max_cpu_percent` must be between 0 and 100
- `api.port` cannot be 0
- `retention_days` must be > 0
