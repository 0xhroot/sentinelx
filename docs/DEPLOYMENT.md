# SentinelX Deployment Guide

## Table of Contents

1. [Single-Host Deployment](#1-single-host-deployment)
2. [Multi-Host Fleet Deployment](#2-multi-host-fleet-deployment)
3. [TLS/mTLS Configuration](#3-tlsmtls-configuration)
4. [Database Setup](#4-database-setup)
5. [systemd Service Deployment](#5-systemd-service-deployment)
6. [Docker Deployment](#6-docker-deployment)
7. [Environment Variables](#7-environment-variables)
8. [Firewall Considerations](#8-firewall-considerations)

---

## 1. Single-Host Deployment

A single-host deployment runs the SentinelX backend, telemetry engine, detection pipeline, and all engines on one machine. This is the simplest deployment model.

### Directory layout

```
/etc/sentinelx/
├── sentinelx.toml               # Configuration file
/var/lib/sentinelx/
├── sentinelx.db                 # SQLite database (WAL mode)
├── evidence/                    # Forensic evidence snapshots
/var/log/sentinelx/
├── sentinelx.log                # Application logs (if file_output=true)
```

### Create directories and user

```bash
sudo useradd -r -s /usr/sbin/nologin sentinelx
sudo mkdir -p /etc/sentinelx /var/lib/sentinelx/evidence /var/log/sentinelx
sudo chown -R sentinelx:sentinelx /var/lib/sentinelx /var/log/sentinelx
```

### Install binaries

```bash
sudo cp target/release/sentinelx-backend /usr/local/bin/
sudo cp target/release/sentinelx-cli /usr/local/bin/
sudo chmod 755 /usr/local/bin/sentinelx-backend /usr/local/bin/sentinelx-cli
```

### Install configuration

```bash
sudo cp sentinelx.toml /etc/sentinelx/sentinelx.toml
sudo chmod 640 /etc/sentinelx/sentinelx.toml
```

### Set up database path

The database path is configured in `sentinelx.toml` under `[storage]`:

```toml
[storage]
database_path = "/var/lib/sentinelx/sentinelx.db"
```

The SQLite database is created automatically on first run with WAL journal mode, auto-vacuum, and a 5-second busy timeout. If the configured path is unreachable, the backend falls back to an in-memory SQLite database.

### Start the service

```bash
sudo sentinelx-backend --host 0.0.0.0 --port 8443 --config /etc/sentinelx/sentinelx.toml
```

### Verify

```bash
# Health check
curl -s http://localhost:8443/api/health | jq .

# System status
curl -s http://localhost:8443/api/status | jq .

# List telemetry providers
curl -s http://localhost:8443/api/telemetry/providers | jq .
```

---

## 2. Multi-Host Fleet Deployment

SentinelX supports multi-host fleet management with a central coordinator and remote agents.

### Architecture

```
                    ┌─────────────────────────┐
                    │    Fleet Coordinator     │
                    │    (sentinelx-backend)   │
                    │    Port 8443 (API)       │
                    │    Port 8543 (transport) │
                    └────────┬────────────────┘
                             │ mTLS / TCP
              ┌──────────────┼──────────────┐
              │              │              │
    ┌─────────▼───┐  ┌──────▼──────┐  ┌───▼─────────┐
    │  Agent A    │  │  Agent B    │  │  Agent C    │
    │  (web-01)   │  │  (db-01)    │  │  (api-01)   │
    │  Pipeline   │  │  Pipeline   │  │  Pipeline   │
    │  Telemetry  │  │  Telemetry  │  │  Telemetry  │
    └─────────────┘  └─────────────┘  └─────────────┘
```

### Coordinator setup

The coordinator runs as part of the backend process. It manages:

- Agent registration and heartbeat tracking
- Policy distribution
- Remote action execution
- Health monitoring (Healthy / Degraded / Offline)
- Incident aggregation

Configuration in `sentinelx.toml`:

```toml
[api]
host = "0.0.0.0"
port = 8443
```

### Agent setup

Each agent runs a local SentinelX instance that connects to the coordinator. The agent:

- Sends heartbeats every 30 seconds with system health, telemetry status, and detection stats
- Receives and applies distributed policies
- Executes remote actions (kill process, run scan, collect forensics)
- Runs its own local pipeline and telemetry engine

The fleet manager is initialized in the backend:

```rust
let coordinator = Arc::new(CoordinatorEngine::new(
    CoordinatorConfig::default(),
    fleet_tx,
));
let fleet_manager = Arc::new(FleetManager::new(coordinator));
fleet_manager.start().await;
```

### Fleet management API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /api/fleet` | GET | Fleet overview (agent counts, stats, uptime) |
| `GET /api/fleet/agents` | GET | List all agents with status |
| `GET /api/fleet/agents/{id}` | GET | Detailed info for one agent |
| `POST /api/fleet/agents/{id}/deregister` | POST | Remove agent from fleet |
| `POST /api/fleet/heartbeat` | POST | Receive agent heartbeat |
| `GET /api/fleet/policies` | GET | List distributed policies |
| `POST /api/fleet/policies` | POST | Distribute new policy |
| `GET /api/fleet/actions` | GET | List recent remote actions |
| `POST /api/fleet/actions` | POST | Request new remote action |
| `GET /api/fleet/actions/{id}` | GET | Get action detail |
| `GET /api/fleet/stats` | GET | Fleet statistics |

### Fleet CLI commands

```bash
sentinelx fleet              # Fleet overview with agent counts and stats
sentinelx fleet-agents       # List all agents with status
sentinelx fleet-agent <id>   # Detailed agent information
sentinelx fleet-policies     # List distributed policies
sentinelx fleet-actions      # List recent remote actions
```

### Health status logic

| Status | Condition |
|--------|-----------|
| **Healthy** | Last heartbeat within timeout (default 30s) |
| **Degraded** | Last heartbeat between timeout and 3x timeout |
| **Offline** | Last heartbeat older than 3x timeout |

### Fleet database schema

Five tables support fleet management:

| Table | Purpose |
|-------|---------|
| `fleet_agents` | Registered agent metadata |
| `fleet_health` | System health snapshots |
| `fleet_policies` | Distributed policy records |
| `remote_actions` | Remote action audit trail |
| `heartbeat_history` | Heartbeat history |

---

## 3. TLS/mTLS Configuration

### API TLS

Enable TLS for the REST API in `sentinelx.toml`:

```toml
[api]
tls_enabled = true
host = "0.0.0.0"
port = 8443
```

### Transport TLS (fleet communication)

The fleet transport layer supports optional TLS via `tokio-rustls` and `rustls`. Configure in `TransportConfig`:

```rust
pub struct TlsConfig {
    pub cert_path: PathBuf,      // Server/client certificate
    pub key_path: PathBuf,       // Private key
    pub ca_cert_path: PathBuf,   // CA certificate for verification
}
```

TLS configuration in `TransportConfig`:

```rust
TransportConfig {
    tls: Some(TlsConfig {
        cert_path: "/etc/sentinelx/certs/server.pem".into(),
        key_path: "/etc/sentinelx/certs/server-key.pem".into(),
        ca_cert_path: "/etc/sentinelx/certs/ca.pem".into(),
    }),
    compress: true,
    max_retries: 5,
    retry_delay_ms: 1000,
    reconnect_delay_ms: 5000,
    heartbeat_interval_secs: 30,
    buffer_size: 8192,
}
```

### Generate self-signed certificates

For development or internal deployments:

```bash
# Generate CA
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
    -keyout ca-key.pem -out ca.pem \
    -subj "/CN=SentinelX CA"

# Generate server certificate
openssl req -newkey rsa:2048 -nodes \
    -keyout server-key.pem -out server.csr \
    -subj "/CN=sentinelx-server"

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out server.pem -days 365

# Generate client certificate (for mTLS)
openssl req -newkey rsa:2048 -nodes \
    -keyout client-key.pem -out client.csr \
    -subj "/CN=sentinelx-agent"

openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out client.pem -days 365
```

### Transport features

- Length-prefixed framing: `[4 bytes LE length][JSON payload]`
- Protocol version negotiation on connect
- Gzip compression for payloads > 1KB (configurable)
- Message acknowledgement for critical message types (Registration, Policy, RemoteAction)
- Maximum message size: 16 MB

### Wire format

```
[4 bytes: u32 LE length] [JSON-serialized Message struct]
```

### Message types requiring acknowledgement

| Message Type | Direction | Ack |
|-------------|-----------|-----|
| Registration | Agent → Coordinator | RegistrationAck |
| Policy | Coordinator → Agent | PolicyAck |
| RemoteAction | Coordinator → Agent | RemoteActionResult |
| Heartbeat | Agent → Coordinator | HeartbeatAck |
| VersionNegotiation | Both | VersionNegotiationAck |

---

## 4. Database Setup

### SQLite (default)

SentinelX uses SQLite via `sqlx` with the following configuration:

```rust
SqliteConnectOptions::from_str(database_path)?
    .create_if_missing(true)
    .journal_mode(SqliteJournalMode::Wal)
    .busy_timeout(Duration::from_secs(5))
    .auto_vacuum(SqliteAutoVacuum::Full)
```

Connection pool: 5 max connections, 10-second acquire timeout.

### Production database

```toml
[storage]
database_path = "/var/lib/sentinelx/sentinelx.db"
retention_days = 90
max_events = 1000000
```

Ensure the directory is writable by the sentinelx user:

```bash
sudo chown sentinelx:sentinelx /var/lib/sentinelx
```

### In-memory database

If the configured database path fails, the backend falls back to SQLite in-memory mode:

```rust
Store::new("sqlite::memory:").await
```

This is useful for testing but data is lost on restart.

### Database tables

| Table | Purpose |
|-------|---------|
| `events` | Security events |
| `threats` | Detected threats |
| `evidence` | Evidence records |
| `assessment_results` | Assessment scores per object |
| `incidents` | Security incidents |
| `threat_decisions` | Threat engine decisions |
| `correlation_graph` | Correlation graph edges |
| `telemetry_events` | Telemetry events |
| `behavior_profiles` | Behavioral profiles |
| `iocs` | Indicators of Compromise |
| `yara_rules` | YARA detection rules |
| `sigma_rules` | Sigma detection rules |
| `cves` | CVE vulnerability tracking |
| `fleet_agents` | Fleet agent metadata |
| `fleet_health` | Fleet health snapshots |
| `fleet_policies` | Distributed policies |
| `remote_actions` | Remote action audit trail |
| `heartbeat_history` | Heartbeat history |

### Data retention

Configure automatic cleanup:

```toml
[storage]
retention_days = 90
max_events = 1000000
```

The `expire_old()` method on repositories handles cleanup of records older than the retention period.

### Backup

```bash
# Online backup using SQLite .backup
sqlite3 /var/lib/sentinelx/sentinelx.db ".backup '/var/backups/sentinelx/sentinelx-$(date +%Y%m%d).db'"

# Or use file-level backup (WAL mode requires checkpoint first)
sudo -u sentinelx sqlite3 /var/lib/sentinelx/sentinelx.db "PRAGMA wal_checkpoint(TRUNCATE);"
sudo cp /var/lib/sentinelx/sentinelx.db /var/backups/sentinelx/sentinelx-$(date +%Y%m%d).db
```

---

## 5. systemd Service Deployment

### Backend service

Create `/etc/systemd/system/sentinelx.service`:

```ini
[Unit]
Description=SentinelX Runtime Integrity & Rootkit Detection Platform
Documentation=https://github.com/sentinelx/sentinelx
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=sentinelx
Group=sentinelx
ExecStart=/usr/local/bin/sentinelx-backend \
    --host 0.0.0.0 \
    --port 8443 \
    --config /etc/sentinelx/sentinelx.toml
Restart=on-failure
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/sentinelx /var/log/sentinelx
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=no
ProtectControlGroups=yes
RestrictSUIDSGID=yes
MemoryMax=256M
CPUQuota=50%

# Required capabilities for eBPF, fanotify, netlink, audit
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_PERFMON CAP_AUDIT_WRITE CAP_AUDIT_CONTROL CAP_KILL CAP_NET_ADMIN

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinelx

[Install]
WantedBy=multi-user.target
```

### Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable sentinelx
sudo systemctl start sentinelx

# Check status
sudo systemctl status sentinelx

# View logs
sudo journalctl -u sentinelx -f
```

### CLI periodic scan via timer

Create `/etc/systemd/system/sentinelx-scan.service`:

```ini
[Unit]
Description=SentinelX Periodic Scan
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sentinelx-cli scan
User=sentinelx
Group=sentinelx
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_PERFMON CAP_AUDIT_WRITE
```

Create `/etc/systemd/system/sentinelx-scan.timer`:

```ini
[Unit]
Description=Run SentinelX scan every 60 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=60min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now sentinelx-scan.timer
```

---

## 6. Docker Deployment

### Production Docker Compose

```yaml
version: "3.8"
services:
  sentinelx:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: sentinelx
    privileged: true
    restart: unless-stopped
    ports:
      - "8443:8443"
    volumes:
      - sentinelx-data:/var/lib/sentinelx
      - sentinelx-logs:/var/log/sentinelx
      - ./sentinelx.toml:/etc/sentinelx/sentinelx.toml:ro
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
    environment:
      - RUST_LOG=info
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: "0.5"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8443/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

  dashboard:
    image: node:18-slim
    container_name: sentinelx-dashboard
    working_dir: /app
    volumes:
      - ./apps/dashboard:/app:ro
    ports:
      - "3000:3000"
    command: ["npx", "serve", "-s", "dist", "-l", "3000"]
    depends_on:
      sentinelx:
        condition: service_healthy

volumes:
  sentinelx-data:
  sentinelx-logs:
```

### Docker networking for fleet

For fleet deployments with coordinator and agents on separate containers:

```yaml
version: "3.8"
services:
  coordinator:
    build: .
    command: ["sentinelx-backend", "--host", "0.0.0.0", "--port", "8443"]
    privileged: true
    ports:
      - "8443:8443"
      - "8543:8543"
    networks:
      - sentinelx-net
    volumes:
      - coordinator-data:/var/lib/sentinelx

  agent-web:
    build: .
    command: ["sentinelx-backend", "--host", "0.0.0.0", "--port", "8443"]
    privileged: true
    networks:
      - sentinelx-net
    volumes:
      - agent-web-data:/var/lib/sentinelx
    depends_on:
      - coordinator

networks:
  sentinelx-net:
    driver: bridge

volumes:
  coordinator-data:
  agent-web-data:
```

### Container capabilities

| Capability | Purpose | Required for |
|-----------|---------|-------------|
| `CAP_BPF` | eBPF program loading | eBPF telemetry provider |
| `CAP_SYS_ADMIN` | fanotify, eBPF, mount operations | fanotify provider, eBPF |
| `CAP_PERFMON` | Performance monitoring | eBPF perf events |
| `CAP_AUDIT_WRITE` | Audit event generation | Audit telemetry provider |
| `CAP_AUDIT_CONTROL` | Audit configuration | Audit subsystem control |
| `CAP_KILL` | Process termination | Response engine (kill process) |
| `CAP_NET_ADMIN` | Network configuration | Netlink monitoring |

Without these capabilities, SentinelX degrades gracefully: telemetry providers report `Degraded` status and the pipeline falls back to proc scanning.

---

## 7. Environment Variables

### Runtime environment

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Tracing log level filter (trace, debug, info, warn, error) |
| `RUST_BACKTRACE` | `0` | Set to `1` for backtraces on panic |

### Configuration precedence

1. CLI arguments (`--host`, `--port`, `--config`)
2. Configuration file (`sentinelx.toml`)
3. Compiled defaults in `Settings::default()`

### Default values (from source)

| Setting | Default | Source |
|---------|---------|--------|
| `general.hostname` | Auto-detected via `hostname::get()` | `settings.rs:87` |
| `general.scan_interval_seconds` | 60 | `settings.rs:88` |
| `general.baseline_on_start` | true | `settings.rs:89` |
| `general.max_memory_mb` | 150 | `settings.rs:8` |
| `general.max_cpu_percent` | 3.0 | `settings.rs:9` |
| `api.host` | `127.0.0.1` | `settings.rs:126` |
| `api.port` | 8443 | `settings.rs:127` |
| `api.tls_enabled` | false | `settings.rs:128` |
| `storage.database_path` | `/var/lib/sentinelx/sentinelx.db` | `settings.rs:6` |
| `storage.retention_days` | 90 | `settings.rs:121` |
| `storage.max_events` | 1,000,000 | `settings.rs:122` |
| `logging.level` | `info` | `settings.rs:7` |
| `ebpf.max_events_per_second` | 10,000 | `settings.rs:142` |

---

## 8. Firewall Considerations

### API port

The backend listens on the configured port (default 8443). For single-host deployments, bind to localhost only:

```toml
[api]
host = "127.0.0.1"
port = 8443
```

For fleet deployments, allow external access:

```bash
# ufw (Ubuntu/Debian)
sudo ufw allow 8443/tcp comment "SentinelX API"

# firewalld (Fedora/RHEL)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 8443 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8443 -j DROP
```

### Fleet transport port

If using fleet management, the transport layer listens on a separate port:

```bash
# Allow transport between coordinator and agents
sudo ufw allow from 10.0.0.0/8 to any port 8543/tcp comment "SentinelX Fleet Transport"
```

### CORS configuration

Configure allowed origins in `sentinelx.toml`:

```toml
[api]
cors_origins = ["https://dashboard.example.com"]
```

### Recommended firewall rules for production

```bash
# Allow API from management network only
sudo ufw allow from 10.0.1.0/24 to any port 8443/tcp

# Allow transport from agent network only
sudo ufw allow from 10.0.2.0/24 to any port 8543/tcp

# Allow SSH from management
sudo ufw allow from 10.0.1.0/24 to any port 22/tcp

# Default deny incoming
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

### Telemetry providers

Telemetry providers use local kernel interfaces only and do not require network ports:

| Provider | Interface | Network required |
|----------|-----------|-----------------|
| eBPF | Kernel maps, ring buffers | No |
| fanotify | `/proc`, filesystem | No |
| netlink | `AF_NETLINK` socket (local) | No |
| audit | `NETLINK_AUDIT` socket (local) | No |
| proc scanner | `/proc` filesystem | No |
