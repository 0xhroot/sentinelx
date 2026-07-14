# Deployment Guide

## Single-Host Deployment

The simplest deployment model runs all SentinelX components on one machine.

### Directory Layout

```
/etc/sentinelx/
├── sentinelx.toml               # Configuration file
/var/lib/sentinelx/
├── sentinelx.db                 # SQLite database (WAL mode)
├── evidence/                    # Forensic evidence snapshots
/var/log/sentinelx/
├── sentinelx.log                # Application logs
```

### Setup

```bash
# Create user and directories
sudo useradd -r -s /usr/sbin/nologin sentinelx
sudo mkdir -p /etc/sentinelx /var/lib/sentinelx/evidence /var/log/sentinelx
sudo chown -R sentinelx:sentinelx /var/lib/sentinelx /var/log/sentinelx

# Install binaries
sudo cp target/release/sentinelx-backend /usr/local/bin/
sudo cp target/release/sentinelx-cli /usr/local/bin/
sudo chmod 755 /usr/local/bin/sentinelx-backend /usr/local/bin/sentinelx-cli

# Install configuration
sudo cp sentinelx.toml /etc/sentinelx/sentinelx.toml
sudo chmod 640 /etc/sentinelx/sentinelx.toml
```

### Start

```bash
sudo sentinelx-backend --host 0.0.0.0 --port 8443 --config /etc/sentinelx/sentinelx.toml
```

### Verify

```bash
curl -s http://localhost:8443/api/health | jq .
curl -s http://localhost:8443/api/status | jq .
curl -s http://localhost:8443/api/telemetry/providers | jq .
```

## Multi-Host Fleet Deployment

SentinelX supports fleet management with a central coordinator and remote agents.

```
                    ┌─────────────────────────┐
                    │    Fleet Coordinator     │
                    │    Port 8443 (API)       │
                    │    Port 8543 (transport) │
                    └────────┬────────────────┘
                             │ mTLS / TCP
              ┌──────────────┼──────────────┐
              │              │              │
    ┌─────────▼───┐  ┌──────▼──────┐  ┌───▼─────────┐
    │  Agent A    │  │  Agent B    │  │  Agent C    │
    │  Pipeline   │  │  Pipeline   │  │  Pipeline   │
    │  Telemetry  │  │  Telemetry  │  │  Telemetry  │
    └─────────────┘  └─────────────┘  └─────────────┘
```

### Coordinator Setup

The coordinator runs as part of the backend process and manages:

- Agent registration and heartbeat tracking
- Policy distribution
- Remote action execution
- Health monitoring (Healthy / Degraded / Offline)
- Incident aggregation

### Agent Setup

Each agent runs a local SentinelX instance that:

- Sends heartbeats every 30 seconds
- Receives and applies distributed policies
- Executes remote actions (kill process, run scan, collect forensics)
- Runs its own local pipeline and telemetry engine

## TLS/mTLS Configuration

### API TLS

```toml
[api]
tls_enabled = true
host = "0.0.0.0"
port = 8443
```

### Transport TLS (Fleet)

Configure TLS for agent-coordinator communication:

```rust
TransportConfig {
    tls: Some(TlsConfig {
        cert_path: "/etc/sentinelx/certs/server.pem",
        key_path: "/etc/sentinelx/certs/server-key.pem",
        ca_cert_path: "/etc/sentinelx/certs/ca.pem",
    }),
    compress: true,
    max_retries: 5,
    retry_delay_ms: 1000,
    heartbeat_interval_secs: 30,
}
```

### Generate Self-Signed Certificates

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

### Wire Format

```
[4 bytes: u32 LE length] [JSON-serialized Message struct]
```

- Length-prefixed framing for message boundaries
- Gzip compression for payloads > 1KB
- Message acknowledgement for critical message types
- Maximum message size: 16 MB

## systemd Service Deployment

### Service Unit

```ini
[Unit]
Description=SentinelX Security Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinelx-backend --config /etc/sentinelx/sentinelx.toml
Restart=always
RestartSec=5
User=sentinelx
Group=sentinelx
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_PERFMON CAP_AUDIT_WRITE CAP_AUDIT_CONTROL CAP_KILL CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable sentinelx
sudo systemctl start sentinelx
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libsqlite3-0 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/sentinelx-backend /usr/local/bin/
COPY --from=builder /app/target/release/sentinelx-cli /usr/local/bin/
ENTRYPOINT ["sentinelx-backend"]
```

### Run

```bash
docker build -t sentinelx .
docker run --privileged --network host \
  -v /etc/sentinelx:/etc/sentinelx \
  -v /var/lib/sentinelx:/var/lib/sentinelx \
  sentinelx
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Override log level (`trace`, `debug`, `info`, `warn`, `error`) |
| `SENTINELX_CONFIG` | Path to configuration file |

## Firewall Considerations

| Port | Protocol | Purpose |
|------|----------|---------|
| 8443 | TCP | REST API |
| 8543 | TCP | Fleet transport (agent-coordinator) |

Restrict API access to trusted networks. For fleet deployments, restrict transport port to internal network only.
