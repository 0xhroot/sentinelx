# Fleet Management Guide

SentinelX supports multi-host fleet management with a central coordinator and distributed agents.

## Architecture

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

## Components

### Coordinator

Runs as part of the `sentinelx-backend` process. Manages:

- Agent registration and heartbeat tracking
- Policy distribution
- Remote action execution
- Health monitoring (Healthy / Degraded / Offline)
- Incident aggregation

### Agent

Each agent runs a local SentinelX instance that:

- Sends heartbeats every 30 seconds with system health, telemetry status, and detection stats
- Receives and applies distributed policies
- Executes remote actions (kill process, run scan, collect forensics)
- Runs its own local pipeline and telemetry engine

## Transport Layer

### Features

- **TLS encryption**: Optional mTLS via tokio-rustls
- **Compression**: Gzip for payloads > 1KB (~60% reduction)
- **Reliability**: Message acknowledgement for critical messages
- **Framing**: Length-prefixed `[4 bytes LE length][JSON payload]`
- **Max message size**: 16 MB

### Message Types

| Message | Direction | Ack Required |
|---------|-----------|-------------|
| Registration | Agent → Coordinator | RegistrationAck |
| Heartbeat | Agent → Coordinator | HeartbeatAck |
| Policy | Coordinator → Agent | PolicyAck |
| RemoteAction | Coordinator → Agent | RemoteActionResult |
| VersionNegotiation | Both | VersionNegotiationAck |

### Configuration

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
    reconnect_delay_ms: 5000,
    heartbeat_interval_secs: 30,
    buffer_size: 8192,
}
```

## Health Status

| Status | Condition |
|--------|-----------|
| **Healthy** | Last heartbeat within timeout (default 30s) |
| **Degraded** | Last heartbeat between timeout and 3x timeout |
| **Offline** | Last heartbeat older than 3x timeout |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/fleet` | Fleet overview |
| GET | `/api/fleet/agents` | List all agents |
| GET | `/api/fleet/agents/{id}` | Agent details |
| POST | `/api/fleet/agents/{id}/deregister` | Remove agent |
| POST | `/api/fleet/heartbeat` | Receive heartbeat |
| GET | `/api/fleet/policies` | List policies |
| POST | `/api/fleet/policies` | Distribute policy |
| GET | `/api/fleet/actions` | List remote actions |
| POST | `/api/fleet/actions` | Request remote action |
| GET | `/api/fleet/actions/{id}` | Action detail |
| GET | `/api/fleet/stats` | Fleet statistics |

## CLI Commands

```bash
sentinelx-cli fleet              # Fleet overview
sentinelx-cli fleet-agents       # List all agents
sentinelx-cli fleet-agent <id>   # Agent details
sentinelx-cli fleet-policies     # Distributed policies
sentinelx-cli fleet-actions      # Recent remote actions
```

## Policy Distribution

Policies define detection and response rules applied across the fleet:

```bash
# Distribute a policy
curl -X POST http://localhost:8443/api/fleet/policies \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production-policy",
    "description": "Standard production monitoring",
    "config": {
      "severity_threshold": "medium",
      "response_enabled": true
    }
  }'
```

## Remote Actions

Execute actions on remote agents:

```bash
# Request a remote scan
curl -X POST http://localhost:8443/api/fleet/actions \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-web-01",
    "action_type": "scan",
    "parameters": {}
  }'
```

### Available Remote Actions

| Action | Description |
|--------|-------------|
| `scan` | Run full detection scan |
| `forensics` | Collect forensic snapshot |
| `kill_process` | Terminate process by PID |
| `block_connection` | Block network connection |

## Database Schema

Five tables support fleet management:

| Table | Purpose |
|-------|---------|
| `fleet_agents` | Registered agent metadata |
| `fleet_health` | System health snapshots |
| `fleet_policies` | Distributed policy records |
| `remote_actions` | Remote action audit trail |
| `heartbeat_history` | Heartbeat history |

## Capacity Planning

| Fleet Size | Coordinator Requirements |
|-----------|------------------------|
| 1–10 agents | 2 CPU cores, 256 MB RAM |
| 10–100 agents | 4 CPU cores, 512 MB RAM |
| 100–1000 agents | 8 CPU cores, 1 GB RAM |

### Per-Agent Resource Usage

| Resource | Usage |
|----------|-------|
| RAM | ~50–100 MB |
| CPU | ~1–3% |
| Network | ~1–5 KB/s |
| Disk | ~10–50 MB/day |

## Limitations

The fleet management system is currently in **alpha** status:

- Agent-coordinator communication is experimental
- Policy distribution may not propagate to all agents reliably
- Heartbeat monitoring has limited timeout configuration
- Remote response actions are best-effort
- No TLS for inter-node communication yet (planned)
- No mutual authentication between agents and coordinator yet

For production multi-host deployments, fleet features should be considered unstable.
