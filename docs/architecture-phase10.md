# SentinelX Phase 10: Fleet Management Architecture

## Overview

Phase 10 transforms SentinelX from a standalone Linux EDR into a distributed multi-host security platform. It introduces four new crates (transport, agent, coordinator, fleet) that enable multiple SentinelX agents to communicate with a central coordinator over secure channels, with policy distribution, heartbeat monitoring, and remote response capabilities.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Fleet Dashboard                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────────┐  │
│  │ Fleet    │ │ Agent    │ │ Policy   │ │ Remote Response   │  │
│  │ Overview │ │ List     │ │ Manager  │ │ Console           │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────────┘  │
└─────────────────────────┬────────────────────────────────────────┘
                          │ REST API
┌─────────────────────────▼────────────────────────────────────────┐
│                     Fleet Manager                                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ FleetManager                                               │  │
│  │  ├─ Agent Registration    ├─ Policy Distribution           │  │
│  │  ├─ Heartbeat Tracking    ├─ Remote Action Queue           │  │
│  │  ├─ Health Monitoring     └─ Event Broadcast               │  │
│  └────────────────────────────┬───────────────────────────────┘  │
│                               │                                  │
│  ┌────────────────────────────▼───────────────────────────────┐  │
│  │ CoordinatorEngine                                          │  │
│  │  ├─ Agent Records        ├─ Heartbeat History              │  │
│  │  ├─ Policy Records       ├─ Incident Aggregation           │  │
│  │  └─ Stats Collection     └─ Stale Agent Detection          │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────┬────────────────────────────────────────┘
                          │ mTLS Transport
┌─────────────────────────▼────────────────────────────────────────┐
│                   Transport Layer                                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ TransportManager                                           │  │
│  │  ├─ TLS/mTLS (rustls)      ├─ Compression (gzip)          │  │
│  │  ├─ Message Framing         ├─ Reconnection                │  │
│  │  ├─ Retry Logic             ├─ Version Negotiation         │  │
│  │  └─ Statistics Tracking     └─ Message Acknowledgement     │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────┬──────────────────────────────────────┬────────────────┘
           │                                      │
┌──────────▼──────────┐              ┌────────────▼────────────────┐
│   SentinelX Agent   │              │   SentinelX Agent           │
│   (Host A)          │              │   (Host B)                  │
│  ┌────────────────┐ │              │  ┌────────────────┐        │
│  │ AgentEngine    │ │              │  │ AgentEngine    │        │
│  │ ├─ Heartbeat   │ │              │  │ ├─ Heartbeat   │        │
│  │ ├─ Policies    │ │              │  │ ├─ Policies    │        │
│  │ ├─ Actions     │ │              │  │ ├─ Actions     │        │
│  │ └─ Telemetry   │ │              │  │ └─ Telemetry   │        │
│  └────────────────┘ │              │  └────────────────┘        │
│  ┌────────────────┐ │              │  ┌────────────────┐        │
│  │ Local Pipeline │ │              │  │ Local Pipeline │        │
│  │ Detection      │ │              │  │ Detection      │        │
│  │ Response       │ │              │  │ Response       │        │
│  └────────────────┘ │              │  └────────────────┘        │
└─────────────────────┘              └────────────────────────────┘
```

## Crate Architecture

### 1. Transport (`crates/transport/`)

**Purpose:** Secure, reliable message transport between agents and coordinator.

**Key Types:**
- `TransportConfig` - Configuration (TLS, compression, retry, reconnect)
- `Message` - Wire format (id, type, payload, timestamp, version, flags)
- `MessageEnvelope` - Routing wrapper (source, dest, correlation)
- `TransportManager` - Connection management and statistics
- `TransportError` - Error types (TLS, Connection, Protocol, Retry)

**Message Protocol:**
- Length-prefixed framing (4-byte LE length + JSON payload)
- Protocol version negotiation on connect
- Gzip compression for payloads > 1KB
- Message acknowledgement for critical messages (Registration, Policy, RemoteAction)

**TLS Implementation:**
- `tokio-rustls` + `rustls` for TLS
- `rustls-pemfile` for certificate loading
- Self-signed CA support via `TlsConfig` (cert, key, CA cert paths)
- Optional TLS (disabled by default for development)

**Features:**
- `compress_message()` / `decompress_message()` - Gzip compression
- `serialize_message()` / `deserialize_message()` - Length-prefixed wire format
- `connect_with_retry()` - Retry with configurable attempts and delay
- `spawn_reconnector()` - Background reconnection task
- `start_server()` - TLS-enabled TCP listener

### 2. Agent (`crates/agent/`)

**Purpose:** Endpoint agent that runs on each monitored host.

**Key Types:**
- `AgentConfig` - Agent configuration (coordinator address, heartbeat interval)
- `AgentEngine` - Core agent logic
- `AgentStatus` - Current agent state
- `HeartbeatPayload` - System health, telemetry status, detection stats
- `PolicyPayload` - Distributed policy configuration
- `RemoteActionRequest` / `RemoteActionResult` - Remote command execution

**Agent Lifecycle:**
1. **Initialization** - Detect hostname, kernel, distribution, architecture
2. **Registration** - Send Registration message to coordinator
3. **Connected** - Send heartbeats, receive policies, handle actions
4. **Disconnected** - Graceful shutdown

**Heartbeat (every 30s):**
- System health (CPU, memory, disk, load average)
- Telemetry status (active providers, events, drops)
- Detection stats (threats, incidents, scans)

**Policy Receipt:**
- Receive Policy messages from coordinator
- Store locally in HashMap
- Send PolicyAck back

**Remote Action Execution:**
- Receive RemoteAction messages
- Queue via mpsc channel
- Execute locally (kill process, collect memory, etc.)
- Send RemoteActionResult back

**System Detection:**
- `/etc/hostname` for hostname
- `/proc/version` for kernel version
- `/etc/os-release` for distribution
- `/proc/meminfo` for memory stats
- `/proc/loadavg` for load averages

### 3. Coordinator (`crates/coordinator/`)

**Purpose:** Central coordination point for all fleet agents.

**Key Types:**
- `CoordinatorConfig` - Bind address, heartbeat timeout, max agents
- `CoordinatorEngine` - Core coordinator logic
- `AgentRecord` - Registered agent information
- `HeartbeatRecord` - Heartbeat data with timestamps
- `PolicyRecord` - Distributed policy with version tracking
- `CoordinatorStats` - Aggregate statistics

**Responsibilities:**
- **Agent Registration** - Register/unregister agents, track metadata
- **Heartbeat Tracking** - Receive heartbeats, update agent status
- **Health Monitoring** - Detect stale/degraded/offline agents
- **Policy Distribution** - Create and distribute policies to all agents
- **Incident Aggregation** - Collect incidents from agents
- **Event Broadcasting** - broadcast::channel for internal events

**Health Status Logic:**
- `Healthy` - Last heartbeat within timeout
- `Degraded` - Last heartbeat between timeout and 3x timeout
- `Offline` - Last heartbeat older than 3x timeout

**Events:**
- `AgentRegistered(String)` - New agent connected
- `AgentDisconnected(String)` - Agent went offline
- `HeartbeatReceived(String)` - Heartbeat received
- `IncidentAggregated(String)` - Incident collected
- `PolicyDistributed(String)` - Policy sent to agents

### 4. Fleet (`crates/fleet/`)

**Purpose:** High-level fleet management and orchestration.

**Key Types:**
- `FleetConfig` - Combined coordinator + agent configuration
- `FleetManager` - Top-level fleet management
- `FleetOverview` - Aggregate fleet statistics
- `FleetAgentInfo` - Extended agent information
- `RemoteActionRecord` - Remote action audit trail

**Responsibilities:**
- **Agent Lifecycle** - Register, track, unregister agents
- **Heartbeat Processing** - Route heartbeats to coordinator
- **Action Management** - Create, track, complete remote actions
- **Policy Distribution** - Delegate to coordinator
- **Overview** - Aggregate stats across all agents

**Events:**
- `AgentRegistered(String)`
- `AgentHeartbeat(String)`
- `ActionRequested(String)`
- `ActionCompleted(String)`

## Database Schema

### Tables (5 new)

| Table | Primary Key | Purpose |
|-------|-------------|---------|
| `fleet_agents` | `id TEXT` | Registered agent metadata |
| `fleet_health` | `id INTEGER AUTO` | System health snapshots |
| `fleet_policies` | `id TEXT` | Distributed policy records |
| `remote_actions` | `id TEXT` | Remote action audit trail |
| `heartbeat_history` | `id INTEGER AUTO` | Heartbeat history |

### Repositories (5 new)

| Repository | Table | Methods |
|-----------|-------|---------|
| `FleetAgentRepository` | `fleet_agents` | insert, find_by_id, find_all, find_by_status, update_heartbeat, update_stats, delete, count, count_by_status |
| `FleetHealthRepository` | `fleet_health` | insert, find_by_agent_id, find_recent, cleanup_old |
| `FleetPolicyRepository` | `fleet_policies` | insert, find_by_id, find_all, find_by_type, update_enabled, delete |
| `RemoteActionRepository` | `remote_actions` | insert, find_by_id, find_by_agent_id, find_by_status, update_status, cleanup_old |
| `HeartbeatHistoryRepository` | `heartbeat_history` | insert, find_by_agent_id, find_recent, cleanup_old |

## REST API

### Fleet Endpoints

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

## CLI Commands

| Command | Description |
|---------|-------------|
| `sentinelx fleet` | Fleet overview with agent counts and stats |
| `sentinelx fleet-agents` | List all agents with status |
| `sentinelx fleet-agent <id>` | Detailed agent information |
| `sentinelx fleet-policies` | List distributed policies |
| `sentinelx fleet-actions` | List recent remote actions |

## Message Protocol

### Message Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `Registration` | Agent → Coordinator | Agent registration |
| `RegistrationAck` | Coordinator → Agent | Registration confirmed |
| `Heartbeat` | Agent → Coordinator | Periodic health report |
| `HeartbeatAck` | Coordinator → Agent | Heartbeat acknowledged |
| `Policy` | Coordinator → Agent | Policy distribution |
| `PolicyAck` | Agent → Coordinator | Policy received |
| `RemoteAction` | Coordinator → Agent | Execute action |
| `RemoteActionResult` | Agent → Coordinator | Action result |
| `Incident` | Agent → Coordinator | Incident report |
| `Threat` | Agent → Coordinator | Threat report |
| `VersionNegotiation` | Both | Protocol version |
| `Ping` / `Pong` | Both | Connectivity check |

### Wire Format

```
[4 bytes: length (LE)] [JSON payload]
```

- Length prefix: `u32` little-endian
- Payload: JSON-serialized `Message` struct
- Optional gzip compression for large payloads

## Security

- **mTLS**: Optional mutual TLS authentication (rustls)
- **Certificate Management**: CA-signed certificates via TlsConfig
- **Message Signing**: Correlation IDs for request-response matching
- **Replay Protection**: Timestamp-based message validation
- **Rate Limiting**: Configurable max agents and heartbeat intervals
- **Version Negotiation**: Protocol version checking on connect

## Performance

- **1000+ agents**: Async architecture with tokio
- **Connection Pooling**: HashMap-based connection management
- **Compression**: Gzip reduces bandwidth by ~60% for telemetry data
- **Batch Processing**: Heartbeat aggregation and incident batching
- **Lock-Free Stats**: AtomicU64 for high-frequency counters

## Test Coverage

| Crate | Tests | Focus |
|-------|-------|-------|
| sentinelx-transport | 16 | Serialization, compression, version negotiation, stats |
| sentinelx-agent | 14 | Creation, start/stop, heartbeat, policies, system detection |
| sentinelx-coordinator | 10 | Registration, heartbeat, stale detection, policies, stats |
| sentinelx-fleet | 10 | Overview, agents, heartbeats, actions, policies |
| **Total new** | **50** | |

## Integration Points

### Backend (main.rs)
```rust
let (fleet_tx, _fleet_rx) = tokio::sync::mpsc::channel(100);
let coordinator = Arc::new(CoordinatorEngine::new(CoordinatorConfig::default(), fleet_tx));
let fleet_manager = Arc::new(FleetManager::new(coordinator));
fleet_manager.start().await;
// Added to AppState as fleet_manager: Arc<FleetManager>
```

### CLI
```rust
// sentinelx fleet           → Fleet overview
// sentinelx fleet-agents    → Agent list
// sentinelx fleet-agent ID  → Agent detail
// sentinelx fleet-policies  → Policy list
// sentinelx fleet-actions   → Action list
```

### Database
- 5 new tables in store.rs migrations
- 5 new repositories following existing pattern
- All indexes on frequently queried columns
