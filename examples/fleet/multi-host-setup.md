# SentinelX Fleet — Multi-Host Monitoring Setup

This guide covers deploying SentinelX across multiple Linux hosts with centralized
fleet management via the REST API.

## Architecture

```
┌──────────────┐
│  Management  │   sentinelx backend (fleet manager)
│     Host     │   http://<mgmt>:8443/api/fleet/*
└──────┬───────┘
       │  REST API (heartbeat + remote actions)
       ├──────────────────┬──────────────────┐
       ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Agent A    │  │   Agent B    │  │   Agent C    │
│  web-01      │  │  db-01       │  │  worker-01   │
│  sentinelx   │  │  sentinelx   │  │  sentinelx   │
│  (agent)     │  │  (agent)     │  │  (agent)     │
└──────────────┘  └──────────────┘  └──────────────┘
```

Each agent runs a standalone SentinelX instance with detection enabled and sends
periodic heartbeats to the management host. The management host provides the
central dashboard and fleet APIs.

## 1. Deploy the Management Host

Install SentinelX on the central host and enable the API server:

```toml
# /etc/sentinelx/sentinelx.toml on the management host
[general]
hostname = "sentinelx-mgmt"
scan_interval_seconds = 300
baseline_on_start = true
max_memory_mb = 256
max_cpu_percent = 5.0

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
severity_threshold = "low"
mitre_attack_mapping = true
evidence_collection = true

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
retention_days = 180
max_events = 5000000

[api]
enabled = true
host = "0.0.0.0"
port = 8443
tls_enabled = true
cors_origins = ["https://dashboard.internal"]

[logging]
level = "info"
format = "pretty"
file_output = true
json_format = true

[ebpf]
enabled = true
map_size = 20480
perf_buffer_pages = 128
max_events_per_second = 20000
```

Start the management host:

```bash
sudo sentinelx-cli scan   # Initial baseline
sudo sentinelx-cli monitor --interval 300
```

## 2. Deploy Agent Hosts

On each agent host, configure the agent to point at the management host.
SentinelX agents use the `sentinelx-transport` crate to send heartbeats
and receive remote actions.

```toml
# /etc/sentinelx/sentinelx.toml on each agent host
[general]
hostname = "web-01"
scan_interval_seconds = 60
baseline_on_start = true
max_memory_mb = 150
max_cpu_percent = 3.0

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
severity_threshold = "low"
mitre_attack_mapping = true
evidence_collection = true

[storage]
database_path = "/var/lib/sentinelx/sentinelx.db"
evidence_path = "/var/lib/sentinelx/evidence"
log_path = "/var/log/sentinelx"
retention_days = 90
max_events = 1000000

[api]
enabled = true
host = "127.0.0.1"
port = 8443
tls_enabled = false
cors_origins = []

[logging]
level = "info"
format = "compact"
file_output = true
json_format = true

[ebpf]
enabled = true
map_size = 10240
perf_buffer_pages = 64
max_events_per_second = 10000
```

Start each agent:

```bash
sudo sentinelx-cli scan
sudo sentinelx-cli monitor --interval 60
```

## 3. Register Agents

Agents register with the management host via heartbeats. The fleet manager
auto-registers unknown agents on first heartbeat.

Send a manual heartbeat from any agent (or let the agent do it automatically):

```bash
curl -X POST http://<mgmt>:8443/api/fleet/heartbeat \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "web-01",
    "hostname": "web-01",
    "status": "healthy",
    "version": "1.0.0"
  }'
```

## 4. Monitor Fleet Status

Check fleet overview from the management host:

```bash
# Fleet overview
curl -s http://<mgmt>:8443/api/fleet | python3 -m json.tool

# List all registered agents
curl -s http://<mgmt>:8443/api/fleet/agents | python3 -m json.tool

# Agent detail
curl -s http://<mgmt>:8443/api/fleet/agents/web-01 | python3 -m json.tool

# Fleet statistics
curl -s http://<mgmt>:8443/api/fleet/stats | python3 -m json.tool
```

Or via CLI:

```bash
sentinelx fleet
sentinelx fleet-agents
sentinelx fleet-agent web-01
```

## 5. Distribute Policies

Push monitoring policies to all agents from the management host:

```bash
curl -X POST http://<mgmt>:8443/api/fleet/policies \
  -H "Content-Type: application/json" \
  -d '{
    "name": "enable-full-monitoring",
    "policy_type": "monitoring",
    "config": {
      "process_monitoring": true,
      "network_monitoring": true,
      "module_monitoring": true,
      "memory_monitoring": true,
      "syscall_monitoring": true,
      "file_integrity_monitoring": true
    }
  }'
```

List distributed policies:

```bash
curl -s http://<mgmt>:8443/api/fleet/policies | python3 -m json.tool
```

## 6. Remote Actions

Trigger actions on specific agents from the management host:

```bash
# Trigger a scan on a specific agent
curl -X POST http://<mgmt>:8443/api/fleet/actions \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "web-01",
    "action_type": "scan",
    "params": {}
  }'

# Collect forensics from a specific agent
curl -X POST http://<mgmt>:8443/api/fleet/actions \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "db-01",
    "action_type": "forensics",
    "params": {}
  }'

# List recent remote actions
curl -s http://<mgmt>:8443/api/fleet/actions | python3 -m json.tool

# Get action detail
curl -s http://<mgmt>:8443/api/fleet/actions/<action-id> | python3 -m json.tool
```

## 7. Deregister an Agent

To remove an agent from the fleet:

```bash
curl -X POST http://<mgmt>:8443/api/fleet/agents/web-01/deregister
```

## Security Considerations

- **TLS**: Always enable TLS on the management host API in production
  (`tls_enabled = true` with valid cert/key paths).
- **Network Isolation**: Bind the API to an internal network interface
  and firewall port 8443.
- **Authentication**: SentinelX currently supports unauthenticated API access.
  Use network-level controls (mTLS, VPN, reverse proxy) to restrict access.
- **Credentials**: Never embed credentials in configuration files committed
  to version control.
- **Privilege**: Agents running with eBPF sensors require root or CAP_BPF.
  Minimize privilege where possible using capabilities rather than full root.
