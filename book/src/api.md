# REST API Reference

SentinelX exposes a REST API via Axum with OpenAPI documentation. The default listen address is `0.0.0.0:8443`.

## Health and Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/status` | System status with metrics |

## Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Run a detection scan |
| GET | `/api/detectors` | List available detectors |

## Detection Results

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/processes` | List running processes |
| GET | `/api/modules` | List kernel modules |
| GET | `/api/network` | List network connections |
| GET | `/api/integrity` | Kernel and file integrity status |

## Threats and Incidents

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threats` | List threats with risk scores |
| GET | `/api/incidents` | Security incidents |
| GET | `/api/timeline` | Threat event timeline |
| GET | `/api/correlation` | Correlation graph |

## Assessment

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/assessment` | Assessment results |
| GET | `/api/assessment/{object_id}` | Assessment for specific object |

## Telemetry

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/telemetry` | Telemetry engine status |
| GET | `/api/telemetry/events` | Recent telemetry events |
| GET | `/api/telemetry/stats` | Telemetry bus statistics |
| GET | `/api/telemetry/providers` | Registered providers |
| GET | `/api/telemetry/providers/health` | Provider health with uptime and drop rates |
| GET | `/api/telemetry/providers/latency` | Provider kernel latency |

## Behavioral Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/behavior` | Behavioral engine status |
| GET | `/api/behavior/profiles` | Behavioral profiles |
| GET | `/api/behavior/stats` | Scoring weights and statistics |

## Threat Intelligence

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/intel` | Intelligence engine status |
| GET | `/api/intel/mitre` | MITRE ATT&CK technique coverage |
| GET | `/api/intel/iocs` | Loaded Indicators of Compromise |
| GET | `/api/intel/iocs/check` | Check an IoC value |
| GET | `/api/intel/cves` | Tracked CVEs |
| GET | `/api/intel/yara` | Loaded YARA rules |
| GET | `/api/intel/sigma` | Loaded Sigma rules |

## Response Engine

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/response` | Response engine status and history |
| GET | `/api/response/workflows` | Available workflows and policies |
| GET | `/api/response/audit` | Response audit log |

## Forensics and Reporting

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/forensics` | Collect forensic snapshot |
| GET | `/api/report` | Generate report |
| POST | `/api/export` | Export data |

## Evidence

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/evidence` | List evidence records |
| GET | `/api/evidence/{id}` | Get evidence by ID |

## Fleet Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/fleet` | Fleet overview (agent counts, stats, uptime) |
| GET | `/api/fleet/agents` | List all agents with status |
| GET | `/api/fleet/agents/{id}` | Detailed info for one agent |
| POST | `/api/fleet/agents/{id}/deregister` | Remove agent from fleet |
| POST | `/api/fleet/heartbeat` | Receive agent heartbeat |
| GET | `/api/fleet/policies` | List distributed policies |
| POST | `/api/fleet/policies` | Distribute new policy |
| GET | `/api/fleet/actions` | List recent remote actions |
| POST | `/api/fleet/actions` | Request new remote action |
| GET | `/api/fleet/actions/{id}` | Get action detail |
| GET | `/api/fleet/stats` | Fleet statistics |

## Configuration

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/config` | Current configuration |
| PUT | `/api/config` | Update configuration |

## Response Format

All endpoints return JSON. Successful responses:

```json
{
  "status": "ok",
  "data": { ... }
}
```

Error responses:

```json
{
  "status": "error",
  "error": "Description of the error"
}
```

## CORS

CORS origins are configured in `sentinelx.toml`:

```toml
[api]
cors_origins = ["http://localhost:3000"]
```

## TLS

Enable TLS for the API:

```toml
[api]
tls_enabled = true
```

See [Deployment](deployment.md) for TLS certificate setup.
