# Plugin Development Guide

SentinelX supports extensibility through custom rules and response actions.

## Custom Detection Rules

### Rule Engine

The `sentinelx-rule-engine` crate provides a TOML-based rule definition system for user-defined detection rules.

### Rule Format

Rules are defined in TOML files and loaded at startup:

```toml
[[rules]]
name = "suspicious_ssh_backdoor"
description = "Detects SSH backdoor via unusual authorized_keys"
severity = "high"
mitre_attack = "T1098"

[[rules.conditions]]
field = "process.command_line"
operator = "contains"
value = "authorized_keys"

[[rules.conditions]]
field = "file.path"
operator = "matches"
pattern = "\\.ssh/authorized_keys$"

[[rules.actions]]
type = "alert"
severity = "critical"
```

### Condition Operators

| Operator | Description |
|----------|-------------|
| `equals` | Exact string match |
| `contains` | Substring match |
| `matches` | Regex pattern match |
| `gt` / `lt` | Numeric comparison |
| `in` | Value in list |
| `exists` | Field existence check |

### Rule Loading

```toml
[detection]
custom_rules_path = "/etc/sentinelx/rules/"
```

Place `.toml` rule files in the configured directory. Rules are loaded on startup and can be reloaded via API:

```bash
curl -X POST http://localhost:8443/api/config/reload-rules
```

## Custom Response Actions

### Response Action Trait

Implement the `ResponseAction` trait to create custom response actions:

```rust
#[async_trait]
pub trait ResponseAction: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn execute(&self, context: &ResponseContext) -> Result<ResponseResult>;
}
```

### ResponseContext

The context provides:

- Threat details (severity, type, indicators)
- Affected object information
- Evidence references
- Configuration settings

### ResponseResult

```rust
pub struct ResponseResult {
    pub success: bool,
    pub message: String,
    pub action_taken: String,
    pub duration_ms: u64,
}
```

### Safety Controls

All response actions respect:

- **Dry-run mode**: `--dry-run` flag or `response.dry_run = true` in config
- **Rate limiting**: Configurable rate limits per action type
- **Severity thresholds**: Only act on threats above configured severity
- **Audit logging**: Every action is logged regardless of dry-run mode

### Response Configuration

```toml
[response]
enabled = true
dry_run = false
max_actions_per_minute = 10
default_actions = ["alert"]
severity_threshold = "medium"
```

### Available Built-in Actions

| Action | Description |
|--------|-------------|
| `alert` | Generate alert notification |
| `kill_process` | Terminate malicious process |
| `block_connection` | Block network connection via iptables |
| `quarantine_file` | Move suspicious file to quarantine |
| `isolate_host` | Network isolation (fleet) |

## Custom Telemetry Providers

### TelemetryProvider Trait

```rust
#[async_trait]
pub trait TelemetryProvider: Send + Sync {
    fn name(&self) -> &str;
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    fn status(&self) -> ProviderStatus;
}
```

### Provider Lifecycle

1. `start()` — Initialize the provider and begin event collection
2. Events are sent to the `TelemetryBus`
3. `stop()` — Gracefully shut down the provider

### Provider Status

```rust
pub enum ProviderStatus {
    Running,
    Degraded(String),
    Stopped,
    Error(String),
}
```

## Intelligence Engine Extension

### Custom IoC Sources

Add custom IoC databases by placing files in the configured directory:

```toml
[intelligence]
ioc_path = "/etc/sentinelx/iocs/"
yara_path = "/etc/sentinelx/rules/yara/"
sigma_path = "/etc/sentinelx/rules/sigma/"
```

### IoC File Format

```
# One IoC per line
hash:sha256:abcdef1234567890...
ip:192.168.1.100
domain:evil.example.com
url:https://evil.example.com/payload
```

## Architecture

### Plugin Isolation

- Detection rules run in the main pipeline process
- Response actions execute with the same privileges as SentinelX
- Telemetry providers run as async tasks within the Tokio runtime

### Future: Dynamic Plugin Loading (v2.0)

The roadmap includes:

- Dynamic plugin loading via shared libraries
- Sandboxed plugin execution
- Plugin marketplace for community contributions
- Plugin API for detection, response, and telemetry
