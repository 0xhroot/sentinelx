# CLI Reference

`sentinelx-cli` provides a full-featured command-line interface for SentinelX.

## Global Options

```bash
sentinelx-cli [OPTIONS] <COMMAND>

--config <PATH>    Path to configuration file
```

## Scanning and Monitoring

### scan

Run a full detection scan across all detectors.

```bash
sentinelx-cli scan
```

### monitor

Run continuous monitoring with periodic scans.

```bash
sentinelx-cli monitor --interval 60
```

| Option | Default | Description |
|--------|---------|-------------|
| `--interval` | 60 | Scan interval in seconds |

### monitor-live

Live monitoring of telemetry events in real-time.

```bash
sentinelx-cli monitor-live --interval 1
```

## System Information

### status

Show system status, metrics, and detector information.

```bash
sentinelx-cli status
```

### config

Show current configuration.

```bash
sentinelx-cli config
```

### ebpf

Show eBPF kernel sensor status and capabilities.

```bash
sentinelx-cli ebpf
```

## Detection Results

### integrity

Show kernel and file integrity status.

```bash
sentinelx-cli integrity
```

### modules

List loaded kernel modules with trust assessment.

```bash
sentinelx-cli modules
```

### processes

List running processes with suspicious indicators.

```bash
sentinelx-cli processes
```

### network

List active network connections.

```bash
sentinelx-cli network
```

## Assessment and Analysis

### assess

Run the central assessment engine.

```bash
sentinelx-cli assess --object-type process
```

| Option | Description |
|--------|-------------|
| `--object-type` | Object type to assess: `process`, `module`, `network`, `service` |

### threats

Show threat decisions with risk scores.

```bash
sentinelx-cli threats
```

### incidents

Show correlated security incidents.

```bash
sentinelx-cli incidents
```

### timeline

Display the threat event timeline.

```bash
sentinelx-cli timeline
```

### graph

Show the correlation graph and rules.

```bash
sentinelx-cli graph
```

## Telemetry

### telemetry

Show real-time telemetry engine status and events.

```bash
sentinelx-cli telemetry
```

### events

Show recent telemetry events.

```bash
sentinelx-cli events --count 20
```

| Option | Default | Description |
|--------|---------|-------------|
| `--count` | 20 | Number of events to display |

### providers

Show registered telemetry providers.

```bash
sentinelx-cli providers
```

### providers-health

Show telemetry provider health with diagnostics.

```bash
sentinelx-cli providers-health
```

## Behavioral Analysis

### behavior

Show behavioral engine status and rules.

```bash
sentinelx-cli behavior
```

### behavior-profiles

Show behavioral profiles.

```bash
sentinelx-cli behavior-profiles
```

### behavior-stats

Show behavioral statistics and scoring weights.

```bash
sentinelx-cli behavior-stats
```

## Threat Intelligence

### intel

Show threat intelligence engine status.

```bash
sentinelx-cli intel
```

### mitre

Show MITRE ATT&CK technique coverage.

```bash
sentinelx-cli mitre
```

### iocs

Show loaded Indicators of Compromise.

```bash
sentinelx-cli iocs
```

### ioc-check

Check if an IoC is known malicious.

```bash
sentinelx-cli ioc-check hash <value>
```

### cves

Show tracked CVE vulnerabilities.

```bash
sentinelx-cli cves
```

### yara

Show loaded YARA rules.

```bash
sentinelx-cli yara
```

### sigma

Show loaded Sigma detection rules.

```bash
sentinelx-cli sigma
```

## Response

### response

Show response engine status and history.

```bash
sentinelx-cli response
```

### workflows

Show available workflows and policies.

```bash
sentinelx-cli workflows
```

### audit

Show response audit log.

```bash
sentinelx-cli audit
```

## Forensics and Reporting

### forensics

Collect a comprehensive forensic snapshot.

```bash
sentinelx-cli forensics
```

### export

Export threats or reports to a file.

```bash
sentinelx-cli export --format json --output /var/lib/sentinelx/reports
sentinelx-cli export --format markdown --output /var/lib/sentinelx/reports
```

| Option | Description |
|--------|-------------|
| `--format` | Output format: `json`, `markdown` |
| `--output` | Output directory path |

## Fleet Management

### fleet

Show fleet overview with agent counts and stats.

```bash
sentinelx-cli fleet
```

### fleet-agents

List all fleet agents with status.

```bash
sentinelx-cli fleet-agents
```

### fleet-agent

Show detailed information for a specific agent.

```bash
sentinelx-cli fleet-agent <id>
```

### fleet-policies

Show distributed fleet policies.

```bash
sentinelx-cli fleet-policies
```

### fleet-actions

Show recent remote actions.

```bash
sentinelx-cli fleet-actions
```

## Command Summary

| Command | Description |
|---------|-------------|
| `scan` | Run full detection scan |
| `monitor` | Continuous monitoring mode |
| `monitor-live` | Live telemetry event monitoring |
| `status` | System status and metrics |
| `config` | Show configuration |
| `ebpf` | eBPF kernel sensor status |
| `integrity` | Kernel and file integrity |
| `modules` | Kernel modules with trust |
| `processes` | Running processes |
| `network` | Network connections |
| `assess` | Run assessment engine |
| `threats` | Threat decisions |
| `incidents` | Security incidents |
| `timeline` | Event timeline |
| `graph` | Correlation graph |
| `telemetry` | Telemetry engine status |
| `events` | Recent telemetry events |
| `providers` | Telemetry providers |
| `providers-health` | Provider health diagnostics |
| `behavior` | Behavioral engine status |
| `behavior-profiles` | Behavioral profiles |
| `behavior-stats` | Behavioral statistics |
| `intel` | Intelligence engine status |
| `mitre` | MITRE ATT&CK coverage |
| `iocs` | Indicators of Compromise |
| `ioc-check` | Check IoC value |
| `cves` | Tracked CVEs |
| `yara` | YARA rules |
| `sigma` | Sigma rules |
| `response` | Response engine status |
| `workflows` | Response workflows |
| `audit` | Response audit log |
| `forensics` | Collect forensic snapshot |
| `export` | Export reports |
| `fleet` | Fleet overview |
| `fleet-agents` | List fleet agents |
| `fleet-agent` | Agent details |
| `fleet-policies` | Fleet policies |
| `fleet-actions` | Remote actions |
