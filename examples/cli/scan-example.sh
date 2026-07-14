#!/usr/bin/env bash
# SentinelX CLI Usage Examples
# These commands demonstrate every CLI subcommand available in sentinelx.
# Requires: sentinelx binary in PATH (or adjust PATH below).
#
# Global flag:
#   --config <path>    Path to a custom sentinelx.toml config file

set -euo pipefail

BIN="${SENTINELX_BIN:-sentinelx-cli}"

echo "=== SentinelX CLI Examples ==="
echo ""

# ── Full Detection Scan ───────────────────────────────────────────────────────
echo "# Run a full detection scan across all enabled detectors"
${BIN} scan
echo ""

# ── Continuous Monitor Mode ───────────────────────────────────────────────────
echo "# Run continuous monitoring with a 60-second scan interval (default)"
${BIN} monitor
echo ""

echo "# Run continuous monitoring with a 30-second scan interval"
${BIN} monitor --interval 30
echo ""

# ── System Status ─────────────────────────────────────────────────────────────
echo "# Show system status, metrics, and detector count"
${BIN} status
echo ""

# ── Kernel & File Integrity ───────────────────────────────────────────────────
echo "# Show kernel and file integrity status (secure boot, kptr_restrict, etc.)"
${BIN} integrity
echo ""

# ── Loaded Kernel Modules ─────────────────────────────────────────────────────
echo "# List loaded kernel modules with trust assessment"
${BIN} modules
echo ""

# ── Running Processes ─────────────────────────────────────────────────────────
echo "# List running processes with suspicious indicators"
${BIN} processes
echo ""

# ── Network Connections ───────────────────────────────────────────────────────
echo "# List active network connections"
${BIN} network
echo ""

# ── Threat Timeline ───────────────────────────────────────────────────────────
echo "# Display the threat event timeline"
${BIN} timeline
echo ""

# ── Forensics Snapshot ────────────────────────────────────────────────────────
echo "# Collect a comprehensive forensic snapshot"
${BIN} forensics
echo ""

# ── Export Report ──────────────────────────────────────────────────────────────
echo "# Export threats to JSON in a local directory"
${BIN} export --format json --output sentinelx-report
echo ""

echo "# Export threats to Markdown"
${BIN} export --format markdown --output sentinelx-report
echo ""

# ── Show Configuration ────────────────────────────────────────────────────────
echo "# Display current resolved configuration"
${BIN} config
echo ""

# ── Assessment Engine ─────────────────────────────────────────────────────────
echo "# Run the central assessment engine (all object types)"
${BIN} assess
echo ""

echo "# Run assessment filtered to processes only"
${BIN} assess --object-type process
echo ""

echo "# Run assessment filtered to files"
${BIN} assess --object-type file
echo ""

echo "# Run assessment filtered to kernel modules"
${BIN} assess --object-type kernel_module
echo ""

# ── Incidents ─────────────────────────────────────────────────────────────────
echo "# Show correlated security incidents"
${BIN} incidents
echo ""

# ── Threats ───────────────────────────────────────────────────────────────────
echo "# Show threat decisions with risk scores"
${BIN} threats
echo ""

# ── Correlation Graph ─────────────────────────────────────────────────────────
echo "# Show the correlation graph and rules"
${BIN} graph
echo ""

# ── Response Engine ───────────────────────────────────────────────────────────
echo "# Show response engine status and history"
${BIN} response
echo ""

# ── Workflows & Policies ──────────────────────────────────────────────────────
echo "# Show available response workflows and policies"
${BIN} workflows
echo ""

# ── Audit Log ─────────────────────────────────────────────────────────────────
echo "# Show response audit log"
${BIN} audit
echo ""

# ── Telemetry ─────────────────────────────────────────────────────────────────
echo "# Show real-time telemetry engine status"
${BIN} telemetry
echo ""

echo "# Show last 50 telemetry events"
${BIN} events --count 50
echo ""

echo "# Show registered telemetry providers"
${BIN} providers
echo ""

echo "# Live monitoring of telemetry events (refresh every 2 seconds)"
${BIN} monitor-live --interval 2
echo ""

# ── Behavioral Analysis ──────────────────────────────────────────────────────
echo "# Show behavioral analysis engine status and rules"
${BIN} behavior
echo ""

echo "# Show behavioral profiles for tracked objects"
${BIN} behavior-profiles
echo ""

echo "# Show behavioral statistics and scoring weights"
${BIN} behavior-stats
echo ""

# ── Threat Intelligence ──────────────────────────────────────────────────────
echo "# Show threat intelligence engine status"
${BIN} intel
echo ""

echo "# Show MITRE ATT&CK technique coverage"
${BIN} mitre
echo ""

echo "# Show loaded Indicators of Compromise"
${BIN} iocs
echo ""

echo "# Check if a specific hash IoC is known malicious"
${BIN} ioc-check hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
echo ""

echo "# Check if an IP IoC is known malicious"
${BIN} ioc-check ip_address 192.168.1.100
echo ""

echo "# Show tracked CVE vulnerabilities"
${BIN} cves
echo ""

echo "# Show loaded YARA rules"
${BIN} yara
echo ""

echo "# Show loaded Sigma detection rules"
${BIN} sigma
echo ""

# ── eBPF Kernel Sensor ───────────────────────────────────────────────────────
echo "# Show eBPF kernel sensor status and capabilities"
${BIN} ebpf
echo ""

echo "# Show telemetry provider health with detailed diagnostics"
${BIN} providers-health
echo ""

# ── Fleet Management ──────────────────────────────────────────────────────────
echo "# Show fleet overview and agent management"
${BIN} fleet
echo ""

echo "# List all fleet agents"
${BIN} fleet-agents
echo ""

echo "# Show detailed info for a specific agent"
${BIN} fleet-agent agent-001
echo ""

echo "# Show distributed fleet policies"
${BIN} fleet-policies
echo ""

echo "# Show recent remote actions"
${BIN} fleet-actions
echo ""

echo "=== CLI examples complete ==="
