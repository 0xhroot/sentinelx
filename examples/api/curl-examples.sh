#!/usr/bin/env bash
# Comprehensive SentinelX REST API curl examples.
# Usage: ./curl-examples.sh [HOST] [PORT]

set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-8443}"
BASE="http://${HOST}:${PORT}"
H="Content-Type: application/json"

echo "SentinelX API Examples — ${BASE}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── Health & Status ──"
curl -s "${BASE}/api/health"
curl -s "${BASE}/api/status"
echo ""

echo "# ── Kernel Integrity ──"
curl -s "${BASE}/api/kernel/integrity"
echo ""

echo "# ── Memory Integrity ──"
curl -s "${BASE}/api/memory/integrity"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# DETECTION
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── Run Full Scan ──"
curl -s -X POST "${BASE}/api/scan"
echo ""

echo "# ── Run Specific Detector (e.g. hook_detection) ──"
curl -s -X POST "${BASE}/api/scan/hook_detection"
echo ""

echo "# ── List Detectors ──"
curl -s "${BASE}/api/detectors"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# THREATS
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── List Threats ──"
curl -s "${BASE}/api/threats"
echo ""

echo "# ── Threat Statistics ──"
curl -s "${BASE}/api/threats/stats"
echo ""

echo "# ── Get Single Threat ──"
THREAT_ID=$(curl -s "${BASE}/api/threats" | python3 -c "import sys,json; ts=json.load(sys.stdin); print(ts[0]['id'] if ts else '')" 2>/dev/null || true)
if [ -n "$THREAT_ID" ]; then
  curl -s "${BASE}/api/threats/${THREAT_ID}"
fi
echo ""

echo "# ── Acknowledge a Threat ──"
if [ -n "${THREAT_ID:-}" ]; then
  curl -s -X POST "${BASE}/api/threats/${THREAT_ID}/acknowledge"
fi
echo ""

echo "# ── Resolve a Threat ──"
if [ -n "${THREAT_ID:-}" ]; then
  curl -s -X POST "${BASE}/api/threats/${THREAT_ID}/resolve"
fi
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# FORENSICS & EVIDENCE
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── Processes ──"
curl -s "${BASE}/api/processes"
echo ""

echo "# ── Kernel Modules ──"
curl -s "${BASE}/api/modules"
echo ""

echo "# ── Network Connections ──"
curl -s "${BASE}/api/network"
echo ""

echo "# ── Collect Forensic Snapshot ──"
curl -s "${BASE}/api/forensics"
echo ""

echo "# ── Generate Report ──"
curl -s "${BASE}/api/report"
echo ""

echo "# ── List Evidence ──"
curl -s "${BASE}/api/evidence"
echo ""

echo "# ── Trigger Evidence Collection ──"
curl -s -X POST "${BASE}/api/evidence/collect"
echo ""

echo "# ── Evidence Statistics ──"
curl -s "${BASE}/api/evidence/stats"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# TIMELINE & INCIDENTS
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── Timeline ──"
curl -s "${BASE}/api/timeline"
echo ""

echo "# ── Events (stored) ──"
curl -s "${BASE}/api/events"
echo ""

echo "# ── Live Events Stream ──"
curl -s "${BASE}/api/events/live"
echo ""

echo "# ── List Incidents ──"
curl -s "${BASE}/api/incidents"
echo ""

echo "# ── Get Single Incident ──"
INC_ID=$(curl -s "${BASE}/api/incidents" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['incidents'][0]['id'] if d.get('incidents') else '')" 2>/dev/null || true)
if [ -n "$INC_ID" ]; then
  curl -s "${BASE}/api/incidents/${INC_ID}"
fi
echo ""

echo "# ── Update Incident Status ──"
if [ -n "${INC_ID:-}" ]; then
  curl -s -X POST "${BASE}/api/incidents/${INC_ID}/status" \
    -H "${H}" -d '{"status":"investigating"}'
fi
echo ""

echo "# ── Threat Decisions ──"
curl -s "${BASE}/api/threat-decisions"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# CORRELATION & SCORING
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── List Correlations ──"
curl -s "${BASE}/api/correlations"
echo ""

echo "# ── Run Correlations ──"
curl -s -X POST "${BASE}/api/correlations/run"
echo ""

echo "# ── Correlation Statistics ──"
curl -s "${BASE}/api/correlations/stats"
echo ""

echo "# ── Run Threat Scoring ──"
curl -s -X POST "${BASE}/api/scoring/run"
echo ""

echo "# ── Graph Overview ──"
curl -s "${BASE}/api/graph"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# RULES ENGINE
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── List Rules ──"
curl -s "${BASE}/api/rules"
echo ""

echo "# ── Add a Rule ──"
curl -s -X POST "${BASE}/api/rules" \
  -H "${H}" -d '{
  "name": "detect_crypto_miner",
  "description": "Alert on known crypto mining process names",
  "enabled": true,
  "severity": "high",
  "category": "cryptomining",
  "condition": {
    "field": "process_name",
    "operator": "in",
    "value": ["xmrig","minerd","cpuminer","ethminer"]
  },
  "actions": [
    {"type":"alert"},
    {"type":"log_event"}
  ],
  "tags": ["cryptomining","performance"]
}'
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# TRUST ENGINE
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── Trust Sources ──"
curl -s "${BASE}/api/trust"
echo ""

echo "# ── Record Confirmed Positive ──"
curl -s -X POST "${BASE}/api/trust/test-detector/positive"
echo ""

echo "# ── Record False Positive ──"
curl -s -X POST "${BASE}/api/trust/test-detector/false-positive"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# RESPONSE & WORKFLOWS
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── Response History ──"
curl -s "${BASE}/api/responses"
echo ""

echo "# ── Response Audit Log ──"
curl -s "${BASE}/api/responses/audit"
echo ""

echo "# ── Workflows & Policies ──"
curl -s "${BASE}/api/workflows"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# TELEMETRY
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── Telemetry Events (stored) ──"
curl -s "${BASE}/api/telemetry"
echo ""

echo "# ── Live Telemetry ──"
curl -s "${BASE}/api/telemetry/live"
echo ""

echo "# ── Telemetry Providers ──"
curl -s "${BASE}/api/telemetry/providers"
echo ""

echo "# ── Provider Health ──"
curl -s "${BASE}/api/telemetry/providers/health"
echo ""

echo "# ── Provider Latency ──"
curl -s "${BASE}/api/telemetry/providers/latency"
echo ""

echo "# ── Telemetry Rate ──"
curl -s "${BASE}/api/telemetry/providers/rate"
echo ""

echo "# ── Provider Capabilities ──"
curl -s "${BASE}/api/telemetry/providers/capabilities"
echo ""

echo "# ── Telemetry Stats ──"
curl -s "${BASE}/api/telemetry/stats"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# BEHAVIORAL ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── Behavior Profiles ──"
curl -s "${BASE}/api/behavior/profiles"
echo ""

echo "# ── Record a Behavior Event ──"
curl -s -X POST "${BASE}/api/behavior/record" \
  -H "${H}" -d '{
  "provider": "process_monitor",
  "object_id": "process/1234",
  "category": "execution",
  "event_type": "process_start",
  "pid": 1234,
  "uid": 0,
  "command_line": "/usr/bin/suspicious --flag",
  "description": "Suspicious process started",
  "severity": "medium",
  "confidence": 0.75
}'
echo ""

echo "# ── Behavior Stats ──"
curl -s "${BASE}/api/behavior/stats"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── Intelligence Stats ──"
curl -s "${BASE}/api/intelligence/stats"
echo ""

echo "# ── List IoCs ──"
curl -s "${BASE}/api/intelligence/iocs"
echo ""

echo "# ── Add an IoC ──"
curl -s -X POST "${BASE}/api/intelligence/iocs" \
  -H "${H}" -d '{
  "ioc_type": "hash",
  "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "severity": "critical",
  "confidence": 0.95,
  "source": "threat-intel-feed",
  "description": "Known malware sample hash"
}'
echo ""

echo "# ── Check an IoC ──"
curl -s "${BASE}/api/intelligence/iocs/hash/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
echo ""

echo "# ── MITRE ATT&CK Techniques ──"
curl -s "${BASE}/api/intelligence/mitre"
echo ""

echo "# ── YARA Rules ──"
curl -s "${BASE}/api/intelligence/yara"
echo ""

echo "# ── Sigma Rules ──"
curl -s "${BASE}/api/intelligence/sigma"
echo ""

echo "# ── CVE Entries ──"
curl -s "${BASE}/api/intelligence/cves"
echo ""

echo "# ── Global Reputation ──"
curl -s "${BASE}/api/intelligence/reputation"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# FLEET MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

echo "# ── Fleet Overview ──"
curl -s "${BASE}/api/fleet"
echo ""

echo "# ── Fleet Agents ──"
curl -s "${BASE}/api/fleet/agents"
echo ""

echo "# ── Fleet Stats ──"
curl -s "${BASE}/api/fleet/stats"
echo ""

echo "# ── Fleet Policies ──"
curl -s "${BASE}/api/fleet/policies"
echo ""

echo "# ── Distribute a Policy ──"
curl -s -X POST "${BASE}/api/fleet/policies" \
  -H "${H}" -d '{
  "name": "enable-file-integrity",
  "policy_type": "monitoring",
  "config": {
    "file_integrity_monitoring": true
  }
}'
echo ""

echo "# ── Fleet Actions ──"
curl -s "${BASE}/api/fleet/actions"
echo ""

echo "# ── Request a Remote Action ──"
curl -s -X POST "${BASE}/api/fleet/actions" \
  -H "${H}" -d '{
  "agent_id": "agent-001",
  "action_type": "scan",
  "params": {}
}'
echo ""

echo "# ── Send Heartbeat ──"
curl -s -X POST "${BASE}/api/fleet/heartbeat" \
  -H "${H}" -d '{
  "agent_id": "agent-001",
  "hostname": "web-server-01",
  "status": "healthy",
  "version": "1.0.0"
}'
echo ""

echo "=== All examples complete ==="
