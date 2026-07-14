#!/usr/bin/env bash
# SentinelX API Health Check & Basic Usage
# Usage: ./health-check.sh [HOST] [PORT]

set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-8443}"
BASE="http://${HOST}:${PORT}"

echo "=== SentinelX API Health Check ==="
echo "Target: ${BASE}"
echo ""

# ── Health Check ──────────────────────────────────────────────────────────────
echo "--- Health ---"
curl -s "${BASE}/api/health" | python3 -m json.tool
echo ""

# ── Status ────────────────────────────────────────────────────────────────────
echo "--- Status (metrics + detector count) ---"
curl -s "${BASE}/api/status" | python3 -m json.tool
echo ""

# ── List Threats ──────────────────────────────────────────────────────────────
echo "--- Recent Threats ---"
curl -s "${BASE}/api/threats" | python3 -m json.tool
echo ""

# ── Threat Statistics ─────────────────────────────────────────────────────────
echo "--- Threat Statistics ---"
curl -s "${BASE}/api/threats/stats" | python3 -m json.tool
echo ""

# ── Run Full Scan ─────────────────────────────────────────────────────────────
echo "--- Running Full Scan ---"
curl -s -X POST "${BASE}/api/scan" | python3 -m json.tool
echo ""

# ── Run a Specific Detector ───────────────────────────────────────────────────
echo "--- Running hook_detection detector ---"
curl -s -X POST "${BASE}/api/scan/hook_detection" | python3 -m json.tool
echo ""

# ── Timeline ──────────────────────────────────────────────────────────────────
echo "--- Threat Timeline ---"
curl -s "${BASE}/api/timeline" | python3 -m json.tool
echo ""

# ── Incidents ─────────────────────────────────────────────────────────────────
echo "--- Incidents ---"
curl -s "${BASE}/api/incidents" | python3 -m json.tool
echo ""

# ── Telemetry Events ─────────────────────────────────────────────────────────
echo "--- Telemetry Events (last 100) ---"
curl -s "${BASE}/api/telemetry" | python3 -m json.tool
echo ""

# ── Live Telemetry ────────────────────────────────────────────────────────────
echo "--- Live Telemetry Events (in-memory buffer) ---"
curl -s "${BASE}/api/telemetry/live" | python3 -m json.tool
echo ""

# ── Telemetry Stats ───────────────────────────────────────────────────────────
echo "--- Telemetry Bus Stats ---"
curl -s "${BASE}/api/telemetry/stats" | python3 -m json.tool
echo ""

# ── Detectors ─────────────────────────────────────────────────────────────────
echo "--- Loaded Detectors ---"
curl -s "${BASE}/api/detectors" | python3 -m json.tool
echo ""

echo "=== Health check complete ==="
