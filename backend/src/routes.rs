use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Json;
use serde::Serialize;
use tokio::sync::RwLock;

use sentinelx_behavior::engine::BehaviorEngine;
use sentinelx_common::types::ThreatEvent;
use sentinelx_database::repository::{
    EventRepository, EvidenceRepository, IncidentRepository, ResponseAuditRepository,
    TelemetryEventRepository, ThreatDecisionRepository, ThreatRepository,
};
use sentinelx_database::Store;
use sentinelx_detector::DetectionEngine;
use sentinelx_fleet::FleetManager;
use sentinelx_forensics::ForensicsCollector;
use sentinelx_incident::IncidentEngine;
use sentinelx_intelligence::engine::IntelligenceEngine;
use sentinelx_reporting::ReportGenerator;
use sentinelx_response::ResponseEngine;
use sentinelx_rule_engine::Rule;
use sentinelx_telemetry::{MetricsCollector, MetricsSnapshot, ProviderManager, TelemetryEngine};
use sentinelx_threat::ThreatEngine;
use sentinelx_timeline::TimelineEngine;

use crate::error::ApiError;

pub struct AppState {
    pub store: Arc<Store>,
    pub engine: Arc<DetectionEngine>,
    pub metrics: MetricsCollector,
    pub timeline: Arc<RwLock<TimelineEngine>>,
    pub incident_engine: Arc<IncidentEngine>,
    pub threat_engine: Arc<ThreatEngine>,
    pub response_engine: Arc<RwLock<ResponseEngine>>,
    pub telemetry_engine: Arc<TelemetryEngine>,
    pub behavior_engine: Arc<BehaviorEngine>,
    pub intelligence_engine: Arc<IntelligenceEngine>,
    pub provider_manager: Arc<ProviderManager>,
    pub fleet_manager: Arc<FleetManager>,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub metrics: MetricsSnapshot,
    pub detector_count: usize,
}

#[derive(Serialize)]
pub struct ScanResponse {
    pub threats_found: usize,
    pub threats: Vec<ThreatEvent>,
}

#[derive(Serialize)]
pub struct DetectorsResponse {
    pub detectors: Vec<sentinelx_detector::DetectorInfo>,
}

#[derive(Serialize)]
pub struct ThreatStatsResponse {
    pub total: i64,
    pub unacknowledged: i64,
    pub critical: i64,
    pub high: i64,
}

#[derive(Serialize)]
pub struct KernelIntegrityResponse {
    pub secure_boot: bool,
    pub kptr_restricted: bool,
    pub dmesg_restrict: bool,
    pub lockdown: String,
    pub checks: Vec<IntegrityCheck>,
}

#[derive(Serialize)]
pub struct IntegrityCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct MemoryIntegrityResponse {
    pub total_memory_kb: u64,
    pub available_memory_kb: u64,
    pub used_memory_kb: u64,
    pub swap_total_kb: u64,
    pub swap_used_kb: u64,
    pub checks: Vec<IntegrityCheck>,
}

pub fn router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/api/health", get(health))
        .route("/api/status", get(status))
        .route("/api/threats", get(list_threats))
        .route("/api/threats/stats", get(threat_stats))
        .route("/api/threats/{id}", get(get_threat))
        .route("/api/threats/{id}/acknowledge", post(acknowledge_threat))
        .route("/api/threats/{id}/resolve", post(resolve_threat))
        .route("/api/events", get(list_events))
        .route("/api/processes", get(list_processes))
        .route("/api/modules", get(list_modules))
        .route("/api/network", get(list_network))
        .route("/api/scan", post(scan_all))
        .route("/api/scan/{detector}", post(scan_detector))
        .route("/api/forensics", get(collect_forensics))
        .route("/api/report", get(generate_report))
        .route("/api/timeline", get(get_timeline))
        .route("/api/detectors", get(list_detectors))
        .route("/api/kernel/integrity", get(kernel_integrity))
        .route("/api/memory/integrity", get(memory_integrity))
        .route("/api/evidence", get(list_evidence))
        .route("/api/evidence/collect", post(collect_evidence))
        .route("/api/evidence/stats", get(evidence_stats))
        .route("/api/rules", get(list_rules))
        .route("/api/rules", post(add_rule))
        .route("/api/rules/{id}", get(get_rule))
        .route("/api/rules/{id}", axum::routing::delete(delete_rule))
        .route("/api/correlations", get(list_correlations))
        .route("/api/correlations/run", post(run_correlations))
        .route("/api/correlations/stats", get(correlation_stats))
        .route("/api/scoring/run", post(run_scoring))
        .route("/api/trust", get(list_trust_sources))
        .route("/api/trust/{source}", get(get_trust_source))
        .route("/api/trust/{source}/positive", post(record_positive))
        .route(
            "/api/trust/{source}/false-positive",
            post(record_false_positive),
        )
        .route("/api/incidents", get(list_incidents))
        .route("/api/incidents/{id}", get(get_incident))
        .route("/api/incidents/{id}/status", post(update_incident_status))
        .route("/api/threat-decisions", get(list_threat_decisions))
        .route("/api/threat-decisions/{id}", get(get_threat_decision))
        .route("/api/graph", get(get_graph))
        .route("/api/graph/{node_id}", get(get_graph_node))
        .route("/api/responses", get(list_responses))
        .route("/api/responses/audit", get(list_audit))
        .route(
            "/api/responses/audit/{threat_id}",
            get(get_audit_for_threat),
        )
        .route("/api/workflows", get(list_workflows))
        .route("/api/telemetry", get(list_telemetry_events))
        .route("/api/telemetry/live", get(live_telemetry_events))
        .route("/api/telemetry/providers", get(list_telemetry_providers))
        .route("/api/telemetry/providers/health", get(provider_health))
        .route("/api/telemetry/providers/latency", get(kernel_latency))
        .route("/api/telemetry/providers/rate", get(telemetry_rate))
        .route(
            "/api/telemetry/providers/capabilities",
            get(provider_capabilities),
        )
        .route("/api/telemetry/stats", get(telemetry_stats))
        .route("/api/events/live", get(live_events_stream))
        .route("/api/behavior/profiles", get(list_behavior_profiles))
        .route(
            "/api/behavior/profiles/{object_id}",
            get(get_behavior_profile),
        )
        .route("/api/behavior/record", post(record_behavior_event))
        .route("/api/behavior/stats", get(behavior_stats))
        .route("/api/intelligence/stats", get(intelligence_stats))
        .route("/api/intelligence/iocs", get(list_iocs))
        .route("/api/intelligence/iocs", post(add_ioc))
        .route("/api/intelligence/iocs/{type}/{value}", get(check_ioc))
        .route(
            "/api/intelligence/iocs/{type}/{value}",
            axum::routing::delete(delete_ioc),
        )
        .route("/api/intelligence/mitre", get(list_mitre_techniques))
        .route("/api/intelligence/mitre/{id}", get(get_mitre_technique))
        .route("/api/intelligence/yara", get(list_yara_rules))
        .route("/api/intelligence/yara", post(add_yara_rule))
        .route("/api/intelligence/yara/{name}", get(get_yara_rule))
        .route("/api/intelligence/sigma", get(list_sigma_rules))
        .route("/api/intelligence/sigma", post(add_sigma_rule))
        .route("/api/intelligence/sigma/{name}", get(get_sigma_rule))
        .route("/api/intelligence/cves", get(list_cves))
        .route("/api/intelligence/cves", post(add_cve))
        .route("/api/intelligence/cves/{id}", get(get_cve))
        .route("/api/intelligence/reputation", get(get_reputation))
        .route("/api/fleet", get(fleet_overview))
        .route("/api/fleet/agents", get(fleet_agents))
        .route("/api/fleet/agents/{id}", get(fleet_agent_detail))
        .route(
            "/api/fleet/agents/{id}/deregister",
            post(fleet_deregister_agent),
        )
        .route("/api/fleet/heartbeat", post(fleet_heartbeat))
        .route("/api/fleet/policies", get(fleet_policies))
        .route("/api/fleet/policies", post(fleet_distribute_policy))
        .route("/api/fleet/actions", get(fleet_actions))
        .route("/api/fleet/actions", post(fleet_request_action))
        .route("/api/fleet/actions/{id}", get(fleet_action_detail))
        .route("/api/fleet/stats", get(fleet_stats))
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let metrics = state.metrics.snapshot();
    let detector_count = state.engine.registry().count().await;
    Json(StatusResponse {
        metrics,
        detector_count,
    })
}

async fn list_threats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ThreatRow>>, ApiError> {
    let repo = ThreatRepository::new(&state.store);
    let threats = repo
        .find_unacknowledged(&sentinelx_common::Severity::Info, 100)
        .await?;
    Ok(Json(
        threats
            .into_iter()
            .map(|t| ThreatRow {
                id: t.id,
                timestamp: t.timestamp,
                severity: t.severity,
                category: t.category,
                title: t.title,
                description: t.description,
                source_detector: t.source_detector,
                acknowledged: t.acknowledged,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
pub struct ThreatRow {
    pub id: String,
    pub timestamp: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub source_detector: String,
    pub acknowledged: bool,
}

async fn get_threat(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ThreatRow>, ApiError> {
    let repo = ThreatRepository::new(&state.store);
    let threat = repo
        .find_by_id(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Threat {} not found", id)))?;
    Ok(Json(ThreatRow {
        id: threat.id,
        timestamp: threat.timestamp,
        severity: threat.severity,
        category: threat.category,
        title: threat.title,
        description: threat.description,
        source_detector: threat.source_detector,
        acknowledged: threat.acknowledged,
    }))
}

async fn acknowledge_threat(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let repo = ThreatRepository::new(&state.store);
    repo.acknowledge(&id).await?;
    Ok(StatusCode::OK)
}

async fn resolve_threat(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let repo = ThreatRepository::new(&state.store);
    repo.resolve(&id).await?;
    Ok(StatusCode::OK)
}

async fn threat_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ThreatStatsResponse>, ApiError> {
    let repo = ThreatRepository::new(&state.store);
    let stats = repo.stats().await?;
    Ok(Json(ThreatStatsResponse {
        total: stats.total,
        unacknowledged: stats.unacknowledged,
        critical: stats.critical,
        high: stats.high,
    }))
}

async fn list_events(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<sentinelx_database::repository::EventRow>>, ApiError> {
    let repo = EventRepository::new(&state.store);
    let events = repo.find_all(200).await?;
    Ok(Json(events))
}

async fn list_processes(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Vec<sentinelx_common::ProcessInfo>>, ApiError> {
    let collector = ForensicsCollector::new();
    let processes = collector.collect_process_tree();
    Ok(Json(processes))
}

async fn list_modules(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Vec<sentinelx_common::KernelModuleInfo>>, ApiError> {
    let collector = ForensicsCollector::new();
    let modules = collector.collect_kernel_modules();
    Ok(Json(modules))
}

async fn list_network(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Vec<sentinelx_common::NetworkConnection>>, ApiError> {
    let collector = ForensicsCollector::new();
    let connections = collector.collect_network_state();
    Ok(Json(connections))
}

async fn scan_all(State(state): State<Arc<AppState>>) -> Result<Json<ScanResponse>, ApiError> {
    state.metrics.record_scan();
    let threats = state.engine.run_scan().await;

    if !threats.is_empty() {
        let repo = ThreatRepository::new(&state.store);
        for threat in &threats {
            if let Err(e) = repo.insert(threat).await {
                tracing::error!("Failed to persist threat {}: {}", threat.id, e);
            }
        }
    }

    let threats_found = threats.len();
    Ok(Json(ScanResponse {
        threats_found,
        threats,
    }))
}

async fn scan_detector(
    State(state): State<Arc<AppState>>,
    Path(detector): Path<String>,
) -> Result<Json<ScanResponse>, ApiError> {
    let threats = state
        .engine
        .registry()
        .run_detector(&detector)
        .await
        .map_err(|e| ApiError::Detection(e.to_string()))?;

    if !threats.is_empty() {
        let repo = ThreatRepository::new(&state.store);
        for threat in &threats {
            if let Err(e) = repo.insert(threat).await {
                tracing::error!("Failed to persist threat {}: {}", threat.id, e);
            }
        }
    }

    let threats_found = threats.len();
    Ok(Json(ScanResponse {
        threats_found,
        threats,
    }))
}

async fn collect_forensics(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<sentinelx_common::types::ForensicSnapshot>, ApiError> {
    let collector = ForensicsCollector::new();
    let snapshot = collector.collect_all();
    Ok(Json(snapshot))
}

async fn generate_report(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.metrics.record_scan();
    let threats = state.engine.run_scan().await;
    let generator = ReportGenerator::new();
    let report_json = generator.generate_json_report(&threats);
    let report_value: serde_json::Value =
        serde_json::from_str(&report_json).unwrap_or(serde_json::Value::Null);
    Ok(Json(report_value))
}

async fn get_timeline(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let timeline = state.timeline.read().await;
    let json_str = timeline.to_json();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&json_str).unwrap_or_default();
    Ok(Json(entries))
}

async fn list_detectors(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DetectorsResponse>, ApiError> {
    let detectors = state.engine.registry().list_detectors().await;
    Ok(Json(DetectorsResponse { detectors }))
}

async fn kernel_integrity(State(_state): State<Arc<AppState>>) -> Json<KernelIntegrityResponse> {
    let mut checks = Vec::new();

    let kptr_restrict = std::fs::read_to_string("/proc/sys/kernel/kptr_restrict")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let kptr_restricted = kptr_restrict != "0";
    checks.push(IntegrityCheck {
        name: "kptr_restrict".to_string(),
        passed: kptr_restricted,
        detail: format!("Current value: {}", kptr_restrict),
    });

    let dmesg_restrict = std::fs::read_to_string("/proc/sys/kernel/dmesg_restrict")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let dmesg_restricted = dmesg_restrict != "0";
    checks.push(IntegrityCheck {
        name: "dmesg_restrict".to_string(),
        passed: dmesg_restricted,
        detail: format!("Current value: {}", dmesg_restrict),
    });

    let secure_boot = std::fs::read_to_string(
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    )
    .map(|b| b.as_bytes().last().copied() == Some(1))
    .unwrap_or(false);
    checks.push(IntegrityCheck {
        name: "secure_boot".to_string(),
        passed: secure_boot,
        detail: if secure_boot {
            "Enabled".to_string()
        } else {
            "Disabled or not available".to_string()
        },
    });

    let lockdown = std::fs::read_to_string("/sys/kernel/security/lockdown")
        .map(|s| {
            if s.contains("[none]") {
                "none".to_string()
            } else if s.contains("[integrity]") {
                "integrity".to_string()
            } else if s.contains("[confidentiality]") {
                "confidentiality".to_string()
            } else {
                s.trim().to_string()
            }
        })
        .unwrap_or_else(|_| "not available".to_string());
    checks.push(IntegrityCheck {
        name: "kernel_lockdown".to_string(),
        passed: lockdown != "none" && lockdown != "not available",
        detail: format!("Mode: {}", lockdown),
    });

    Json(KernelIntegrityResponse {
        secure_boot,
        kptr_restricted,
        dmesg_restrict: dmesg_restricted,
        lockdown,
        checks,
    })
}

async fn memory_integrity(State(_state): State<Arc<AppState>>) -> Json<MemoryIntegrityResponse> {
    let mut total_kb: u64 = 0;
    let mut available_kb: u64 = 0;
    let mut swap_total_kb: u64 = 0;
    let mut swap_free_kb: u64 = 0;

    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let val: u64 = parts[1].parse().unwrap_or(0);
                match parts[0] {
                    "MemTotal:" => total_kb = val,
                    "MemAvailable:" => available_kb = val,
                    "SwapTotal:" => swap_total_kb = val,
                    "SwapFree:" => swap_free_kb = val,
                    _ => {}
                }
            }
        }
    }

    let used_kb = total_kb.saturating_sub(available_kb);
    let swap_used_kb = swap_total_kb.saturating_sub(swap_free_kb);

    let mut checks = Vec::new();

    let kptr_restrict = std::fs::read_to_string("/proc/sys/kernel/kptr_restrict")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    checks.push(IntegrityCheck {
        name: "Kernel Pointer Exposure".to_string(),
        passed: kptr_restrict != "0",
        detail: format!("kptr_restrict = {}", kptr_restrict),
    });

    let vm_unprivileged = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map(|s| s.trim().to_string())
        .ok();
    if let Some(val) = &vm_unprivileged {
        checks.push(IntegrityCheck {
            name: "Unprivileged UserNS".to_string(),
            passed: val == "0",
            detail: format!("unprivileged_userns_clone = {}", val),
        });
    }

    Json(MemoryIntegrityResponse {
        total_memory_kb: total_kb,
        available_memory_kb: available_kb,
        used_memory_kb: used_kb,
        swap_total_kb,
        swap_used_kb,
        checks,
    })
}

#[derive(Serialize)]
pub struct EvidenceResponse {
    pub id: String,
    pub timestamp: String,
    pub evidence_type: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub data: serde_json::Value,
    pub tags: Vec<String>,
    pub confidence: f64,
}

#[derive(Serialize)]
pub struct EvidenceListResponse {
    pub evidence: Vec<EvidenceResponse>,
    pub total: usize,
}

#[derive(Serialize)]
pub struct EvidenceStatsResponse {
    pub total: usize,
    pub by_type: std::collections::HashMap<String, usize>,
    pub by_severity: std::collections::HashMap<String, usize>,
    pub by_source: std::collections::HashMap<String, usize>,
}

async fn list_evidence(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EvidenceListResponse>, ApiError> {
    let repo = EvidenceRepository::new(&state.store);
    let evidence_rows = repo.find_all(500).await?;

    let evidence: Vec<EvidenceResponse> = evidence_rows
        .into_iter()
        .map(|e| EvidenceResponse {
            id: e.id,
            timestamp: e.timestamp,
            evidence_type: e.evidence_type,
            severity: e.severity,
            source: e.source,
            description: e.description,
            data: serde_json::from_str(&e.data).unwrap_or_default(),
            tags: serde_json::from_str(&e.tags).unwrap_or_default(),
            confidence: e.confidence,
        })
        .collect();

    let total = evidence.len();
    Ok(Json(EvidenceListResponse { evidence, total }))
}

async fn collect_evidence(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.engine.run_evidence_collection().await;
    let repo = EvidenceRepository::new(&state.store);
    let stats = repo.stats().await?;
    Ok(Json(serde_json::json!({
        "message": "Evidence collection completed and persisted",
        "evidence_count": stats.total
    })))
}

async fn evidence_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EvidenceStatsResponse>, ApiError> {
    let repo = EvidenceRepository::new(&state.store);
    let stats = repo.stats().await?;

    let by_type: std::collections::HashMap<String, usize> = stats
        .by_type
        .into_iter()
        .map(|(k, v)| (k, v as usize))
        .collect();
    let by_severity: std::collections::HashMap<String, usize> = stats
        .by_severity
        .into_iter()
        .map(|(k, v)| (k, v as usize))
        .collect();
    let by_source: std::collections::HashMap<String, usize> = stats
        .by_source
        .into_iter()
        .map(|(k, v)| (k, v as usize))
        .collect();

    Ok(Json(EvidenceStatsResponse {
        total: stats.total as usize,
        by_type,
        by_severity,
        by_source,
    }))
}

#[derive(Serialize)]
pub struct RulesResponse {
    pub rules: Vec<serde_json::Value>,
    pub total: usize,
}

#[derive(serde::Deserialize)]
pub struct AddRuleRequest {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub severity: String,
    pub category: String,
    pub condition: sentinelx_rule_engine::RuleCondition,
    pub actions: Vec<sentinelx_rule_engine::RuleAction>,
    pub tags: Vec<String>,
}

async fn list_rules(State(state): State<Arc<AppState>>) -> Result<Json<RulesResponse>, ApiError> {
    let rule_engine = state.engine.rule_engine().read().await;
    let rules: Vec<serde_json::Value> = rule_engine
        .list_rules()
        .iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();
    let total = rules.len();
    Ok(Json(RulesResponse { rules, total }))
}

async fn get_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rule_engine = state.engine.rule_engine().read().await;
    let uuid = uuid::Uuid::parse_str(&id)
        .map_err(|e| ApiError::Validation(format!("Invalid rule ID: {}", e)))?;
    let rule = rule_engine
        .get_rule(uuid)
        .ok_or_else(|| ApiError::NotFound(format!("Rule {} not found", id)))?;
    Ok(Json(serde_json::to_value(rule).unwrap_or_default()))
}

async fn add_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddRuleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let now = chrono::Utc::now();
    let rule = Rule {
        id: uuid::Uuid::new_v4(),
        name: req.name,
        description: req.description,
        enabled: req.enabled,
        severity: req.severity,
        category: req.category,
        condition: req.condition,
        actions: req.actions,
        tags: req.tags,
        created_at: now,
        updated_at: now,
    };

    let mut rule_engine = state.engine.rule_engine().write().await;
    rule_engine.add_rule(rule.clone());

    Ok(Json(serde_json::json!({
        "message": "Rule added successfully",
        "rule_id": rule.id.to_string()
    })))
}

async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let uuid = uuid::Uuid::parse_str(&id)
        .map_err(|e| ApiError::Validation(format!("Invalid rule ID: {}", e)))?;
    let mut rule_engine = state.engine.rule_engine().write().await;
    if rule_engine.remove_rule(uuid) {
        Ok(StatusCode::OK)
    } else {
        Err(ApiError::NotFound(format!("Rule {} not found", id)))
    }
}

#[derive(Serialize)]
pub struct CorrelationListResponse {
    pub correlations: Vec<serde_json::Value>,
    pub total: usize,
}

async fn list_correlations(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CorrelationListResponse>, ApiError> {
    let correlation_engine = state.engine.correlation_engine().read().await;
    let results = correlation_engine.results();
    let correlations: Vec<serde_json::Value> = results
        .iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();
    let total = correlations.len();
    Ok(Json(CorrelationListResponse {
        correlations,
        total,
    }))
}

async fn run_correlations(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let threats = state.engine.run_scan().await;
    state.engine.run_evidence_collection().await;

    let evidence_store = state.engine.evidence_store().read().await;
    let evidence: Vec<sentinelx_evidence::Evidence> = evidence_store.evidence.clone();
    drop(evidence_store);

    let results = state.engine.run_correlation(&threats, &evidence).await;
    let result_count = results.len();

    Ok(Json(serde_json::json!({
        "message": "Correlation scan completed",
        "threats_found": threats.len(),
        "correlations_found": result_count,
        "correlations": results,
    })))
}

async fn correlation_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let stats = state.engine.correlation_stats().await;
    Ok(Json(serde_json::json!({
        "total_correlations": stats.total_correlations,
        "by_rule": stats.by_rule,
        "by_kind": stats.by_kind,
    })))
}

async fn run_scoring(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let threats = state.engine.run_scan().await;
    state.engine.run_evidence_collection().await;

    let evidence_store = state.engine.evidence_store().read().await;
    let evidence: Vec<sentinelx_evidence::Evidence> = evidence_store.evidence.clone();
    drop(evidence_store);

    state.engine.run_correlation(&threats, &evidence).await;

    let scores = state.engine.run_scoring(&threats, &evidence).await;
    let scored_count = scores.len();

    Ok(Json(serde_json::json!({
        "message": "Threat scoring completed",
        "threats_scored": scored_count,
        "scores": scores,
    })))
}

async fn list_trust_sources(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let trust_engine = state.engine.trust_engine().read().await;
    let sources: Vec<&sentinelx_detector::trust::SourceTrust> = trust_engine.all_sources();
    let total = sources.len();
    Ok(Json(serde_json::json!({
        "sources": sources,
        "total": total,
    })))
}

async fn get_trust_source(
    State(state): State<Arc<AppState>>,
    Path(source): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let trust_engine = state.engine.trust_engine().read().await;
    let source_info = trust_engine
        .get_source(&source)
        .ok_or_else(|| ApiError::NotFound(format!("Source {} not found", source)))?;
    Ok(Json(serde_json::to_value(source_info).unwrap_or_default()))
}

async fn record_positive(
    State(state): State<Arc<AppState>>,
    Path(source): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut trust_engine = state.engine.trust_engine().write().await;
    trust_engine.record_confirmed_positive(&source);
    let trust_score = trust_engine.get_trust(&source);
    Ok(Json(serde_json::json!({
        "message": format!("Recorded confirmed positive for {}", source),
        "trust_score": trust_score,
    })))
}

async fn record_false_positive(
    State(state): State<Arc<AppState>>,
    Path(source): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut trust_engine = state.engine.trust_engine().write().await;
    trust_engine.record_false_positive(&source);
    let trust_score = trust_engine.get_trust(&source);
    Ok(Json(serde_json::json!({
        "message": format!("Recorded false positive for {}", source),
        "trust_score": trust_score,
    })))
}

#[derive(Serialize)]
pub struct IncidentResponse {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub severity: String,
    pub confidence: f64,
    pub created_at: String,
    pub updated_at: String,
    pub evidence_ids: String,
    pub object_ids: String,
    pub attack_chain: String,
    pub mitre_mappings: String,
    pub recommended_response: Option<String>,
    pub tags: String,
}

#[derive(Serialize)]
pub struct IncidentListResponse {
    pub incidents: Vec<IncidentResponse>,
    pub total: usize,
}

async fn list_incidents(
    State(state): State<Arc<AppState>>,
) -> Result<Json<IncidentListResponse>, ApiError> {
    let repo = IncidentRepository::new(&state.store);
    let rows = repo.find_all(500).await?;
    let total = rows.len();
    let incidents: Vec<IncidentResponse> = rows
        .into_iter()
        .map(|r| IncidentResponse {
            id: r.id,
            title: r.title,
            description: r.description,
            status: r.status,
            severity: r.severity,
            confidence: r.confidence,
            created_at: r.created_at,
            updated_at: r.updated_at,
            evidence_ids: r.evidence_ids,
            object_ids: r.object_ids,
            attack_chain: r.attack_chain,
            mitre_mappings: r.mitre_mappings,
            recommended_response: r.recommended_response,
            tags: r.tags,
        })
        .collect();
    Ok(Json(IncidentListResponse { incidents, total }))
}

async fn get_incident(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<IncidentResponse>, ApiError> {
    let repo = IncidentRepository::new(&state.store);
    let row = repo
        .find_by_id(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Incident {} not found", id)))?;
    Ok(Json(IncidentResponse {
        id: row.id,
        title: row.title,
        description: row.description,
        status: row.status,
        severity: row.severity,
        confidence: row.confidence,
        created_at: row.created_at,
        updated_at: row.updated_at,
        evidence_ids: row.evidence_ids,
        object_ids: row.object_ids,
        attack_chain: row.attack_chain,
        mitre_mappings: row.mitre_mappings,
        recommended_response: row.recommended_response,
        tags: row.tags,
    }))
}

async fn update_incident_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> Result<StatusCode, ApiError> {
    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Validation("Missing 'status' field".to_string()))?;

    let repo = IncidentRepository::new(&state.store);
    let updated = repo.update_status(&id, status).await?;
    if updated {
        Ok(StatusCode::OK)
    } else {
        Err(ApiError::NotFound(format!("Incident {} not found", id)))
    }
}

#[derive(Serialize)]
pub struct ThreatDecisionResponse {
    pub id: String,
    pub incident_id: String,
    pub severity: String,
    pub risk_score_final: f64,
    pub confidence: f64,
    pub priority: String,
    pub description: String,
    pub recommendation: String,
    pub created_at: String,
    pub tags: String,
}

#[derive(Serialize)]
pub struct ThreatDecisionListResponse {
    pub threats: Vec<ThreatDecisionResponse>,
    pub total: usize,
}

async fn list_threat_decisions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ThreatDecisionListResponse>, ApiError> {
    let repo = ThreatDecisionRepository::new(&state.store);
    let rows = repo.find_all(500).await?;
    let total = rows.len();
    let threats: Vec<ThreatDecisionResponse> = rows
        .into_iter()
        .map(|r| ThreatDecisionResponse {
            id: r.id,
            incident_id: r.incident_id,
            severity: r.severity,
            risk_score_final: r.risk_score_final,
            confidence: r.confidence,
            priority: r.priority,
            description: r.description,
            recommendation: r.recommendation,
            created_at: r.created_at,
            tags: r.tags,
        })
        .collect();
    Ok(Json(ThreatDecisionListResponse { threats, total }))
}

async fn get_threat_decision(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ThreatDecisionResponse>, ApiError> {
    let repo = ThreatDecisionRepository::new(&state.store);
    let row = repo
        .find_by_id(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Threat decision {} not found", id)))?;
    Ok(Json(ThreatDecisionResponse {
        id: row.id,
        incident_id: row.incident_id,
        severity: row.severity,
        risk_score_final: row.risk_score_final,
        confidence: row.confidence,
        priority: row.priority,
        description: row.description,
        recommendation: row.recommendation,
        created_at: row.created_at,
        tags: row.tags,
    }))
}

async fn get_graph(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let incident_engine = state.incident_engine.as_ref();
    let threat_engine = state.threat_engine.as_ref();

    let incidents = incident_engine.list_incidents().await;
    let decisions = threat_engine.list_decisions().await;

    Ok(Json(serde_json::json!({
        "incidents": incidents.len(),
        "threats": decisions.len(),
        "message": "Graph data from in-memory engines"
    })))
}

async fn get_graph_node(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let incident_engine = state.incident_engine.as_ref();
    if let Ok(uuid) = uuid::Uuid::parse_str(&node_id) {
        if let Some(incident) = incident_engine.get_incident(uuid).await {
            return Ok(Json(serde_json::json!({
                "type": "incident",
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity.as_str(),
            })));
        }
    }

    Ok(Json(serde_json::json!({
        "error": format!("Node {} not found", node_id)
    })))
}

#[derive(Serialize)]
pub struct ResponseListResponse {
    pub responses: Vec<serde_json::Value>,
    pub total: usize,
}

async fn list_responses(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ResponseListResponse>, ApiError> {
    let repo = ResponseAuditRepository::new(&state.store);
    let rows = repo.find_all(500).await?;
    let total = rows.len();
    let responses: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "timestamp": r.timestamp,
                "threat_id": r.threat_id,
                "workflow_name": r.workflow_name,
                "action_type": r.action_type,
                "action_params": r.action_params,
                "result": r.result,
                "duration_ms": r.duration_ms,
                "rollback_status": r.rollback_status,
                "dry_run": r.dry_run,
            })
        })
        .collect();
    Ok(Json(ResponseListResponse { responses, total }))
}

#[derive(Serialize)]
pub struct AuditListResponse {
    pub records: Vec<serde_json::Value>,
    pub total: usize,
    pub summary: serde_json::Value,
}

async fn list_audit(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AuditListResponse>, ApiError> {
    let repo = ResponseAuditRepository::new(&state.store);
    let rows = repo.find_all(500).await?;
    let total = rows.len();
    let result_counts = repo.count_by_result().await.unwrap_or_default();

    let records: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "timestamp": r.timestamp,
                "threat_id": r.threat_id,
                "workflow_name": r.workflow_name,
                "action_type": r.action_type,
                "result": r.result,
                "duration_ms": r.duration_ms,
                "rollback_status": r.rollback_status,
                "dry_run": r.dry_run,
            })
        })
        .collect();

    let summary = serde_json::json!({
        "total": total,
        "by_result": result_counts,
    });

    Ok(Json(AuditListResponse {
        records,
        total,
        summary,
    }))
}

async fn get_audit_for_threat(
    State(state): State<Arc<AppState>>,
    Path(threat_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let repo = ResponseAuditRepository::new(&state.store);
    let rows = repo.find_by_threat_id(&threat_id).await?;
    let records: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "timestamp": r.timestamp,
                "workflow_name": r.workflow_name,
                "action_type": r.action_type,
                "result": r.result,
                "duration_ms": r.duration_ms,
                "rollback_status": r.rollback_status,
                "dry_run": r.dry_run,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "threat_id": threat_id,
        "records": records,
        "total": records.len(),
    })))
}

async fn list_workflows(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let response_engine = state.response_engine.read().await;
    let workflows = response_engine.workflow_engine().workflows();
    let policies = response_engine.policy_engine().policies();

    let wf_json: Vec<serde_json::Value> = workflows
        .iter()
        .map(|w| {
            serde_json::json!({
                "name": w.name,
                "description": w.description,
                "trigger_severity": w.trigger_severity,
                "steps": w.steps.len(),
            })
        })
        .collect();

    let policy_json: Vec<serde_json::Value> = policies
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "description": p.description,
                "severity_threshold": p.severity_threshold,
                "confidence_threshold": p.confidence_threshold,
                "allowed_actions": p.allowed_actions,
                "timeout_seconds": p.timeout_seconds,
                "approval_required": p.approval_required,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "workflows": wf_json,
        "policies": policy_json,
        "safety": {
            "dry_run": response_engine.safety().dry_run,
            "never_kill_init": response_engine.safety().never_kill_init,
            "never_unload_core_modules": response_engine.safety().never_unload_core_modules,
        },
    })))
}

async fn list_telemetry_events(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let repo = TelemetryEventRepository::new(&state.store);
    let events = repo
        .find_all(100)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to query telemetry events: {}", e)))?;

    let total = repo.count().await.unwrap_or(0);

    let events_json: Vec<serde_json::Value> = events
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "timestamp": r.timestamp,
                "provider": r.provider,
                "category": r.category,
                "event_type": r.event_type,
                "pid": r.pid,
                "uid": r.uid,
                "namespace": r.namespace,
                "container": r.container,
                "object_id": r.object_id,
                "metadata": serde_json::from_str::<serde_json::Value>(&r.metadata).unwrap_or(serde_json::Value::Null),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "events": events_json,
        "total": total,
    })))
}

async fn live_telemetry_events(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let recent = state.telemetry_engine.recent_events(50).await;

    let events_json: Vec<serde_json::Value> = recent
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "timestamp": e.timestamp,
                "provider": e.provider,
                "category": e.category.as_str(),
                "event_type": e.event_type.as_str(),
                "pid": e.pid,
                "uid": e.uid,
                "object_id": e.object_id,
            })
        })
        .collect();

    Json(serde_json::json!({
        "events": events_json,
        "total": events_json.len(),
    }))
}

async fn list_telemetry_providers(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let providers = state.telemetry_engine.provider_infos().await;

    let providers_json: Vec<serde_json::Value> = providers
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "status": p.status.as_str(),
                "events_received": p.events_received,
                "events_dropped": p.events_dropped,
            })
        })
        .collect();

    Json(serde_json::json!({
        "providers": providers_json,
        "total": providers_json.len(),
    }))
}

async fn telemetry_stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let stats = state.telemetry_engine.bus_stats();

    Json(serde_json::json!({
        "total_events": stats.total_events,
        "dropped_events": stats.dropped_events,
        "active_providers": stats.active_providers,
        "buffer_size": stats.buffer_size,
        "buffer_capacity": stats.buffer_capacity,
        "current_rate_per_second": stats.current_rate_per_second,
    }))
}

async fn provider_health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let providers = state.telemetry_engine.provider_infos().await;
    let now = chrono::Utc::now();

    let health_json: Vec<serde_json::Value> = providers
        .into_iter()
        .map(|p| {
            let uptime = p.started_at.map(|t| {
                let duration = now.signed_duration_since(t);
                duration.num_seconds().max(0) as u64
            });
            serde_json::json!({
                "name": p.name,
                "status": p.status.as_str(),
                "events_received": p.events_received,
                "events_dropped": p.events_dropped,
                "started_at": p.started_at,
                "uptime_seconds": uptime,
                "drop_rate_percent": if p.events_received > 0 {
                    (p.events_dropped as f64 / p.events_received as f64 * 100.0).round()
                } else {
                    0.0
                },
            })
        })
        .collect();

    let running = health_json
        .iter()
        .filter(|h| h["status"] == "running")
        .count();
    let degraded = health_json
        .iter()
        .filter(|h| h["status"] == "degraded")
        .count();
    let stopped = health_json
        .iter()
        .filter(|h| h["status"] == "stopped")
        .count();

    Json(serde_json::json!({
        "providers": health_json,
        "summary": {
            "total": health_json.len(),
            "running": running,
            "degraded": degraded,
            "stopped": stopped,
        }
    }))
}

async fn kernel_latency(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let reports = state.provider_manager.latency_report();

    let reports_json: Vec<serde_json::Value> = reports
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "provider": r.provider,
                "avg_latency_us": r.avg_latency_us,
                "max_latency_us": r.max_latency_us,
                "samples": r.samples,
            })
        })
        .collect();

    Json(serde_json::json!({
        "latency": reports_json,
        "total_providers": reports_json.len(),
    }))
}

async fn telemetry_rate(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let stats = state.telemetry_engine.bus_stats();
    let provider_infos = state.telemetry_engine.provider_infos().await;

    let rates_json: Vec<serde_json::Value> = provider_infos
        .into_iter()
        .map(|p| {
            let drop_rate = if p.events_received > 0 {
                (p.events_dropped as f64 / p.events_received as f64 * 100.0).round()
            } else {
                0.0
            };
            serde_json::json!({
                "provider": p.name,
                "events_received": p.events_received,
                "events_dropped": p.events_dropped,
                "drop_rate_percent": drop_rate,
            })
        })
        .collect();

    Json(serde_json::json!({
        "rates": rates_json,
        "total_events": stats.total_events,
        "dropped_events": stats.dropped_events,
        "current_rate_per_second": stats.current_rate_per_second,
    }))
}

async fn provider_capabilities(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let caps = state.provider_manager.capabilities();
    let preferred = state.provider_manager.preferred_order();

    let caps_json: Vec<serde_json::Value> = caps
        .iter()
        .map(|c| {
            serde_json::json!({
                "capability": format!("{:?}", c.capability),
                "available": c.available,
                "reason": c.reason,
            })
        })
        .collect();

    let preferred_json: Vec<String> = preferred.iter().map(|c| format!("{:?}", c)).collect();

    Json(serde_json::json!({
        "capabilities": caps_json,
        "preferred_order": preferred_json,
        "active_providers": state.provider_manager.active_providers(),
    }))
}

async fn live_events_stream(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let recent = state.telemetry_engine.recent_events(100).await;

    let events_json: Vec<serde_json::Value> = recent
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "timestamp": e.timestamp,
                "provider": e.provider,
                "category": e.category.as_str(),
                "event_type": e.event_type.as_str(),
                "pid": e.pid,
                "uid": e.uid,
                "object_id": e.object_id,
            })
        })
        .collect();

    Json(serde_json::json!({
        "events": events_json,
        "total": events_json.len(),
    }))
}

// --- Behavior API ---

#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub struct RecordBehaviorEventRequest {
    pub provider: String,
    pub object_id: String,
    pub category: String,
    pub event_type: String,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub command_line: Option<String>,
    pub description: String,
    pub severity: Option<String>,
    pub confidence: Option<f64>,
    pub metadata: Option<serde_json::Value>,
}

async fn list_behavior_profiles(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let profiles = state.behavior_engine.list_profiles().await;
    let total = profiles.len();
    let profiles_json: Vec<serde_json::Value> = profiles
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "object_id": p.object_id,
                "first_seen": p.first_seen.to_rfc3339(),
                "last_seen": p.last_seen.to_rfc3339(),
                "execution_count": p.execution_count,
                "connection_count": p.connection_count,
                "privilege_changes": p.privilege_changes,
                "persistence_events": p.persistence_events,
                "integrity_violations": p.integrity_violations,
                "historical_score": p.historical_score,
                "categories": p.categories,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "profiles": profiles_json,
        "total": total,
    })))
}

async fn get_behavior_profile(
    State(state): State<Arc<AppState>>,
    Path(object_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let profile = state
        .behavior_engine
        .get_profile(&object_id)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("Profile for {} not found", object_id)))?;
    Ok(Json(serde_json::json!({
        "id": profile.id.to_string(),
        "object_id": profile.object_id,
        "first_seen": profile.first_seen.to_rfc3339(),
        "last_seen": profile.last_seen.to_rfc3339(),
        "execution_count": profile.execution_count,
        "connection_count": profile.connection_count,
        "privilege_changes": profile.privilege_changes,
        "persistence_events": profile.persistence_events,
        "integrity_violations": profile.integrity_violations,
        "historical_score": profile.historical_score,
        "categories": profile.categories,
    })))
}

async fn record_behavior_event(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RecordBehaviorEventRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let category = sentinelx_behavior::types::BehaviorCategory::parse_from(&req.category)
        .ok_or_else(|| ApiError::Validation(format!("Invalid category: {}", req.category)))?;

    let _severity_str = req.severity.as_deref().unwrap_or("low");
    let confidence = req.confidence.unwrap_or(0.5);

    let event = sentinelx_behavior::types::BehaviorEvent {
        timestamp: chrono::Utc::now(),
        category,
        description: req.description,
        risk_level: confidence * 100.0,
        metadata: req.metadata.unwrap_or(serde_json::Value::Null),
    };

    state
        .behavior_engine
        .record_event(&req.object_id, event)
        .await;
    let profile = state
        .behavior_engine
        .get_profile(&req.object_id)
        .await
        .ok_or_else(|| {
            ApiError::Internal("Failed to retrieve profile after recording".to_string())
        })?;

    let score = state.behavior_engine.evaluate_object(&req.object_id).await;

    Ok(Json(serde_json::json!({
        "message": "Event recorded successfully",
        "object_id": profile.object_id,
        "severity": score.as_ref().map(|s| s.severity.as_str()).unwrap_or("info"),
        "risk_score": score.as_ref().map(|s| s.final_score).unwrap_or(0.0),
        "confidence": score.as_ref().map(|s| s.assessment_score).unwrap_or(0.0),
        "execution_count": profile.execution_count,
        "connection_count": profile.connection_count,
    })))
}

async fn behavior_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let counts = state.behavior_engine.count_by_severity().await;
    let profiles = state.behavior_engine.list_profiles().await;
    Ok(Json(serde_json::json!({
        "total_profiles": profiles.len(),
        "by_severity": counts,
    })))
}

// --- Intelligence API ---

async fn intelligence_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let stats = state.intelligence_engine.stats().await;
    Ok(Json(serde_json::json!({
        "total_iocs": stats.total_iocs,
        "iocs_by_type": stats.iocs_by_type,
        "mitre_techniques": stats.total_mitre_techniques,
        "yara_rules": stats.total_yara_rules,
        "sigma_rules": stats.total_sigma_rules,
        "cves": stats.total_cves,
    })))
}

async fn list_iocs(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let iocs = state.intelligence_engine.list_iocs_limit(200).await;
    let total = iocs.len();
    let iocs_json: Vec<serde_json::Value> = iocs
        .into_iter()
        .map(|i| {
            serde_json::json!({
                "id": i.id.to_string(),
                "type": i.ioc_type.as_str(),
                "value": i.value,
                "severity": i.severity,
                "confidence": i.confidence,
                "source": i.source,
                "description": i.description,
                "first_seen": i.first_seen.to_rfc3339(),
                "last_seen": i.last_seen.to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "iocs": iocs_json,
        "total": total,
    })))
}

#[derive(serde::Deserialize)]
pub struct AddIoCRequest {
    pub ioc_type: String,
    pub value: String,
    pub severity: String,
    pub confidence: f64,
    pub source: String,
    pub description: String,
    pub tags: Option<Vec<String>>,
}

async fn add_ioc(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddIoCRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ioc_type = sentinelx_intelligence::IoC::parse_type(&req.ioc_type)
        .ok_or_else(|| ApiError::Validation(format!("Invalid IOC type: {}", req.ioc_type)))?;

    let mut ioc = sentinelx_intelligence::IoC::new(ioc_type, &req.value, &req.source)
        .with_severity(&req.severity)
        .with_confidence(req.confidence)
        .with_description(&req.description);
    if let Some(tags) = &req.tags {
        ioc = ioc.with_tags(tags.clone());
    }

    state.intelligence_engine.add_ioc(ioc).await;
    Ok(Json(serde_json::json!({
        "message": "IOC added successfully",
        "value": req.value,
    })))
}

async fn check_ioc(
    State(state): State<Arc<AppState>>,
    Path((ioc_type, value)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let found = state
        .intelligence_engine
        .get_ioc_by_str(&ioc_type, &value)
        .await;
    match found {
        Some(ioc) => Ok(Json(serde_json::json!({
            "found": true,
            "ioc": {
                "id": ioc.id.to_string(),
                "type": ioc.ioc_type.as_str(),
                "value": ioc.value,
                "severity": ioc.severity,
                "confidence": ioc.confidence,
                "source": ioc.source,
            },
        }))),
        None => Ok(Json(serde_json::json!({
            "found": false,
            "message": format!("IoC {}:{} not found", ioc_type, value),
        }))),
    }
}

async fn delete_ioc(
    State(state): State<Arc<AppState>>,
    Path((ioc_type, value)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let deleted = state
        .intelligence_engine
        .remove_ioc_by_str(&ioc_type, &value)
        .await;
    if deleted {
        Ok(StatusCode::OK)
    } else {
        Err(ApiError::NotFound(format!(
            "IoC {}:{} not found",
            ioc_type, value
        )))
    }
}

async fn list_mitre_techniques(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let techniques = state.intelligence_engine.list_mitre_techniques().await;
    let techniques_json: Vec<serde_json::Value> = techniques
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "tactic": t.tactic,
                "detection": t.detection,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "techniques": techniques_json,
        "total": techniques_json.len(),
    })))
}

async fn get_mitre_technique(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let technique = state
        .intelligence_engine
        .get_mitre_technique(&id)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("MITRE technique {} not found", id)))?;
    Ok(Json(serde_json::json!({
        "id": technique.id,
        "name": technique.name,
        "description": technique.description,
        "tactic": technique.tactic,
        "detection": technique.detection,
    })))
}

async fn list_yara_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rules = state.intelligence_engine.list_yara_rules().await;
    let total = rules.len();
    let rules_json: Vec<serde_json::Value> = rules
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "description": r.description,
                "author": r.author,
                "severity": r.severity,
                "tags": r.tags,
                "enabled": r.enabled,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "rules": rules_json,
        "total": total,
    })))
}

#[derive(serde::Deserialize)]
pub struct AddYaraRuleRequest {
    pub name: String,
    pub description: String,
    pub author: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub rule_content: String,
}

async fn add_yara_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddYaraRuleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rule = sentinelx_intelligence::YaraRule::new(&req.name, &req.rule_content)
        .with_description(&req.description)
        .with_author(&req.author)
        .with_severity(&req.severity)
        .with_tags(req.tags);
    state.intelligence_engine.add_yara_rule(rule).await;
    Ok(Json(serde_json::json!({
        "message": "YARA rule added successfully",
        "name": req.name,
    })))
}

async fn get_yara_rule(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rule = state
        .intelligence_engine
        .get_yara_rule(&name)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("YARA rule {} not found", name)))?;
    Ok(Json(serde_json::json!({
        "id": rule.id.to_string(),
        "name": rule.name,
        "description": rule.description,
        "author": rule.author,
        "severity": rule.severity,
        "tags": rule.tags,
        "enabled": rule.enabled,
    })))
}

async fn list_sigma_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rules = state.intelligence_engine.list_sigma_rules().await;
    let total = rules.len();
    let rules_json: Vec<serde_json::Value> = rules
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "description": r.description,
                "author": r.author,
                "severity": r.severity,
                "tags": r.tags,
                "detection_condition": r.detection.condition,
                "enabled": r.enabled,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "rules": rules_json,
        "total": total,
    })))
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub struct AddSigmaRuleRequest {
    pub name: String,
    pub description: String,
    pub author: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub logsource_category: Option<String>,
    pub logsource_product: Option<String>,
    pub logsource_service: Option<String>,
    pub detection_condition: String,
    pub detection_fields: Option<Vec<String>>,
    pub falsepositives: Option<Vec<String>>,
}

async fn add_sigma_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddSigmaRuleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut rule = sentinelx_intelligence::SigmaRule::new(&req.name)
        .with_description(&req.description)
        .with_author(&req.author)
        .with_severity(&req.severity)
        .with_tags(req.tags)
        .with_falsepositives(req.falsepositives.unwrap_or_default());

    if let Some(cat) = &req.logsource_category {
        rule = rule.with_logsource_category(cat);
    }
    if let Some(prod) = &req.logsource_product {
        rule = rule.with_logsource_product(prod);
    }
    if let Some(svc) = &req.logsource_service {
        rule = rule.with_logsource_service(svc);
    }

    state.intelligence_engine.add_sigma_rule(rule).await;
    Ok(Json(serde_json::json!({
        "message": "Sigma rule added successfully",
        "name": req.name,
    })))
}

async fn get_sigma_rule(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rule = state
        .intelligence_engine
        .get_sigma_rule(&name)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("Sigma rule {} not found", name)))?;
    Ok(Json(serde_json::json!({
        "id": rule.id.to_string(),
        "name": rule.name,
        "description": rule.description,
        "author": rule.author,
        "severity": rule.severity,
        "tags": rule.tags,
        "detection_condition": rule.detection.condition,
        "enabled": rule.enabled,
    })))
}

async fn list_cves(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let cves = state.intelligence_engine.list_cves_limit(100).await;
    let total = cves.len();
    let cves_json: Vec<serde_json::Value> = cves
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "description": c.description,
                "severity": c.severity,
                "cvss_score": c.cvss_score,
                "affected_products": c.affected_products,
                "published_at": c.published_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "cves": cves_json,
        "total": total,
    })))
}

#[derive(serde::Deserialize)]
pub struct AddCveRequest {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: f64,
    pub affected_products: Option<Vec<String>>,
    pub references: Option<Vec<String>>,
}

async fn add_cve(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddCveRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut cve = sentinelx_intelligence::CveEntry::new(&req.id, req.cvss_score)
        .with_description(&req.description)
        .with_severity(&req.severity);
    if let Some(products) = &req.affected_products {
        cve = cve.with_affected_products(products.clone());
    }
    if let Some(refs) = &req.references {
        cve = cve.with_references(refs.clone());
    }
    state.intelligence_engine.add_cve(cve).await;
    Ok(Json(serde_json::json!({
        "message": "CVE added successfully",
        "id": req.id,
    })))
}

async fn get_cve(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let cve = state
        .intelligence_engine
        .get_cve(&id)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("CVE {} not found", id)))?;
    Ok(Json(serde_json::json!({
        "id": cve.id,
        "description": cve.description,
        "severity": cve.severity,
        "cvss_score": cve.cvss_score,
        "affected_products": cve.affected_products,
        "published_at": cve.published_at.to_rfc3339(),
    })))
}

async fn get_reputation(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let reputation = state.intelligence_engine.get_global_reputation().await;
    Ok(Json(serde_json::json!({
        "score": reputation.score,
        "known_malicious": reputation.known_malicious,
        "detection_count": reputation.detection_count,
        "sources": reputation.sources,
        "last_checked": reputation.last_checked.to_rfc3339(),
    })))
}

// --- Fleet Management API ---

async fn fleet_overview(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let overview = state.fleet_manager.overview().await;
    Ok(Json(serde_json::to_value(overview).unwrap_or_default()))
}

async fn fleet_agents(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let agents = state.fleet_manager.agent_list().await;
    let agents_json: Vec<serde_json::Value> = agents
        .into_iter()
        .map(|a| serde_json::to_value(a).unwrap_or_default())
        .collect();
    Ok(Json(serde_json::json!({
        "agents": agents_json,
        "total": agents_json.len(),
    })))
}

async fn fleet_agent_detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let agent = state
        .fleet_manager
        .agent_info(&id)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("Agent {} not found", id)))?;
    Ok(Json(serde_json::to_value(agent).unwrap_or_default()))
}

async fn fleet_deregister_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.fleet_manager.unregister_agent(&id).await;
    Ok(StatusCode::OK)
}

async fn fleet_heartbeat(
    State(state): State<Arc<AppState>>,
    Json(heartbeat): Json<sentinelx_fleet::HeartbeatPayload>,
) -> Result<StatusCode, ApiError> {
    state.fleet_manager.process_heartbeat(heartbeat).await;
    Ok(StatusCode::OK)
}

async fn fleet_policies(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let policies = state.fleet_manager.policy_list().await;
    let policies_json: Vec<serde_json::Value> = policies
        .into_iter()
        .map(|p| serde_json::to_value(p).unwrap_or_default())
        .collect();
    Ok(Json(serde_json::json!({
        "policies": policies_json,
        "total": policies_json.len(),
    })))
}

#[derive(serde::Deserialize)]
pub struct DistributePolicyRequest {
    pub name: String,
    pub policy_type: String,
    pub config: serde_json::Value,
}

async fn fleet_distribute_policy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DistributePolicyRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let policy_id = state
        .fleet_manager
        .distribute_policy(req.name, req.policy_type, req.config)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to distribute policy: {}", e)))?;
    Ok(Json(serde_json::json!({
        "policy_id": policy_id,
        "message": "Policy distributed successfully",
    })))
}

async fn fleet_actions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let actions = state.fleet_manager.action_list(100).await;
    let actions_json: Vec<serde_json::Value> = actions
        .into_iter()
        .map(|a| serde_json::to_value(a).unwrap_or_default())
        .collect();
    Ok(Json(serde_json::json!({
        "actions": actions_json,
        "total": actions_json.len(),
    })))
}

#[derive(serde::Deserialize)]
pub struct RequestActionRequest {
    pub agent_id: String,
    pub action_type: String,
    pub params: serde_json::Value,
}

async fn fleet_request_action(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RequestActionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let action_type: sentinelx_fleet::RemoteActionType =
        serde_json::from_value(serde_json::json!(req.action_type))
            .map_err(|e| ApiError::Validation(format!("Invalid action type: {}", e)))?;
    let action_id = state
        .fleet_manager
        .request_action(req.agent_id, action_type, req.params)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to request action: {}", e)))?;
    Ok(Json(serde_json::json!({
        "action_id": action_id,
        "message": "Action requested successfully",
    })))
}

async fn fleet_action_detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let actions = state.fleet_manager.action_list(1000).await;
    let action = actions.into_iter().find(|a| a.action_id == id);
    match action {
        Some(a) => Ok(Json(serde_json::to_value(a).unwrap_or_default())),
        None => Err(ApiError::NotFound(format!("Action {} not found", id))),
    }
}

async fn fleet_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let overview = state.fleet_manager.overview().await;
    Ok(Json(serde_json::json!({
        "total_agents": overview.total_agents,
        "healthy_agents": overview.healthy_agents,
        "degraded_agents": overview.degraded_agents,
        "offline_agents": overview.offline_agents,
        "total_heartbeats": overview.total_heartbeats,
        "total_incidents": overview.total_incidents,
        "total_threats": overview.total_threats,
        "total_policies": overview.total_policies,
        "total_actions": overview.total_actions,
        "uptime_secs": overview.uptime_secs,
    })))
}
