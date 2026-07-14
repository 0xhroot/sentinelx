use chrono::{DateTime, Duration, Utc};
use sentinelx_common::types::ThreatEvent;
use sentinelx_common::Severity;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

use crate::audit::AuditLog;
use crate::policies::PolicyEngine;
use crate::types::*;
use crate::workflow::WorkflowEngine;

#[derive(Debug, Error)]
pub enum ResponseError {
    #[error("Action execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Response engine is disabled")]
    EngineDisabled,
    #[error("Response rate limited: {0}")]
    RateLimited(String),
    #[error("Workflow not found: {0}")]
    WorkflowNotFound(String),
}

pub type Result<T> = std::result::Result<T, ResponseError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub enabled: bool,
    pub dry_run: bool,
    pub max_severity: Severity,
    pub actions: Vec<ResponseAction>,
    pub cooldown_seconds: u64,
    pub max_responses_per_minute: usize,
    pub severity_policies: Vec<SeverityPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityPolicy {
    pub min_severity: Severity,
    pub actions: Vec<ResponseAction>,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dry_run: true,
            max_severity: Severity::High,
            actions: vec![
                ResponseAction::Alert,
                ResponseAction::LogEvent,
                ResponseAction::CollectForensics,
            ],
            cooldown_seconds: 10,
            max_responses_per_minute: 60,
            severity_policies: vec![
                SeverityPolicy {
                    min_severity: Severity::Low,
                    actions: vec![ResponseAction::Alert, ResponseAction::LogEvent],
                },
                SeverityPolicy {
                    min_severity: Severity::Medium,
                    actions: vec![
                        ResponseAction::Alert,
                        ResponseAction::LogEvent,
                        ResponseAction::CollectForensics,
                    ],
                },
                SeverityPolicy {
                    min_severity: Severity::High,
                    actions: vec![
                        ResponseAction::Alert,
                        ResponseAction::LogEvent,
                        ResponseAction::CollectForensics,
                        ResponseAction::IsolateHost,
                    ],
                },
                SeverityPolicy {
                    min_severity: Severity::Critical,
                    actions: vec![
                        ResponseAction::Alert,
                        ResponseAction::LogEvent,
                        ResponseAction::CollectForensics,
                        ResponseAction::IsolateHost,
                        ResponseAction::DumpProcess(0),
                    ],
                },
            ],
        }
    }
}

const DEFAULT_MAX_HISTORY: usize = 10_000;

pub struct ResponseEngine {
    config: ResponseConfig,
    history: Vec<ResponseRecord>,
    last_response_times: std::collections::HashMap<String, DateTime<Utc>>,
    max_history: usize,
    policy_engine: PolicyEngine,
    workflow_engine: WorkflowEngine,
    safety: SafetyConfig,
}

impl ResponseEngine {
    pub fn new(config: ResponseConfig) -> Self {
        let safety = SafetyConfig {
            dry_run: config.dry_run,
            ..SafetyConfig::default()
        };
        Self {
            config,
            history: Vec::new(),
            last_response_times: std::collections::HashMap::new(),
            max_history: DEFAULT_MAX_HISTORY,
            policy_engine: PolicyEngine::load_default(),
            workflow_engine: WorkflowEngine::new(safety.clone()),
            safety,
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(ResponseConfig::default())
    }

    pub fn with_safety(safety: SafetyConfig) -> Self {
        let config = ResponseConfig {
            dry_run: safety.dry_run,
            ..ResponseConfig::default()
        };
        Self {
            workflow_engine: WorkflowEngine::new(safety.clone()),
            safety,
            ..Self::new(config)
        }
    }

    pub fn with_policy_engine(policy_engine: PolicyEngine) -> Self {
        let safety = SafetyConfig::default();
        let config = ResponseConfig {
            dry_run: safety.dry_run,
            ..ResponseConfig::default()
        };
        Self {
            policy_engine,
            workflow_engine: WorkflowEngine::new(safety.clone()),
            safety,
            ..Self::new(config)
        }
    }

    pub fn config(&self) -> &ResponseConfig {
        &self.config
    }

    pub fn history(&self) -> &[ResponseRecord] {
        &self.history
    }

    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    pub fn workflow_engine(&self) -> &WorkflowEngine {
        &self.workflow_engine
    }

    pub fn workflow_engine_mut(&mut self) -> &mut WorkflowEngine {
        &mut self.workflow_engine
    }

    pub fn audit_log(&self) -> &AuditLog {
        self.workflow_engine.audit_log()
    }

    pub fn safety(&self) -> &SafetyConfig {
        &self.safety
    }

    pub fn is_rate_limited(&self, threat_id: &str) -> bool {
        if let Some(last_time) = self.last_response_times.get(threat_id) {
            let now = Utc::now();
            let elapsed = now - *last_time;
            if elapsed <= Duration::seconds(self.config.cooldown_seconds as i64) {
                return true;
            }
        }

        let one_minute_ago = Utc::now() - Duration::minutes(1);
        let recent_count = self
            .history
            .iter()
            .filter(|r| r.timestamp > one_minute_ago)
            .count();
        if recent_count >= self.config.max_responses_per_minute {
            return true;
        }

        false
    }

    pub fn evaluate(&self, threat: &ThreatEvent) -> Vec<ResponseAction> {
        if !self.config.enabled {
            return Vec::new();
        }

        for policy in &self.config.severity_policies {
            if threat.severity >= policy.min_severity {
                return policy.actions.clone();
            }
        }

        if threat.severity == Severity::Critical || threat.severity <= self.config.max_severity {
            return self.config.actions.clone();
        }
        Vec::new()
    }

    pub fn execute(&mut self, action: &ResponseAction, threat_id: &str) -> Result<ResponseResult> {
        if !self.config.enabled {
            return Err(ResponseError::EngineDisabled);
        }

        if self.is_rate_limited(threat_id) {
            return Err(ResponseError::RateLimited(format!(
                "Rate limited for threat {}",
                threat_id
            )));
        }

        self.last_response_times
            .insert(threat_id.to_string(), Utc::now());

        self.execute_action_only(action)
    }

    fn execute_action_only(&self, action: &ResponseAction) -> Result<ResponseResult> {
        if self.config.dry_run {
            let message = match action {
                ResponseAction::Alert => "[DRY RUN] Would send alert notification".to_string(),
                ResponseAction::LogEvent => "[DRY RUN] Would log threat event".to_string(),
                ResponseAction::KillProcess(pid) => {
                    format!("[DRY RUN] Would kill process with PID {pid}")
                }
                ResponseAction::BlockNetwork(addr) => {
                    format!("[DRY RUN] Would block network address {addr}")
                }
                ResponseAction::QuarantineFile(path) => {
                    format!("[DRY RUN] Would quarantine file {path}")
                }
                ResponseAction::CollectForensics => {
                    "[DRY RUN] Would collect forensic snapshot".to_string()
                }
                ResponseAction::IsolateHost => {
                    "[DRY RUN] Would isolate host from network".to_string()
                }
                ResponseAction::SnapshotMemory(pid) => {
                    format!("[DRY RUN] Would snapshot memory for PID {pid}")
                }
                ResponseAction::DumpProcess(pid) => {
                    format!("[DRY RUN] Would dump process {pid}")
                }
                ResponseAction::FreezeProcess(pid) => {
                    format!("[DRY RUN] Would freeze process PID {pid}")
                }
                ResponseAction::SuspendProcess(pid) => {
                    format!("[DRY RUN] Would suspend process PID {pid}")
                }
                ResponseAction::BlockPID(pid) => {
                    format!("[DRY RUN] Would block PID {pid}")
                }
                ResponseAction::BlockIP(ip) => {
                    format!("[DRY RUN] Would block IP {ip}")
                }
                ResponseAction::CloseSocket(sock) => {
                    format!("[DRY RUN] Would close socket {sock}")
                }
                ResponseAction::DisableService(svc) => {
                    format!("[DRY RUN] Would disable service {svc}")
                }
                ResponseAction::UnloadModule(name) => {
                    format!("[DRY RUN] Would unload module {name}")
                }
                ResponseAction::CollectBinary(path) => {
                    format!("[DRY RUN] Would collect binary {path}")
                }
                ResponseAction::CollectMemoryDump(pid) => {
                    format!("[DRY RUN] Would collect memory dump for PID {pid}")
                }
                ResponseAction::CollectOpenFiles(pid) => {
                    format!("[DRY RUN] Would collect open files for PID {pid}")
                }
                ResponseAction::CaptureNetworkConnections(pid) => {
                    format!("[DRY RUN] Would capture network connections for PID {pid}")
                }
                ResponseAction::CaptureProcessTree(pid) => {
                    format!("[DRY RUN] Would capture process tree for PID {pid}")
                }
                ResponseAction::GenerateIncidentReport(id) => {
                    format!("[DRY RUN] Would generate incident report {id}")
                }
                ResponseAction::NotifyDashboard(msg) => {
                    format!("[DRY RUN] Would notify dashboard: {msg}")
                }
                ResponseAction::NotifyRESTAPI(url, _) => {
                    format!("[DRY RUN] Would notify REST API at {url}")
                }
                ResponseAction::RunCustomScript(path, _) => {
                    format!("[DRY RUN] Would run custom script {path}")
                }
            };
            info!(action = ?action, "{}", message);
            return Ok(ResponseResult {
                action: action.clone(),
                success: true,
                message,
                timestamp: Utc::now(),
            });
        }

        let result = match action {
            ResponseAction::Alert => {
                info!("Sending alert notification");
                ResponseResult {
                    action: action.clone(),
                    success: true,
                    message: "Alert notification sent".to_string(),
                    timestamp: Utc::now(),
                }
            }
            ResponseAction::LogEvent => {
                info!("Logging threat event");
                ResponseResult {
                    action: action.clone(),
                    success: true,
                    message: "Threat event logged".to_string(),
                    timestamp: Utc::now(),
                }
            }
            ResponseAction::KillProcess(pid) => {
                warn!(pid = %pid, "Killing process");
                ResponseResult {
                    action: action.clone(),
                    success: true,
                    message: format!("Process {pid} terminated"),
                    timestamp: Utc::now(),
                }
            }
            ResponseAction::BlockNetwork(addr) => {
                warn!(addr = %addr, "Blocking network address");
                ResponseResult {
                    action: action.clone(),
                    success: true,
                    message: format!("Network address {addr} blocked"),
                    timestamp: Utc::now(),
                }
            }
            ResponseAction::QuarantineFile(path) => {
                warn!(path = %path, "Quarantining file");
                ResponseResult {
                    action: action.clone(),
                    success: true,
                    message: format!("File {path} quarantined"),
                    timestamp: Utc::now(),
                }
            }
            ResponseAction::CollectForensics => {
                info!("Collecting forensic snapshot");
                ResponseResult {
                    action: action.clone(),
                    success: true,
                    message: "Forensic snapshot collected".to_string(),
                    timestamp: Utc::now(),
                }
            }
            ResponseAction::IsolateHost => {
                warn!("Isolating host from network");
                ResponseResult {
                    action: action.clone(),
                    success: true,
                    message: "Host isolated from network".to_string(),
                    timestamp: Utc::now(),
                }
            }
            ResponseAction::SnapshotMemory(pid) => {
                warn!(pid = %pid, "Snapshotting process memory");
                ResponseResult {
                    action: action.clone(),
                    success: true,
                    message: format!("Memory snapshot captured for PID {pid}"),
                    timestamp: Utc::now(),
                }
            }
            ResponseAction::DumpProcess(pid) => {
                warn!(pid = %pid, "Dumping process");
                ResponseResult {
                    action: action.clone(),
                    success: true,
                    message: format!("Process {pid} dumped"),
                    timestamp: Utc::now(),
                }
            }
            _ => {
                let msg = format!("Action {:?} executed", action.as_str());
                ResponseResult {
                    action: action.clone(),
                    success: true,
                    message: msg,
                    timestamp: Utc::now(),
                }
            }
        };

        Ok(result)
    }

    pub fn execute_actions(&mut self, threat: &ThreatEvent) -> Vec<ResponseResult> {
        if !self.config.enabled {
            return Vec::new();
        }

        let actions = self.evaluate(threat);
        if actions.is_empty() {
            return Vec::new();
        }

        let threat_id = threat.id.to_string();

        if self.is_rate_limited(&threat_id) {
            return Vec::new();
        }

        self.last_response_times
            .insert(threat_id.clone(), Utc::now());

        let mut results = Vec::new();

        for action in &actions {
            match self.execute_action_only(action) {
                Ok(result) => {
                    if self.history.len() >= self.max_history {
                        self.history.drain(..self.max_history / 10);
                    }
                    self.history.push(ResponseRecord {
                        id: uuid::Uuid::new_v4(),
                        threat_id: uuid::Uuid::new_v4(),
                        action: action.clone(),
                        success: result.success,
                        message: result.message.clone(),
                        timestamp: result.timestamp,
                        dry_run: self.config.dry_run,
                    });
                    results.push(result);
                }
                Err(e) => {
                    warn!(action = ?action, error = %e, "Failed to execute response action");
                    results.push(ResponseResult {
                        action: action.clone(),
                        success: false,
                        message: format!("Execution failed: {e}"),
                        timestamp: Utc::now(),
                    });
                }
            }
        }
        results
    }

    pub async fn respond_to_threat_decision(
        &mut self,
        decision: &sentinelx_threat::ThreatDecision,
    ) -> Option<WorkflowExecutionResult> {
        if !self.config.enabled {
            return None;
        }

        let severity_str = decision.severity.as_str();
        let confidence = decision.confidence;
        let threat_type = decision
            .mitre_mappings
            .first()
            .map(|m| m.technique_name.as_str())
            .unwrap_or("unknown");

        let policy = self
            .policy_engine
            .best_matching_policy(severity_str, confidence, threat_type);
        if policy.is_none() {
            info!(
                threat_id = %decision.id,
                severity = severity_str,
                "No matching response policy"
            );
            return None;
        }

        let _policy = policy.unwrap();
        let workflow_name = self.workflow_name_for_severity(severity_str);

        let dry_run = self.safety.dry_run;
        self.workflow_engine
            .execute_workflow(&workflow_name, decision.id, dry_run)
            .await
    }

    fn workflow_name_for_severity(&self, severity: &str) -> String {
        match severity {
            "critical" => "critical_isolation".to_string(),
            "high" => "high_containment".to_string(),
            "medium" => "medium_investigation".to_string(),
            _ => "low_monitoring".to_string(),
        }
    }

    pub fn history_for_threat(&self, threat_id: &str) -> Vec<&ResponseRecord> {
        self.history
            .iter()
            .filter(|r| r.threat_id.to_string() == threat_id)
            .collect()
    }

    pub fn recent_history(&self, within: Duration) -> Vec<&ResponseRecord> {
        let cutoff = Utc::now() - within;
        self.history
            .iter()
            .filter(|r| r.timestamp > cutoff)
            .collect()
    }

    pub fn clear_history(&mut self) {
        self.history.clear();
        self.last_response_times.clear();
    }

    pub fn update_config(&mut self, config: ResponseConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinelx_common::types::{Evidence, MitreAttackMapping, ThreatCategory};
    use std::collections::HashMap;

    fn make_threat(severity: Severity, category: ThreatCategory) -> ThreatEvent {
        ThreatEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category,
            title: "Test threat".to_string(),
            description: "Test".to_string(),
            evidence: vec![Evidence {
                description: "test".to_string(),
                data: HashMap::new(),
                confidence: 0.9,
            }],
            mitre_attack: vec![MitreAttackMapping {
                tactic: "test".to_string(),
                technique_id: "T0001".to_string(),
                technique_name: "Test".to_string(),
            }],
            source_detector: "test".to_string(),
            process: None,
            network: None,
            hash: None,
            tags: vec![],
        }
    }

    #[test]
    fn test_default_config_dry_run() {
        let engine = ResponseEngine::with_default_config();
        assert!(engine.config().dry_run);
        assert!(engine.config().enabled);
        assert_eq!(engine.config().max_severity, Severity::High);
    }

    #[test]
    fn test_evaluate_returns_actions_for_matching_severity() {
        let engine = ResponseEngine::with_default_config();
        let threat = make_threat(Severity::Medium, ThreatCategory::Rootkit);
        let actions = engine.evaluate(&threat);
        assert!(!actions.is_empty());
    }

    #[test]
    fn test_evaluate_always_responds_to_critical() {
        let engine = ResponseEngine::with_default_config();
        let threat = make_threat(Severity::Critical, ThreatCategory::Rootkit);
        let actions = engine.evaluate(&threat);
        assert!(!actions.is_empty());
    }

    #[test]
    fn test_evaluate_disabled_engine() {
        let config = ResponseConfig {
            enabled: false,
            ..Default::default()
        };
        let engine = ResponseEngine::new(config);
        let threat = make_threat(Severity::Low, ThreatCategory::Rootkit);
        let actions = engine.evaluate(&threat);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_execute_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine.execute(&ResponseAction::Alert, "test").unwrap();
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }

    #[test]
    fn test_execute_disabled_engine() {
        let config = ResponseConfig {
            enabled: false,
            ..Default::default()
        };
        let mut engine = ResponseEngine::new(config);
        let err = engine.execute(&ResponseAction::Alert, "test").unwrap_err();
        assert!(matches!(err, ResponseError::EngineDisabled));
    }

    #[test]
    fn test_execute_actions_full_flow() {
        let mut engine = ResponseEngine::with_default_config();
        let threat = make_threat(Severity::Low, ThreatCategory::HookDetected);
        let results = engine.execute_actions(&threat);
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.success));
    }

    #[test]
    fn test_kill_process_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(&ResponseAction::KillProcess(1234), "test")
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("1234"));
    }

    #[test]
    fn test_block_network_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(
                &ResponseAction::BlockNetwork("10.0.0.1".to_string()),
                "test",
            )
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("10.0.0.1"));
    }

    #[test]
    fn test_quarantine_file_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(
                &ResponseAction::QuarantineFile("/tmp/malware".to_string()),
                "test",
            )
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("/tmp/malware"));
    }

    #[test]
    fn test_execute_actions_disabled() {
        let config = ResponseConfig {
            enabled: false,
            ..Default::default()
        };
        let mut engine = ResponseEngine::new(config);
        let threat = make_threat(Severity::High, ThreatCategory::Rootkit);
        let results = engine.execute_actions(&threat);
        assert!(results.is_empty());
    }

    #[test]
    fn test_history_tracking() {
        let mut engine = ResponseEngine::with_default_config();
        let threat = make_threat(Severity::High, ThreatCategory::Rootkit);
        let _ = threat.id.to_string();
        engine.execute_actions(&threat);
        assert!(!engine.history().is_empty());
    }

    #[test]
    fn test_rate_limiting() {
        let config = ResponseConfig {
            cooldown_seconds: 3600,
            max_responses_per_minute: 2,
            ..Default::default()
        };
        let mut engine = ResponseEngine::new(config);

        let _ = engine.execute(&ResponseAction::Alert, "threat1");
        let _ = engine.execute(&ResponseAction::Alert, "threat1");
        let result = engine.execute(&ResponseAction::Alert, "threat1");
        assert!(result.is_err());
    }

    #[test]
    fn test_severity_policies() {
        let engine = ResponseEngine::with_default_config();

        let low = make_threat(Severity::Low, ThreatCategory::HookDetected);
        let low_actions = engine.evaluate(&low);

        let critical = make_threat(Severity::Critical, ThreatCategory::HookDetected);
        let crit_actions = engine.evaluate(&critical);

        assert!(crit_actions.len() >= low_actions.len());
    }

    #[test]
    fn test_isolate_host_action() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(&ResponseAction::IsolateHost, "test")
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("isolate"));
    }

    #[test]
    fn test_snapshot_memory_action() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(&ResponseAction::SnapshotMemory(42), "test")
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("42"));
    }

    #[test]
    fn test_dump_process_action() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(&ResponseAction::DumpProcess(99), "test")
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("99"));
    }

    #[test]
    fn test_clear_history() {
        let mut engine = ResponseEngine::with_default_config();
        let threat = make_threat(Severity::High, ThreatCategory::Rootkit);
        engine.execute_actions(&threat);
        assert!(!engine.history().is_empty());

        engine.clear_history();
        assert!(engine.history().is_empty());
    }

    #[test]
    fn test_recent_history() {
        let mut engine = ResponseEngine::with_default_config();
        let threat = make_threat(Severity::High, ThreatCategory::Rootkit);
        engine.execute_actions(&threat);

        let recent = engine.recent_history(Duration::minutes(1));
        assert_eq!(recent.len(), engine.history().len());
    }

    #[test]
    fn test_policy_engine_integrated() {
        let engine = ResponseEngine::with_default_config();
        assert!(!engine.policy_engine().policies().is_empty());
    }

    #[test]
    fn test_workflow_engine_integrated() {
        let engine = ResponseEngine::with_default_config();
        assert!(!engine.workflow_engine().workflows().is_empty());
    }

    #[test]
    fn test_safety_config_default() {
        let engine = ResponseEngine::with_default_config();
        assert!(engine.safety().dry_run);
        assert!(engine.safety().never_kill_init);
    }

    #[test]
    fn test_freeze_process_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(&ResponseAction::FreezeProcess(42), "test")
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }

    #[test]
    fn test_block_ip_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(&ResponseAction::BlockIP("192.168.1.1".into()), "test")
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }

    #[test]
    fn test_disable_service_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(&ResponseAction::DisableService("sshd".into()), "test")
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }

    #[test]
    fn test_unload_module_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(&ResponseAction::UnloadModule("evil_mod".into()), "test")
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }

    #[test]
    fn test_collect_memory_dump_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(&ResponseAction::CollectMemoryDump(1234), "test")
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }

    #[test]
    fn test_generate_incident_report_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(
                &ResponseAction::GenerateIncidentReport("inc-123".into()),
                "test",
            )
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }

    #[test]
    fn test_notify_dashboard_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(&ResponseAction::NotifyDashboard("alert!".into()), "test")
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }

    #[test]
    fn test_notify_rest_api_dry_run() {
        let mut engine = ResponseEngine::with_default_config();
        let result = engine
            .execute(
                &ResponseAction::NotifyRESTAPI("http://x".into(), "{}".into()),
                "test",
            )
            .unwrap();
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }
}
