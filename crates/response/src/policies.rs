use tracing::warn;

use crate::types::{
    severity_meets_threshold, ResponseAction, ResponsePolicy, ResponsePolicyConfig,
};

pub struct PolicyEngine {
    config: ResponsePolicyConfig,
}

impl PolicyEngine {
    pub fn new(config: ResponsePolicyConfig) -> Self {
        Self { config }
    }

    pub fn from_toml_str(toml_str: &str) -> Result<Self, String> {
        let config: ResponsePolicyConfig =
            toml::from_str(toml_str).map_err(|e| format!("Failed to parse TOML: {e}"))?;
        Ok(Self::new(config))
    }

    pub fn load_default() -> Self {
        Self::new(ResponsePolicyConfig::default())
    }

    pub fn config(&self) -> &ResponsePolicyConfig {
        &self.config
    }

    pub fn policies(&self) -> &[ResponsePolicy] {
        &self.config.policies
    }

    pub fn find_matching_policies(
        &self,
        severity: &str,
        confidence: f64,
        threat_type: &str,
    ) -> Vec<&ResponsePolicy> {
        self.config
            .policies
            .iter()
            .filter(|p| {
                severity_meets_threshold(severity, &p.severity_threshold)
                    && confidence >= p.confidence_threshold
                    && (p.threat_types.contains(&"*".to_string())
                        || p.threat_types.iter().any(|t| t == threat_type))
            })
            .collect()
    }

    pub fn best_matching_policy(
        &self,
        severity: &str,
        confidence: f64,
        threat_type: &str,
    ) -> Option<&ResponsePolicy> {
        let mut matches = self.find_matching_policies(severity, confidence, threat_type);
        matches.sort_by(|a, b| {
            let a_rank = severity_rank(&a.severity_threshold);
            let b_rank = severity_rank(&b.severity_threshold);
            b_rank.cmp(&a_rank)
        });
        matches.into_iter().next()
    }

    pub fn is_action_allowed(&self, policy: &ResponsePolicy, action: &ResponseAction) -> bool {
        let action_str = action.as_str();
        policy.allowed_actions.iter().any(|a| a == action_str)
    }

    pub fn actions_for_policy(&self, policy: &ResponsePolicy) -> Vec<ResponseAction> {
        policy
            .allowed_actions
            .iter()
            .filter_map(|s| action_from_str(s))
            .collect()
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

pub fn action_from_str(s: &str) -> Option<ResponseAction> {
    match s {
        "alert" => Some(ResponseAction::Alert),
        "log_event" => Some(ResponseAction::LogEvent),
        "freeze_process" => Some(ResponseAction::FreezeProcess(0)),
        "suspend_process" => Some(ResponseAction::SuspendProcess(0)),
        "kill_process" => Some(ResponseAction::KillProcess(0)),
        "block_pid" => Some(ResponseAction::BlockPID(0)),
        "block_ip" => Some(ResponseAction::BlockIP(String::new())),
        "close_socket" => Some(ResponseAction::CloseSocket(String::new())),
        "disable_service" => Some(ResponseAction::DisableService(String::new())),
        "unload_module" => Some(ResponseAction::UnloadModule(String::new())),
        "collect_binary" => Some(ResponseAction::CollectBinary(String::new())),
        "collect_memory_dump" => Some(ResponseAction::CollectMemoryDump(0)),
        "collect_open_files" => Some(ResponseAction::CollectOpenFiles(0)),
        "capture_network_connections" => Some(ResponseAction::CaptureNetworkConnections(0)),
        "capture_process_tree" => Some(ResponseAction::CaptureProcessTree(0)),
        "generate_incident_report" => Some(ResponseAction::GenerateIncidentReport(String::new())),
        "notify_dashboard" => Some(ResponseAction::NotifyDashboard(String::new())),
        "notify_rest_api" => Some(ResponseAction::NotifyRESTAPI(String::new(), String::new())),
        "run_custom_script" => Some(ResponseAction::RunCustomScript(String::new(), vec![])),
        _ => {
            warn!(action = s, "Unknown action type in policy");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_default_policies() {
        let engine = PolicyEngine::load_default();
        assert!(!engine.policies().is_empty());
    }

    #[test]
    fn test_find_matching_policies() {
        let engine = PolicyEngine::load_default();
        let matches = engine.find_matching_policies("critical", 0.9, "rootkit");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|p| p.name == "critical_host_isolation"));
    }

    #[test]
    fn test_find_matching_policies_low_severity() {
        let engine = PolicyEngine::load_default();
        let matches = engine.find_matching_policies("low", 0.5, "anomaly");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_find_no_matching_policies() {
        let engine = PolicyEngine::load_default();
        let matches = engine.find_matching_policies("info", 0.1, "unknown");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_best_matching_policy() {
        let engine = PolicyEngine::load_default();
        let best = engine.best_matching_policy("critical", 0.9, "rootkit");
        assert!(best.is_some());
        assert_eq!(best.unwrap().name, "critical_host_isolation");
    }

    #[test]
    fn test_wildcard_threat_type() {
        let engine = PolicyEngine::load_default();
        let matches = engine.find_matching_policies("medium", 0.6, "anything");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_is_action_allowed() {
        let engine = PolicyEngine::load_default();
        let policy = engine.policies().first().unwrap();
        assert!(engine.is_action_allowed(policy, &ResponseAction::Alert));
        assert!(engine.is_action_allowed(policy, &ResponseAction::LogEvent));
    }

    #[test]
    fn test_actions_for_policy() {
        let engine = PolicyEngine::load_default();
        let policy = engine.policies().first().unwrap();
        let actions = engine.actions_for_policy(policy);
        assert!(!actions.is_empty());
    }

    #[test]
    fn test_from_toml_str() {
        let toml_str = r#"
[[policies]]
name = "test_policy"
description = "Test"
threat_types = ["test"]
severity_threshold = "high"
confidence_threshold = 0.5
allowed_actions = ["alert", "log_event"]
timeout_seconds = 60
rollback_enabled = false
approval_required = false
"#;
        let engine = PolicyEngine::from_toml_str(toml_str).unwrap();
        assert_eq!(engine.policies().len(), 1);
        assert_eq!(engine.policies()[0].name, "test_policy");
    }

    #[test]
    fn test_from_toml_str_invalid() {
        let result = PolicyEngine::from_toml_str("not valid toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_action_from_str_known() {
        assert!(action_from_str("alert").is_some());
        assert!(action_from_str("kill_process").is_some());
        assert!(action_from_str("block_ip").is_some());
        assert!(action_from_str("unload_module").is_some());
        assert!(action_from_str("run_custom_script").is_some());
    }

    #[test]
    fn test_action_from_str_unknown() {
        assert!(action_from_str("nonexistent_action").is_none());
    }
}
