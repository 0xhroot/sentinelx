use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseAction {
    Alert,
    LogEvent,
    FreezeProcess(u32),
    SuspendProcess(u32),
    KillProcess(u32),
    BlockPID(u32),
    BlockIP(String),
    CloseSocket(String),
    DisableService(String),
    UnloadModule(String),
    CollectBinary(String),
    CollectMemoryDump(u32),
    CollectOpenFiles(u32),
    CaptureNetworkConnections(u32),
    CaptureProcessTree(u32),
    GenerateIncidentReport(String),
    NotifyDashboard(String),
    NotifyRESTAPI(String, String),
    RunCustomScript(String, Vec<String>),
    #[serde(rename = "BlockNetwork")]
    BlockNetwork(String),
    #[serde(rename = "QuarantineFile")]
    QuarantineFile(String),
    #[serde(rename = "CollectForensics")]
    CollectForensics,
    #[serde(rename = "IsolateHost")]
    IsolateHost,
    #[serde(rename = "SnapshotMemory")]
    SnapshotMemory(u32),
    #[serde(rename = "DumpProcess")]
    DumpProcess(u32),
}

impl ResponseAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::LogEvent => "log_event",
            Self::FreezeProcess(_) => "freeze_process",
            Self::SuspendProcess(_) => "suspend_process",
            Self::KillProcess(_) => "kill_process",
            Self::BlockPID(_) => "block_pid",
            Self::BlockIP(_) => "block_ip",
            Self::CloseSocket(_) => "close_socket",
            Self::DisableService(_) => "disable_service",
            Self::UnloadModule(_) => "unload_module",
            Self::CollectBinary(_) => "collect_binary",
            Self::CollectMemoryDump(_) => "collect_memory_dump",
            Self::CollectOpenFiles(_) => "collect_open_files",
            Self::CaptureNetworkConnections(_) => "capture_network_connections",
            Self::CaptureProcessTree(_) => "capture_process_tree",
            Self::GenerateIncidentReport(_) => "generate_incident_report",
            Self::NotifyDashboard(_) => "notify_dashboard",
            Self::NotifyRESTAPI(_, _) => "notify_rest_api",
            Self::RunCustomScript(_, _) => "run_custom_script",
            Self::BlockNetwork(_) => "block_network",
            Self::QuarantineFile(_) => "quarantine_file",
            Self::CollectForensics => "collect_forensics",
            Self::IsolateHost => "isolate_host",
            Self::SnapshotMemory(_) => "snapshot_memory",
            Self::DumpProcess(_) => "dump_process",
        }
    }

    pub fn is_dangerous(&self) -> bool {
        matches!(
            self,
            Self::KillProcess(_)
                | Self::SuspendProcess(_)
                | Self::FreezeProcess(_)
                | Self::UnloadModule(_)
                | Self::DisableService(_)
                | Self::BlockPID(_)
                | Self::RunCustomScript(_, _)
                | Self::QuarantineFile(_)
                | Self::IsolateHost
        )
    }

    pub fn parameter_summary(&self) -> String {
        match self {
            Self::Alert => String::new(),
            Self::LogEvent => String::new(),
            Self::FreezeProcess(pid) => format!("pid={pid}"),
            Self::SuspendProcess(pid) => format!("pid={pid}"),
            Self::KillProcess(pid) => format!("pid={pid}"),
            Self::BlockPID(pid) => format!("pid={pid}"),
            Self::BlockIP(ip) => format!("ip={ip}"),
            Self::CloseSocket(sock) => format!("socket={sock}"),
            Self::DisableService(svc) => format!("service={svc}"),
            Self::UnloadModule(mod_name) => format!("module={mod_name}"),
            Self::CollectBinary(path) => format!("path={path}"),
            Self::CollectMemoryDump(pid) => format!("pid={pid}"),
            Self::CollectOpenFiles(pid) => format!("pid={pid}"),
            Self::CaptureNetworkConnections(pid) => format!("pid={pid}"),
            Self::CaptureProcessTree(pid) => format!("pid={pid}"),
            Self::GenerateIncidentReport(id) => format!("incident={id}"),
            Self::NotifyDashboard(msg) => format!("msg={msg}"),
            Self::NotifyRESTAPI(url, _) => format!("url={url}"),
            Self::RunCustomScript(path, _) => format!("script={path}"),
            Self::BlockNetwork(addr) => format!("addr={addr}"),
            Self::QuarantineFile(path) => format!("path={path}"),
            Self::CollectForensics => String::new(),
            Self::IsolateHost => String::new(),
            Self::SnapshotMemory(pid) => format!("pid={pid}"),
            Self::DumpProcess(pid) => format!("pid={pid}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePolicy {
    pub name: String,
    pub description: String,
    pub threat_types: Vec<String>,
    pub severity_threshold: String,
    pub confidence_threshold: f64,
    pub allowed_actions: Vec<String>,
    pub timeout_seconds: u64,
    pub rollback_enabled: bool,
    pub approval_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePolicyConfig {
    pub policies: Vec<ResponsePolicy>,
}

impl Default for ResponsePolicyConfig {
    fn default() -> Self {
        Self {
            policies: vec![
                ResponsePolicy {
                    name: "critical_host_isolation".to_string(),
                    description: "Isolate host on critical threats".to_string(),
                    threat_types: vec![
                        "rootkit".to_string(),
                        "privilege_escalation".to_string(),
                        "hook_detected".to_string(),
                    ],
                    severity_threshold: "critical".to_string(),
                    confidence_threshold: 0.7,
                    allowed_actions: vec![
                        "alert".to_string(),
                        "log_event".to_string(),
                        "kill_process".to_string(),
                        "block_ip".to_string(),
                        "collect_memory_dump".to_string(),
                        "capture_process_tree".to_string(),
                        "generate_incident_report".to_string(),
                        "notify_dashboard".to_string(),
                    ],
                    timeout_seconds: 300,
                    rollback_enabled: false,
                    approval_required: false,
                },
                ResponsePolicy {
                    name: "high_threat_containment".to_string(),
                    description: "Contain high-severity threats".to_string(),
                    threat_types: vec!["*".to_string()],
                    severity_threshold: "high".to_string(),
                    confidence_threshold: 0.6,
                    allowed_actions: vec![
                        "alert".to_string(),
                        "log_event".to_string(),
                        "freeze_process".to_string(),
                        "capture_network_connections".to_string(),
                        "collect_open_files".to_string(),
                        "generate_incident_report".to_string(),
                    ],
                    timeout_seconds: 120,
                    rollback_enabled: true,
                    approval_required: false,
                },
                ResponsePolicy {
                    name: "medium_threat_investigation".to_string(),
                    description: "Investigate medium-severity threats".to_string(),
                    threat_types: vec!["*".to_string()],
                    severity_threshold: "medium".to_string(),
                    confidence_threshold: 0.5,
                    allowed_actions: vec![
                        "alert".to_string(),
                        "log_event".to_string(),
                        "capture_process_tree".to_string(),
                        "collect_open_files".to_string(),
                    ],
                    timeout_seconds: 60,
                    rollback_enabled: true,
                    approval_required: false,
                },
                ResponsePolicy {
                    name: "low_threat_monitoring".to_string(),
                    description: "Monitor low-severity threats".to_string(),
                    threat_types: vec!["*".to_string()],
                    severity_threshold: "low".to_string(),
                    confidence_threshold: 0.3,
                    allowed_actions: vec!["alert".to_string(), "log_event".to_string()],
                    timeout_seconds: 30,
                    rollback_enabled: false,
                    approval_required: false,
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub action: ResponseAction,
    pub description: String,
    pub rollback_action: Option<ResponseAction>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub name: String,
    pub description: String,
    pub steps: Vec<WorkflowStep>,
    pub trigger_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkflowStepResult {
    Success,
    Failed(String),
    Skipped(String),
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecution {
    pub action: ResponseAction,
    pub result: WorkflowStepResult,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub rolled_back: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecutionResult {
    pub workflow_name: String,
    pub threat_id: uuid::Uuid,
    pub steps: Vec<StepExecution>,
    pub overall_success: bool,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RollbackStatus {
    None,
    Applied,
    Failed,
    NotRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: uuid::Uuid,
    pub timestamp: DateTime<Utc>,
    pub threat_id: uuid::Uuid,
    pub workflow_name: String,
    pub action: ResponseAction,
    pub result: WorkflowStepResult,
    pub duration_ms: u64,
    pub errors: Vec<String>,
    pub rollback_status: RollbackStatus,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConfig {
    pub dry_run: bool,
    pub never_kill_init: bool,
    pub never_unload_core_modules: bool,
    pub never_quarantine_system_binaries: bool,
    pub never_delete_files: bool,
    pub protected_pids: Vec<u32>,
    pub protected_modules: Vec<String>,
    pub protected_paths: Vec<String>,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            dry_run: true,
            never_kill_init: true,
            never_unload_core_modules: true,
            never_quarantine_system_binaries: true,
            never_delete_files: true,
            protected_pids: vec![1],
            protected_modules: vec![
                "vmlinux".to_string(),
                "core".to_string(),
                "nvidia".to_string(),
                "drm".to_string(),
                "kvm".to_string(),
            ],
            protected_paths: vec![
                "/usr/bin".to_string(),
                "/usr/sbin".to_string(),
                "/bin".to_string(),
                "/sbin".to_string(),
                "/lib".to_string(),
                "/lib64".to_string(),
                "/boot".to_string(),
                "/usr/lib".to_string(),
                "/usr/lib64".to_string(),
                "/etc".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseResult {
    pub action: ResponseAction,
    pub success: bool,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRecord {
    pub id: uuid::Uuid,
    pub threat_id: uuid::Uuid,
    pub action: ResponseAction,
    pub success: bool,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub dry_run: bool,
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

pub fn severity_meets_threshold(severity: &str, threshold: &str) -> bool {
    severity_rank(severity) >= severity_rank(threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_as_str() {
        assert_eq!(ResponseAction::Alert.as_str(), "alert");
        assert_eq!(ResponseAction::KillProcess(123).as_str(), "kill_process");
        assert_eq!(
            ResponseAction::BlockIP("1.2.3.4".to_string()).as_str(),
            "block_ip"
        );
        assert_eq!(
            ResponseAction::UnloadModule("evil".to_string()).as_str(),
            "unload_module"
        );
        assert_eq!(
            ResponseAction::NotifyRESTAPI("http://x".to_string(), "{}".to_string()).as_str(),
            "notify_rest_api"
        );
        assert_eq!(
            ResponseAction::BlockNetwork("10.0.0.1".into()).as_str(),
            "block_network"
        );
        assert_eq!(
            ResponseAction::QuarantineFile("/tmp/x".into()).as_str(),
            "quarantine_file"
        );
        assert_eq!(
            ResponseAction::CollectForensics.as_str(),
            "collect_forensics"
        );
        assert_eq!(ResponseAction::IsolateHost.as_str(), "isolate_host");
        assert_eq!(
            ResponseAction::SnapshotMemory(42).as_str(),
            "snapshot_memory"
        );
        assert_eq!(ResponseAction::DumpProcess(99).as_str(), "dump_process");
    }

    #[test]
    fn test_action_is_dangerous() {
        assert!(ResponseAction::KillProcess(1).is_dangerous());
        assert!(ResponseAction::UnloadModule("x".into()).is_dangerous());
        assert!(ResponseAction::DisableService("x".into()).is_dangerous());
        assert!(ResponseAction::RunCustomScript("x".into(), vec![]).is_dangerous());
        assert!(ResponseAction::QuarantineFile("x".into()).is_dangerous());
        assert!(ResponseAction::IsolateHost.is_dangerous());
        assert!(!ResponseAction::Alert.is_dangerous());
        assert!(!ResponseAction::LogEvent.is_dangerous());
        assert!(!ResponseAction::CollectBinary("x".into()).is_dangerous());
    }

    #[test]
    fn test_parameter_summary() {
        assert_eq!(
            ResponseAction::KillProcess(42).parameter_summary(),
            "pid=42"
        );
        assert_eq!(
            ResponseAction::BlockIP("10.0.0.1".into()).parameter_summary(),
            "ip=10.0.0.1"
        );
        assert_eq!(
            ResponseAction::DisableService("sshd".into()).parameter_summary(),
            "service=sshd"
        );
    }

    #[test]
    fn test_default_policy_config() {
        let config = ResponsePolicyConfig::default();
        assert_eq!(config.policies.len(), 4);
        assert!(config
            .policies
            .iter()
            .any(|p| p.name == "critical_host_isolation"));
    }

    #[test]
    fn test_default_safety_config() {
        let safety = SafetyConfig::default();
        assert!(safety.dry_run);
        assert!(safety.never_kill_init);
        assert!(safety.protected_pids.contains(&1));
    }

    #[test]
    fn test_severity_meets_threshold() {
        assert!(severity_meets_threshold("critical", "high"));
        assert!(severity_meets_threshold("high", "high"));
        assert!(!severity_meets_threshold("medium", "high"));
        assert!(!severity_meets_threshold("low", "critical"));
        assert!(severity_meets_threshold("info", "info"));
    }

    #[test]
    fn test_workflow_step_result_equality() {
        assert_eq!(WorkflowStepResult::Success, WorkflowStepResult::Success);
        assert_ne!(
            WorkflowStepResult::Success,
            WorkflowStepResult::Failed("x".into())
        );
    }
}
