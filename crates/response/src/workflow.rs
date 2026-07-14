use chrono::Utc;
use tracing::{debug, info, warn};

use crate::audit::AuditLog;
use crate::types::{
    AuditRecord, ResponseAction, RollbackStatus, SafetyConfig, StepExecution, Workflow,
    WorkflowExecutionResult, WorkflowStep, WorkflowStepResult,
};

pub struct WorkflowEngine {
    workflows: Vec<Workflow>,
    safety: SafetyConfig,
    audit_log: AuditLog,
}

impl WorkflowEngine {
    pub fn new(safety: SafetyConfig) -> Self {
        let mut engine = Self {
            workflows: Vec::new(),
            safety,
            audit_log: AuditLog::new(),
        };
        engine.register_default_workflows();
        engine
    }

    fn register_default_workflows(&mut self) {
        self.workflows.push(Workflow {
            name: "critical_isolation".to_string(),
            description: "Full isolation for critical threats".to_string(),
            trigger_severity: "critical".to_string(),
            steps: vec![
                WorkflowStep {
                    action: ResponseAction::Alert,
                    description: "Send critical alert".to_string(),
                    rollback_action: None,
                    timeout_seconds: None,
                },
                WorkflowStep {
                    action: ResponseAction::LogEvent,
                    description: "Log threat event".to_string(),
                    rollback_action: None,
                    timeout_seconds: None,
                },
                WorkflowStep {
                    action: ResponseAction::CaptureProcessTree(0),
                    description: "Capture process tree before containment".to_string(),
                    rollback_action: None,
                    timeout_seconds: Some(30),
                },
                WorkflowStep {
                    action: ResponseAction::CollectMemoryDump(0),
                    description: "Collect memory dump for forensics".to_string(),
                    rollback_action: None,
                    timeout_seconds: Some(60),
                },
                WorkflowStep {
                    action: ResponseAction::CaptureNetworkConnections(0),
                    description: "Capture network connections".to_string(),
                    rollback_action: None,
                    timeout_seconds: Some(15),
                },
                WorkflowStep {
                    action: ResponseAction::KillProcess(0),
                    description: "Terminate malicious process".to_string(),
                    rollback_action: None,
                    timeout_seconds: Some(10),
                },
                WorkflowStep {
                    action: ResponseAction::GenerateIncidentReport(String::new()),
                    description: "Generate incident report".to_string(),
                    rollback_action: None,
                    timeout_seconds: None,
                },
                WorkflowStep {
                    action: ResponseAction::NotifyDashboard(
                        "Critical threat contained".to_string(),
                    ),
                    description: "Notify dashboard".to_string(),
                    rollback_action: None,
                    timeout_seconds: None,
                },
            ],
        });

        self.workflows.push(Workflow {
            name: "high_containment".to_string(),
            description: "Containment for high-severity threats".to_string(),
            trigger_severity: "high".to_string(),
            steps: vec![
                WorkflowStep {
                    action: ResponseAction::Alert,
                    description: "Send alert".to_string(),
                    rollback_action: None,
                    timeout_seconds: None,
                },
                WorkflowStep {
                    action: ResponseAction::LogEvent,
                    description: "Log event".to_string(),
                    rollback_action: None,
                    timeout_seconds: None,
                },
                WorkflowStep {
                    action: ResponseAction::CaptureProcessTree(0),
                    description: "Capture process tree".to_string(),
                    rollback_action: None,
                    timeout_seconds: Some(30),
                },
                WorkflowStep {
                    action: ResponseAction::FreezeProcess(0),
                    description: "Freeze suspicious process".to_string(),
                    rollback_action: Some(ResponseAction::SuspendProcess(0)),
                    timeout_seconds: Some(10),
                },
                WorkflowStep {
                    action: ResponseAction::CaptureNetworkConnections(0),
                    description: "Capture network connections".to_string(),
                    rollback_action: None,
                    timeout_seconds: Some(15),
                },
                WorkflowStep {
                    action: ResponseAction::GenerateIncidentReport(String::new()),
                    description: "Generate incident report".to_string(),
                    rollback_action: None,
                    timeout_seconds: None,
                },
            ],
        });

        self.workflows.push(Workflow {
            name: "medium_investigation".to_string(),
            description: "Investigation for medium-severity threats".to_string(),
            trigger_severity: "medium".to_string(),
            steps: vec![
                WorkflowStep {
                    action: ResponseAction::Alert,
                    description: "Send alert".to_string(),
                    rollback_action: None,
                    timeout_seconds: None,
                },
                WorkflowStep {
                    action: ResponseAction::LogEvent,
                    description: "Log event".to_string(),
                    rollback_action: None,
                    timeout_seconds: None,
                },
                WorkflowStep {
                    action: ResponseAction::CaptureProcessTree(0),
                    description: "Capture process tree".to_string(),
                    rollback_action: None,
                    timeout_seconds: Some(30),
                },
                WorkflowStep {
                    action: ResponseAction::CollectOpenFiles(0),
                    description: "Collect open files".to_string(),
                    rollback_action: None,
                    timeout_seconds: Some(30),
                },
            ],
        });

        self.workflows.push(Workflow {
            name: "low_monitoring".to_string(),
            description: "Monitoring for low-severity threats".to_string(),
            trigger_severity: "low".to_string(),
            steps: vec![
                WorkflowStep {
                    action: ResponseAction::Alert,
                    description: "Send alert".to_string(),
                    rollback_action: None,
                    timeout_seconds: None,
                },
                WorkflowStep {
                    action: ResponseAction::LogEvent,
                    description: "Log event".to_string(),
                    rollback_action: None,
                    timeout_seconds: None,
                },
            ],
        });
    }

    pub fn register_workflow(&mut self, workflow: Workflow) {
        self.workflows.push(workflow);
    }

    pub fn workflows(&self) -> &[Workflow] {
        &self.workflows
    }

    pub fn get_workflow(&self, name: &str) -> Option<&Workflow> {
        self.workflows.iter().find(|w| w.name == name)
    }

    pub fn workflow_for_severity(&self, severity: &str) -> Option<&Workflow> {
        let rank = severity_rank(severity);
        let mut candidates: Vec<&Workflow> = self
            .workflows
            .iter()
            .filter(|w| severity_rank(&w.trigger_severity) <= rank)
            .collect();
        if candidates.is_empty() {
            return self
                .workflows
                .iter()
                .min_by_key(|w| severity_rank(&w.trigger_severity));
        }
        candidates.sort_by(|a, b| {
            severity_rank(&b.trigger_severity).cmp(&severity_rank(&a.trigger_severity))
        });
        candidates.into_iter().next()
    }

    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    pub fn audit_log_mut(&mut self) -> &mut AuditLog {
        &mut self.audit_log
    }

    pub async fn execute_workflow(
        &mut self,
        workflow_name: &str,
        threat_id: uuid::Uuid,
        dry_run: bool,
    ) -> Option<WorkflowExecutionResult> {
        let workflow = match self.get_workflow(workflow_name) {
            Some(w) => w.clone(),
            None => {
                warn!(workflow = workflow_name, "Workflow not found");
                return None;
            }
        };

        let started_at = Utc::now();
        let mut step_executions = Vec::new();
        let mut overall_success = true;

        for step in &workflow.steps {
            let step_result = self.execute_step(step, threat_id, dry_run).await;

            self.audit_log.record(AuditRecord {
                id: uuid::Uuid::new_v4(),
                timestamp: Utc::now(),
                threat_id,
                workflow_name: workflow_name.to_string(),
                action: step.action.clone(),
                result: step_result.result.clone(),
                duration_ms: step_result.duration_ms,
                errors: step_result.error.clone().into_iter().collect(),
                rollback_status: if step_result.rolled_back {
                    RollbackStatus::Applied
                } else {
                    RollbackStatus::None
                },
                dry_run,
            });

            if step_result.result == WorkflowStepResult::Success
                || matches!(step_result.result, WorkflowStepResult::Skipped(_))
            {
                // continue
            } else {
                overall_success = false;

                if let Some(ref rollback) = step.rollback_action {
                    let rollback_step = WorkflowStep {
                        action: rollback.clone(),
                        description: format!("Rollback: {}", step.description),
                        rollback_action: None,
                        timeout_seconds: None,
                    };
                    let rollback_result =
                        self.execute_step(&rollback_step, threat_id, dry_run).await;

                    self.audit_log.record(AuditRecord {
                        id: uuid::Uuid::new_v4(),
                        timestamp: Utc::now(),
                        threat_id,
                        workflow_name: workflow_name.to_string(),
                        action: rollback_step.action.clone(),
                        result: rollback_result.result.clone(),
                        duration_ms: rollback_result.duration_ms,
                        errors: rollback_result.error.into_iter().collect(),
                        rollback_status: RollbackStatus::Applied,
                        dry_run,
                    });
                }
            }

            step_executions.push(step_result);
        }

        let completed_at = Utc::now();
        let duration_ms = (completed_at - started_at).num_milliseconds() as u64;

        Some(WorkflowExecutionResult {
            workflow_name: workflow_name.to_string(),
            threat_id,
            steps: step_executions,
            overall_success,
            started_at,
            completed_at,
            duration_ms,
            dry_run,
        })
    }

    async fn execute_step(
        &self,
        step: &WorkflowStep,
        _threat_id: uuid::Uuid,
        dry_run: bool,
    ) -> StepExecution {
        let start = Utc::now();

        if let Some(ref reason) = self.check_safety(&step.action) {
            warn!(
                action = ?step.action,
                reason = reason,
                "Action blocked by safety check"
            );
            let duration = (Utc::now() - start).num_milliseconds() as u64;
            return StepExecution {
                action: step.action.clone(),
                result: WorkflowStepResult::Skipped(format!("Safety: {reason}")),
                duration_ms: duration,
                error: Some(format!("Blocked by safety: {reason}")),
                rolled_back: false,
            };
        }

        if dry_run {
            let message = format!("[DRY RUN] {}", step.description);
            info!(action = ?step.action, "{}", message);
            let duration = (Utc::now() - start).num_milliseconds() as u64;
            return StepExecution {
                action: step.action.clone(),
                result: WorkflowStepResult::Success,
                duration_ms: duration,
                error: None,
                rolled_back: false,
            };
        }

        let _message = execute_action_real(&step.action);
        let duration = (Utc::now() - start).num_milliseconds() as u64;

        debug!(
            action = ?step.action,
            duration_ms = duration,
            "Step executed"
        );

        StepExecution {
            action: step.action.clone(),
            result: WorkflowStepResult::Success,
            duration_ms: duration,
            error: None,
            rolled_back: false,
        }
    }

    fn check_safety(&self, action: &ResponseAction) -> Option<String> {
        match action {
            ResponseAction::KillProcess(pid) => {
                if self.safety.never_kill_init && self.safety.protected_pids.contains(pid) {
                    return Some(format!("Cannot kill protected PID {pid} (init)"));
                }
                None
            }
            ResponseAction::FreezeProcess(pid)
            | ResponseAction::SuspendProcess(pid)
            | ResponseAction::BlockPID(pid) => {
                if self.safety.never_kill_init && self.safety.protected_pids.contains(pid) {
                    return Some(format!("Cannot modify protected PID {pid} (init)"));
                }
                None
            }
            ResponseAction::UnloadModule(name) => {
                if self.safety.never_unload_core_modules
                    && self
                        .safety
                        .protected_modules
                        .iter()
                        .any(|m| name.contains(m.as_str()))
                {
                    return Some(format!("Cannot unload protected module '{name}'"));
                }
                None
            }
            ResponseAction::CollectBinary(path) => {
                if self.safety.never_quarantine_system_binaries
                    && self
                        .safety
                        .protected_paths
                        .iter()
                        .any(|p| path.starts_with(p))
                {
                    return Some(format!("Cannot collect system binary '{path}'"));
                }
                None
            }
            ResponseAction::RunCustomScript(_, _) => {
                if self.safety.dry_run {
                    return Some("Custom scripts blocked in dry-run mode".to_string());
                }
                None
            }
            _ => None,
        }
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

fn execute_action_real(action: &ResponseAction) -> String {
    match action {
        ResponseAction::Alert => "Alert sent".to_string(),
        ResponseAction::LogEvent => "Event logged".to_string(),
        ResponseAction::FreezeProcess(pid) => format!("Process {pid} frozen"),
        ResponseAction::SuspendProcess(pid) => format!("Process {pid} suspended"),
        ResponseAction::KillProcess(pid) => format!("Process {pid} terminated"),
        ResponseAction::BlockPID(pid) => format!("PID {pid} blocked"),
        ResponseAction::BlockIP(ip) => format!("IP {ip} blocked"),
        ResponseAction::CloseSocket(sock) => format!("Socket {sock} closed"),
        ResponseAction::DisableService(svc) => format!("Service {svc} disabled"),
        ResponseAction::UnloadModule(name) => format!("Module {name} unloaded"),
        ResponseAction::CollectBinary(path) => format!("Binary {path} collected"),
        ResponseAction::CollectMemoryDump(pid) => format!("Memory dump for PID {pid} collected"),
        ResponseAction::CollectOpenFiles(pid) => format!("Open files for PID {pid} collected"),
        ResponseAction::CaptureNetworkConnections(pid) => {
            format!("Network connections for PID {pid} captured")
        }
        ResponseAction::CaptureProcessTree(pid) => {
            format!("Process tree for PID {pid} captured")
        }
        ResponseAction::GenerateIncidentReport(id) => {
            format!("Incident report {id} generated")
        }
        ResponseAction::NotifyDashboard(msg) => format!("Dashboard notified: {msg}"),
        ResponseAction::NotifyRESTAPI(url, _) => format!("REST API notified at {url}"),
        ResponseAction::RunCustomScript(path, _) => format!("Script {path} executed"),
        ResponseAction::BlockNetwork(addr) => format!("Network address {addr} blocked"),
        ResponseAction::QuarantineFile(path) => format!("File {path} quarantined"),
        ResponseAction::CollectForensics => "Forensic snapshot collected".to_string(),
        ResponseAction::IsolateHost => "Host isolated from network".to_string(),
        ResponseAction::SnapshotMemory(pid) => format!("Memory snapshot for PID {pid} captured"),
        ResponseAction::DumpProcess(pid) => format!("Process {pid} dumped"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workflow_engine_default_workflows() {
        let engine = WorkflowEngine::new(SafetyConfig::default());
        assert_eq!(engine.workflows().len(), 4);
        assert!(engine.get_workflow("critical_isolation").is_some());
        assert!(engine.get_workflow("high_containment").is_some());
        assert!(engine.get_workflow("medium_investigation").is_some());
        assert!(engine.get_workflow("low_monitoring").is_some());
    }

    #[test]
    fn test_workflow_for_severity() {
        let engine = WorkflowEngine::new(SafetyConfig::default());

        let wf = engine.workflow_for_severity("critical");
        assert!(wf.is_some());
        assert_eq!(wf.unwrap().name, "critical_isolation");

        let wf = engine.workflow_for_severity("high");
        assert!(wf.is_some());
        assert_eq!(wf.unwrap().name, "high_containment");

        let wf = engine.workflow_for_severity("medium");
        assert!(wf.is_some());
        assert_eq!(wf.unwrap().name, "medium_investigation");

        let wf = engine.workflow_for_severity("low");
        assert!(wf.is_some());
        assert_eq!(wf.unwrap().name, "low_monitoring");

        let wf = engine.workflow_for_severity("info");
        assert!(wf.is_some());
        assert_eq!(wf.unwrap().name, "low_monitoring");
    }

    #[test]
    fn test_register_custom_workflow() {
        let mut engine = WorkflowEngine::new(SafetyConfig::default());
        let custom = Workflow {
            name: "custom".to_string(),
            description: "Custom workflow".to_string(),
            trigger_severity: "high".to_string(),
            steps: vec![WorkflowStep {
                action: ResponseAction::Alert,
                description: "Alert".to_string(),
                rollback_action: None,
                timeout_seconds: None,
            }],
        };
        engine.register_workflow(custom);
        assert!(engine.get_workflow("custom").is_some());
    }

    #[tokio::test]
    async fn test_execute_workflow_dry_run() {
        let mut engine = WorkflowEngine::new(SafetyConfig::default());
        let result = engine
            .execute_workflow("low_monitoring", uuid::Uuid::new_v4(), true)
            .await;
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.overall_success);
        assert!(result.dry_run);
        assert_eq!(result.steps.len(), 2);
    }

    #[tokio::test]
    async fn test_execute_workflow_not_found() {
        let mut engine = WorkflowEngine::new(SafetyConfig::default());
        let result = engine
            .execute_workflow("nonexistent", uuid::Uuid::new_v4(), true)
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_execute_workflow_records_audit() {
        let mut engine = WorkflowEngine::new(SafetyConfig::default());
        engine
            .execute_workflow("low_monitoring", uuid::Uuid::new_v4(), true)
            .await;
        assert!(engine.audit_log().count() > 0);
    }

    #[test]
    fn test_safety_blocks_kill_init() {
        let engine = WorkflowEngine::new(SafetyConfig::default());
        let result = engine.check_safety(&ResponseAction::KillProcess(1));
        assert!(result.is_some());
        assert!(result.unwrap().contains("init"));
    }

    #[test]
    fn test_safety_allows_normal_kill() {
        let engine = WorkflowEngine::new(SafetyConfig::default());
        let result = engine.check_safety(&ResponseAction::KillProcess(1234));
        assert!(result.is_none());
    }

    #[test]
    fn test_safety_blocks_core_module() {
        let engine = WorkflowEngine::new(SafetyConfig::default());
        let result = engine.check_safety(&ResponseAction::UnloadModule("vmlinux".into()));
        assert!(result.is_some());
    }

    #[test]
    fn test_safety_blocks_custom_script_in_dry_run() {
        let engine = WorkflowEngine::new(SafetyConfig::default());
        let result =
            engine.check_safety(&ResponseAction::RunCustomScript("test.sh".into(), vec![]));
        assert!(result.is_some());
    }

    #[test]
    fn test_safety_blocks_system_binary() {
        let engine = WorkflowEngine::new(SafetyConfig::default());
        let result = engine.check_safety(&ResponseAction::CollectBinary("/usr/bin/ls".into()));
        assert!(result.is_some());
    }
}
