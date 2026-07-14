use chrono::{Duration, Utc};

use crate::types::{AuditRecord, RollbackStatus, WorkflowStepResult};

pub struct AuditLog {
    records: Vec<AuditRecord>,
    max_records: usize,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            max_records: 50_000,
        }
    }

    pub fn with_capacity(max_records: usize) -> Self {
        Self {
            records: Vec::new(),
            max_records,
        }
    }

    pub fn record(&mut self, record: AuditRecord) {
        if self.records.len() >= self.max_records {
            let drain_count = (self.max_records / 10).max(1);
            self.records.drain(..drain_count);
        }
        self.records.push(record);
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    pub fn count(&self) -> usize {
        self.records.len()
    }

    pub fn for_threat(&self, threat_id: uuid::Uuid) -> Vec<&AuditRecord> {
        self.records
            .iter()
            .filter(|r| r.threat_id == threat_id)
            .collect()
    }

    pub fn for_workflow(&self, workflow_name: &str) -> Vec<&AuditRecord> {
        self.records
            .iter()
            .filter(|r| r.workflow_name == workflow_name)
            .collect()
    }

    pub fn recent(&self, within: Duration) -> Vec<&AuditRecord> {
        let cutoff = Utc::now() - within;
        self.records
            .iter()
            .filter(|r| r.timestamp > cutoff)
            .collect()
    }

    pub fn failed_records(&self) -> Vec<&AuditRecord> {
        self.records
            .iter()
            .filter(|r| matches!(r.result, WorkflowStepResult::Failed(_)))
            .collect()
    }

    pub fn rollbacks_applied(&self) -> Vec<&AuditRecord> {
        self.records
            .iter()
            .filter(|r| r.rollback_status == RollbackStatus::Applied)
            .collect()
    }

    pub fn summary(&self) -> AuditSummary {
        let total = self.records.len();
        let succeeded = self
            .records
            .iter()
            .filter(|r| r.result == WorkflowStepResult::Success)
            .count();
        let failed = self
            .records
            .iter()
            .filter(|r| matches!(r.result, WorkflowStepResult::Failed(_)))
            .count();
        let skipped = self
            .records
            .iter()
            .filter(|r| matches!(r.result, WorkflowStepResult::Skipped(_)))
            .count();
        let rollbacks = self
            .records
            .iter()
            .filter(|r| r.rollback_status == RollbackStatus::Applied)
            .count();
        let dry_run = self.records.iter().filter(|r| r.dry_run).count();

        AuditSummary {
            total,
            succeeded,
            failed,
            skipped,
            rollbacks,
            dry_run,
        }
    }

    pub fn clear(&mut self) {
        self.records.clear();
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditSummary {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub rollbacks: usize,
    pub dry_run: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ResponseAction;
    use uuid::Uuid;

    fn make_audit_record(workflow: &str, threat_id: uuid::Uuid, success: bool) -> AuditRecord {
        AuditRecord {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            threat_id,
            workflow_name: workflow.to_string(),
            action: ResponseAction::Alert,
            result: if success {
                WorkflowStepResult::Success
            } else {
                WorkflowStepResult::Failed("test error".to_string())
            },
            duration_ms: 10,
            errors: if success {
                vec![]
            } else {
                vec!["test error".to_string()]
            },
            rollback_status: RollbackStatus::None,
            dry_run: true,
        }
    }

    #[test]
    fn test_audit_log_record_and_count() {
        let mut log = AuditLog::new();
        let tid = Uuid::new_v4();
        log.record(make_audit_record("wf1", tid, true));
        log.record(make_audit_record("wf1", tid, false));
        assert_eq!(log.count(), 2);
    }

    #[test]
    fn test_audit_log_for_threat() {
        let mut log = AuditLog::new();
        let tid1 = Uuid::new_v4();
        let tid2 = Uuid::new_v4();
        log.record(make_audit_record("wf1", tid1, true));
        log.record(make_audit_record("wf1", tid2, true));
        log.record(make_audit_record("wf1", tid1, false));
        assert_eq!(log.for_threat(tid1).len(), 2);
        assert_eq!(log.for_threat(tid2).len(), 1);
    }

    #[test]
    fn test_audit_log_for_workflow() {
        let mut log = AuditLog::new();
        let tid = Uuid::new_v4();
        log.record(make_audit_record("wf1", tid, true));
        log.record(make_audit_record("wf2", tid, true));
        assert_eq!(log.for_workflow("wf1").len(), 1);
        assert_eq!(log.for_workflow("wf2").len(), 1);
    }

    #[test]
    fn test_audit_log_summary() {
        let mut log = AuditLog::new();
        let tid = Uuid::new_v4();
        log.record(make_audit_record("wf1", tid, true));
        log.record(make_audit_record("wf1", tid, true));
        log.record(make_audit_record("wf1", tid, false));

        let summary = log.summary();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 2);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_audit_log_failed_records() {
        let mut log = AuditLog::new();
        let tid = Uuid::new_v4();
        log.record(make_audit_record("wf1", tid, true));
        log.record(make_audit_record("wf1", tid, false));
        assert_eq!(log.failed_records().len(), 1);
    }

    #[test]
    fn test_audit_log_clear() {
        let mut log = AuditLog::new();
        let tid = Uuid::new_v4();
        log.record(make_audit_record("wf1", tid, true));
        assert_eq!(log.count(), 1);
        log.clear();
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn test_audit_log_capacity_eviction() {
        let mut log = AuditLog::with_capacity(5);
        let tid = Uuid::new_v4();
        for _ in 0..10 {
            log.record(make_audit_record("wf1", tid, true));
        }
        assert!(log.count() <= 5);
    }
}
