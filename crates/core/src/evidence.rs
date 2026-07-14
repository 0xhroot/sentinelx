use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::assessment::AssessmentResult;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CoreEvidenceType {
    FileIntegrity,
    ProcessIntegrity,
    NetworkIntegrity,
    KernelIntegrity,
    MemoryIntegrity,
    ModuleIntegrity,
    PersistenceIntegrity,
    SystemIntegrity,
    UserActivity,
    SecurityEvent,
}

impl CoreEvidenceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CoreEvidenceType::FileIntegrity => "file_integrity",
            CoreEvidenceType::ProcessIntegrity => "process_integrity",
            CoreEvidenceType::NetworkIntegrity => "network_integrity",
            CoreEvidenceType::KernelIntegrity => "kernel_integrity",
            CoreEvidenceType::MemoryIntegrity => "memory_integrity",
            CoreEvidenceType::ModuleIntegrity => "module_integrity",
            CoreEvidenceType::PersistenceIntegrity => "persistence_integrity",
            CoreEvidenceType::SystemIntegrity => "system_integrity",
            CoreEvidenceType::UserActivity => "user_activity",
            CoreEvidenceType::SecurityEvent => "security_event",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoreSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl CoreSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            CoreSeverity::Info => "info",
            CoreSeverity::Low => "low",
            CoreSeverity::Medium => "medium",
            CoreSeverity::High => "high",
            CoreSeverity::Critical => "critical",
        }
    }
}

/// Immutable evidence record. All fields set at construction time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreEvidence {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub object_id: String,
    pub evidence_type: CoreEvidenceType,
    pub source: String,
    pub confidence: f64,
    pub severity: CoreSeverity,
    pub metadata_snapshot: HashMap<String, serde_json::Value>,
    pub assessment_snapshot: Option<AssessmentResult>,
    pub assessment_id: Option<Uuid>,
    pub related_evidence: Vec<Uuid>,
    pub data: HashMap<String, serde_json::Value>,
}

impl CoreEvidence {
    pub fn new(
        object_id: impl Into<String>,
        evidence_type: CoreEvidenceType,
        severity: CoreSeverity,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            object_id: object_id.into(),
            evidence_type,
            severity,
            source: source.into(),
            confidence: 1.0,
            metadata_snapshot: HashMap::new(),
            assessment_snapshot: None,
            assessment_id: None,
            related_evidence: Vec::new(),
            data: HashMap::new(),
        }
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_metadata_snapshot(mut self, snapshot: HashMap<String, serde_json::Value>) -> Self {
        self.metadata_snapshot = snapshot;
        self
    }

    pub fn with_assessment(mut self, assessment: AssessmentResult) -> Self {
        self.assessment_snapshot = Some(assessment);
        self
    }

    pub fn with_assessment_id(mut self, assessment_id: uuid::Uuid) -> Self {
        self.assessment_id = Some(assessment_id);
        self
    }

    pub fn with_related_evidence(mut self, evidence_id: Uuid) -> Self {
        self.related_evidence.push(evidence_id);
        self
    }

    pub fn with_data(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.data.insert(key.into(), value);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.data
            .insert(format!("tag:{}", tag.into()), serde_json::Value::Bool(true));
        self
    }
}

// --- Bidirectional conversions ---

impl CoreEvidence {
    /// Convert a ThreatEvent into one or more CoreEvidence items.
    pub fn from_threat_event(
        event: &sentinelx_common::types::ThreatEvent,
        detector_name: &str,
    ) -> Vec<Self> {
        let mut evidence_items = Vec::new();

        let severity = match event.severity {
            sentinelx_common::severity::Severity::Info => CoreSeverity::Info,
            sentinelx_common::severity::Severity::Low => CoreSeverity::Low,
            sentinelx_common::severity::Severity::Medium => CoreSeverity::Medium,
            sentinelx_common::severity::Severity::High => CoreSeverity::High,
            sentinelx_common::severity::Severity::Critical => CoreSeverity::Critical,
        };

        let evidence_type = threat_category_to_evidence_type(&event.category);

        let mut data = HashMap::new();
        data.insert(
            "threat_id".to_string(),
            serde_json::Value::String(event.id.to_string()),
        );
        data.insert(
            "threat_title".to_string(),
            serde_json::Value::String(event.title.clone()),
        );
        data.insert(
            "threat_description".to_string(),
            serde_json::Value::String(event.description.clone()),
        );
        data.insert(
            "threat_category".to_string(),
            serde_json::Value::String(event.category.as_str().to_string()),
        );
        data.insert(
            "source_detector".to_string(),
            serde_json::Value::String(event.source_detector.clone()),
        );

        for tag in &event.tags {
            data.insert(format!("tag:{}", tag), serde_json::Value::Bool(true));
        }

        let object_id = if let Some(ref proc) = event.process {
            format!("process:{}", proc.pid)
        } else {
            format!("threat:{}", event.id)
        };

        let confidence = event.evidence.first().map(|e| e.confidence).unwrap_or(1.0);

        let mut metadata_snapshot = HashMap::new();
        for ev in &event.evidence {
            for (k, v) in &ev.data {
                metadata_snapshot.insert(k.clone(), v.clone());
            }
        }

        evidence_items.push(CoreEvidence {
            id: Uuid::new_v4(),
            timestamp: event.timestamp,
            object_id,
            evidence_type,
            source: detector_name.to_string(),
            confidence,
            severity,
            metadata_snapshot,
            assessment_snapshot: None,
            assessment_id: None,
            related_evidence: Vec::new(),
            data,
        });

        evidence_items
    }

    /// Convert back to a ThreatEvent for backward compatibility.
    pub fn to_threat_event(&self) -> sentinelx_common::types::ThreatEvent {
        let severity = match self.severity {
            CoreSeverity::Info => sentinelx_common::severity::Severity::Info,
            CoreSeverity::Low => sentinelx_common::severity::Severity::Low,
            CoreSeverity::Medium => sentinelx_common::severity::Severity::Medium,
            CoreSeverity::High => sentinelx_common::severity::Severity::High,
            CoreSeverity::Critical => sentinelx_common::severity::Severity::Critical,
        };

        let category = evidence_type_to_threat_category(&self.evidence_type);

        let title = self
            .data
            .get("threat_title")
            .and_then(|v| v.as_str())
            .unwrap_or("Evidence collected")
            .to_string();

        let description = self
            .data
            .get("threat_description")
            .and_then(|v| v.as_str())
            .unwrap_or("Evidence was collected by the pipeline")
            .to_string();

        let source_detector = self
            .data
            .get("source_detector")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.source)
            .to_string();

        let mut evidence_data = HashMap::new();
        for (k, v) in &self.metadata_snapshot {
            evidence_data.insert(k.clone(), v.clone());
        }

        let tags: Vec<String> = self
            .data
            .keys()
            .filter(|k| k.starts_with("tag:"))
            .map(|k| k[4..].to_string())
            .collect();

        sentinelx_common::types::ThreatEvent {
            id: self.id,
            timestamp: self.timestamp,
            severity,
            category,
            title,
            description,
            evidence: vec![sentinelx_common::types::Evidence {
                description: self.description_text(),
                data: evidence_data,
                confidence: self.confidence,
            }],
            mitre_attack: vec![],
            source_detector,
            process: None,
            network: None,
            hash: None,
            tags,
        }
    }

    /// Convert from the existing sentinelx-evidence::Evidence type.
    pub fn from_legacy_evidence(evidence: &sentinelx_evidence::Evidence) -> Self {
        let severity = match evidence.severity {
            sentinelx_evidence::Severity::Info => CoreSeverity::Info,
            sentinelx_evidence::Severity::Low => CoreSeverity::Low,
            sentinelx_evidence::Severity::Medium => CoreSeverity::Medium,
            sentinelx_evidence::Severity::High => CoreSeverity::High,
            sentinelx_evidence::Severity::Critical => CoreSeverity::Critical,
        };

        let evidence_type = match evidence.evidence_type {
            sentinelx_evidence::EvidenceType::FileIntegrity => CoreEvidenceType::FileIntegrity,
            sentinelx_evidence::EvidenceType::ProcessIntegrity => {
                CoreEvidenceType::ProcessIntegrity
            }
            sentinelx_evidence::EvidenceType::NetworkIntegrity => {
                CoreEvidenceType::NetworkIntegrity
            }
            sentinelx_evidence::EvidenceType::KernelIntegrity => CoreEvidenceType::KernelIntegrity,
            sentinelx_evidence::EvidenceType::MemoryIntegrity => CoreEvidenceType::MemoryIntegrity,
            sentinelx_evidence::EvidenceType::ModuleIntegrity => CoreEvidenceType::ModuleIntegrity,
            sentinelx_evidence::EvidenceType::PersistenceIntegrity => {
                CoreEvidenceType::PersistenceIntegrity
            }
            sentinelx_evidence::EvidenceType::SystemIntegrity => CoreEvidenceType::SystemIntegrity,
            sentinelx_evidence::EvidenceType::UserActivity => CoreEvidenceType::UserActivity,
            sentinelx_evidence::EvidenceType::SecurityEvent => CoreEvidenceType::SecurityEvent,
        };

        let mut data = evidence.data.clone();
        for tag in &evidence.tags {
            data.insert(format!("tag:{}", tag), serde_json::Value::Bool(true));
        }

        Self {
            id: evidence.id,
            timestamp: evidence.timestamp,
            object_id: format!("legacy:{}", evidence.source),
            evidence_type,
            source: evidence.source.clone(),
            confidence: evidence.confidence,
            severity,
            metadata_snapshot: HashMap::new(),
            assessment_snapshot: None,
            assessment_id: None,
            related_evidence: evidence.related_evidence.clone(),
            data,
        }
    }

    /// Convert to the existing sentinelx-evidence::Evidence type.
    pub fn into_legacy_evidence(self) -> sentinelx_evidence::Evidence {
        let severity = match self.severity {
            CoreSeverity::Info => sentinelx_evidence::Severity::Info,
            CoreSeverity::Low => sentinelx_evidence::Severity::Low,
            CoreSeverity::Medium => sentinelx_evidence::Severity::Medium,
            CoreSeverity::High => sentinelx_evidence::Severity::High,
            CoreSeverity::Critical => sentinelx_evidence::Severity::Critical,
        };

        let evidence_type = match self.evidence_type {
            CoreEvidenceType::FileIntegrity => sentinelx_evidence::EvidenceType::FileIntegrity,
            CoreEvidenceType::ProcessIntegrity => {
                sentinelx_evidence::EvidenceType::ProcessIntegrity
            }
            CoreEvidenceType::NetworkIntegrity => {
                sentinelx_evidence::EvidenceType::NetworkIntegrity
            }
            CoreEvidenceType::KernelIntegrity => sentinelx_evidence::EvidenceType::KernelIntegrity,
            CoreEvidenceType::MemoryIntegrity => sentinelx_evidence::EvidenceType::MemoryIntegrity,
            CoreEvidenceType::ModuleIntegrity => sentinelx_evidence::EvidenceType::ModuleIntegrity,
            CoreEvidenceType::PersistenceIntegrity => {
                sentinelx_evidence::EvidenceType::PersistenceIntegrity
            }
            CoreEvidenceType::SystemIntegrity => sentinelx_evidence::EvidenceType::SystemIntegrity,
            CoreEvidenceType::UserActivity => sentinelx_evidence::EvidenceType::UserActivity,
            CoreEvidenceType::SecurityEvent => sentinelx_evidence::EvidenceType::SecurityEvent,
        };

        let tags: Vec<String> = self
            .data
            .keys()
            .filter(|k| k.starts_with("tag:"))
            .map(|k| k[4..].to_string())
            .collect();

        let description = self.description_text();

        let data: HashMap<String, serde_json::Value> = self
            .data
            .into_iter()
            .filter(|(k, _)| !k.starts_with("tag:"))
            .collect();

        sentinelx_evidence::Evidence {
            id: self.id,
            timestamp: self.timestamp,
            evidence_type,
            severity,
            source: self.source,
            description,
            data,
            tags,
            confidence: self.confidence,
            related_evidence: self.related_evidence,
        }
    }

    fn description_text(&self) -> String {
        self.data
            .get("threat_description")
            .and_then(|v| v.as_str())
            .or_else(|| self.data.get("threat_title").and_then(|v| v.as_str()))
            .unwrap_or("Evidence collected")
            .to_string()
    }
}

fn threat_category_to_evidence_type(
    category: &sentinelx_common::types::ThreatCategory,
) -> CoreEvidenceType {
    use sentinelx_common::types::ThreatCategory;
    match category {
        ThreatCategory::HookDetected
        | ThreatCategory::SuspiciousSyscall
        | ThreatCategory::Rootkit
        | ThreatCategory::EbpfAbuse => CoreEvidenceType::KernelIntegrity,
        ThreatCategory::HiddenProcess | ThreatCategory::DkomAttack => {
            CoreEvidenceType::ProcessIntegrity
        }
        ThreatCategory::HiddenConnection | ThreatCategory::ReverseShell => {
            CoreEvidenceType::NetworkIntegrity
        }
        ThreatCategory::HiddenModule | ThreatCategory::LivepatchAbuse => {
            CoreEvidenceType::ModuleIntegrity
        }
        ThreatCategory::MemoryTampering | ThreatCategory::FilelessMalware => {
            CoreEvidenceType::MemoryIntegrity
        }
        ThreatCategory::IntegrityViolation => CoreEvidenceType::FileIntegrity,
        ThreatCategory::PersistenceMechanism => CoreEvidenceType::PersistenceIntegrity,
        ThreatCategory::PrivilegeEscalation | ThreatCategory::ContainerEscape => {
            CoreEvidenceType::SecurityEvent
        }
        ThreatCategory::Unknown => CoreEvidenceType::SystemIntegrity,
    }
}

fn evidence_type_to_threat_category(
    evidence_type: &CoreEvidenceType,
) -> sentinelx_common::types::ThreatCategory {
    use sentinelx_common::types::ThreatCategory;
    match evidence_type {
        CoreEvidenceType::KernelIntegrity => ThreatCategory::HookDetected,
        CoreEvidenceType::ProcessIntegrity => ThreatCategory::HiddenProcess,
        CoreEvidenceType::NetworkIntegrity => ThreatCategory::HiddenConnection,
        CoreEvidenceType::ModuleIntegrity => ThreatCategory::HiddenModule,
        CoreEvidenceType::MemoryIntegrity => ThreatCategory::MemoryTampering,
        CoreEvidenceType::FileIntegrity => ThreatCategory::IntegrityViolation,
        CoreEvidenceType::PersistenceIntegrity => ThreatCategory::PersistenceMechanism,
        CoreEvidenceType::SystemIntegrity => ThreatCategory::Unknown,
        CoreEvidenceType::UserActivity => ThreatCategory::Unknown,
        CoreEvidenceType::SecurityEvent => ThreatCategory::PrivilegeEscalation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_threat_event() -> sentinelx_common::types::ThreatEvent {
        use chrono::Utc;
        use sentinelx_common::pid::Pid;
        use sentinelx_common::types::{NamespaceInfo, ProcessInfo, ProcessStatus};

        sentinelx_common::types::ThreatEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: sentinelx_common::severity::Severity::High,
            category: sentinelx_common::types::ThreatCategory::HookDetected,
            title: "Test hook detected".to_string(),
            description: "A hook was detected".to_string(),
            evidence: vec![sentinelx_common::types::Evidence {
                description: "hook evidence".to_string(),
                data: HashMap::from([(
                    "hook_type".to_string(),
                    serde_json::Value::String("syscall".to_string()),
                )]),
                confidence: 0.85,
            }],
            mitre_attack: vec![],
            source_detector: "hook_detection".to_string(),
            process: Some(ProcessInfo {
                pid: Pid::new(1234),
                ppid: Pid::new(1),
                name: "test_proc".to_string(),
                binary_path: "/usr/bin/test".to_string(),
                command_line: vec!["test".to_string()],
                user: "root".to_string(),
                uid: 0,
                gid: 0,
                start_time: Utc::now(),
                status: ProcessStatus::Running,
                hash: None,
                namespace: NamespaceInfo::default(),
                capabilities: vec![],
                threads: 1,
                memory_usage_kb: 1024,
            }),
            network: None,
            hash: None,
            tags: vec!["hook".to_string(), "kernel".to_string()],
        }
    }

    #[test]
    fn test_core_evidence_creation() {
        let evidence = CoreEvidence::new(
            "process:1234",
            CoreEvidenceType::KernelIntegrity,
            CoreSeverity::High,
            "test_source",
        );
        assert_eq!(evidence.object_id, "process:1234");
        assert_eq!(evidence.evidence_type, CoreEvidenceType::KernelIntegrity);
        assert_eq!(evidence.severity, CoreSeverity::High);
        assert_eq!(evidence.source, "test_source");
        assert_eq!(evidence.confidence, 1.0);
    }

    #[test]
    fn test_core_evidence_builder() {
        let mut assessment = AssessmentResult::new("test", "test_assessor");
        assessment.confidence = 0.9;

        let evidence = CoreEvidence::new(
            "file:/etc/passwd",
            CoreEvidenceType::FileIntegrity,
            CoreSeverity::Critical,
            "file_integrity",
        )
        .with_confidence(0.95)
        .with_assessment(assessment)
        .with_data("key".to_string(), serde_json::Value::Bool(true))
        .with_tag("important");

        assert_eq!(evidence.confidence, 0.95);
        assert!(evidence.assessment_snapshot.is_some());
        assert_eq!(
            evidence.data.get("key"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn test_from_threat_event() {
        let event = make_threat_event();
        let evidence_items = CoreEvidence::from_threat_event(&event, "hook_detection");
        assert_eq!(evidence_items.len(), 1);

        let ev = &evidence_items[0];
        assert_eq!(ev.severity, CoreSeverity::High);
        assert_eq!(ev.evidence_type, CoreEvidenceType::KernelIntegrity);
        assert_eq!(ev.source, "hook_detection");
        assert_eq!(ev.object_id, "process:1234");
        assert_eq!(ev.confidence, 0.85);
        assert_eq!(
            ev.data.get("threat_title").and_then(|v| v.as_str()),
            Some("Test hook detected")
        );
        assert!(ev.data.contains_key("tag:hook"));
        assert!(ev.data.contains_key("tag:kernel"));
    }

    #[test]
    fn test_to_threat_event_roundtrip() {
        let event = make_threat_event();
        let evidence_items = CoreEvidence::from_threat_event(&event, "hook_detection");
        let reconstructed = evidence_items[0].to_threat_event();

        assert_eq!(
            reconstructed.severity,
            sentinelx_common::severity::Severity::High
        );
        assert_eq!(
            reconstructed.category,
            sentinelx_common::types::ThreatCategory::HookDetected
        );
        assert_eq!(reconstructed.source_detector, "hook_detection");
        assert!(reconstructed.tags.contains(&"hook".to_string()));
        assert!(reconstructed.tags.contains(&"kernel".to_string()));
    }

    #[test]
    fn test_from_legacy_evidence() {
        let legacy = sentinelx_evidence::Evidence::new(
            sentinelx_evidence::EvidenceType::KernelIntegrity,
            sentinelx_evidence::Severity::Critical,
            "hook_detector".to_string(),
            "Hook found".to_string(),
        )
        .with_data(
            "hook_type".to_string(),
            serde_json::Value::String("syscall".to_string()),
        )
        .with_tag("hook".to_string())
        .with_confidence(0.9);

        let core = CoreEvidence::from_legacy_evidence(&legacy);
        assert_eq!(core.severity, CoreSeverity::Critical);
        assert_eq!(core.evidence_type, CoreEvidenceType::KernelIntegrity);
        assert_eq!(core.source, "hook_detector");
        assert_eq!(core.confidence, 0.9);
        assert!(core.data.contains_key("tag:hook"));
        assert_eq!(
            core.data.get("hook_type"),
            Some(&serde_json::Value::String("syscall".to_string()))
        );
    }

    #[test]
    fn test_into_legacy_evidence_roundtrip() {
        let core = CoreEvidence::new(
            "process:1",
            CoreEvidenceType::MemoryIntegrity,
            CoreSeverity::High,
            "test",
        )
        .with_confidence(0.88)
        .with_data("custom_key".to_string(), serde_json::json!("value"))
        .with_tag("memory");

        let legacy = core.clone().into_legacy_evidence();
        assert_eq!(legacy.severity, sentinelx_evidence::Severity::High);
        assert_eq!(
            legacy.evidence_type,
            sentinelx_evidence::EvidenceType::MemoryIntegrity
        );
        assert_eq!(legacy.source, "test");
        assert_eq!(legacy.confidence, 0.88);
        assert!(legacy.tags.contains(&"memory".to_string()));
        assert_eq!(
            legacy.data.get("custom_key"),
            Some(&serde_json::json!("value"))
        );
    }

    #[test]
    fn test_severity_ordering() {
        assert!(CoreSeverity::Info < CoreSeverity::Low);
        assert!(CoreSeverity::Low < CoreSeverity::Medium);
        assert!(CoreSeverity::Medium < CoreSeverity::High);
        assert!(CoreSeverity::High < CoreSeverity::Critical);
    }

    #[test]
    fn test_evidence_type_as_str() {
        assert_eq!(CoreEvidenceType::FileIntegrity.as_str(), "file_integrity");
        assert_eq!(
            CoreEvidenceType::KernelIntegrity.as_str(),
            "kernel_integrity"
        );
        assert_eq!(
            CoreEvidenceType::PersistenceIntegrity.as_str(),
            "persistence_integrity"
        );
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(CoreSeverity::Info.as_str(), "info");
        assert_eq!(CoreSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn test_threat_event_without_process() {
        use sentinelx_common::types::ThreatCategory;

        let event = sentinelx_common::types::ThreatEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: sentinelx_common::severity::Severity::Low,
            category: ThreatCategory::IntegrityViolation,
            title: "File modified".to_string(),
            description: "A file was modified".to_string(),
            evidence: vec![],
            mitre_attack: vec![],
            source_detector: "file_integrity".to_string(),
            process: None,
            network: None,
            hash: None,
            tags: vec![],
        };

        let evidence = CoreEvidence::from_threat_event(&event, "file_integrity");
        assert_eq!(evidence[0].object_id, format!("threat:{}", event.id));
    }
}
