use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IncidentStatus {
    Open,
    Investigating,
    Contained,
    Resolved,
    Closed,
}

impl IncidentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Investigating => "investigating",
            Self::Contained => "contained",
            Self::Resolved => "resolved",
            Self::Closed => "closed",
        }
    }

    pub fn parse_from(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Self::Open),
            "investigating" => Some(Self::Investigating),
            "contained" => Some(Self::Contained),
            "resolved" => Some(Self::Resolved),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IncidentSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl IncidentSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn parse_from(s: &str) -> Option<Self> {
        match s {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChainStep {
    pub order: usize,
    pub evidence_id: String,
    pub object_id: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub status: IncidentStatus,
    pub severity: IncidentSeverity,
    pub confidence: f64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub evidence_ids: Vec<String>,
    pub object_ids: Vec<String>,
    pub assessment_ids: Vec<String>,
    pub related_processes: Vec<String>,
    pub related_files: Vec<String>,
    pub related_modules: Vec<String>,
    pub attack_chain: Vec<AttackChainStep>,
    pub mitre_mappings: Vec<MitreMapping>,
    pub recommended_response: Option<String>,
    pub tags: Vec<String>,
    pub metadata: serde_json::Value,
}

impl Incident {
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        severity: IncidentSeverity,
        confidence: f64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            description: description.into(),
            status: IncidentStatus::Open,
            severity,
            confidence: confidence.clamp(0.0, 1.0),
            created_at: now,
            updated_at: now,
            evidence_ids: Vec::new(),
            object_ids: Vec::new(),
            assessment_ids: Vec::new(),
            related_processes: Vec::new(),
            related_files: Vec::new(),
            related_modules: Vec::new(),
            attack_chain: Vec::new(),
            mitre_mappings: Vec::new(),
            recommended_response: None,
            tags: Vec::new(),
            metadata: serde_json::Value::Null,
        }
    }

    pub fn with_status(mut self, status: IncidentStatus) -> Self {
        self.status = status;
        self.updated_at = Utc::now();
        self
    }

    pub fn with_evidence(mut self, evidence_id: impl Into<String>) -> Self {
        self.evidence_ids.push(evidence_id.into());
        self
    }

    pub fn with_object(mut self, object_id: impl Into<String>) -> Self {
        self.object_ids.push(object_id.into());
        self
    }

    pub fn with_assessment(mut self, assessment_id: impl Into<String>) -> Self {
        self.assessment_ids.push(assessment_id.into());
        self
    }

    pub fn with_process(mut self, process_id: impl Into<String>) -> Self {
        self.related_processes.push(process_id.into());
        self
    }

    pub fn with_file(mut self, file_path: impl Into<String>) -> Self {
        self.related_files.push(file_path.into());
        self
    }

    pub fn with_module(mut self, module_name: impl Into<String>) -> Self {
        self.related_modules.push(module_name.into());
        self
    }

    pub fn with_attack_step(
        mut self,
        order: usize,
        evidence_id: impl Into<String>,
        object_id: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        self.attack_chain.push(AttackChainStep {
            order,
            evidence_id: evidence_id.into(),
            object_id: object_id.into(),
            description: description.into(),
            timestamp: Utc::now(),
        });
        self
    }

    pub fn with_mitre(
        mut self,
        technique_id: impl Into<String>,
        technique_name: impl Into<String>,
        tactic: impl Into<String>,
    ) -> Self {
        self.mitre_mappings.push(MitreMapping {
            technique_id: technique_id.into(),
            technique_name: technique_name.into(),
            tactic: tactic.into(),
        });
        self
    }

    pub fn with_recommended_response(mut self, response: impl Into<String>) -> Self {
        self.recommended_response = Some(response.into());
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn escalate_severity(&mut self, new_severity: IncidentSeverity) {
        if new_severity.rank() > self.severity.rank() {
            self.severity = new_severity;
            self.updated_at = Utc::now();
        }
    }

    pub fn update_status(&mut self, new_status: IncidentStatus) {
        self.status = new_status;
        self.updated_at = Utc::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_creation() {
        let incident = Incident::new(
            "Rootkit Detected",
            "Hidden kernel module loaded",
            IncidentSeverity::Critical,
            0.95,
        );
        assert_eq!(incident.title, "Rootkit Detected");
        assert_eq!(incident.severity, IncidentSeverity::Critical);
        assert_eq!(incident.confidence, 0.95);
        assert_eq!(incident.status, IncidentStatus::Open);
    }

    #[test]
    fn test_incident_with_evidence() {
        let incident = Incident::new("Test", "Desc", IncidentSeverity::High, 0.8)
            .with_evidence("ev-001")
            .with_evidence("ev-002")
            .with_object("process:1234")
            .with_process("1234");
        assert_eq!(incident.evidence_ids.len(), 2);
        assert_eq!(incident.object_ids.len(), 1);
        assert_eq!(incident.related_processes.len(), 1);
    }

    #[test]
    fn test_severity_escalation() {
        let mut incident = Incident::new("Test", "Desc", IncidentSeverity::Low, 0.5);
        incident.escalate_severity(IncidentSeverity::Critical);
        assert_eq!(incident.severity, IncidentSeverity::Critical);
        incident.escalate_severity(IncidentSeverity::Medium);
        assert_eq!(incident.severity, IncidentSeverity::Critical);
    }

    #[test]
    fn test_status_update() {
        let mut incident = Incident::new("Test", "Desc", IncidentSeverity::High, 0.8);
        assert_eq!(incident.status, IncidentStatus::Open);
        incident.update_status(IncidentStatus::Investigating);
        assert_eq!(incident.status, IncidentStatus::Investigating);
    }

    #[test]
    fn test_severity_ranking() {
        assert!(IncidentSeverity::Critical.rank() > IncidentSeverity::High.rank());
        assert!(IncidentSeverity::High.rank() > IncidentSeverity::Medium.rank());
        assert!(IncidentSeverity::Medium.rank() > IncidentSeverity::Low.rank());
        assert!(IncidentSeverity::Low.rank() > IncidentSeverity::Info.rank());
    }

    #[test]
    fn test_attack_chain() {
        let incident = Incident::new("Test", "Desc", IncidentSeverity::High, 0.8)
            .with_attack_step(1, "ev-001", "process:1234", "Suspicious process spawned")
            .with_attack_step(2, "ev-002", "file:/tmp/evil", "Malicious file created")
            .with_attack_step(3, "ev-003", "kernel_module:rootkit", "Rootkit loaded");
        assert_eq!(incident.attack_chain.len(), 3);
        assert_eq!(incident.attack_chain[0].order, 1);
        assert_eq!(incident.attack_chain[2].object_id, "kernel_module:rootkit");
    }

    #[test]
    fn test_mitre_mapping() {
        let incident = Incident::new("Test", "Desc", IncidentSeverity::High, 0.8).with_mitre(
            "T1014",
            "Rootkit",
            "Defense Evasion",
        );
        assert_eq!(incident.mitre_mappings.len(), 1);
        assert_eq!(incident.mitre_mappings[0].technique_id, "T1014");
    }

    #[test]
    fn test_confidence_clamping() {
        let incident = Incident::new("Test", "Desc", IncidentSeverity::High, 1.5);
        assert_eq!(incident.confidence, 1.0);
        let incident2 = Incident::new("Test", "Desc", IncidentSeverity::High, -0.5);
        assert_eq!(incident2.confidence, 0.0);
    }
}
