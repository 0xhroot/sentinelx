use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatSeverity {
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatPriority {
    Immediate,
    High,
    Normal,
    Low,
    Informational,
}

impl ThreatPriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::High => "high",
            Self::Normal => "normal",
            Self::Low => "low",
            Self::Informational => "informational",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub trust: f64,
    pub integrity: f64,
    pub risk: f64,
    pub reputation: f64,
    pub evidence_count: f64,
    pub incident_complexity: f64,
    pub rule_confidence: f64,
    pub final_score: f64,
}

impl RiskScore {
    pub fn new() -> Self {
        Self {
            trust: 0.0,
            integrity: 0.0,
            risk: 0.0,
            reputation: 0.0,
            evidence_count: 0.0,
            incident_complexity: 0.0,
            rule_confidence: 0.0,
            final_score: 0.0,
        }
    }

    pub fn severity_from_score(score: f64) -> ThreatSeverity {
        match score as u32 {
            0..=20 => ThreatSeverity::Info,
            21..=40 => ThreatSeverity::Low,
            41..=60 => ThreatSeverity::Medium,
            61..=80 => ThreatSeverity::High,
            _ => ThreatSeverity::Critical,
        }
    }
}

impl Default for RiskScore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDecision {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub severity: ThreatSeverity,
    pub risk_score: RiskScore,
    pub confidence: f64,
    pub priority: ThreatPriority,
    pub mitre_mappings: Vec<MitreMapping>,
    pub description: String,
    pub recommendation: String,
    pub response_plan: Option<String>,
    pub created_at: DateTime<Utc>,
    pub tags: Vec<String>,
    pub metadata: serde_json::Value,
}

impl ThreatDecision {
    pub fn new(
        incident_id: Uuid,
        severity: ThreatSeverity,
        confidence: f64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            incident_id,
            severity,
            risk_score: RiskScore::new(),
            confidence: confidence.clamp(0.0, 1.0),
            priority: ThreatPriority::Normal,
            mitre_mappings: Vec::new(),
            description: description.into(),
            recommendation: String::new(),
            response_plan: None,
            created_at: Utc::now(),
            tags: Vec::new(),
            metadata: serde_json::Value::Null,
        }
    }

    pub fn with_risk_score(mut self, score: RiskScore) -> Self {
        self.risk_score = score;
        self
    }

    pub fn with_priority(mut self, priority: ThreatPriority) -> Self {
        self.priority = priority;
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

    pub fn with_recommendation(mut self, rec: impl Into<String>) -> Self {
        self.recommendation = rec.into();
        self
    }

    pub fn with_response_plan(mut self, plan: impl Into<String>) -> Self {
        self.response_plan = Some(plan.into());
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_decision_creation() {
        let incident_id = Uuid::new_v4();
        let decision = ThreatDecision::new(
            incident_id,
            ThreatSeverity::Critical,
            0.95,
            "Rootkit detected",
        );
        assert_eq!(decision.incident_id, incident_id);
        assert_eq!(decision.severity, ThreatSeverity::Critical);
        assert_eq!(decision.confidence, 0.95);
    }

    #[test]
    fn test_risk_score_severity() {
        assert_eq!(RiskScore::severity_from_score(10.0), ThreatSeverity::Info);
        assert_eq!(RiskScore::severity_from_score(30.0), ThreatSeverity::Low);
        assert_eq!(RiskScore::severity_from_score(50.0), ThreatSeverity::Medium);
        assert_eq!(RiskScore::severity_from_score(70.0), ThreatSeverity::High);
        assert_eq!(
            RiskScore::severity_from_score(90.0),
            ThreatSeverity::Critical
        );
    }

    #[test]
    fn test_confidence_clamping() {
        let incident_id = Uuid::new_v4();
        let d = ThreatDecision::new(incident_id, ThreatSeverity::High, 1.5, "Test");
        assert_eq!(d.confidence, 1.0);
        let d2 = ThreatDecision::new(incident_id, ThreatSeverity::High, -0.5, "Test");
        assert_eq!(d2.confidence, 0.0);
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(ThreatSeverity::Critical.as_str(), "critical");
        assert_eq!(ThreatSeverity::Info.as_str(), "info");
    }

    #[test]
    fn test_priority_as_str() {
        assert_eq!(ThreatPriority::Immediate.as_str(), "immediate");
        assert_eq!(ThreatPriority::Normal.as_str(), "normal");
    }

    #[test]
    fn test_builder_chain() {
        let incident_id = Uuid::new_v4();
        let decision = ThreatDecision::new(incident_id, ThreatSeverity::High, 0.9, "Test")
            .with_priority(ThreatPriority::Immediate)
            .with_recommendation("Kill process")
            .with_response_plan("Isolate host")
            .with_tag("rootkit")
            .with_mitre("T1014", "Rootkit", "Defense Evasion");
        assert_eq!(decision.priority, ThreatPriority::Immediate);
        assert_eq!(decision.recommendation, "Kill process");
        assert!(decision.response_plan.is_some());
        assert_eq!(decision.tags.len(), 1);
        assert_eq!(decision.mitre_mappings.len(), 1);
    }
}
