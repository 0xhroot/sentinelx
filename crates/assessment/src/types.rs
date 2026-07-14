use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectAssessment {
    pub id: Uuid,
    pub object_id: String,
    pub timestamp: DateTime<Utc>,
    pub trust: u32,
    pub integrity: u32,
    pub risk: u32,
    pub reputation: u32,
    pub confidence: f64,
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
    pub metadata_references: Vec<String>,
    pub version: u32,
}

impl ObjectAssessment {
    pub fn new(object_id: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            object_id: object_id.into(),
            timestamp: Utc::now(),
            trust: 0,
            integrity: 0,
            risk: 0,
            reputation: 0,
            confidence: 0.0,
            reasons: Vec::new(),
            warnings: Vec::new(),
            metadata_references: Vec::new(),
            version: 1,
        }
    }

    pub fn with_trust(mut self, trust: u32) -> Self {
        self.trust = trust.min(100);
        self
    }

    pub fn with_integrity(mut self, integrity: u32) -> Self {
        self.integrity = integrity.min(100);
        self
    }

    pub fn with_risk(mut self, risk: u32) -> Self {
        self.risk = risk.min(100);
        self
    }

    pub fn with_reputation(mut self, reputation: u32) -> Self {
        self.reputation = reputation.min(100);
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reasons.push(reason.into());
        self
    }

    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    pub fn with_metadata_reference(mut self, reference: impl Into<String>) -> Self {
        self.metadata_references.push(reference.into());
        self
    }

    pub fn with_version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    pub fn risk_level(&self) -> &str {
        match self.risk {
            0..=20 => "none",
            21..=40 => "low",
            41..=60 => "medium",
            61..=80 => "high",
            _ => "critical",
        }
    }

    pub fn trust_level(&self) -> &str {
        match self.trust {
            0..=30 => "untrusted",
            31..=60 => "unknown",
            _ => "trusted",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_assessment_creation() {
        let assessment = ObjectAssessment::new("process:1234")
            .with_trust(80)
            .with_integrity(90)
            .with_risk(20)
            .with_reputation(70)
            .with_confidence(0.85)
            .with_reason("Package verified")
            .with_warning("Running as root");

        assert_eq!(assessment.object_id, "process:1234");
        assert_eq!(assessment.trust, 80);
        assert_eq!(assessment.integrity, 90);
        assert_eq!(assessment.risk, 20);
        assert_eq!(assessment.reputation, 70);
        assert_eq!(assessment.confidence, 0.85);
        assert_eq!(assessment.reasons.len(), 1);
        assert_eq!(assessment.warnings.len(), 1);
        assert_eq!(assessment.version, 1);
    }

    #[test]
    fn test_score_clamping() {
        let assessment = ObjectAssessment::new("test")
            .with_trust(150)
            .with_integrity(200)
            .with_risk(100)
            .with_reputation(0);

        assert_eq!(assessment.trust, 100);
        assert_eq!(assessment.integrity, 100);
        assert_eq!(assessment.risk, 100);
        assert_eq!(assessment.reputation, 0);
    }

    #[test]
    fn test_confidence_clamping() {
        let assessment = ObjectAssessment::new("test")
            .with_confidence(1.5)
            .with_confidence(-0.5);

        assert_eq!(assessment.confidence, 0.0);
    }

    #[test]
    fn test_risk_level() {
        assert_eq!(ObjectAssessment::new("t").with_risk(0).risk_level(), "none");
        assert_eq!(
            ObjectAssessment::new("t").with_risk(10).risk_level(),
            "none"
        );
        assert_eq!(ObjectAssessment::new("t").with_risk(25).risk_level(), "low");
        assert_eq!(
            ObjectAssessment::new("t").with_risk(50).risk_level(),
            "medium"
        );
        assert_eq!(
            ObjectAssessment::new("t").with_risk(70).risk_level(),
            "high"
        );
        assert_eq!(
            ObjectAssessment::new("t").with_risk(90).risk_level(),
            "critical"
        );
    }

    #[test]
    fn test_trust_level() {
        assert_eq!(
            ObjectAssessment::new("t").with_trust(10).trust_level(),
            "untrusted"
        );
        assert_eq!(
            ObjectAssessment::new("t").with_trust(50).trust_level(),
            "unknown"
        );
        assert_eq!(
            ObjectAssessment::new("t").with_trust(80).trust_level(),
            "trusted"
        );
    }
}
