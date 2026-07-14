use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::object::ObjectType;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TrustLevel {
    Trusted,
    Untrusted,
    Unknown,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Trusted => "trusted",
            TrustLevel::Untrusted => "untrusted",
            TrustLevel::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IntegrityLevel {
    Intact,
    Tampered,
    Unknown,
}

impl IntegrityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            IntegrityLevel::Intact => "intact",
            IntegrityLevel::Tampered => "tampered",
            IntegrityLevel::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::None => "none",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ReputationLevel {
    Known,
    Suspicious,
    Malicious,
    Unknown,
}

impl ReputationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReputationLevel::Known => "known",
            ReputationLevel::Suspicious => "suspicious",
            ReputationLevel::Malicious => "malicious",
            ReputationLevel::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentResult {
    pub object_id: String,
    pub trust: TrustLevel,
    pub integrity: IntegrityLevel,
    pub confidence: f64,
    pub risk: RiskLevel,
    pub reputation: ReputationLevel,
    pub assessed_at: DateTime<Utc>,
    pub assessor: String,
}

impl AssessmentResult {
    pub fn new(object_id: impl Into<String>, assessor: impl Into<String>) -> Self {
        Self {
            object_id: object_id.into(),
            trust: TrustLevel::Unknown,
            integrity: IntegrityLevel::Unknown,
            confidence: 0.0,
            risk: RiskLevel::None,
            reputation: ReputationLevel::Unknown,
            assessed_at: Utc::now(),
            assessor: assessor.into(),
        }
    }

    pub fn with_trust(mut self, trust: TrustLevel) -> Self {
        self.trust = trust;
        self
    }

    pub fn with_integrity(mut self, integrity: IntegrityLevel) -> Self {
        self.integrity = integrity;
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_risk(mut self, risk: RiskLevel) -> Self {
        self.risk = risk;
        self
    }

    pub fn with_reputation(mut self, reputation: ReputationLevel) -> Self {
        self.reputation = reputation;
        self
    }
}

#[async_trait::async_trait]
pub trait ObjectAssessor: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn supported_object_types(&self) -> Vec<ObjectType>;
    async fn assess(
        &self,
        object: &crate::object::SentinelObject,
    ) -> Result<AssessmentResult, crate::error::CoreError>;
}

pub struct AssessmentEngine {
    assessors: Vec<std::sync::Arc<dyn ObjectAssessor>>,
}

impl AssessmentEngine {
    pub fn new() -> Self {
        Self {
            assessors: Vec::new(),
        }
    }

    pub fn register(&mut self, assessor: std::sync::Arc<dyn ObjectAssessor>) {
        self.assessors.push(assessor);
    }

    pub fn assessor_count(&self) -> usize {
        self.assessors.len()
    }

    pub async fn assess_all(
        &self,
        objects: &mut [crate::object::SentinelObject],
    ) -> Result<usize, crate::error::CoreError> {
        let mut enriched = 0;

        for object in objects.iter_mut() {
            for assessor in &self.assessors {
                let supported = assessor.supported_object_types();
                if supported.is_empty() || supported.contains(&object.object_type) {
                    match assessor.assess(object).await {
                        Ok(result) => {
                            object.assessments.push(result);
                            enriched += 1;
                        }
                        Err(e) => {
                            tracing::warn!(
                                assessor = assessor.name(),
                                object_id = %object.id,
                                error = %e,
                                "Assessment failed"
                            );
                        }
                    }
                }
            }
        }

        Ok(enriched)
    }
}

impl Default for AssessmentEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_as_str() {
        assert_eq!(TrustLevel::Trusted.as_str(), "trusted");
        assert_eq!(TrustLevel::Untrusted.as_str(), "untrusted");
        assert_eq!(TrustLevel::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::None < RiskLevel::Low);
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_assessment_result_builder() {
        let result = AssessmentResult::new("process:1234", "test_assessor")
            .with_trust(TrustLevel::Trusted)
            .with_integrity(IntegrityLevel::Intact)
            .with_confidence(0.95)
            .with_risk(RiskLevel::Low)
            .with_reputation(ReputationLevel::Known);

        assert_eq!(result.object_id, "process:1234");
        assert_eq!(result.trust, TrustLevel::Trusted);
        assert_eq!(result.integrity, IntegrityLevel::Intact);
        assert_eq!(result.confidence, 0.95);
        assert_eq!(result.risk, RiskLevel::Low);
        assert_eq!(result.reputation, ReputationLevel::Known);
        assert_eq!(result.assessor, "test_assessor");
    }

    #[test]
    fn test_confidence_clamped() {
        let result = AssessmentResult::new("test", "test").with_confidence(2.0);
        assert_eq!(result.confidence, 1.0);

        let result = AssessmentResult::new("test", "test").with_confidence(-1.0);
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn test_assessment_engine_new() {
        let engine = AssessmentEngine::new();
        assert_eq!(engine.assessor_count(), 0);
    }

    #[test]
    fn test_risk_level_as_str() {
        assert_eq!(RiskLevel::None.as_str(), "none");
        assert_eq!(RiskLevel::Critical.as_str(), "critical");
    }

    #[test]
    fn test_reputation_level_as_str() {
        assert_eq!(ReputationLevel::Known.as_str(), "known");
        assert_eq!(ReputationLevel::Malicious.as_str(), "malicious");
    }
}
