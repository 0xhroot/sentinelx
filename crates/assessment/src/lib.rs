pub mod assessors;
pub mod config;
pub mod error;
pub mod store;
pub mod types;

pub use assessors::{
    Assessor, FileAssessor, KernelAssessor, MemoryAssessor, ModuleAssessor, NetworkAssessor,
    ProcessAssessor, ServiceAssessor,
};
pub use config::ScoringConfig;
pub use error::{AssessmentError, Result};
pub use store::AssessmentStore;
pub use types::ObjectAssessment;

use async_trait::async_trait;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};
use std::sync::Arc;

/// Adapter that wraps a new `Assessor` implementation to work with the
/// existing `ObjectAssessor` trait in the pipeline.
pub struct AssessorAdapter {
    inner: Arc<dyn Assessor>,
    config: ScoringConfig,
}

impl AssessorAdapter {
    pub fn new(inner: Arc<dyn Assessor>) -> Self {
        Self {
            inner,
            config: ScoringConfig::load_default(),
        }
    }

    pub fn with_config(inner: Arc<dyn Assessor>, config: ScoringConfig) -> Self {
        Self { inner, config }
    }
}

#[async_trait]
impl sentinelx_core::assessment::ObjectAssessor for AssessorAdapter {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn description(&self) -> &str {
        self.inner.description()
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        self.inner.supported_object_types()
    }

    async fn assess(
        &self,
        object: &SentinelObject,
    ) -> std::result::Result<sentinelx_core::assessment::AssessmentResult, CoreError> {
        let new_assessment = self
            .inner
            .assess(object, &self.config)
            .await
            .map_err(|e| CoreError::Assessment(e.to_string()))?;

        let trust = if new_assessment.trust >= 61 {
            sentinelx_core::assessment::TrustLevel::Trusted
        } else if new_assessment.trust >= 21 {
            sentinelx_core::assessment::TrustLevel::Unknown
        } else {
            sentinelx_core::assessment::TrustLevel::Untrusted
        };

        let integrity = if new_assessment.integrity >= 60 {
            sentinelx_core::assessment::IntegrityLevel::Intact
        } else if new_assessment.integrity >= 20 {
            sentinelx_core::assessment::IntegrityLevel::Unknown
        } else {
            sentinelx_core::assessment::IntegrityLevel::Tampered
        };

        let risk = if new_assessment.risk >= 81 {
            sentinelx_core::assessment::RiskLevel::Critical
        } else if new_assessment.risk >= 61 {
            sentinelx_core::assessment::RiskLevel::High
        } else if new_assessment.risk >= 41 {
            sentinelx_core::assessment::RiskLevel::Medium
        } else if new_assessment.risk >= 21 {
            sentinelx_core::assessment::RiskLevel::Low
        } else {
            sentinelx_core::assessment::RiskLevel::None
        };

        let reputation = match new_assessment.reputation {
            0..=30 => sentinelx_core::assessment::ReputationLevel::Malicious,
            31..=50 => sentinelx_core::assessment::ReputationLevel::Suspicious,
            51..=80 => sentinelx_core::assessment::ReputationLevel::Known,
            _ => sentinelx_core::assessment::ReputationLevel::Known,
        };

        Ok(
            sentinelx_core::assessment::AssessmentResult::new(&object.id, self.inner.name())
                .with_trust(trust)
                .with_integrity(integrity)
                .with_risk(risk)
                .with_reputation(reputation)
                .with_confidence(new_assessment.confidence),
        )
    }
}

/// Helper to create all 7 assessor adapters from the new assessor implementations.
pub fn create_all_assessors() -> Vec<Arc<dyn sentinelx_core::assessment::ObjectAssessor>> {
    vec![
        Arc::new(AssessorAdapter::new(Arc::new(ProcessAssessor))),
        Arc::new(AssessorAdapter::new(Arc::new(ModuleAssessor))),
        Arc::new(AssessorAdapter::new(Arc::new(NetworkAssessor))),
        Arc::new(AssessorAdapter::new(Arc::new(ServiceAssessor))),
        Arc::new(AssessorAdapter::new(Arc::new(FileAssessor))),
        Arc::new(AssessorAdapter::new(Arc::new(MemoryAssessor))),
        Arc::new(AssessorAdapter::new(Arc::new(KernelAssessor))),
    ]
}
