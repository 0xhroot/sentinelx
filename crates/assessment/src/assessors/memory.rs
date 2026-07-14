use async_trait::async_trait;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::config::ScoringConfig;
use crate::types::ObjectAssessment;

use super::Assessor;

pub struct MemoryAssessor;

#[async_trait]
impl Assessor for MemoryAssessor {
    fn name(&self) -> &str {
        "memory-assessor"
    }

    fn description(&self) -> &str {
        "Evaluates memory region trust, integrity, risk, reputation, and confidence"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::MemoryRegion]
    }

    async fn assess(
        &self,
        object: &SentinelObject,
        config: &ScoringConfig,
    ) -> Result<ObjectAssessment, CoreError> {
        let props = &object.metadata.properties;
        let trust_factors = Vec::new();
        let mut integrity_factors = Vec::new();
        let mut risk_factors = Vec::new();
        let reputation_factors = Vec::new();
        let mut confidence_factors = Vec::new();
        let mut reasons: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        if props.get("is_modified").and_then(|v| v.as_bool()) == Some(true) {
            integrity_factors.push("hash_mismatch");
            integrity_factors.push("unexpected_modification");
            risk_factors.push("executable_memory");
            warnings.push("Memory region has been modified".to_string());
        } else {
            integrity_factors.push("hash_match");
            integrity_factors.push("no_unexpected_changes");
        }

        if let Some(rs) = props.get("risk_score").and_then(|v| v.as_f64()) {
            if rs > 0.7 {
                risk_factors.push("executable_memory");
                warnings.push(format!("High memory risk score: {:.2}", rs));
            }
        }

        if props.get("is_executable").and_then(|v| v.as_bool()) == Some(true) {
            risk_factors.push("executable_memory");
        }

        if props.get("is_writable").and_then(|v| v.as_bool()) == Some(true)
            && props.get("is_executable").and_then(|v| v.as_bool()) == Some(true)
        {
            risk_factors.push("executable_memory");
            warnings.push("Writable+executable memory region (W^X violation)".to_string());
        }

        if props.get("kernel_region").and_then(|v| v.as_bool()) == Some(true) {
            risk_factors.push("kernel_object");
        }

        if let Some(name) = props.get("name").and_then(|v| v.as_str()) {
            confidence_factors.push("metadata_completeness");
            reasons.push(format!("Region: {}", name));
        }

        if !object.metadata.hashes.is_empty() {
            integrity_factors.push("hash_available");
            confidence_factors.push("hash_available");
        }

        let meta_count = props.len() + object.metadata.hashes.len();
        if meta_count > 3 {
            confidence_factors.push("metadata_completeness");
        }

        let assessment = ObjectAssessment::new(&object.id)
            .with_trust(config.compute_trust(&trust_factors))
            .with_integrity(config.compute_integrity(&integrity_factors))
            .with_risk(config.compute_risk(&risk_factors))
            .with_reputation(config.compute_reputation(&reputation_factors))
            .with_confidence(config.compute_confidence(&confidence_factors));

        let mut assessment = assessment;
        for reason in reasons {
            assessment = assessment.with_reason(reason);
        }
        for warning in warnings {
            assessment = assessment.with_warning(warning);
        }
        assessment = assessment.with_metadata_reference(format!("object:{}", object.id));

        Ok(assessment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScoringConfig;
    use sentinelx_core::object::ObjectMetadata;

    #[tokio::test]
    async fn test_modified_memory() {
        let assessor = MemoryAssessor;
        let config = ScoringConfig::load_default();
        let mut metadata = ObjectMetadata::new();
        metadata
            .properties
            .insert("is_modified".to_string(), serde_json::json!(true));
        metadata
            .properties
            .insert("is_executable".to_string(), serde_json::json!(true));
        let object = SentinelObject::new(ObjectType::MemoryRegion, "test", "memory:0x1234")
            .with_metadata(metadata);
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.integrity < 50);
        assert!(assessment.risk > 10);
    }

    #[tokio::test]
    async fn test_wxorx_violation() {
        let assessor = MemoryAssessor;
        let config = ScoringConfig::load_default();
        let mut metadata = ObjectMetadata::new();
        metadata
            .properties
            .insert("is_writable".to_string(), serde_json::json!(true));
        metadata
            .properties
            .insert("is_executable".to_string(), serde_json::json!(true));
        let object = SentinelObject::new(ObjectType::MemoryRegion, "test", "memory:0x5678")
            .with_metadata(metadata);
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.risk > 10);
        assert!(assessment.warnings.iter().any(|w| w.contains("W^X")));
    }
}
