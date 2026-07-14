use async_trait::async_trait;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::config::ScoringConfig;
use crate::types::ObjectAssessment;

use super::Assessor;

pub struct NetworkAssessor;

#[async_trait]
impl Assessor for NetworkAssessor {
    fn name(&self) -> &str {
        "network-assessor"
    }

    fn description(&self) -> &str {
        "Evaluates network connection trust, integrity, risk, reputation, and confidence"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::NetworkConnection]
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
        let mut reputation_factors = Vec::new();
        let mut confidence_factors = Vec::new();
        let mut reasons: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        if props.get("is_hidden").and_then(|v| v.as_bool()) == Some(true) {
            integrity_factors.push("unexpected_modification");
            risk_factors.push("network_exposed");
            warnings.push("Hidden network connection detected".to_string());
        } else {
            integrity_factors.push("no_unexpected_changes");
        }

        if props.get("orphaned").and_then(|v| v.as_bool()) == Some(true) {
            risk_factors.push("persistence");
            warnings.push("Orphaned network connection (no associated process)".to_string());
        }

        if props.get("pid").and_then(|v| v.as_u64()).is_some() {
            confidence_factors.push("multiple_data_sources");
            reasons.push("Associated with a process".to_string());
        }

        if props.get("uid").and_then(|v| v.as_u64()) == Some(0) {
            risk_factors.push("runs_as_root");
            warnings.push("Connection owned by root".to_string());
        }

        if let Some(process_name) = props.get("process_name").and_then(|v| v.as_str()) {
            if !process_name.is_empty() {
                confidence_factors.push("metadata_completeness");
                reasons.push(format!("Process: {}", process_name));
            }
        }

        if object.metadata.package_info.is_some() {
            reputation_factors.push("official_package");
            confidence_factors.push("package_verification");
        }

        if !object.metadata.hashes.is_empty() {
            confidence_factors.push("hash_available");
        }

        let meta_count = props.len();
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
    async fn test_normal_connection() {
        let assessor = NetworkAssessor;
        let config = ScoringConfig::load_default();
        let mut metadata = ObjectMetadata::new();
        metadata
            .properties
            .insert("pid".to_string(), serde_json::json!(1234));
        metadata
            .properties
            .insert("process_name".to_string(), serde_json::json!("nginx"));
        let object = SentinelObject::new(ObjectType::NetworkConnection, "test", "network:tcp:80")
            .with_metadata(metadata);
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert_eq!(assessment.risk, 0);
        assert!(assessment.reasons.iter().any(|r| r.contains("nginx")));
    }

    #[tokio::test]
    async fn test_hidden_connection_high_risk() {
        let assessor = NetworkAssessor;
        let config = ScoringConfig::load_default();
        let mut metadata = ObjectMetadata::new();
        metadata
            .properties
            .insert("is_hidden".to_string(), serde_json::json!(true));
        let object = SentinelObject::new(ObjectType::NetworkConnection, "test", "network:hidden")
            .with_metadata(metadata);
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.risk > 10);
        assert!(assessment.warnings.iter().any(|w| w.contains("Hidden")));
    }
}
