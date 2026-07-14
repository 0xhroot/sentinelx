use async_trait::async_trait;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::config::ScoringConfig;
use crate::types::ObjectAssessment;

use super::Assessor;

pub struct ServiceAssessor;

#[async_trait]
impl Assessor for ServiceAssessor {
    fn name(&self) -> &str {
        "service-assessor"
    }

    fn description(&self) -> &str {
        "Evaluates service/persistence mechanism trust, integrity, risk, reputation, and confidence"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::Service]
    }

    async fn assess(
        &self,
        object: &SentinelObject,
        config: &ScoringConfig,
    ) -> Result<ObjectAssessment, CoreError> {
        let props = &object.metadata.properties;
        let mut trust_factors = Vec::new();
        let mut integrity_factors = Vec::new();
        let mut risk_factors = Vec::new();
        let mut reputation_factors = Vec::new();
        let mut confidence_factors = Vec::new();
        let mut reasons: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        risk_factors.push("persistence");

        if let Some(classification) = props.get("classification").and_then(|v| v.as_str()) {
            match classification {
                "TrustedOS" => {
                    trust_factors.push("official_package");
                    trust_factors.push("known_system_object");
                    reputation_factors.push("official_package");
                    reasons.push("Classified as Trusted OS component".to_string());
                }
                "TrustedPackage" => {
                    trust_factors.push("official_package");
                    reputation_factors.push("official_package");
                    confidence_factors.push("package_verification");
                    reasons.push("Classified as Trusted Package".to_string());
                }
                "Suspicious" => {
                    trust_factors.push("unknown_source");
                    reputation_factors.push("unknown_executable");
                    warnings.push("Classified as Suspicious".to_string());
                }
                "Malicious" => {
                    trust_factors.push("unknown_source");
                    reputation_factors.push("unknown_executable");
                    warnings.push("Classified as Malicious".to_string());
                }
                _ => {
                    trust_factors.push("unknown_source");
                    warnings.push("Classification: Unknown".to_string());
                }
            }
        } else {
            trust_factors.push("unknown_source");
            warnings.push("No classification available".to_string());
        }

        if props.get("is_symlink").and_then(|v| v.as_bool()) == Some(true) {
            integrity_factors.push("unexpected_modification");
            risk_factors.push("capabilities");
            warnings.push("Symlink-based persistence entry".to_string());
        } else {
            integrity_factors.push("no_unexpected_changes");
        }

        if let Some(ownership) = &object.metadata.ownership {
            if ownership.uid == 0 {
                risk_factors.push("runs_as_root");
            }
        }

        if let Some(permissions) = &object.metadata.permissions {
            if permissions.mode & 0o002 != 0 {
                trust_factors.push("world_writable");
                warnings.push("World-writable service file".to_string());
            } else {
                trust_factors.push("correct_permissions");
            }
            confidence_factors.push("filesystem_consistency");
        }

        if object.metadata.package_info.is_some() {
            reputation_factors.push("official_package");
            confidence_factors.push("package_verification");
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
    async fn test_trusted_os_service() {
        let assessor = ServiceAssessor;
        let config = ScoringConfig::load_default();
        let mut metadata = ObjectMetadata::new();
        metadata
            .properties
            .insert("classification".to_string(), serde_json::json!("TrustedOS"));
        let object = SentinelObject::new(ObjectType::Service, "test", "service:sshd")
            .with_metadata(metadata);
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.trust >= 70);
        assert!(assessment.reasons.iter().any(|r| r.contains("Trusted OS")));
    }

    #[tokio::test]
    async fn test_suspicious_service() {
        let assessor = ServiceAssessor;
        let config = ScoringConfig::load_default();
        let mut metadata = ObjectMetadata::new();
        metadata.properties.insert(
            "classification".to_string(),
            serde_json::json!("Suspicious"),
        );
        let object = SentinelObject::new(ObjectType::Service, "test", "service:evil")
            .with_metadata(metadata);
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.trust < 50);
        assert!(assessment.warnings.iter().any(|w| w.contains("Suspicious")));
    }
}
