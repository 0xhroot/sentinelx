use async_trait::async_trait;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::config::ScoringConfig;
use crate::types::ObjectAssessment;

use super::Assessor;

pub struct FileAssessor;

#[async_trait]
impl Assessor for FileAssessor {
    fn name(&self) -> &str {
        "file-assessor"
    }

    fn description(&self) -> &str {
        "Evaluates file trust, integrity, risk, reputation, and confidence"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::File]
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

        if props.get("is_modified").and_then(|v| v.as_bool()) == Some(true) {
            integrity_factors.push("hash_mismatch");
            integrity_factors.push("unexpected_modification");
            warnings.push("File has been modified".to_string());
        } else {
            integrity_factors.push("hash_match");
            integrity_factors.push("no_unexpected_changes");
        }

        if props.get("is_readable").and_then(|v| v.as_bool()) == Some(false) {
            integrity_factors.push("permission_anomaly");
            warnings.push("File is not readable".to_string());
        }

        if let Some(ownership) = &object.metadata.ownership {
            if ownership.uid == 0 {
                trust_factors.push("known_system_object");
            }
        }

        if let Some(permissions) = &object.metadata.permissions {
            if permissions.is_world_writable {
                trust_factors.push("world_writable");
                risk_factors.push("world_writable");
                warnings.push("World-writable file".to_string());
            } else {
                trust_factors.push("correct_permissions");
            }
            if permissions.is_setuid || permissions.is_setgid {
                risk_factors.push("suid_binary");
                warnings.push("SUID/SGID file detected".to_string());
            }
            confidence_factors.push("filesystem_consistency");
        }

        if object.metadata.package_info.is_some() {
            trust_factors.push("official_package");
            reputation_factors.push("official_package");
            integrity_factors.push("package_verified");
            confidence_factors.push("package_verification");
            reasons.push("Owned by a package".to_string());
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
    use sentinelx_core::object::{ObjectMetadata, PackageInfo};

    #[tokio::test]
    async fn test_modified_file() {
        let assessor = FileAssessor;
        let config = ScoringConfig::load_default();
        let mut metadata = ObjectMetadata::new();
        metadata
            .properties
            .insert("is_modified".to_string(), serde_json::json!(true));
        metadata
            .properties
            .insert("is_readable".to_string(), serde_json::json!(true));
        let object = SentinelObject::new(ObjectType::File, "test", "file:/etc/passwd")
            .with_metadata(metadata);
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.integrity < 50);
        assert!(assessment.warnings.iter().any(|w| w.contains("modified")));
    }

    #[tokio::test]
    async fn test_packaged_file() {
        let assessor = FileAssessor;
        let config = ScoringConfig::load_default();
        let mut metadata = ObjectMetadata::new();
        metadata
            .properties
            .insert("is_readable".to_string(), serde_json::json!(true));
        metadata.package_info = Some(PackageInfo {
            name: "bash".to_string(),
            version: "5.2".to_string(),
            manager: "pacman".to_string(),
        });
        let object = SentinelObject::new(ObjectType::File, "test", "file:/usr/bin/bash")
            .with_metadata(metadata);
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.trust >= 70);
        assert!(assessment.reasons.iter().any(|r| r.contains("package")));
    }
}
