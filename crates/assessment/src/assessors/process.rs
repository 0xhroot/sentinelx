use async_trait::async_trait;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::config::ScoringConfig;
use crate::types::ObjectAssessment;

use super::Assessor;

pub struct ProcessAssessor;

#[async_trait]
impl Assessor for ProcessAssessor {
    fn name(&self) -> &str {
        "process-assessor"
    }

    fn description(&self) -> &str {
        "Evaluates process trust, integrity, risk, reputation, and confidence"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::Process]
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

        let has_package = object.metadata.package_info.is_some();
        if has_package {
            trust_factors.push("official_package");
            reputation_factors.push("official_package");
            confidence_factors.push("package_verification");
            reasons.push("Has package information".to_string());
        }

        if let Some(ownership) = &object.metadata.ownership {
            if ownership.uid == 0 {
                risk_factors.push("runs_as_root");
                warnings.push("Process runs as root".to_string());
            }
            trust_factors.push("known_system_object");
        }

        if let Some(permissions) = &object.metadata.permissions {
            if permissions.mode & 0o002 != 0 {
                trust_factors.push("world_writable");
                warnings.push("World-writable process binary".to_string());
            } else {
                trust_factors.push("correct_permissions");
            }
            confidence_factors.push("filesystem_consistency");
        }

        if props.get("hidden_dkom").and_then(|v| v.as_bool()) == Some(true) {
            integrity_factors.push("hash_mismatch");
            risk_factors.push("kernel_object");
            warnings.push("DKOM hidden process detected".to_string());
        }

        if props.get("orphaned").and_then(|v| v.as_bool()) == Some(true) {
            risk_factors.push("persistence");
            warnings.push("Orphaned process (no parent)".to_string());
        }

        if props.get("is_kernel_thread").and_then(|v| v.as_bool()) == Some(true) {
            risk_factors.push("kernel_object");
        }

        if !object.metadata.hashes.is_empty() {
            integrity_factors.push("hash_available");
            confidence_factors.push("hash_available");
        }

        if has_package {
            integrity_factors.push("package_verified");
            confidence_factors.push("package_verification");
        }

        let meta_count = props.len()
            + object.metadata.hashes.len()
            + object.metadata.tags.len()
            + if object.metadata.ownership.is_some() {
                1
            } else {
                0
            }
            + if object.metadata.permissions.is_some() {
                1
            } else {
                0
            }
            + if object.metadata.package_info.is_some() {
                1
            } else {
                0
            };
        if meta_count > 5 {
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
    use sentinelx_core::object::{ObjectMetadata, OwnershipInfo, PackageInfo};

    fn make_process_object() -> SentinelObject {
        let mut metadata = ObjectMetadata::new();
        metadata.ownership = Some(OwnershipInfo {
            uid: 1000,
            gid: 1000,
            user: "user".to_string(),
            group: "user".to_string(),
        });
        metadata.package_info = Some(PackageInfo {
            name: "bash".to_string(),
            version: "5.2".to_string(),
            manager: "pacman".to_string(),
        });
        metadata
            .hashes
            .insert("sha256".to_string(), "abc123".to_string());
        metadata
            .properties
            .insert("pid".to_string(), serde_json::json!(1234));

        SentinelObject::new(ObjectType::Process, "test", "1234").with_metadata(metadata)
    }

    #[tokio::test]
    async fn test_process_assessment() {
        let assessor = ProcessAssessor;
        let config = ScoringConfig::load_default();
        let object = make_process_object();
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert_eq!(assessment.object_id, "process:1234");
        assert!(assessment.trust > 50);
        assert!(assessment.integrity > 50);
        assert!(assessment.confidence > 0.5);
        assert!(assessment
            .reasons
            .contains(&"Has package information".to_string()));
    }

    #[tokio::test]
    async fn test_process_root_warning() {
        let assessor = ProcessAssessor;
        let config = ScoringConfig::load_default();
        let mut object = make_process_object();
        object.metadata.ownership.as_mut().unwrap().uid = 0;
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.risk > 0);
        assert!(assessment.warnings.iter().any(|w| w.contains("root")));
    }

    #[tokio::test]
    async fn test_process_hidden_dkom() {
        let assessor = ProcessAssessor;
        let config = ScoringConfig::load_default();
        let mut object = make_process_object();
        object
            .metadata
            .properties
            .insert("hidden_dkom".to_string(), serde_json::json!(true));
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.risk >= 20);
        assert!(assessment.warnings.iter().any(|w| w.contains("DKOM")));
    }
}
