use async_trait::async_trait;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::config::ScoringConfig;
use crate::types::ObjectAssessment;

use super::Assessor;

pub struct ModuleAssessor;

#[async_trait]
impl Assessor for ModuleAssessor {
    fn name(&self) -> &str {
        "module-assessor"
    }

    fn description(&self) -> &str {
        "Evaluates kernel module trust, integrity, risk, reputation, and confidence"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::KernelModule]
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

        risk_factors.push("kernel_object");

        if props.get("is_builtin").and_then(|v| v.as_bool()) == Some(true) {
            trust_factors.push("known_system_object");
            trust_factors.push("official_package");
            reasons.push("Built-in kernel module".to_string());
        }

        if let Some(sig) = props.get("signature_valid").and_then(|v| v.as_bool()) {
            if sig {
                trust_factors.push("package_verification");
                integrity_factors.push("hash_match");
                reputation_factors.push("signed_binary");
                confidence_factors.push("signature_verified");
                reasons.push("Valid kernel module signature".to_string());
            } else {
                trust_factors.push("unknown_source");
                integrity_factors.push("hash_mismatch");
                reputation_factors.push("unknown_executable");
                warnings.push("Invalid kernel module signature".to_string());
            }
        }

        if props.get("dkom_suspected").and_then(|v| v.as_bool()) == Some(true) {
            integrity_factors.push("unexpected_modification");
            risk_factors.push("kernel_object");
            warnings.push("DKOM (Direct Kernel Object Manipulation) suspected".to_string());
        }

        if let Some(ts) = props.get("trust_score").and_then(|v| v.as_f64()) {
            if ts >= 0.7 {
                trust_factors.push("official_package");
                reasons.push(format!("High trust score: {:.2}", ts));
            } else if ts < 0.4 {
                trust_factors.push("unknown_source");
                warnings.push(format!("Low trust score: {:.2}", ts));
            }
        }

        if let Some(ownership) = &object.metadata.ownership {
            if ownership.uid == 0 {
                confidence_factors.push("metadata_completeness");
            }
        }

        if !object.metadata.hashes.is_empty() {
            integrity_factors.push("hash_available");
            confidence_factors.push("hash_available");
        }

        if object.metadata.package_info.is_some() {
            reputation_factors.push("official_package");
            confidence_factors.push("package_verification");
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

    fn make_builtin_module() -> SentinelObject {
        let mut metadata = ObjectMetadata::new();
        metadata
            .properties
            .insert("is_builtin".to_string(), serde_json::json!(true));
        metadata
            .properties
            .insert("signature_valid".to_string(), serde_json::json!(true));
        metadata
            .hashes
            .insert("sha256".to_string(), "abc".to_string());
        SentinelObject::new(ObjectType::KernelModule, "test", "kernel_module:e1000")
            .with_metadata(metadata)
    }

    #[tokio::test]
    async fn test_builtin_module_high_trust() {
        let assessor = ModuleAssessor;
        let config = ScoringConfig::load_default();
        let object = make_builtin_module();
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.trust >= 70);
        assert!(assessment.reasons.iter().any(|r| r.contains("Built-in")));
    }

    #[tokio::test]
    async fn test_invalid_signature_low_trust() {
        let assessor = ModuleAssessor;
        let config = ScoringConfig::load_default();
        let mut metadata = ObjectMetadata::new();
        metadata
            .properties
            .insert("signature_valid".to_string(), serde_json::json!(false));
        let object = SentinelObject::new(ObjectType::KernelModule, "test", "kernel_module:evil")
            .with_metadata(metadata);
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.trust < 50);
        assert!(assessment.warnings.iter().any(|w| w.contains("Invalid")));
    }
}
