use async_trait::async_trait;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::config::ScoringConfig;
use crate::types::ObjectAssessment;

use super::Assessor;

pub struct KernelAssessor;

#[async_trait]
impl Assessor for KernelAssessor {
    fn name(&self) -> &str {
        "kernel-assessor"
    }

    fn description(&self) -> &str {
        "Evaluates kernel integrity, hardening, hooks, and overall security posture"
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

        if let Some(kernel_obj_type) = props.get("kernel_obj_type").and_then(|v| v.as_str()) {
            match kernel_obj_type {
                "HookDetection" => {
                    integrity_factors.push("hash_mismatch");
                    integrity_factors.push("unexpected_modification");
                    risk_factors.push("kernel_object");
                    warnings.push("Kernel hook detected".to_string());
                }
                "IntegrityViolation" => {
                    integrity_factors.push("hash_mismatch");
                    integrity_factors.push("unexpected_modification");
                    risk_factors.push("kernel_object");
                    reputation_factors.push("unknown_executable");
                    warnings.push("Kernel integrity violation".to_string());
                }
                "HardeningCheck" => {
                    if let Some(severity) = props.get("severity").and_then(|v| v.as_str()) {
                        match severity {
                            "Critical" | "High" => {
                                risk_factors.push("kernel_object");
                                warnings.push("Critical kernel hardening issue".to_string());
                            }
                            "Medium" => {
                                risk_factors.push("kernel_object");
                            }
                            _ => {}
                        }
                    }
                    trust_factors.push("known_system_object");
                    reasons.push("Kernel hardening check".to_string());
                }
                _ => {}
            }
        }

        if props.get("kptr_restricted").and_then(|v| v.as_bool()) == Some(true) {
            trust_factors.push("standard_configuration");
            reasons.push("kptr_restrict is enabled".to_string());
        }

        if props.get("dmesg_restrict").and_then(|v| v.as_bool()) == Some(true) {
            trust_factors.push("standard_configuration");
            reasons.push("dmesg_restrict is enabled".to_string());
        }

        if props.get("modules_disabled").and_then(|v| v.as_bool()) == Some(true) {
            trust_factors.push("standard_configuration");
            reasons.push("Module loading is disabled".to_string());
        }

        if props.get("secure_boot").and_then(|v| v.as_bool()) == Some(true) {
            trust_factors.push("official_package");
            reputation_factors.push("verified_publisher");
            reasons.push("Secure Boot enabled".to_string());
        }

        if let Some(name) = props.get("name").and_then(|v| v.as_str()) {
            confidence_factors.push("metadata_completeness");
            reasons.push(format!("Check: {}", name));
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
    async fn test_hook_detection() {
        let assessor = KernelAssessor;
        let config = ScoringConfig::load_default();
        let mut metadata = ObjectMetadata::new();
        metadata.properties.insert(
            "kernel_obj_type".to_string(),
            serde_json::json!("HookDetection"),
        );
        let object = SentinelObject::new(ObjectType::KernelModule, "test", "kernel:hook_check")
            .with_metadata(metadata);
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.risk > 10);
        assert!(assessment.warnings.iter().any(|w| w.contains("hook")));
    }

    #[tokio::test]
    async fn test_hardening_check_pass() {
        let assessor = KernelAssessor;
        let config = ScoringConfig::load_default();
        let mut metadata = ObjectMetadata::new();
        metadata.properties.insert(
            "kernel_obj_type".to_string(),
            serde_json::json!("HardeningCheck"),
        );
        metadata
            .properties
            .insert("kptr_restricted".to_string(), serde_json::json!(true));
        metadata
            .properties
            .insert("dmesg_restrict".to_string(), serde_json::json!(true));
        metadata
            .properties
            .insert("secure_boot".to_string(), serde_json::json!(true));
        let object = SentinelObject::new(ObjectType::KernelModule, "test", "kernel:hardening")
            .with_metadata(metadata);
        let assessment = assessor.assess(&object, &config).await.unwrap();

        assert!(assessment.trust >= 70);
        assert!(assessment.reasons.len() >= 3);
    }
}
