use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct ScoringConfig {
    pub trust: DimensionConfig,
    pub integrity: DimensionConfig,
    pub risk: DimensionConfig,
    pub reputation: DimensionConfig,
    pub confidence: ConfidenceConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DimensionConfig {
    pub base: u32,
    pub factors: HashMap<String, i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfidenceConfig {
    pub base: f64,
    pub factors: HashMap<String, f64>,
}

impl ScoringConfig {
    pub fn load_default() -> Self {
        Self::load_from_str(DEFAULT_CONFIG).unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to parse default scoring config: {}, using hardcoded defaults",
                e
            );
            Self::hardcoded()
        })
    }

    pub fn load_from_str(s: &str) -> crate::Result<Self> {
        toml::from_str(s).map_err(|e| crate::AssessmentError::Config(e.to_string()))
    }

    pub fn load_from_path(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::AssessmentError::Config(format!("Failed to read {}: {}", path.display(), e))
        })?;
        Self::load_from_str(&content)
    }

    pub fn hardcoded() -> Self {
        Self::load_from_str(DEFAULT_CONFIG).expect("hardcoded config must parse")
    }

    pub fn compute_trust(&self, factors: &[&str]) -> u32 {
        let mut score = self.trust.base;
        for factor in factors {
            if let Some(&points) = self.trust.factors.get(*factor) {
                if points > 0 {
                    score = score.saturating_add(points as u32);
                } else {
                    score = score.saturating_sub((-points) as u32);
                }
            }
        }
        score.min(100)
    }

    pub fn compute_integrity(&self, factors: &[&str]) -> u32 {
        let mut score = self.integrity.base;
        for factor in factors {
            if let Some(&points) = self.integrity.factors.get(*factor) {
                if points > 0 {
                    score = score.saturating_add(points as u32);
                } else {
                    score = score.saturating_sub((-points) as u32);
                }
            }
        }
        score.min(100)
    }

    pub fn compute_risk(&self, factors: &[&str]) -> u32 {
        let mut score = self.risk.base;
        for factor in factors {
            if let Some(&points) = self.risk.factors.get(*factor) {
                if points > 0 {
                    score = score.saturating_add(points as u32);
                } else {
                    score = score.saturating_sub((-points) as u32);
                }
            }
        }
        score.min(100)
    }

    pub fn compute_reputation(&self, factors: &[&str]) -> u32 {
        let mut score = self.reputation.base;
        for factor in factors {
            if let Some(&points) = self.reputation.factors.get(*factor) {
                if points > 0 {
                    score = score.saturating_add(points as u32);
                } else {
                    score = score.saturating_sub((-points) as u32);
                }
            }
        }
        score.min(100)
    }

    pub fn compute_confidence(&self, factors: &[&str]) -> f64 {
        let mut score = self.confidence.base;
        for factor in factors {
            if let Some(&bonus) = self.confidence.factors.get(*factor) {
                score += bonus;
            }
        }
        score.clamp(0.0, 1.0)
    }
}

const DEFAULT_CONFIG: &str = r#"
[trust]
base = 50

[trust.factors]
official_package = 25
trusted_directory = 20
correct_permissions = 10
known_system_object = 15
package_verification = 15
repository_standard = 10
standard_configuration = 5
unknown_source = -30
suspicious_location = -40
world_writable = -20
setuid_binary = -15

[integrity]
base = 50

[integrity.factors]
hash_match = 30
package_verified = 20
permissions_consistent = 15
no_unexpected_changes = 20
immutable_attributes = 15
hash_mismatch = -40
unexpected_modification = -35
permission_anomaly = -20

[risk]
base = 0

[risk.factors]
runs_as_root = 25
kernel_object = 20
network_exposed = 15
persistence = 15
capabilities = 10
privileged_execution = 10
critical_filesystem_access = 5
suid_binary = 20
world_writable = 10
executable_memory = 15

[reputation]
base = 50

[reputation.factors]
official_package = 25
vendor_known = 20
third_party_package = 15
unknown_executable = -25
aur_package = -5
local_build = -10
foreign_package = -10
signed_binary = 15
verified_publisher = 20

[confidence]
base = 0.5

[confidence.factors]
metadata_completeness = 0.15
package_verification = 0.15
multiple_data_sources = 0.1
filesystem_consistency = 0.05
assessment_consistency = 0.05
hash_available = 0.1
signature_verified = 0.1
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_parses() {
        let config = ScoringConfig::load_default();
        assert_eq!(config.trust.base, 50);
        assert_eq!(config.risk.base, 0);
        assert_eq!(config.confidence.base, 0.5);
    }

    #[test]
    fn test_compute_trust() {
        let config = ScoringConfig::load_default();
        let score = config.compute_trust(&["official_package", "correct_permissions"]);
        assert_eq!(score, 85); // 50 + 25 + 10
    }

    #[test]
    fn test_compute_trust_with_negative() {
        let config = ScoringConfig::load_default();
        let score = config.compute_trust(&["unknown_source"]);
        assert_eq!(score, 20); // 50 - 30
    }

    #[test]
    fn test_compute_risk() {
        let config = ScoringConfig::load_default();
        let score = config.compute_risk(&["runs_as_root", "network_exposed"]);
        assert_eq!(score, 40); // 0 + 25 + 15
    }

    #[test]
    fn test_compute_confidence() {
        let config = ScoringConfig::load_default();
        let score = config.compute_confidence(&["metadata_completeness", "hash_available"]);
        assert!((score - 0.75).abs() < 0.001); // 0.5 + 0.15 + 0.1
    }

    #[test]
    fn test_score_clamping() {
        let config = ScoringConfig::load_default();
        let score = config.compute_trust(&[
            "official_package",
            "trusted_directory",
            "correct_permissions",
            "known_system_object",
            "package_verification",
            "repository_standard",
            "standard_configuration",
        ]);
        assert_eq!(score, 100); // clamped, actual sum would be 150
    }
}
