use crate::file_analysis::{ExecRisk, FileMetadata};

#[derive(Debug, Clone)]
pub struct TrustConfig {
    pub score_base: i32,
    pub score_official_package: i32,
    pub score_standard_directory: i32,
    pub score_exec_trusted: i32,
    pub score_exec_verified: i32,
    pub score_standard_permissions: i32,
    pub score_regular_file: i32,
    pub score_exec_tmp: i32,
    pub score_exec_home: i32,
    pub score_exec_suspicious: i32,
    pub score_file_modified: i32,
    pub score_unknown_owner: i32,
    pub score_unsigned_binary: i32,
    pub score_world_writable: i32,
    pub score_setuid: i32,
    pub score_setgid: i32,
    pub score_symlink_outside: i32,
    pub score_no_package_manager: i32,
    pub threshold_suspicious: i32,
    pub threshold_malicious: i32,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            score_base: 60,
            score_official_package: 25,
            score_standard_directory: 20,
            score_exec_trusted: 10,
            score_exec_verified: 5,
            score_standard_permissions: 10,
            score_regular_file: 5,
            score_exec_tmp: -60,
            score_exec_home: -30,
            score_exec_suspicious: -20,
            score_file_modified: -30,
            score_unknown_owner: -20,
            score_unsigned_binary: -20,
            score_world_writable: -20,
            score_setuid: -25,
            score_setgid: -10,
            score_symlink_outside: -15,
            score_no_package_manager: -10,
            threshold_suspicious: 50,
            threshold_malicious: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    TrustedOS,
    TrustedPackage,
    Unknown,
    Suspicious,
    Malicious,
}

impl Classification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TrustedOS => "trusted_os",
            Self::TrustedPackage => "trusted_package",
            Self::Unknown => "unknown",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrustScore {
    pub score: i32,
    pub classification: Classification,
    pub confidence: f64,
    pub reasons: Vec<String>,
}

pub struct TrustEngine {
    config: TrustConfig,
}

impl TrustEngine {
    pub fn new(config: TrustConfig) -> Self {
        Self { config }
    }

    pub fn default_engine() -> Self {
        Self::new(TrustConfig::default())
    }

    pub fn score(
        &self,
        file_meta: &FileMetadata,
        has_package: bool,
        package_name: Option<&str>,
        exec_risks: &[ExecRisk],
        is_standard_dir: bool,
    ) -> TrustScore {
        let mut score = self.config.score_base;
        let mut reasons = Vec::new();
        let mut confidence_factors = Vec::new();

        if let Some(name) = package_name {
            score += self.config.score_official_package;
            reasons.push(format!("owned by package '{}'", name));
            confidence_factors.push(0.9);
        } else if !has_package {
            score += self.config.score_unknown_owner;
            reasons.push("no package ownership".to_string());
            confidence_factors.push(0.5);
        }

        if is_standard_dir {
            score += self.config.score_standard_directory;
            reasons.push("in standard system directory".to_string());
            confidence_factors.push(0.8);
        }

        for risk in exec_risks {
            match risk {
                ExecRisk::Trusted => {
                    score += self.config.score_exec_trusted;
                    reasons.push("ExecStart binary in trusted path".to_string());
                    confidence_factors.push(0.9);
                }
                ExecRisk::Verified => {
                    score += self.config.score_exec_verified;
                    reasons.push("ExecStart binary in verified path".to_string());
                    confidence_factors.push(0.7);
                }
                ExecRisk::Suspicious => {
                    score += self.config.score_exec_suspicious;
                    reasons.push("ExecStart binary in suspicious path".to_string());
                    confidence_factors.push(0.4);
                }
                ExecRisk::Critical => {
                    score += self.config.score_exec_tmp;
                    reasons.push("ExecStart binary in critical path (/tmp, /dev/shm)".to_string());
                    confidence_factors.push(0.2);
                }
            }
        }

        if file_meta.exists {
            if file_meta.standard_permissions() {
                score += self.config.score_standard_permissions;
                confidence_factors.push(0.7);
            }
            if file_meta.is_world_writable() {
                score += self.config.score_world_writable;
                reasons.push("world-writable file".to_string());
                confidence_factors.push(0.3);
            }
            if file_meta.is_setuid() {
                score += self.config.score_setuid;
                reasons.push("setuid bit set".to_string());
                confidence_factors.push(0.3);
            }
            if file_meta.is_setgid() {
                score += self.config.score_setgid;
                reasons.push("setgid bit set".to_string());
                confidence_factors.push(0.4);
            }
            if file_meta.is_file {
                score += self.config.score_regular_file;
            }
        } else if file_meta.is_symlink {
            score += self.config.score_symlink_outside;
            reasons.push("symlink to non-existent target".to_string());
            confidence_factors.push(0.3);
        }

        let classification = if score >= self.config.threshold_suspicious + 40 {
            if score >= 90 {
                Classification::TrustedOS
            } else {
                Classification::TrustedPackage
            }
        } else if score >= self.config.threshold_suspicious {
            Classification::Unknown
        } else if score >= self.config.threshold_malicious {
            Classification::Suspicious
        } else {
            Classification::Malicious
        };

        let confidence = if confidence_factors.is_empty() {
            0.5
        } else {
            confidence_factors.iter().sum::<f64>() / confidence_factors.len() as f64
        };

        TrustScore {
            score,
            classification,
            confidence,
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_analysis::FileMetadata;

    fn default_file_meta() -> FileMetadata {
        FileMetadata {
            exists: true,
            is_symlink: false,
            is_file: true,
            is_dir: false,
            uid: 0,
            gid: 0,
            permissions: 0o644,
            size: 1000,
            dev: 0,
            ino: 0,
        }
    }

    #[test]
    fn test_trust_score_trusted_os() {
        let engine = TrustEngine::default_engine();
        let meta = default_file_meta();
        let score = engine.score(&meta, true, Some("systemd"), &[], true);
        assert_eq!(score.classification, Classification::TrustedOS);
        assert!(score.score >= 90);
    }

    #[test]
    fn test_trust_score_trusted_package() {
        let engine = TrustEngine::default_engine();
        let meta = default_file_meta();
        let score = engine.score(&meta, true, Some("openssl"), &[], true);
        assert!(matches!(
            score.classification,
            Classification::TrustedOS | Classification::TrustedPackage
        ));
    }

    #[test]
    fn test_trust_score_unknown() {
        let engine = TrustEngine::default_engine();
        let meta = default_file_meta();
        let score = engine.score(&meta, false, None, &[], false);
        assert_eq!(score.classification, Classification::Unknown);
        assert!(score.score >= 30 && score.score < 90);
    }

    #[test]
    fn test_trust_score_suspicious_exec() {
        let engine = TrustEngine::default_engine();
        let meta = default_file_meta();
        let score = engine.score(
            &meta,
            false,
            None,
            &[crate::file_analysis::ExecRisk::Critical],
            false,
        );
        assert!(
            score.classification == Classification::Suspicious
                || score.classification == Classification::Malicious
        );
    }

    #[test]
    fn test_trust_score_malicious_tmp_exec() {
        let engine = TrustEngine::default_engine();
        let mut meta = default_file_meta();
        meta.uid = 1000;
        meta.gid = 1000;
        let score = engine.score(
            &meta,
            false,
            None,
            &[crate::file_analysis::ExecRisk::Critical],
            false,
        );
        assert_eq!(score.classification, Classification::Malicious);
    }

    #[test]
    fn test_trust_score_world_writable() {
        let engine = TrustEngine::default_engine();
        let mut meta = default_file_meta();
        meta.permissions = 0o666;
        let score = engine.score(&meta, true, Some("bash"), &[], true);
        assert!(score.score < 110);
        assert!(score.reasons.iter().any(|r| r.contains("world-writable")));
    }

    #[test]
    fn test_trust_score_setuid() {
        let engine = TrustEngine::default_engine();
        let mut meta = default_file_meta();
        meta.permissions = 0o4755;
        let score = engine.score(&meta, true, Some("sudo"), &[], true);
        assert!(score.reasons.iter().any(|r| r.contains("setuid")));
    }

    #[test]
    fn test_trust_score_symlink_broken() {
        let engine = TrustEngine::default_engine();
        let mut meta = default_file_meta();
        meta.exists = false;
        meta.is_symlink = true;
        let score = engine.score(&meta, false, None, &[], false);
        assert!(score.reasons.iter().any(|r| r.contains("symlink")));
    }

    #[test]
    fn test_custom_config_thresholds() {
        let config = TrustConfig {
            threshold_suspicious: 80,
            threshold_malicious: 60,
            ..Default::default()
        };
        let engine = TrustEngine::new(config);
        let meta = default_file_meta();
        let score = engine.score(&meta, true, Some("bash"), &[], true);
        assert!(score.score >= 90);
    }

    #[test]
    fn test_classification_as_str() {
        assert_eq!(Classification::TrustedOS.as_str(), "trusted_os");
        assert_eq!(Classification::TrustedPackage.as_str(), "trusted_package");
        assert_eq!(Classification::Unknown.as_str(), "unknown");
        assert_eq!(Classification::Suspicious.as_str(), "suspicious");
        assert_eq!(Classification::Malicious.as_str(), "malicious");
    }
}
