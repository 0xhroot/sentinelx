use std::collections::HashMap;
use std::io::Read;

use chrono::Utc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use sentinelx_common::hash::HashValue;
use sentinelx_common::severity::Severity;
use sentinelx_common::traits::Detector;
use sentinelx_common::types::{Evidence, MitreAttackMapping, ThreatCategory, ThreatEvent};
use sentinelx_evidence::{
    Evidence as EvidenceItem, EvidenceCollector, EvidenceError, EvidenceType,
};

const CRITICAL_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ld.so.preload",
    "/boot/grub/grub.cfg",
    "/etc/crontab",
];

pub struct IntegrityChecker {
    baseline: HashMap<String, HashValue>,
}

impl IntegrityChecker {
    pub fn new() -> Self {
        Self {
            baseline: HashMap::new(),
        }
    }

    pub fn baseline(&mut self) {
        info!("Building file integrity baseline");

        for path in CRITICAL_FILES {
            if let Some(hash) = Self::hash_file(path) {
                self.baseline.insert(path.to_string(), hash);
                debug!(path = *path, "Baseline recorded");
            } else {
                warn!(path = *path, "Could not hash critical file for baseline");
            }
        }

        info!(count = self.baseline.len(), "File integrity baseline built");
    }

    fn hash_file(path: &str) -> Option<HashValue> {
        let metadata = std::fs::metadata(path).ok()?;
        let mut file = std::fs::File::open(path).ok()?;
        let mut data = Vec::new();
        data.resize_with(metadata.len() as usize, Default::default);
        file.read_exact(&mut data).ok()?;
        Some(HashValue::new(&data))
    }

    fn check_files(&self) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        for path in CRITICAL_FILES {
            if !self.baseline.contains_key(*path) {
                continue;
            }

            let current_hash = match Self::hash_file(path) {
                Some(h) => h,
                None => {
                    warn!(
                        path = *path,
                        "Cannot read critical file during integrity check"
                    );
                    let baseline_hash = self
                        .baseline
                        .get(*path)
                        .expect("path checked via iteration over baseline keys");
                    threats.push(ThreatEvent {
                        id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        severity: Severity::Critical,
                        category: ThreatCategory::IntegrityViolation,
                        title: format!("Critical file unreadable: {}", path),
                        description: format!(
                            "The critical system file {} could not be read during integrity check.",
                            path
                        ),
                        evidence: vec![Evidence {
                            description: "File unreadable".to_string(),
                            data: HashMap::from([
                                (
                                    "path".to_string(),
                                    serde_json::Value::String(path.to_string()),
                                ),
                                (
                                    "baseline_hash".to_string(),
                                    serde_json::Value::String(baseline_hash.to_string()),
                                ),
                            ]),
                            confidence: 0.95,
                        }],
                        mitre_attack: vec![MitreAttackMapping {
                            tactic: "Defense Evasion".to_string(),
                            technique_id: "T1070".to_string(),
                            technique_name: "Indicator Removal on Host".to_string(),
                        }],
                        source_detector: "file_integrity".to_string(),
                        process: None,
                        network: None,
                        hash: None,
                        tags: vec![
                            "integrity".to_string(),
                            "critical_file".to_string(),
                            "unreadable".to_string(),
                        ],
                    });
                    continue;
                }
            };

            let baseline_hash = self.baseline.get(*path).unwrap();

            if !current_hash.matches(baseline_hash) {
                warn!(
                    path = *path,
                    baseline = baseline_hash.as_hex(),
                    current = current_hash.as_hex(),
                    "Integrity violation detected"
                );

                threats.push(ThreatEvent {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::Critical,
                    category: ThreatCategory::IntegrityViolation,
                    title: format!("Integrity violation: {}", path),
                    description: format!(
                        "Critical system file {} has been modified since baseline. \
                         Expected hash {} but found {}.",
                        path, baseline_hash, current_hash
                    ),
                    evidence: vec![Evidence {
                        description: "File hash mismatch".to_string(),
                        data: HashMap::from([
                            (
                                "path".to_string(),
                                serde_json::Value::String(path.to_string()),
                            ),
                            (
                                "baseline_hash".to_string(),
                                serde_json::Value::String(baseline_hash.to_string()),
                            ),
                            (
                                "current_hash".to_string(),
                                serde_json::Value::String(current_hash.to_string()),
                            ),
                        ]),
                        confidence: 1.0,
                    }],
                    mitre_attack: vec![MitreAttackMapping {
                        tactic: "Defense Evasion".to_string(),
                        technique_id: "T1070.006".to_string(),
                        technique_name: "Timestomp".to_string(),
                    }],
                    source_detector: "file_integrity".to_string(),
                    process: None,
                    network: None,
                    hash: Some(current_hash),
                    tags: vec![
                        "integrity".to_string(),
                        "critical_file".to_string(),
                        "modified".to_string(),
                    ],
                });
            }
        }

        threats
    }
}

impl Default for IntegrityChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl EvidenceCollector for IntegrityChecker {
    async fn collect_evidence(&self) -> Result<Vec<EvidenceItem>, EvidenceError> {
        let mut evidence_items = Vec::new();

        for path in CRITICAL_FILES {
            if !self.baseline.contains_key(*path) {
                continue;
            }

            let current_hash = match Self::hash_file(path) {
                Some(h) => h,
                None => {
                    let baseline_hash = self
                        .baseline
                        .get(*path)
                        .expect("path checked via contains_key above");
                    evidence_items.push(
                        EvidenceItem::new(
                            EvidenceType::FileIntegrity,
                            sentinelx_evidence::Severity::Critical,
                            "file_integrity".to_string(),
                            format!("Critical file unreadable: {}", path),
                        )
                        .with_data(
                            "path".to_string(),
                            serde_json::Value::String(path.to_string()),
                        )
                        .with_data(
                            "baseline_hash".to_string(),
                            serde_json::Value::String(baseline_hash.to_string()),
                        )
                        .with_confidence(0.95)
                        .with_tag("integrity".to_string())
                        .with_tag("critical_file".to_string())
                        .with_tag("unreadable".to_string()),
                    );
                    continue;
                }
            };

            let baseline_hash = self.baseline.get(*path).unwrap();

            if !current_hash.matches(baseline_hash) {
                evidence_items.push(
                    EvidenceItem::new(
                        EvidenceType::FileIntegrity,
                        sentinelx_evidence::Severity::Critical,
                        "file_integrity".to_string(),
                        format!("Integrity violation: {}", path),
                    )
                    .with_data(
                        "path".to_string(),
                        serde_json::Value::String(path.to_string()),
                    )
                    .with_data(
                        "baseline_hash".to_string(),
                        serde_json::Value::String(baseline_hash.to_string()),
                    )
                    .with_data(
                        "current_hash".to_string(),
                        serde_json::Value::String(current_hash.to_string()),
                    )
                    .with_confidence(1.0)
                    .with_tag("integrity".to_string())
                    .with_tag("critical_file".to_string())
                    .with_tag("modified".to_string()),
                );
            }
        }

        Ok(evidence_items)
    }

    fn get_evidence_type(&self) -> EvidenceType {
        EvidenceType::FileIntegrity
    }

    fn get_source(&self) -> String {
        "file_integrity".to_string()
    }
}

#[async_trait::async_trait]
impl Detector for IntegrityChecker {
    fn name(&self) -> &str {
        "file_integrity"
    }

    fn description(&self) -> &str {
        "Monitors critical system files for unauthorized modifications"
    }

    fn category(&self) -> ThreatCategory {
        ThreatCategory::IntegrityViolation
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    async fn detect(&self) -> sentinelx_common::Result<Vec<ThreatEvent>> {
        info!("Running file integrity check");
        let threats = self.check_files();
        info!(
            threat_count = threats.len(),
            "File integrity check complete"
        );
        Ok(threats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_metadata() {
        let d = IntegrityChecker::new();
        assert_eq!(d.name(), "file_integrity");
        assert_eq!(d.category(), ThreatCategory::IntegrityViolation);
    }

    #[tokio::test]
    async fn detect_runs_without_panic() {
        let d = IntegrityChecker::new();
        let result = d.detect().await;
        assert!(result.is_ok());
    }
}
