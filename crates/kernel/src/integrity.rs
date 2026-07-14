use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info, warn};

use chrono::Utc;
use sentinelx_common::hash::HashValue;
use sentinelx_common::severity::Severity;
use sentinelx_common::traits::Detector;
use sentinelx_common::types::{Evidence, MitreAttackMapping, ThreatCategory, ThreatEvent};
use sentinelx_evidence::{
    Evidence as EvidenceItem, EvidenceCollector, EvidenceError, EvidenceType,
};
use uuid::Uuid;

pub struct KernelIntegrityDetector {
    baseline: HashMap<String, HashValue>,
    paths_to_monitor: Vec<&'static str>,
}

impl KernelIntegrityDetector {
    pub fn new() -> Self {
        Self {
            baseline: HashMap::new(),
            paths_to_monitor: vec!["/proc/kallsyms", "/proc/modules", "/sys/module"],
        }
    }

    pub async fn baseline(&mut self) {
        info!("Building kernel integrity baseline");
        for path_str in &self.paths_to_monitor {
            if let Ok(hash) = Self::hash_path(path_str) {
                self.baseline.insert(path_str.to_string(), hash);
                debug!(path = path_str, "Baseline recorded");
            }
        }
        info!(count = self.baseline.len(), "Kernel baseline built");
    }

    fn hash_path(path: &str) -> Result<HashValue, std::io::Error> {
        let data = std::fs::read(path)?;
        Ok(HashValue::new(&data))
    }

    fn read_sysctl_int(key: &str) -> Option<String> {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn check_kptr_restrict() -> Option<IntegrityCheck> {
        let val = Self::read_sysctl_int("kptr_restrict")?;
        if val != "1" && val != "2" {
            Some(IntegrityCheck {
                name: "kptr_restrict".to_string(),
                expected: "1 or 2".to_string(),
                actual: val,
                severity: Severity::Medium,
                description: "kptr_restrict is not hardened. Kernel pointer exposure is possible."
                    .to_string(),
            })
        } else {
            None
        }
    }

    fn check_dmesg_restrict() -> Option<IntegrityCheck> {
        let val = Self::read_sysctl_int("dmesg_restrict")?;
        if val != "1" {
            Some(IntegrityCheck {
                name: "dmesg_restrict".to_string(),
                expected: "1".to_string(),
                actual: val,
                severity: Severity::Low,
                description: "dmesg_restrict is not enabled. Kernel logs are exposed.".to_string(),
            })
        } else {
            None
        }
    }

    fn check_modules_disabled() -> Option<IntegrityCheck> {
        let val = Self::read_sysctl_int("modules_disabled")?;
        if val != "1" {
            Some(IntegrityCheck {
                name: "modules_disabled".to_string(),
                expected: "1 (modules loading disabled)".to_string(),
                actual: val,
                severity: Severity::Info,
                description: "Module loading is not disabled (normal for most systems)."
                    .to_string(),
            })
        } else {
            None
        }
    }

    fn check_secure_boot() -> Option<IntegrityCheck> {
        if Path::new("/sys/firmware/efi").exists() {
            let secure_boot = std::fs::read_to_string(
                "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            );
            match secure_boot {
                Ok(data) => {
                    if let Some(&last_byte) = data.as_bytes().last() {
                        if last_byte != 1 {
                            return Some(IntegrityCheck {
                                name: "secure_boot".to_string(),
                                expected: "enabled".to_string(),
                                actual: "disabled".to_string(),
                                severity: Severity::Medium,
                                description:
                                    "Secure Boot is not enabled. Boot chain integrity cannot be verified.".to_string(),
                            });
                        }
                    }
                    None
                }
                Err(_) => Some(IntegrityCheck {
                    name: "secure_boot".to_string(),
                    expected: "present".to_string(),
                    actual: "unreadable".to_string(),
                    severity: Severity::Low,
                    description: "Cannot read Secure Boot status.".to_string(),
                }),
            }
        } else {
            None
        }
    }

    fn run_harden_checks(&self) -> Vec<IntegrityCheck> {
        let mut checks = Vec::new();
        if let Some(c) = Self::check_kptr_restrict() {
            checks.push(c);
        }
        if let Some(c) = Self::check_dmesg_restrict() {
            checks.push(c);
        }
        if let Some(c) = Self::check_modules_disabled() {
            checks.push(c);
        }
        if let Some(c) = Self::check_secure_boot() {
            checks.push(c);
        }
        checks
    }
}

impl Default for KernelIntegrityDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl EvidenceCollector for KernelIntegrityDetector {
    async fn collect_evidence(&self) -> Result<Vec<EvidenceItem>, EvidenceError> {
        let mut evidence_items = Vec::new();

        for path_str in &self.paths_to_monitor {
            match Self::hash_path(path_str) {
                Ok(current_hash) => {
                    if let Some(baseline_hash) = self.baseline.get(*path_str) {
                        if !current_hash.matches(baseline_hash) {
                            evidence_items.push(
                                EvidenceItem::new(
                                    EvidenceType::KernelIntegrity,
                                    sentinelx_evidence::Severity::Critical,
                                    "kernel_integrity".to_string(),
                                    format!("Kernel integrity violation: {}", path_str),
                                )
                                .with_data(
                                    "path".to_string(),
                                    serde_json::Value::String(path_str.to_string()),
                                )
                                .with_data(
                                    "baseline_hash".to_string(),
                                    serde_json::Value::String(baseline_hash.to_string()),
                                )
                                .with_data(
                                    "current_hash".to_string(),
                                    serde_json::Value::String(current_hash.to_string()),
                                )
                                .with_confidence(0.95)
                                .with_tag("kernel".to_string())
                                .with_tag("integrity".to_string()),
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(path = path_str, error = %e, "Cannot read kernel resource for evidence");
                }
            }
        }

        for check in self.run_harden_checks() {
            evidence_items.push(
                EvidenceItem::new(
                    EvidenceType::KernelIntegrity,
                    match check.severity {
                        Severity::Critical => sentinelx_evidence::Severity::Critical,
                        Severity::High => sentinelx_evidence::Severity::High,
                        Severity::Medium => sentinelx_evidence::Severity::Medium,
                        Severity::Low => sentinelx_evidence::Severity::Low,
                        _ => sentinelx_evidence::Severity::Info,
                    },
                    "kernel_integrity".to_string(),
                    check.description,
                )
                .with_data(
                    "check_name".to_string(),
                    serde_json::Value::String(check.name.clone()),
                )
                .with_data(
                    "expected".to_string(),
                    serde_json::Value::String(check.expected),
                )
                .with_data(
                    "actual".to_string(),
                    serde_json::Value::String(check.actual),
                )
                .with_confidence(0.9)
                .with_tag("kernel".to_string())
                .with_tag("hardening".to_string())
                .with_tag(check.name),
            );
        }

        Ok(evidence_items)
    }

    fn get_evidence_type(&self) -> EvidenceType {
        EvidenceType::KernelIntegrity
    }

    fn get_source(&self) -> String {
        "kernel_integrity".to_string()
    }
}

#[async_trait::async_trait]
impl Detector for KernelIntegrityDetector {
    fn name(&self) -> &str {
        "kernel_integrity"
    }

    fn description(&self) -> &str {
        "Monitors kernel text, read-only sections, sysctl hardening, and critical structures"
    }

    fn category(&self) -> ThreatCategory {
        ThreatCategory::IntegrityViolation
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    async fn detect(&self) -> sentinelx_common::Result<Vec<ThreatEvent>> {
        let mut threats = Vec::new();

        for path_str in &self.paths_to_monitor {
            match Self::hash_path(path_str) {
                Ok(current_hash) => {
                    if let Some(baseline_hash) = self.baseline.get(*path_str) {
                        if !current_hash.matches(baseline_hash) {
                            let mut evidence_map = HashMap::new();
                            evidence_map.insert(
                                "path".to_string(),
                                serde_json::Value::String(path_str.to_string()),
                            );
                            evidence_map.insert(
                                "baseline_hash".to_string(),
                                serde_json::Value::String(baseline_hash.to_string()),
                            );
                            evidence_map.insert(
                                "current_hash".to_string(),
                                serde_json::Value::String(current_hash.to_string()),
                            );

                            threats.push(ThreatEvent {
                                id: Uuid::new_v4(),
                                timestamp: Utc::now(),
                                severity: Severity::Critical,
                                category: ThreatCategory::IntegrityViolation,
                                title: format!("Kernel integrity violation: {}", path_str),
                                description: format!(
                                    "Kernel resource {} has been modified. Baseline hash: {}, Current hash: {}",
                                    path_str, baseline_hash, current_hash
                                ),
                                evidence: vec![Evidence {
                                    description: format!("Hash mismatch on {}", path_str),
                                    data: evidence_map,
                                    confidence: 0.95,
                                }],
                                mitre_attack: vec![MitreAttackMapping {
                                    tactic: "Defense Evasion".to_string(),
                                    technique_id: "T1014".to_string(),
                                    technique_name: "Rootkit".to_string(),
                                }],
                                source_detector: self.name().to_string(),
                                process: None,
                                network: None,
                                hash: Some(current_hash),
                                tags: vec!["kernel".to_string(), "integrity".to_string()],
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!(path = path_str, error = %e, "Cannot read kernel resource");
                }
            }
        }

        for check in self.run_harden_checks() {
            let mut evidence_map = HashMap::new();
            evidence_map.insert(
                "check_name".to_string(),
                serde_json::Value::String(check.name.clone()),
            );
            evidence_map.insert(
                "expected".to_string(),
                serde_json::Value::String(check.expected.clone()),
            );
            evidence_map.insert(
                "actual".to_string(),
                serde_json::Value::String(check.actual.clone()),
            );

            threats.push(ThreatEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                severity: check.severity,
                category: ThreatCategory::IntegrityViolation,
                title: format!("Kernel hardening: {}", check.name),
                description: check.description,
                evidence: vec![Evidence {
                    description: format!("Hardening check failed: {}", check.name),
                    data: evidence_map,
                    confidence: 0.9,
                }],
                mitre_attack: vec![MitreAttackMapping {
                    tactic: "Defense Evasion".to_string(),
                    technique_id: "T1014".to_string(),
                    technique_name: "Rootkit".to_string(),
                }],
                source_detector: self.name().to_string(),
                process: None,
                network: None,
                hash: None,
                tags: vec![
                    "kernel".to_string(),
                    "hardening".to_string(),
                    check.name.clone(),
                ],
            });
        }

        Ok(threats)
    }
}

struct IntegrityCheck {
    name: String,
    expected: String,
    actual: String,
    severity: Severity,
    description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_metadata() {
        let d = KernelIntegrityDetector::new();
        assert_eq!(d.name(), "kernel_integrity");
        assert_eq!(d.category(), ThreatCategory::IntegrityViolation);
    }

    #[tokio::test]
    async fn detect_runs_without_panic() {
        let d = KernelIntegrityDetector::new();
        let result = d.detect().await;
        assert!(result.is_ok());
    }
}
