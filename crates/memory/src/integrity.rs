use std::collections::HashMap;
use tracing::info;

use chrono::Utc;
use sentinelx_common::hash::HashValue;
use sentinelx_common::severity::Severity;
use sentinelx_common::traits::Detector;
use sentinelx_common::types::{Evidence, MitreAttackMapping, ThreatCategory, ThreatEvent};
use sentinelx_evidence::{
    Evidence as EvidenceItem, EvidenceCollector, EvidenceError, EvidenceType,
};
use uuid::Uuid;

pub struct MemoryIntegrityChecker {
    baseline: HashMap<String, HashValue>,
}

impl MemoryIntegrityChecker {
    pub fn new() -> Self {
        Self {
            baseline: HashMap::new(),
        }
    }

    pub fn baseline(&mut self) {
        info!("Building memory integrity baseline");

        if let Some(hash) = Self::hash_file("/proc/kallsyms") {
            self.baseline.insert("/proc/kallsyms".to_string(), hash);
        }

        self.baseline_memory_maps();

        info!(count = self.baseline.len(), "Memory baseline built");
    }

    fn hash_file(path: &str) -> Option<HashValue> {
        let metadata = std::fs::metadata(path).ok()?;
        let mut data = Vec::new();

        if metadata.len() > 10 * 1024 * 1024 {
            return None;
        }

        std::fs::File::open(path).ok().and_then(|mut f| {
            use std::io::Read;
            data.resize_with(metadata.len() as usize, Default::default);
            f.read_exact(&mut data).ok()?;
            Some(HashValue::new(&data))
        })
    }

    fn baseline_memory_maps(&mut self) {
        if let Ok(content) = std::fs::read_to_string("/proc/self/maps") {
            let mut maps_data = Vec::new();
            for line in content.lines() {
                if line.contains("r-xp") || line.contains("r--p") {
                    maps_data.extend_from_slice(line.as_bytes());
                    maps_data.push(b'\n');
                }
            }
            if !maps_data.is_empty() {
                self.baseline
                    .insert("self_maps_r".to_string(), HashValue::new(&maps_data));
            }
        }
    }

    fn collect_self_maps_evidence(&self) -> Option<EvidenceItem> {
        let content = std::fs::read_to_string("/proc/self/maps").ok()?;
        let mut current_data = Vec::new();
        for line in content.lines() {
            if line.contains("r-xp") || line.contains("r--p") {
                current_data.extend_from_slice(line.as_bytes());
                current_data.push(b'\n');
            }
        }

        if current_data.is_empty() {
            return None;
        }

        let current_hash = HashValue::new(&current_data);

        if let Some(baseline) = self.baseline.get("self_maps_r") {
            if !current_hash.matches(baseline) {
                return Some(
                    EvidenceItem::new(
                        EvidenceType::MemoryIntegrity,
                        sentinelx_evidence::Severity::High,
                        "memory_integrity".to_string(),
                        "SentinelX memory maps modified".to_string(),
                    )
                    .with_data(
                        "baseline".to_string(),
                        serde_json::Value::String(baseline.to_string()),
                    )
                    .with_data(
                        "current".to_string(),
                        serde_json::Value::String(current_hash.to_string()),
                    )
                    .with_confidence(0.9)
                    .with_tag("memory".to_string())
                    .with_tag("tampering".to_string()),
                );
            }
        }

        None
    }

    fn collect_kallsyms_evidence(&self) -> Option<EvidenceItem> {
        let hash = Self::hash_file("/proc/kallsyms")?;

        if let Some(baseline) = self.baseline.get("/proc/kallsyms") {
            if !hash.matches(baseline) {
                return Some(
                    EvidenceItem::new(
                        EvidenceType::MemoryIntegrity,
                        sentinelx_evidence::Severity::Critical,
                        "memory_integrity".to_string(),
                        "/proc/kallsyms modified".to_string(),
                    )
                    .with_data(
                        "baseline".to_string(),
                        serde_json::Value::String(baseline.to_string()),
                    )
                    .with_data(
                        "current".to_string(),
                        serde_json::Value::String(hash.to_string()),
                    )
                    .with_confidence(0.95)
                    .with_tag("memory".to_string())
                    .with_tag("kallsyms".to_string()),
                );
            }
        }

        None
    }

    fn check_self_maps_integrity(&self) -> Option<ThreatEvent> {
        let content = std::fs::read_to_string("/proc/self/maps").ok()?;
        let mut current_data = Vec::new();
        for line in content.lines() {
            if line.contains("r-xp") || line.contains("r--p") {
                current_data.extend_from_slice(line.as_bytes());
                current_data.push(b'\n');
            }
        }

        if current_data.is_empty() {
            return None;
        }

        let current_hash = HashValue::new(&current_data);

        if let Some(baseline) = self.baseline.get("self_maps_r") {
            if !current_hash.matches(baseline) {
                return Some(ThreatEvent {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::High,
                    category: ThreatCategory::MemoryTampering,
                    title: "SentinelX memory maps modified".to_string(),
                    description:
                        "The memory mappings of the sentinelx process have changed since baseline."
                            .to_string(),
                    evidence: vec![Evidence {
                        description: "Memory maps hash mismatch".to_string(),
                        data: HashMap::from([
                            (
                                "baseline".to_string(),
                                serde_json::Value::String(baseline.to_string()),
                            ),
                            (
                                "current".to_string(),
                                serde_json::Value::String(current_hash.to_string()),
                            ),
                        ]),
                        confidence: 0.9,
                    }],
                    mitre_attack: vec![MitreAttackMapping {
                        tactic: "Defense Evasion".to_string(),
                        technique_id: "T1055".to_string(),
                        technique_name: "Process Injection".to_string(),
                    }],
                    source_detector: "memory_integrity".to_string(),
                    process: None,
                    network: None,
                    hash: Some(current_hash),
                    tags: vec!["memory".to_string(), "tampering".to_string()],
                });
            }
        }

        None
    }

    fn check_proc_kallsyms(&self) -> Option<ThreatEvent> {
        let hash = Self::hash_file("/proc/kallsyms")?;

        if let Some(baseline) = self.baseline.get("/proc/kallsyms") {
            if !hash.matches(baseline) {
                return Some(ThreatEvent {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::Critical,
                    category: ThreatCategory::MemoryTampering,
                    title: "/proc/kallsyms modified".to_string(),
                    description: "Kernel symbol table has been modified since baseline."
                        .to_string(),
                    evidence: vec![Evidence {
                        description: "kallsyms hash mismatch".to_string(),
                        data: HashMap::from([
                            (
                                "baseline".to_string(),
                                serde_json::Value::String(baseline.to_string()),
                            ),
                            (
                                "current".to_string(),
                                serde_json::Value::String(hash.to_string()),
                            ),
                        ]),
                        confidence: 0.95,
                    }],
                    mitre_attack: vec![MitreAttackMapping {
                        tactic: "Defense Evasion".to_string(),
                        technique_id: "T1014".to_string(),
                        technique_name: "Rootkit".to_string(),
                    }],
                    source_detector: "memory_integrity".to_string(),
                    process: None,
                    network: None,
                    hash: Some(hash),
                    tags: vec!["memory".to_string(), "kallsyms".to_string()],
                });
            }
        }

        None
    }
}

impl Default for MemoryIntegrityChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl EvidenceCollector for MemoryIntegrityChecker {
    async fn collect_evidence(&self) -> Result<Vec<EvidenceItem>, EvidenceError> {
        let mut evidence_items = Vec::new();

        if let Some(item) = self.collect_self_maps_evidence() {
            evidence_items.push(item);
        }

        if let Some(item) = self.collect_kallsyms_evidence() {
            evidence_items.push(item);
        }

        Ok(evidence_items)
    }

    fn get_evidence_type(&self) -> EvidenceType {
        EvidenceType::MemoryIntegrity
    }

    fn get_source(&self) -> String {
        "memory_integrity".to_string()
    }
}

#[async_trait::async_trait]
impl Detector for MemoryIntegrityChecker {
    fn name(&self) -> &str {
        "memory_integrity"
    }

    fn description(&self) -> &str {
        "Monitors kernel memory sections, symbol tables, and process memory mappings"
    }

    fn category(&self) -> ThreatCategory {
        ThreatCategory::MemoryTampering
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    async fn detect(&self) -> sentinelx_common::Result<Vec<ThreatEvent>> {
        let mut threats = Vec::new();

        if let Some(event) = self.check_self_maps_integrity() {
            threats.push(event);
        }

        if let Some(event) = self.check_proc_kallsyms() {
            threats.push(event);
        }

        Ok(threats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_metadata() {
        let d = MemoryIntegrityChecker::new();
        assert_eq!(d.name(), "memory_integrity");
        assert_eq!(d.category(), ThreatCategory::MemoryTampering);
    }

    #[tokio::test]
    async fn detect_runs_without_panic() {
        let d = MemoryIntegrityChecker::new();
        let result = d.detect().await;
        assert!(result.is_ok());
    }
}
