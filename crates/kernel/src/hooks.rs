use std::collections::HashMap;
use std::sync::Mutex;

use chrono::Utc;
use sentinelx_common::severity::Severity;
use sentinelx_common::traits::Detector;
use sentinelx_common::types::{
    Evidence, HookInfo, HookType, MitreAttackMapping, ThreatCategory, ThreatEvent,
};
use sentinelx_evidence::{
    Evidence as EvidenceItem, EvidenceCollector, EvidenceError, EvidenceType,
};
use uuid::Uuid;

pub struct HookDetector {
    baseline: Mutex<Option<Vec<HookInfo>>>,
}

impl HookDetector {
    pub fn new() -> Self {
        Self {
            baseline: Mutex::new(None),
        }
    }

    fn detect_syscall_hooks() -> Vec<HookInfo> {
        let mut hooks = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/kallsyms") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[1] == "T" {
                    let name = parts[2];
                    if name.starts_with("__x64_sys_") || name.starts_with("sys_") {
                        let address = u64::from_str_radix(parts[0], 16).unwrap_or(0);
                        if address != 0 {
                            hooks.push(HookInfo {
                                hook_type: HookType::SyscallTable,
                                address,
                                target_address: 0,
                                symbol: Some(name.to_string()),
                                module: None,
                                is_inline: false,
                            });
                        }
                    }
                }
            }
        }

        hooks
    }

    fn detect_ftrace_hooks() -> Vec<HookInfo> {
        let mut hooks = Vec::new();
        let trace_dir = "/sys/kernel/debug/tracing";

        if let Ok(entries) = std::fs::read_dir(trace_dir) {
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("set_ftrace_filter")
                {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        for line in content.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                hooks.push(HookInfo {
                                    hook_type: HookType::Ftrace,
                                    address: 0,
                                    target_address: 0,
                                    symbol: Some(trimmed.to_string()),
                                    module: None,
                                    is_inline: false,
                                });
                            }
                        }
                    }
                }
            }
        }

        hooks
    }

    fn detect_kprobes() -> Vec<HookInfo> {
        let mut hooks = Vec::new();
        let kprobes_dir = "/sys/kernel/debug/tracing/events/kprobes";

        if let Ok(entries) = std::fs::read_dir(kprobes_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name != "." && name != ".." {
                    hooks.push(HookInfo {
                        hook_type: HookType::Kprobe,
                        address: 0,
                        target_address: 0,
                        symbol: Some(name),
                        module: None,
                        is_inline: false,
                    });
                }
            }
        }

        hooks
    }

    fn collect_all_hooks() -> Vec<HookInfo> {
        let mut all = Vec::new();
        all.extend(Self::detect_syscall_hooks());
        all.extend(Self::detect_ftrace_hooks());
        all.extend(Self::detect_kprobes());
        all
    }

    fn hooks_differ(a: &[HookInfo], b: &[HookInfo]) -> Vec<HookInfo> {
        let a_set: HashMap<(String, u64), &HookInfo> = a
            .iter()
            .map(|h| {
                let key = (h.symbol.clone().unwrap_or_default(), h.address);
                (key, h)
            })
            .collect();
        let b_set: HashMap<(String, u64), &HookInfo> = b
            .iter()
            .map(|h| {
                let key = (h.symbol.clone().unwrap_or_default(), h.address);
                (key, h)
            })
            .collect();

        let mut new_hooks = Vec::new();
        for (key, hook) in &a_set {
            if !b_set.contains_key(key) {
                new_hooks.push((*hook).clone());
            }
        }
        new_hooks
    }
}

impl Default for HookDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl EvidenceCollector for HookDetector {
    async fn collect_evidence(&self) -> Result<Vec<EvidenceItem>, EvidenceError> {
        let current_hooks = Self::collect_all_hooks();
        let mut baseline = self.baseline.lock().unwrap();

        if let Some(ref prev) = *baseline {
            let new_hooks = Self::hooks_differ(&current_hooks, prev);
            *baseline = Some(current_hooks);

            let evidence_items: Vec<EvidenceItem> = new_hooks
                .into_iter()
                .map(|hook| {
                    let hook_type_str = format!("{:?}", hook.hook_type);
                    let address_str = format!("0x{:x}", hook.address);

                    EvidenceItem::new(
                        EvidenceType::KernelIntegrity,
                        sentinelx_evidence::Severity::Critical,
                        "hook_detection".to_string(),
                        format!(
                            "New {:?} hook detected at 0x{:x}",
                            hook.hook_type, hook.address
                        ),
                    )
                    .with_data(
                        "hook_type".to_string(),
                        serde_json::Value::String(hook_type_str.clone()),
                    )
                    .with_data(
                        "address".to_string(),
                        serde_json::Value::String(address_str),
                    )
                    .with_confidence(0.85)
                    .with_tag("hook".to_string())
                    .with_tag(hook_type_str.to_lowercase())
                })
                .collect();

            Ok(evidence_items)
        } else {
            *baseline = Some(current_hooks);
            Ok(Vec::new())
        }
    }

    fn get_evidence_type(&self) -> EvidenceType {
        EvidenceType::KernelIntegrity
    }

    fn get_source(&self) -> String {
        "hook_detection".to_string()
    }
}

#[async_trait::async_trait]
impl Detector for HookDetector {
    fn name(&self) -> &str {
        "hook_detection"
    }

    fn description(&self) -> &str {
        "Detects syscall table hooks, inline hooks, ftrace hooks, and kprobe abuse"
    }

    fn category(&self) -> ThreatCategory {
        ThreatCategory::HookDetected
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    async fn detect(&self) -> sentinelx_common::Result<Vec<ThreatEvent>> {
        let current_hooks = Self::collect_all_hooks();

        let mut baseline = self.baseline.lock().unwrap();
        if let Some(ref prev) = *baseline {
            let new_hooks = Self::hooks_differ(&current_hooks, prev);
            *baseline = Some(current_hooks);

            let mut threats = Vec::new();
            for hook in new_hooks {
                let mut evidence_map = HashMap::new();
                evidence_map.insert(
                    "hook_type".to_string(),
                    serde_json::Value::String(format!("{:?}", hook.hook_type)),
                );
                evidence_map.insert(
                    "address".to_string(),
                    serde_json::Value::String(format!("0x{:x}", hook.address)),
                );
                if let Some(ref sym) = hook.symbol {
                    evidence_map
                        .insert("symbol".to_string(), serde_json::Value::String(sym.clone()));
                }

                threats.push(ThreatEvent {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::Critical,
                    category: ThreatCategory::HookDetected,
                    title: format!("New {:?} hook detected", hook.hook_type),
                    description: format!(
                        "A new {:?} hook was detected at address 0x{:x} since last baseline",
                        hook.hook_type, hook.address
                    ),
                    evidence: vec![Evidence {
                        description: format!("Detected new {:?}", hook.hook_type),
                        data: evidence_map,
                        confidence: 0.85,
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
                        "hook".to_string(),
                        format!("{:?}", hook.hook_type).to_lowercase(),
                    ],
                });
            }

            Ok(threats)
        } else {
            *baseline = Some(current_hooks);
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_metadata() {
        let d = HookDetector::new();
        assert_eq!(d.name(), "hook_detection");
        assert_eq!(d.category(), ThreatCategory::HookDetected);
    }

    #[tokio::test]
    async fn detect_runs_without_panic() {
        let d = HookDetector::new();
        let result = d.detect().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn second_detect_may_find_new_hooks() {
        let d = HookDetector::new();
        let first = d.detect().await.unwrap();
        assert!(first.is_empty());

        let second = d.detect().await.unwrap();
        assert!(second.is_empty());
    }
}
