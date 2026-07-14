use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRuleConfig {
    pub rules: Vec<EvidenceCorrelationRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCorrelationRule {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub requires: Vec<String>,
    pub min_evidence: usize,
    pub min_confidence: f64,
    pub min_assessment_risk: u32,
    pub time_window_seconds: i64,
    pub severity: String,
    pub mitre_techniques: Vec<String>,
    pub recommended_response: String,
}

impl CorrelationRuleConfig {
    pub fn load_default() -> Self {
        Self::parse_from_str(DEFAULT_RULES).unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to parse default correlation rules: {}, using empty config",
                e
            );
            Self { rules: Vec::new() }
        })
    }

    pub fn parse_from_str(s: &str) -> Result<Self, String> {
        toml::from_str(s).map_err(|e| e.to_string())
    }

    pub fn enabled_rules(&self) -> Vec<&EvidenceCorrelationRule> {
        self.rules.iter().filter(|r| r.enabled).collect()
    }

    pub fn find_rule(&self, name: &str) -> Option<&EvidenceCorrelationRule> {
        self.rules.iter().find(|r| r.name == name)
    }
}

impl Default for CorrelationRuleConfig {
    fn default() -> Self {
        Self::load_default()
    }
}

const DEFAULT_RULES: &str = r#"
[[rules]]
name = "kernel_rootkit"
description = "Detects kernel rootkit: hidden process + kernel hook + hidden module"
enabled = true
requires = ["HiddenProcess", "KernelHook", "HiddenModule"]
min_evidence = 3
min_confidence = 0.95
min_assessment_risk = 70
time_window_seconds = 300
severity = "critical"
mitre_techniques = ["T1014", "T1055"]
recommended_response = "Isolate host immediately. Collect forensic snapshot. Kill malicious process."

[[rules]]
name = "privilege_escalation_chain"
description = "Detects privilege escalation followed by persistence"
enabled = true
requires = ["ProcessIntegrity", "PersistenceIntegrity"]
min_evidence = 2
min_confidence = 0.80
min_assessment_risk = 50
time_window_seconds = 600
severity = "high"
mitre_techniques = ["T1068", "T1543"]
recommended_response = "Investigate process tree. Check for unauthorized service creation."

[[rules]]
name = "network_exfiltration"
description = "Detects potential data exfiltration via suspicious network activity"
enabled = true
requires = ["NetworkIntegrity", "ProcessIntegrity"]
min_evidence = 2
min_confidence = 0.70
min_assessment_risk = 40
time_window_seconds = 300
severity = "high"
mitre_techniques = ["T1041", "T1048"]
recommended_response = "Monitor network traffic. Review process network connections."

[[rules]]
name = "file_tampering"
description = "Detects critical file modification with integrity violations"
enabled = true
requires = ["FileIntegrity", "PersistenceIntegrity"]
min_evidence = 2
min_confidence = 0.75
min_assessment_risk = 60
time_window_seconds = 300
severity = "high"
mitre_techniques = ["T1565", "T1542"]
recommended_response = "Restore file from backup. Check for persistence mechanisms."

[[rules]]
name = "memory_manipulation"
description = "Detects suspicious memory region modifications"
enabled = true
requires = ["MemoryIntegrity", "ProcessIntegrity"]
min_evidence = 2
min_confidence = 0.80
min_assessment_risk = 50
time_window_seconds = 300
severity = "high"
mitre_techniques = ["T1055", "T1620"]
recommended_response = "Analyze process memory. Check for code injection."

[[rules]]
name = "multi_indicator_anomaly"
description = "Multiple evidence types from same source indicating compromise"
enabled = true
requires = []
min_evidence = 3
min_confidence = 0.60
min_assessment_risk = 30
time_window_seconds = 600
severity = "medium"
mitre_techniques = ["T1497"]
recommended_response = "Enhanced monitoring. Review all related evidence and assessments."

[[rules]]
name = "suspicious_persistence"
description = "Suspicious persistence mechanism detected"
enabled = true
requires = ["PersistenceIntegrity"]
min_evidence = 1
min_confidence = 0.70
min_assessment_risk = 40
time_window_seconds = 300
severity = "medium"
mitre_techniques = ["T1543", "T1547"]
recommended_response = "Review persistence locations. Verify service integrity."
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_parses() {
        let config = CorrelationRuleConfig::load_default();
        assert!(!config.rules.is_empty());
    }

    #[test]
    fn test_enabled_rules() {
        let config = CorrelationRuleConfig::load_default();
        let enabled = config.enabled_rules();
        assert_eq!(enabled.len(), config.rules.len());
    }

    #[test]
    fn test_find_rule() {
        let config = CorrelationRuleConfig::load_default();
        let rule = config.find_rule("kernel_rootkit");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().severity, "critical");
    }

    #[test]
    fn test_rule_requires() {
        let config = CorrelationRuleConfig::load_default();
        let rule = config.find_rule("kernel_rootkit").unwrap();
        assert_eq!(rule.requires.len(), 3);
        assert!(rule.requires.contains(&"HiddenProcess".to_string()));
    }

    #[test]
    fn test_from_str() {
        let toml_str = r#"
[[rules]]
name = "test_rule"
description = "Test"
enabled = true
requires = ["TestEvidence"]
min_evidence = 1
min_confidence = 0.5
min_assessment_risk = 20
time_window_seconds = 60
severity = "low"
mitre_techniques = ["T1234"]
recommended_response = "Test response"
"#;
        let config = CorrelationRuleConfig::parse_from_str(toml_str).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].name, "test_rule");
    }
}
