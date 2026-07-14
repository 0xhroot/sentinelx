use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BehaviorCategory {
    ProcessAncestry,
    ProcessLifetime,
    ExecFrequency,
    NetworkActivity,
    FileModifications,
    PersistenceCreation,
    PrivilegeEscalation,
    ModuleLoading,
    MemoryUsage,
    CapabilityChanges,
    SuspiciousActions,
}

impl BehaviorCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessAncestry => "process_ancestry",
            Self::ProcessLifetime => "process_lifetime",
            Self::ExecFrequency => "exec_frequency",
            Self::NetworkActivity => "network_activity",
            Self::FileModifications => "file_modifications",
            Self::PersistenceCreation => "persistence_creation",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::ModuleLoading => "module_loading",
            Self::MemoryUsage => "memory_usage",
            Self::CapabilityChanges => "capability_changes",
            Self::SuspiciousActions => "suspicious_actions",
        }
    }

    pub fn parse_from(s: &str) -> Option<Self> {
        match s {
            "process_ancestry" => Some(Self::ProcessAncestry),
            "process_lifetime" => Some(Self::ProcessLifetime),
            "exec_frequency" => Some(Self::ExecFrequency),
            "network_activity" => Some(Self::NetworkActivity),
            "file_modifications" => Some(Self::FileModifications),
            "persistence_creation" => Some(Self::PersistenceCreation),
            "privilege_escalation" => Some(Self::PrivilegeEscalation),
            "module_loading" => Some(Self::ModuleLoading),
            "memory_usage" => Some(Self::MemoryUsage),
            "capability_changes" => Some(Self::CapabilityChanges),
            "suspicious_actions" => Some(Self::SuspiciousActions),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorProfile {
    pub id: Uuid,
    pub object_id: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub execution_count: u64,
    pub connection_count: u64,
    pub privilege_changes: u64,
    pub persistence_events: u64,
    pub integrity_violations: u64,
    pub risk_trend: Vec<f64>,
    pub confidence_trend: Vec<f64>,
    pub historical_score: f64,
    pub categories: Vec<BehaviorEvent>,
    pub metadata: serde_json::Value,
}

impl BehaviorProfile {
    pub fn new(object_id: &str) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            object_id: object_id.to_string(),
            first_seen: now,
            last_seen: now,
            execution_count: 0,
            connection_count: 0,
            privilege_changes: 0,
            persistence_events: 0,
            integrity_violations: 0,
            risk_trend: Vec::new(),
            confidence_trend: Vec::new(),
            historical_score: 0.0,
            categories: Vec::new(),
            metadata: serde_json::Value::Null,
        }
    }

    pub fn with_execution_count(mut self, count: u64) -> Self {
        self.execution_count = count;
        self
    }

    pub fn with_connection_count(mut self, count: u64) -> Self {
        self.connection_count = count;
        self
    }

    pub fn with_privilege_changes(mut self, count: u64) -> Self {
        self.privilege_changes = count;
        self
    }

    pub fn with_persistence_events(mut self, count: u64) -> Self {
        self.persistence_events = count;
        self
    }

    pub fn with_integrity_violations(mut self, count: u64) -> Self {
        self.integrity_violations = count;
        self
    }

    pub fn with_historical_score(mut self, score: f64) -> Self {
        self.historical_score = score;
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn record_event(&mut self, event: BehaviorEvent) {
        self.last_seen = Utc::now();
        match event.category {
            BehaviorCategory::ExecFrequency => self.execution_count += 1,
            BehaviorCategory::NetworkActivity => self.connection_count += 1,
            BehaviorCategory::PrivilegeEscalation => self.privilege_changes += 1,
            BehaviorCategory::PersistenceCreation => self.persistence_events += 1,
            _ => {}
        }
        self.categories.push(event);
    }

    pub fn update_score(&mut self, risk: f64, confidence: f64) {
        self.risk_trend.push(risk);
        self.confidence_trend.push(confidence);
        if self.risk_trend.len() > 100 {
            self.risk_trend.remove(0);
        }
        if self.confidence_trend.len() > 100 {
            self.confidence_trend.remove(0);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorEvent {
    pub timestamp: DateTime<Utc>,
    pub category: BehaviorCategory,
    pub description: String,
    pub risk_level: f64,
    pub metadata: serde_json::Value,
}

impl BehaviorEvent {
    pub fn new(category: BehaviorCategory, description: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            category,
            description: description.to_string(),
            risk_level: 0.0,
            metadata: serde_json::Value::Null,
        }
    }

    pub fn with_risk_level(mut self, risk: f64) -> Self {
        self.risk_level = risk;
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorScore {
    pub profile_id: Uuid,
    pub object_id: String,
    pub frequency_score: f64,
    pub recurrence_score: f64,
    pub escalation_score: f64,
    pub novelty_score: f64,
    pub persistence_score: f64,
    pub correlation_score: f64,
    pub assessment_score: f64,
    pub final_score: f64,
    pub severity: String,
    pub computed_at: DateTime<Utc>,
}

impl BehaviorScore {
    pub fn new(profile_id: Uuid, object_id: &str) -> Self {
        Self {
            profile_id,
            object_id: object_id.to_string(),
            frequency_score: 0.0,
            recurrence_score: 0.0,
            escalation_score: 0.0,
            novelty_score: 0.0,
            persistence_score: 0.0,
            correlation_score: 0.0,
            assessment_score: 0.0,
            final_score: 0.0,
            severity: "info".to_string(),
            computed_at: Utc::now(),
        }
    }

    pub fn compute_severity(&mut self) {
        self.final_score = (self.frequency_score * 0.15
            + self.recurrence_score * 0.20
            + self.escalation_score * 0.25
            + self.novelty_score * 0.10
            + self.persistence_score * 0.15
            + self.correlation_score * 0.05
            + self.assessment_score * 0.10)
            .clamp(0.0, 100.0);

        self.severity = if self.final_score >= 80.0 {
            "critical"
        } else if self.final_score >= 60.0 {
            "high"
        } else if self.final_score >= 40.0 {
            "medium"
        } else if self.final_score >= 20.0 {
            "low"
        } else {
            "info"
        }
        .to_string();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub conditions: Vec<BehaviorCondition>,
    pub action: String,
    pub severity: String,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorCondition {
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRuleConfig {
    pub rules: Vec<BehaviorRule>,
}

impl BehaviorRuleConfig {
    pub fn load_default() -> Self {
        toml::from_str(DEFAULT_RULES).unwrap_or_else(|_| Self { rules: Vec::new() })
    }

    pub fn parse_from_str(toml_str: &str) -> Self {
        toml::from_str(toml_str).unwrap_or_else(|_| Self { rules: Vec::new() })
    }

    pub fn enabled_rules(&self) -> Vec<&BehaviorRule> {
        self.rules.iter().filter(|r| r.enabled).collect()
    }

    pub fn find_rule(&self, name: &str) -> Option<&BehaviorRule> {
        self.rules.iter().find(|r| r.name == name)
    }
}

pub const DEFAULT_RULES: &str = r#"
[[rules]]
name = "repeated_privilege_escalation"
description = "Object repeatedly attempts privilege escalation"
enabled = true
action = "alert"
severity = "critical"
mitre_techniques = ["T1068", "T1548"]

[[rules.conditions]]
field = "privilege_changes"
operator = "gte"
value = 3

[[rules]]
name = "unsigned_executable_persistence"
description = "Unsigned executable with persistence mechanism"
enabled = true
action = "alert"
severity = "high"
mitre_techniques = ["T1547", "T1059"]

[[rules.conditions]]
field = "persistence_events"
operator = "gte"
value = 1

[[rules.conditions]]
field = "integrity_violations"
operator = "gte"
value = 1

[[rules]]
name = "network_exfiltration_pattern"
description = "High network activity with privilege changes"
enabled = true
action = "investigate"
severity = "high"
mitre_techniques = ["T1041", "T1048"]

[[rules.conditions]]
field = "connection_count"
operator = "gte"
value = 100

[[rules.conditions]]
field = "privilege_changes"
operator = "gte"
value = 1

[[rules]]
name = "suspicious_process_behavior"
description = "Process with multiple suspicious indicators"
enabled = true
action = "alert"
severity = "medium"
mitre_techniques = ["T1059", "T1055"]

[[rules.conditions]]
field = "execution_count"
operator = "gte"
value = 50

[[rules.conditions]]
field = "integrity_violations"
operator = "gte"
value = 1

[[rules]]
name = "kernel_module_anomaly"
description = "Kernel module loaded and unloaded repeatedly"
enabled = true
action = "investigate"
severity = "high"
mitre_techniques = ["T1014", "T1547"]

[[rules.conditions]]
field = "execution_count"
operator = "gte"
value = 5

[[rules]]
name = "low_risk_baseline"
description = "Normal behavior baseline"
enabled = true
action = "log"
severity = "info"
mitre_techniques = []

[[rules.conditions]]
field = "execution_count"
operator = "lt"
value = 10
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behavior_category_as_str() {
        assert_eq!(BehaviorCategory::ExecFrequency.as_str(), "exec_frequency");
        assert_eq!(
            BehaviorCategory::PrivilegeEscalation.as_str(),
            "privilege_escalation"
        );
        assert_eq!(
            BehaviorCategory::SuspiciousActions.as_str(),
            "suspicious_actions"
        );
    }

    #[test]
    fn behavior_category_parse() {
        assert_eq!(
            BehaviorCategory::parse_from("exec_frequency"),
            Some(BehaviorCategory::ExecFrequency)
        );
        assert_eq!(
            BehaviorCategory::parse_from("network_activity"),
            Some(BehaviorCategory::NetworkActivity)
        );
        assert_eq!(BehaviorCategory::parse_from("invalid"), None);
    }

    #[test]
    fn behavior_profile_creation() {
        let profile = BehaviorProfile::new("process:1234");
        assert_eq!(profile.object_id, "process:1234");
        assert_eq!(profile.execution_count, 0);
        assert_eq!(profile.connection_count, 0);
    }

    #[test]
    fn behavior_profile_record_event() {
        let mut profile = BehaviorProfile::new("process:1234");
        let event = BehaviorEvent::new(BehaviorCategory::ExecFrequency, "exec event");
        profile.record_event(event);
        assert_eq!(profile.execution_count, 1);
        assert_eq!(profile.categories.len(), 1);
    }

    #[test]
    fn behavior_profile_update_score() {
        let mut profile = BehaviorProfile::new("process:1234");
        profile.update_score(50.0, 0.8);
        assert_eq!(profile.risk_trend.len(), 1);
        assert_eq!(profile.confidence_trend.len(), 1);
    }

    #[test]
    fn behavior_score_compute_severity() {
        let mut score = BehaviorScore::new(Uuid::new_v4(), "test");
        score.frequency_score = 80.0;
        score.escalation_score = 90.0;
        score.compute_severity();
        assert!(score.final_score > 0.0);
        assert!(!score.severity.is_empty());
    }

    #[test]
    fn behavior_rule_config_default() {
        let config = BehaviorRuleConfig::load_default();
        assert!(!config.rules.is_empty());
        assert!(!config.enabled_rules().is_empty());
    }

    #[test]
    fn behavior_rule_config_find() {
        let config = BehaviorRuleConfig::load_default();
        let rule = config.find_rule("repeated_privilege_escalation");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().severity, "critical");
    }

    #[test]
    fn behavior_rule_config_parse() {
        let toml_str = r#"
[[rules]]
name = "test_rule"
description = "Test"
enabled = true
action = "alert"
severity = "medium"
mitre_techniques = ["T1059"]

[[rules.conditions]]
field = "execution_count"
operator = "gte"
value = 10
"#;
        let config = BehaviorRuleConfig::parse_from_str(toml_str);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].name, "test_rule");
    }

    #[test]
    fn behavior_event_creation() {
        let event = BehaviorEvent::new(BehaviorCategory::NetworkActivity, "connection opened")
            .with_risk_level(0.5);
        assert_eq!(event.category, BehaviorCategory::NetworkActivity);
        assert_eq!(event.risk_level, 0.5);
    }

    #[test]
    fn all_categories_parse_roundtrip() {
        let categories = vec![
            BehaviorCategory::ProcessAncestry,
            BehaviorCategory::ProcessLifetime,
            BehaviorCategory::ExecFrequency,
            BehaviorCategory::NetworkActivity,
            BehaviorCategory::FileModifications,
            BehaviorCategory::PersistenceCreation,
            BehaviorCategory::PrivilegeEscalation,
            BehaviorCategory::ModuleLoading,
            BehaviorCategory::MemoryUsage,
            BehaviorCategory::CapabilityChanges,
            BehaviorCategory::SuspiciousActions,
        ];
        for cat in &categories {
            let s = cat.as_str();
            let parsed = BehaviorCategory::parse_from(s);
            assert_eq!(parsed.as_ref(), Some(cat));
        }
    }
}
