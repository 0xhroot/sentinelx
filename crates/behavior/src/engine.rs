use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::types::{
    BehaviorEvent, BehaviorProfile, BehaviorRule, BehaviorRuleConfig, BehaviorScore,
};

pub struct BehaviorEngine {
    profiles: Arc<RwLock<HashMap<String, BehaviorProfile>>>,
    rule_config: BehaviorRuleConfig,
}

impl BehaviorEngine {
    pub fn new() -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
            rule_config: BehaviorRuleConfig::load_default(),
        }
    }

    pub fn with_rules(rule_config: BehaviorRuleConfig) -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
            rule_config,
        }
    }

    pub async fn record_event(&self, object_id: &str, event: BehaviorEvent) {
        let mut profiles = self.profiles.write().await;
        let profile = profiles
            .entry(object_id.to_string())
            .or_insert_with(|| BehaviorProfile::new(object_id));
        profile.record_event(event);
    }

    pub async fn get_profile(&self, object_id: &str) -> Option<BehaviorProfile> {
        let profiles = self.profiles.read().await;
        profiles.get(object_id).cloned()
    }

    pub async fn list_profiles(&self) -> Vec<BehaviorProfile> {
        let profiles = self.profiles.read().await;
        profiles.values().cloned().collect()
    }

    pub async fn list_profiles_by_severity(&self, min_severity: &str) -> Vec<BehaviorProfile> {
        let profiles = self.profiles.read().await;
        profiles
            .values()
            .filter(|p| {
                let score = self.compute_score_for_profile(p);
                severity_rank(&score.severity) >= severity_rank(min_severity)
            })
            .cloned()
            .collect()
    }

    pub async fn count(&self) -> usize {
        let profiles = self.profiles.read().await;
        profiles.len()
    }

    pub async fn count_by_severity(&self) -> HashMap<String, usize> {
        let profiles = self.profiles.read().await;
        let mut counts = HashMap::new();
        for profile in profiles.values() {
            let score = self.compute_score_for_profile(profile);
            *counts.entry(score.severity).or_insert(0) += 1;
        }
        counts
    }

    pub async fn evaluate_object(&self, object_id: &str) -> Option<BehaviorScore> {
        let profiles = self.profiles.read().await;
        let profile = profiles.get(object_id)?;
        let mut score = self.compute_score_for_profile(profile);
        score.compute_severity();
        Some(score)
    }

    pub async fn evaluate_all(&self) -> Vec<BehaviorScore> {
        let profiles = self.profiles.read().await;
        profiles
            .values()
            .map(|p| {
                let mut score = self.compute_score_for_profile(p);
                score.compute_severity();
                score
            })
            .collect()
    }

    pub async fn check_rules(&self, object_id: &str) -> Vec<BehaviorRule> {
        let profiles = self.profiles.read().await;
        let profile = match profiles.get(object_id) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let mut matched = Vec::new();
        for rule in self.rule_config.enabled_rules() {
            if self.evaluate_rule(rule, profile) {
                matched.push(rule.clone());
            }
        }
        matched
    }

    pub async fn clear(&self) {
        let mut profiles = self.profiles.write().await;
        profiles.clear();
    }

    pub fn rule_config(&self) -> &BehaviorRuleConfig {
        &self.rule_config
    }

    fn compute_score_for_profile(&self, profile: &BehaviorProfile) -> BehaviorScore {
        let mut score = BehaviorScore::new(profile.id, &profile.object_id);

        score.frequency_score = (profile.execution_count as f64 / 100.0).min(1.0) * 100.0;
        score.recurrence_score = if profile.categories.len() > 1 {
            let unique_categories: std::collections::HashSet<_> =
                profile.categories.iter().map(|c| &c.category).collect();
            (unique_categories.len() as f64 / 5.0).min(1.0) * 100.0
        } else {
            0.0
        };

        score.escalation_score = if profile.risk_trend.len() >= 2 {
            let recent = &profile.risk_trend[profile.risk_trend.len().saturating_sub(5)..];
            let older = &profile.risk_trend[..profile.risk_trend.len().saturating_sub(5).max(1)];
            let recent_avg = recent.iter().sum::<f64>() / recent.len() as f64;
            let older_avg = if older.is_empty() {
                0.0
            } else {
                older.iter().sum::<f64>() / older.len() as f64
            };
            ((recent_avg - older_avg) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };

        score.novelty_score = if profile.execution_count <= 1 {
            50.0
        } else if profile.execution_count <= 5 {
            30.0
        } else {
            10.0
        };

        score.persistence_score = (profile.persistence_events as f64 / 5.0).min(1.0) * 100.0;

        score.correlation_score = (profile.integrity_violations as f64 / 3.0).min(1.0) * 100.0;

        score.assessment_score = profile.historical_score;

        score
    }

    fn evaluate_rule(&self, rule: &BehaviorRule, profile: &BehaviorProfile) -> bool {
        for condition in &rule.conditions {
            if !self.evaluate_condition(condition, profile) {
                return false;
            }
        }
        true
    }

    fn evaluate_condition(
        &self,
        condition: &crate::types::BehaviorCondition,
        profile: &BehaviorProfile,
    ) -> bool {
        let actual = match condition.field.as_str() {
            "execution_count" => profile.execution_count as f64,
            "connection_count" => profile.connection_count as f64,
            "privilege_changes" => profile.privilege_changes as f64,
            "persistence_events" => profile.persistence_events as f64,
            "integrity_violations" => profile.integrity_violations as f64,
            _ => return false,
        };

        let expected = condition.value.as_f64().unwrap_or(0.0);

        match condition.operator.as_str() {
            "gte" => actual >= expected,
            "lte" => actual <= expected,
            "eq" => (actual - expected).abs() < f64::EPSILON,
            "gt" => actual > expected,
            "lt" => actual < expected,
            _ => false,
        }
    }
}

impl Default for BehaviorEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BehaviorCategory;

    #[tokio::test]
    async fn engine_creation() {
        let engine = BehaviorEngine::new();
        assert_eq!(engine.count().await, 0);
    }

    #[tokio::test]
    async fn engine_record_event() {
        let engine = BehaviorEngine::new();
        let event = BehaviorEvent::new(BehaviorCategory::ExecFrequency, "exec");
        engine.record_event("process:1234", event).await;
        assert_eq!(engine.count().await, 1);

        let profile = engine.get_profile("process:1234").await;
        assert!(profile.is_some());
        assert_eq!(profile.unwrap().execution_count, 1);
    }

    #[tokio::test]
    async fn engine_multiple_events() {
        let engine = BehaviorEngine::new();
        for _ in 0..5 {
            engine
                .record_event(
                    "process:1234",
                    BehaviorEvent::new(BehaviorCategory::ExecFrequency, "exec"),
                )
                .await;
        }
        let profile = engine.get_profile("process:1234").await.unwrap();
        assert_eq!(profile.execution_count, 5);
    }

    #[tokio::test]
    async fn engine_evaluate_object() {
        let engine = BehaviorEngine::new();
        for _ in 0..10 {
            engine
                .record_event(
                    "process:1234",
                    BehaviorEvent::new(BehaviorCategory::ExecFrequency, "exec"),
                )
                .await;
        }
        let score = engine.evaluate_object("process:1234").await;
        assert!(score.is_some());
        let score = score.unwrap();
        assert!(score.final_score >= 0.0);
    }

    #[tokio::test]
    async fn engine_check_rules() {
        let engine = BehaviorEngine::new();
        for _ in 0..5 {
            engine
                .record_event(
                    "process:1234",
                    BehaviorEvent::new(BehaviorCategory::PrivilegeEscalation, "privesc"),
                )
                .await;
        }
        let matched = engine.check_rules("process:1234").await;
        assert!(!matched.is_empty());
    }

    #[tokio::test]
    async fn engine_list_profiles() {
        let engine = BehaviorEngine::new();
        engine
            .record_event(
                "process:1",
                BehaviorEvent::new(BehaviorCategory::ExecFrequency, "exec"),
            )
            .await;
        engine
            .record_event(
                "process:2",
                BehaviorEvent::new(BehaviorCategory::NetworkActivity, "net"),
            )
            .await;
        let profiles = engine.list_profiles().await;
        assert_eq!(profiles.len(), 2);
    }

    #[tokio::test]
    async fn engine_clear() {
        let engine = BehaviorEngine::new();
        engine
            .record_event(
                "process:1",
                BehaviorEvent::new(BehaviorCategory::ExecFrequency, "exec"),
            )
            .await;
        assert_eq!(engine.count().await, 1);
        engine.clear().await;
        assert_eq!(engine.count().await, 0);
    }

    #[tokio::test]
    async fn engine_with_custom_rules() {
        let config = BehaviorRuleConfig::parse_from_str(
            r#"
[[rules]]
name = "custom_rule"
description = "Custom"
enabled = true
action = "alert"
severity = "medium"
mitre_techniques = []

[[rules.conditions]]
field = "execution_count"
operator = "gte"
value = 3
"#,
        );
        let engine = BehaviorEngine::with_rules(config);
        for _ in 0..4 {
            engine
                .record_event(
                    "process:1234",
                    BehaviorEvent::new(BehaviorCategory::ExecFrequency, "exec"),
                )
                .await;
        }
        let matched = engine.check_rules("process:1234").await;
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "custom_rule");
    }

    #[tokio::test]
    async fn engine_count_by_severity() {
        let engine = BehaviorEngine::new();
        engine
            .record_event(
                "process:1",
                BehaviorEvent::new(BehaviorCategory::ExecFrequency, "exec"),
            )
            .await;
        let counts = engine.count_by_severity().await;
        assert!(!counts.is_empty());
    }

    #[test]
    fn severity_rank_works() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        assert!(severity_rank("low") > severity_rank("info"));
    }
}
