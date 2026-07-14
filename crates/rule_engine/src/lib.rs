use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum RuleError {
    #[error("Rule evaluation error: {0}")]
    EvaluationError(String),
    #[error("Rule not found: {0}")]
    NotFound(String),
    #[error("Invalid rule configuration: {0}")]
    InvalidConfig(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleCondition {
    Equals {
        field: String,
        value: serde_json::Value,
    },
    NotEquals {
        field: String,
        value: serde_json::Value,
    },
    GreaterThan {
        field: String,
        value: serde_json::Value,
    },
    LessThan {
        field: String,
        value: serde_json::Value,
    },
    Contains {
        field: String,
        value: String,
    },
    NotContains {
        field: String,
        value: String,
    },
    Regex {
        field: String,
        pattern: String,
    },
    And {
        conditions: Vec<RuleCondition>,
    },
    Or {
        conditions: Vec<RuleCondition>,
    },
    Not {
        condition: Box<RuleCondition>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub severity: String,
    pub category: String,
    pub condition: RuleCondition,
    pub actions: Vec<RuleAction>,
    pub tags: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Alert { message: String },
    Log { level: String, message: String },
    Block { reason: String },
    Escalate { to: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub severity: String,
    pub category: String,
    pub actions: Vec<RuleAction>,
    pub evidence: HashMap<String, serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait RuleEvaluator: Send + Sync {
    async fn evaluate(
        &self,
        context: &HashMap<String, serde_json::Value>,
    ) -> Result<bool, RuleError>;
}

#[derive(Debug, Clone)]
pub struct ConditionEvaluator;

impl ConditionEvaluator {
    pub fn evaluate_condition(
        condition: &RuleCondition,
        context: &HashMap<String, serde_json::Value>,
    ) -> Result<bool, RuleError> {
        Self::evaluate_condition_inner(condition, context, &mut HashMap::new())
    }

    fn evaluate_condition_inner(
        condition: &RuleCondition,
        context: &HashMap<String, serde_json::Value>,
        regex_cache: &mut HashMap<String, regex::Regex>,
    ) -> Result<bool, RuleError> {
        match condition {
            RuleCondition::Equals { field, value } => {
                let field_value = context.get(field).ok_or_else(|| {
                    RuleError::EvaluationError(format!("Field '{}' not found", field))
                })?;
                Ok(field_value == value)
            }
            RuleCondition::NotEquals { field, value } => {
                let field_value = context.get(field).ok_or_else(|| {
                    RuleError::EvaluationError(format!("Field '{}' not found", field))
                })?;
                Ok(field_value != value)
            }
            RuleCondition::GreaterThan { field, value } => {
                let field_value = context.get(field).ok_or_else(|| {
                    RuleError::EvaluationError(format!("Field '{}' not found", field))
                })?;
                match (field_value.as_f64(), value.as_f64()) {
                    (Some(a), Some(b)) => Ok(a > b),
                    _ => Err(RuleError::EvaluationError(
                        "Cannot compare non-numeric values".to_string(),
                    )),
                }
            }
            RuleCondition::LessThan { field, value } => {
                let field_value = context.get(field).ok_or_else(|| {
                    RuleError::EvaluationError(format!("Field '{}' not found", field))
                })?;
                match (field_value.as_f64(), value.as_f64()) {
                    (Some(a), Some(b)) => Ok(a < b),
                    _ => Err(RuleError::EvaluationError(
                        "Cannot compare non-numeric values".to_string(),
                    )),
                }
            }
            RuleCondition::Contains { field, value } => {
                let field_value = context.get(field).ok_or_else(|| {
                    RuleError::EvaluationError(format!("Field '{}' not found", field))
                })?;
                match field_value.as_str() {
                    Some(s) => Ok(s.contains(value.as_str())),
                    None => Ok(false),
                }
            }
            RuleCondition::NotContains { field, value } => {
                let field_value = context.get(field).ok_or_else(|| {
                    RuleError::EvaluationError(format!("Field '{}' not found", field))
                })?;
                match field_value.as_str() {
                    Some(s) => Ok(!s.contains(value.as_str())),
                    None => Ok(true),
                }
            }
            RuleCondition::Regex { field, pattern } => {
                let field_value = context.get(field).ok_or_else(|| {
                    RuleError::EvaluationError(format!("Field '{}' not found", field))
                })?;
                match field_value.as_str() {
                    Some(s) => {
                        let re = regex_cache.entry(pattern.clone()).or_insert_with(|| {
                            regex::Regex::new(pattern).unwrap_or_else(|_| {
                                regex::Regex::new(".^").expect("trivial regex must compile")
                            })
                        });
                        Ok(re.is_match(s))
                    }
                    None => Ok(false),
                }
            }
            RuleCondition::And { conditions } => {
                for condition in conditions {
                    if !Self::evaluate_condition_inner(condition, context, regex_cache)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            RuleCondition::Or { conditions } => {
                for condition in conditions {
                    if Self::evaluate_condition_inner(condition, context, regex_cache)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            RuleCondition::Not { condition } => {
                let result = Self::evaluate_condition_inner(condition, context, regex_cache)?;
                Ok(!result)
            }
        }
    }
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    regex_cache: HashMap<String, regex::Regex>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            regex_cache: HashMap::new(),
        }
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.precompile_regexes(&rule.condition);
        self.rules.push(rule);
    }

    fn precompile_regexes(&mut self, condition: &RuleCondition) {
        match condition {
            RuleCondition::Regex { pattern, .. } => {
                if !self.regex_cache.contains_key(pattern) {
                    if let Ok(re) = regex::Regex::new(pattern) {
                        self.regex_cache.insert(pattern.clone(), re);
                    }
                }
            }
            RuleCondition::And { conditions } | RuleCondition::Or { conditions } => {
                for c in conditions {
                    self.precompile_regexes(c);
                }
            }
            RuleCondition::Not { condition } => {
                self.precompile_regexes(condition);
            }
            _ => {}
        }
    }

    pub fn remove_rule(&mut self, id: Uuid) -> bool {
        let initial_len = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < initial_len
    }

    pub fn get_rule(&self, id: Uuid) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    pub fn list_rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn list_enabled_rules(&self) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.enabled).collect()
    }

    pub async fn evaluate(&self, context: &HashMap<String, serde_json::Value>) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let mut regex_cache = self.regex_cache.clone();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            match ConditionEvaluator::evaluate_condition_inner(
                &rule.condition,
                context,
                &mut regex_cache,
            ) {
                Ok(true) => {
                    matches.push(RuleMatch {
                        rule_id: rule.id,
                        rule_name: rule.name.clone(),
                        severity: rule.severity.clone(),
                        category: rule.category.clone(),
                        actions: rule.actions.clone(),
                        evidence: context.clone(),
                        timestamp: chrono::Utc::now(),
                    });
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(
                        rule_id = %rule.id,
                        rule_name = %rule.name,
                        error = %e,
                        "Rule evaluation failed"
                    );
                }
            }
        }

        matches
    }

    pub fn load_rules(&mut self, rules: Vec<Rule>) {
        for rule in rules {
            self.precompile_regexes(&rule.condition);
            self.rules.push(rule);
        }
    }

    pub fn clear_rules(&mut self) {
        self.rules.clear();
    }

    pub fn count(&self) -> usize {
        self.rules.len()
    }

    pub fn count_enabled(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn rule_engine_new() {
        let engine = RuleEngine::new();
        assert_eq!(engine.count(), 0);
        assert_eq!(engine.count_enabled(), 0);
    }

    #[test]
    fn add_and_remove_rule() {
        let mut engine = RuleEngine::new();
        let rule = Rule {
            id: Uuid::new_v4(),
            name: "Test Rule".to_string(),
            description: "A test rule".to_string(),
            enabled: true,
            severity: "high".to_string(),
            category: "test".to_string(),
            condition: RuleCondition::Equals {
                field: "severity".to_string(),
                value: serde_json::Value::String("high".to_string()),
            },
            actions: vec![],
            tags: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        engine.add_rule(rule.clone());
        assert_eq!(engine.count(), 1);

        assert!(engine.remove_rule(rule.id));
        assert_eq!(engine.count(), 0);
    }

    #[test]
    fn evaluate_equals_condition() {
        let mut context = HashMap::new();
        context.insert(
            "severity".to_string(),
            serde_json::Value::String("high".to_string()),
        );

        let condition = RuleCondition::Equals {
            field: "severity".to_string(),
            value: serde_json::Value::String("high".to_string()),
        };

        assert!(ConditionEvaluator::evaluate_condition(&condition, &context).unwrap());
    }

    #[test]
    fn evaluate_and_condition() {
        let mut context = HashMap::new();
        context.insert(
            "severity".to_string(),
            serde_json::Value::String("high".to_string()),
        );
        context.insert(
            "category".to_string(),
            serde_json::Value::String("rootkit".to_string()),
        );

        let condition = RuleCondition::And {
            conditions: vec![
                RuleCondition::Equals {
                    field: "severity".to_string(),
                    value: serde_json::Value::String("high".to_string()),
                },
                RuleCondition::Equals {
                    field: "category".to_string(),
                    value: serde_json::Value::String("rootkit".to_string()),
                },
            ],
        };

        assert!(ConditionEvaluator::evaluate_condition(&condition, &context).unwrap());
    }

    #[tokio::test]
    async fn rule_engine_evaluate() {
        let mut engine = RuleEngine::new();
        let rule = Rule {
            id: Uuid::new_v4(),
            name: "Critical Rootkit".to_string(),
            description: "Detects critical rootkit".to_string(),
            enabled: true,
            severity: "critical".to_string(),
            category: "rootkit".to_string(),
            condition: RuleCondition::And {
                conditions: vec![
                    RuleCondition::Equals {
                        field: "severity".to_string(),
                        value: serde_json::Value::String("critical".to_string()),
                    },
                    RuleCondition::Equals {
                        field: "category".to_string(),
                        value: serde_json::Value::String("rootkit".to_string()),
                    },
                ],
            },
            actions: vec![RuleAction::Alert {
                message: "Critical rootkit detected".to_string(),
            }],
            tags: vec!["rootkit".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        engine.add_rule(rule);

        let mut context = HashMap::new();
        context.insert(
            "severity".to_string(),
            serde_json::Value::String("critical".to_string()),
        );
        context.insert(
            "category".to_string(),
            serde_json::Value::String("rootkit".to_string()),
        );

        let matches = engine.evaluate(&context).await;
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "Critical Rootkit");
    }
}
