use crate::graph::{EdgeType, GraphNode, InMemoryGraph};
use crate::rules::CorrelationRuleConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvidence {
    pub id: Uuid,
    pub evidence_ids: Vec<String>,
    pub object_ids: Vec<String>,
    pub rule_name: String,
    pub severity: String,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub relationships: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceNode {
    pub evidence_id: String,
    pub object_id: String,
    pub evidence_type: String,
    pub severity: String,
    pub confidence: f64,
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub assessment_risk: Option<u32>,
}

pub struct EvidenceCorrelator {
    graph: InMemoryGraph,
    evidence_store: Vec<EvidenceNode>,
    rule_config: CorrelationRuleConfig,
    correlated: Vec<CorrelatedEvidence>,
}

impl EvidenceCorrelator {
    pub fn new() -> Self {
        Self {
            graph: InMemoryGraph::new(),
            evidence_store: Vec::new(),
            rule_config: CorrelationRuleConfig::load_default(),
            correlated: Vec::new(),
        }
    }

    pub fn with_rules(config: CorrelationRuleConfig) -> Self {
        Self {
            graph: InMemoryGraph::new(),
            evidence_store: Vec::new(),
            rule_config: config,
            correlated: Vec::new(),
        }
    }

    pub fn add_evidence(&mut self, evidence: EvidenceNode) {
        let mut properties = std::collections::HashMap::new();
        properties.insert(
            "object_id".to_string(),
            serde_json::Value::String(evidence.object_id.clone()),
        );
        properties.insert(
            "severity".to_string(),
            serde_json::Value::String(evidence.severity.clone()),
        );
        properties.insert(
            "confidence".to_string(),
            serde_json::json!(evidence.confidence),
        );
        properties.insert(
            "source".to_string(),
            serde_json::Value::String(evidence.source.clone()),
        );

        let node = GraphNode {
            id: evidence.evidence_id.clone(),
            label: format!("{}: {}", evidence.evidence_type, evidence.source),
            node_type: evidence.evidence_type.clone(),
            properties,
        };
        self.graph.add_node(node);
        self.evidence_store.push(evidence);
    }

    pub fn build_relationships(&mut self) {
        let evidence_ids: Vec<String> = self
            .evidence_store
            .iter()
            .map(|e| e.evidence_id.clone())
            .collect();

        for i in 0..evidence_ids.len() {
            for j in (i + 1)..evidence_ids.len() {
                let e1 = &self.evidence_store[i];
                let e2 = &self.evidence_store[j];

                if e1.object_id == e2.object_id && e1.evidence_id != e2.evidence_id {
                    self.graph
                        .connect(&e1.evidence_id, &e2.evidence_id, EdgeType::Connected);
                }

                if e1.source == e2.source
                    && e1.evidence_id != e2.evidence_id
                    && self.evidence_in_time_window(e1, e2, 300)
                {
                    self.graph
                        .connect(&e1.evidence_id, &e2.evidence_id, EdgeType::Opened);
                }
            }
        }
    }

    fn evidence_in_time_window(
        &self,
        e1: &EvidenceNode,
        e2: &EvidenceNode,
        window_secs: i64,
    ) -> bool {
        let diff = e2.timestamp - e1.timestamp;
        diff.num_seconds().abs() <= window_secs
    }

    pub fn correlate(&mut self) -> Vec<CorrelatedEvidence> {
        self.correlated.clear();
        self.build_relationships();

        let enabled_rules: Vec<_> = self
            .rule_config
            .enabled_rules()
            .into_iter()
            .cloned()
            .collect();
        for rule in &enabled_rules {
            self.apply_rule(rule);
        }

        self.correlated.clone()
    }

    fn apply_rule(&mut self, rule: &crate::rules::EvidenceCorrelationRule) {
        if self.evidence_store.len() < rule.min_evidence {
            return;
        }

        let matching_evidence: Vec<&EvidenceNode> = self
            .evidence_store
            .iter()
            .filter(|e| {
                rule.requires.is_empty() || rule.requires.iter().any(|r| r == &e.evidence_type)
            })
            .collect();

        if matching_evidence.len() < rule.min_evidence {
            return;
        }

        let avg_confidence: f64 = matching_evidence.iter().map(|e| e.confidence).sum::<f64>()
            / matching_evidence.len() as f64;

        if avg_confidence < rule.min_confidence {
            return;
        }

        let max_risk = matching_evidence
            .iter()
            .filter_map(|e| e.assessment_risk)
            .max()
            .unwrap_or(0);

        if max_risk < rule.min_assessment_risk {
            return;
        }

        let evidence_ids: Vec<String> = matching_evidence
            .iter()
            .map(|e| e.evidence_id.clone())
            .collect();
        let object_ids: Vec<String> = matching_evidence
            .iter()
            .map(|e| e.object_id.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let relationships: Vec<String> = evidence_ids
            .iter()
            .flat_map(|id| {
                self.graph
                    .get_edges_from(id)
                    .iter()
                    .map(|e| format!("{} -> {} ({})", e.source, e.target, e.edge_type.as_str()))
                    .collect::<Vec<_>>()
            })
            .collect();

        self.correlated.push(CorrelatedEvidence {
            id: Uuid::new_v4(),
            evidence_ids,
            object_ids,
            rule_name: rule.name.clone(),
            severity: rule.severity.clone(),
            confidence: avg_confidence,
            title: format!("{}: {}", rule.name, rule.description),
            description: rule.description.clone(),
            timestamp: Utc::now(),
            relationships,
            mitre_techniques: rule.mitre_techniques.clone(),
        });
    }

    pub fn graph(&self) -> &InMemoryGraph {
        &self.graph
    }

    pub fn correlated(&self) -> &[CorrelatedEvidence] {
        &self.correlated
    }

    pub fn evidence_count(&self) -> usize {
        self.evidence_store.len()
    }

    pub fn clear(&mut self) {
        self.graph.clear();
        self.evidence_store.clear();
        self.correlated.clear();
    }
}

impl Default for EvidenceCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_evidence(
        id: &str,
        object_id: &str,
        evidence_type: &str,
        severity: &str,
        confidence: f64,
        source: &str,
    ) -> EvidenceNode {
        EvidenceNode {
            evidence_id: id.to_string(),
            object_id: object_id.to_string(),
            evidence_type: evidence_type.to_string(),
            severity: severity.to_string(),
            confidence,
            source: source.to_string(),
            timestamp: Utc::now(),
            assessment_risk: Some(60),
        }
    }

    #[test]
    fn test_add_evidence() {
        let mut correlator = EvidenceCorrelator::new();
        correlator.add_evidence(make_evidence(
            "e1",
            "process:1",
            "ProcessIntegrity",
            "high",
            0.9,
            "scanner",
        ));
        assert_eq!(correlator.evidence_count(), 1);
    }

    #[test]
    fn test_build_relationships() {
        let mut correlator = EvidenceCorrelator::new();
        correlator.add_evidence(make_evidence(
            "e1",
            "process:1",
            "ProcessIntegrity",
            "high",
            0.9,
            "scanner",
        ));
        correlator.add_evidence(make_evidence(
            "e2",
            "process:1",
            "MemoryIntegrity",
            "high",
            0.85,
            "scanner",
        ));
        correlator.build_relationships();
        let edges = correlator.graph().get_edges_from("e1");
        assert!(!edges.is_empty());
    }

    #[test]
    fn test_correlate_with_matching_rule() {
        let toml_str = r#"
[[rules]]
name = "test_rule"
description = "Test correlation"
enabled = true
requires = ["ProcessIntegrity", "MemoryIntegrity"]
min_evidence = 2
min_confidence = 0.5
min_assessment_risk = 30
time_window_seconds = 300
severity = "high"
mitre_techniques = ["T1234"]
recommended_response = "Test"
"#;
        let config = CorrelationRuleConfig::parse_from_str(toml_str).unwrap();
        let mut correlator = EvidenceCorrelator::with_rules(config);
        correlator.add_evidence(make_evidence(
            "e1",
            "process:1",
            "ProcessIntegrity",
            "high",
            0.9,
            "scanner",
        ));
        correlator.add_evidence(make_evidence(
            "e2",
            "process:1",
            "MemoryIntegrity",
            "high",
            0.85,
            "scanner",
        ));

        let results = correlator.correlate();
        assert!(!results.is_empty());
        assert_eq!(results[0].rule_name, "test_rule");
    }

    #[test]
    fn test_correlate_no_match() {
        let toml_str = r#"
[[rules]]
name = "test_rule"
description = "Test"
enabled = true
requires = ["KernelIntegrity"]
min_evidence = 1
min_confidence = 0.5
min_assessment_risk = 30
time_window_seconds = 300
severity = "high"
mitre_techniques = []
recommended_response = "Test"
"#;
        let config = CorrelationRuleConfig::parse_from_str(toml_str).unwrap();
        let mut correlator = EvidenceCorrelator::with_rules(config);
        correlator.add_evidence(make_evidence(
            "e1",
            "process:1",
            "ProcessIntegrity",
            "high",
            0.9,
            "scanner",
        ));

        let results = correlator.correlate();
        assert!(results.is_empty());
    }

    #[test]
    fn test_clear() {
        let mut correlator = EvidenceCorrelator::new();
        correlator.add_evidence(make_evidence(
            "e1",
            "process:1",
            "ProcessIntegrity",
            "high",
            0.9,
            "scanner",
        ));
        correlator.clear();
        assert_eq!(correlator.evidence_count(), 0);
    }
}
