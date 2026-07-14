pub mod evidence_correlator;
pub mod graph;
pub mod rules;

use chrono::{DateTime, Duration, Utc};
use sentinelx_common::types::ThreatCategory;
use sentinelx_common::types::ThreatEvent;
use sentinelx_evidence::Evidence;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

pub use evidence_correlator::{CorrelatedEvidence, EvidenceCorrelator, EvidenceNode};
pub use graph::{EdgeType, GraphEdge, GraphNode, GraphPath, InMemoryGraph};
pub use rules::{CorrelationRuleConfig, EvidenceCorrelationRule};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrelationKind {
    CoOccurrence,
    CategoryChain,
    EntityCluster,
    EvidenceCluster,
    TimeWindow,
    SeverityEscalation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub name: String,
    pub description: String,
    pub kind: CorrelationKind,
    pub min_items: usize,
    pub time_window_seconds: i64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub id: Uuid,
    pub rule_name: String,
    pub kind: CorrelationKind,
    pub matched_events: Vec<ThreatEvent>,
    pub matched_evidence: Vec<EvidenceSummary>,
    pub combined_severity: String,
    pub title: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub entity_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub id: Uuid,
    pub evidence_type: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationStats {
    pub total_correlations: usize,
    pub by_rule: HashMap<String, usize>,
    pub by_kind: HashMap<String, usize>,
}

pub struct CorrelationEngine {
    events: Vec<ThreatEvent>,
    evidence_items: Vec<Evidence>,
    rules: Vec<CorrelationRule>,
    results: Vec<CorrelationResult>,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            events: Vec::new(),
            evidence_items: Vec::new(),
            rules: Vec::new(),
            results: Vec::new(),
        };
        engine.add_default_rules();
        engine
    }

    fn add_default_rules(&mut self) {
        self.rules.push(CorrelationRule {
            name: "multi_indicator".to_string(),
            description: "Detects when 3 or more threat events fire in a short time window"
                .to_string(),
            kind: CorrelationKind::CoOccurrence,
            min_items: 3,
            time_window_seconds: 300,
            enabled: true,
        });

        self.rules.push(CorrelationRule {
            name: "privilege_escalation_chain".to_string(),
            description: "Detects privilege escalation followed by persistence mechanism"
                .to_string(),
            kind: CorrelationKind::CategoryChain,
            min_items: 2,
            time_window_seconds: 600,
            enabled: true,
        });

        self.rules.push(CorrelationRule {
            name: "rootkit_indicators".to_string(),
            description: "Detects hook + hidden process + integrity violation together".to_string(),
            kind: CorrelationKind::CoOccurrence,
            min_items: 3,
            time_window_seconds: 300,
            enabled: true,
        });

        self.rules.push(CorrelationRule {
            name: "process_anomaly_cluster".to_string(),
            description: "Detects multiple events from the same process suggesting compromise"
                .to_string(),
            kind: CorrelationKind::EntityCluster,
            min_items: 3,
            time_window_seconds: 600,
            enabled: true,
        });

        self.rules.push(CorrelationRule {
            name: "cross_detector_evidence".to_string(),
            description: "Detects evidence from multiple detector types for the same entity"
                .to_string(),
            kind: CorrelationKind::EvidenceCluster,
            min_items: 2,
            time_window_seconds: 300,
            enabled: true,
        });

        self.rules.push(CorrelationRule {
            name: "severity_escalation".to_string(),
            description: "Detects escalating severity levels for the same category".to_string(),
            kind: CorrelationKind::SeverityEscalation,
            min_items: 3,
            time_window_seconds: 600,
            enabled: true,
        });
    }

    pub fn add_event(&mut self, event: ThreatEvent) {
        self.events.push(event);
    }

    pub fn add_events(&mut self, events: Vec<ThreatEvent>) {
        self.events.extend(events);
    }

    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.evidence_items.push(evidence);
    }

    pub fn add_evidence_items(&mut self, evidence: Vec<Evidence>) {
        self.evidence_items.extend(evidence);
    }

    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    pub fn set_rules(&mut self, rules: Vec<CorrelationRule>) {
        self.rules = rules;
    }

    pub fn correlate(&mut self) -> Vec<CorrelationResult> {
        self.results.clear();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            let matches = match &rule.kind {
                CorrelationKind::CoOccurrence => self.match_co_occurrence(rule),
                CorrelationKind::CategoryChain => self.match_category_chain(rule),
                CorrelationKind::EntityCluster => self.match_entity_cluster(rule),
                CorrelationKind::EvidenceCluster => self.match_evidence_cluster(rule),
                CorrelationKind::TimeWindow => self.match_time_window(rule),
                CorrelationKind::SeverityEscalation => self.match_severity_escalation(rule),
            };
            self.results.extend(matches);
        }

        self.deduplicate_results();
        self.results.clone()
    }

    pub fn results(&self) -> &[CorrelationResult] {
        &self.results
    }

    pub fn stats(&self) -> CorrelationStats {
        let mut by_rule: HashMap<String, usize> = HashMap::new();
        let mut by_kind: HashMap<String, usize> = HashMap::new();

        for result in &self.results {
            *by_rule.entry(result.rule_name.clone()).or_insert(0) += 1;
            let kind_str = format!("{:?}", result.kind);
            *by_kind.entry(kind_str).or_insert(0) += 1;
        }

        CorrelationStats {
            total_correlations: self.results.len(),
            by_rule,
            by_kind,
        }
    }

    fn sorted_event_indices(&self) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..self.events.len()).collect();
        indices.sort_by_key(|&i| self.events[i].timestamp);
        indices
    }

    fn match_co_occurrence(&self, rule: &CorrelationRule) -> Vec<CorrelationResult> {
        let mut results = Vec::new();
        if self.events.len() < rule.min_items {
            return results;
        }

        let indices = self.sorted_event_indices();

        for i in 0..indices.len() {
            let mut cluster_indices = vec![indices[i]];
            for j in (i + 1)..indices.len() {
                let diff = self.events[indices[j]].timestamp - self.events[indices[i]].timestamp;
                if diff <= Duration::seconds(rule.time_window_seconds) {
                    cluster_indices.push(indices[j]);
                } else {
                    break;
                }
            }

            if cluster_indices.len() >= rule.min_items {
                if rule.name == "rootkit_indicators" {
                    let has_hook = cluster_indices
                        .iter()
                        .any(|&i| self.events[i].category == ThreatCategory::HookDetected);
                    let has_hidden = cluster_indices
                        .iter()
                        .any(|&i| self.events[i].category == ThreatCategory::HiddenProcess);
                    let has_integrity = cluster_indices
                        .iter()
                        .any(|&i| self.events[i].category == ThreatCategory::IntegrityViolation);

                    if !(has_hook && has_hidden && has_integrity) {
                        continue;
                    }
                }

                let combined_severity = cluster_indices
                    .iter()
                    .map(|&i| self.events[i].severity)
                    .max()
                    .unwrap_or(sentinelx_common::severity::Severity::Info);

                let events: Vec<ThreatEvent> = cluster_indices
                    .into_iter()
                    .map(|i| self.events[i].clone())
                    .collect();

                let mut description = String::with_capacity(rule.description.len() + 20);
                description.push_str(rule.description.as_str());
                description.push_str(" - triggered by: ");
                for (idx, ev) in events.iter().enumerate() {
                    if idx > 0 {
                        description.push_str(", ");
                    }
                    description.push_str(ev.title.as_str());
                }

                results.push(CorrelationResult {
                    id: Uuid::new_v4(),
                    rule_name: rule.name.clone(),
                    kind: CorrelationKind::CoOccurrence,
                    matched_events: events,
                    matched_evidence: Vec::new(),
                    combined_severity: combined_severity.as_str().to_string(),
                    title: format!("{}: correlated threat", rule.name),
                    description,
                    timestamp: Utc::now(),
                    entity_key: None,
                });
            }
        }

        results
    }

    fn match_category_chain(&self, rule: &CorrelationRule) -> Vec<CorrelationResult> {
        let mut results = Vec::new();

        if rule.name == "privilege_escalation_chain" {
            let pe_indices: Vec<usize> = self
                .events
                .iter()
                .enumerate()
                .filter(|(_, e)| e.category == ThreatCategory::PrivilegeEscalation)
                .map(|(i, _)| i)
                .collect();
            let persistence_indices: Vec<usize> = self
                .events
                .iter()
                .enumerate()
                .filter(|(_, e)| e.category == ThreatCategory::PersistenceMechanism)
                .map(|(i, _)| i)
                .collect();

            if !pe_indices.is_empty() && !persistence_indices.is_empty() {
                let mut chain_indices: Vec<usize> = pe_indices;
                chain_indices.extend_from_slice(&persistence_indices);
                chain_indices.sort_by_key(|&i| self.events[i].timestamp);

                let mut chain_events: Vec<ThreatEvent> = Vec::with_capacity(chain_indices.len());
                for i in chain_indices {
                    chain_events.push(self.events[i].clone());
                }

                results.push(CorrelationResult {
                    id: Uuid::new_v4(),
                    rule_name: rule.name.clone(),
                    kind: CorrelationKind::CategoryChain,
                    matched_events: chain_events,
                    matched_evidence: Vec::new(),
                    combined_severity: "critical".to_string(),
                    title: "Privilege escalation chain detected".to_string(),
                    description:
                        "Privilege escalation followed by persistence mechanism installation"
                            .to_string(),
                    timestamp: Utc::now(),
                    entity_key: None,
                });
            }
        } else {
            let mut category_groups: HashMap<&str, Vec<usize>> = HashMap::new();
            for (i, ev) in self.events.iter().enumerate() {
                category_groups
                    .entry(ev.category.as_str())
                    .or_default()
                    .push(i);
            }

            for (category_str, indices) in &category_groups {
                if indices.len() >= rule.min_items {
                    let combined_severity = indices
                        .iter()
                        .map(|&i| self.events[i].severity)
                        .max()
                        .unwrap_or(sentinelx_common::severity::Severity::Info);

                    let matched: Vec<ThreatEvent> =
                        indices.iter().map(|&i| self.events[i].clone()).collect();

                    results.push(CorrelationResult {
                        id: Uuid::new_v4(),
                        rule_name: rule.name.clone(),
                        kind: CorrelationKind::CategoryChain,
                        matched_events: matched,
                        matched_evidence: Vec::new(),
                        combined_severity: combined_severity.as_str().to_string(),
                        title: format!("Multiple {} events", category_str),
                        description: rule.description.clone(),
                        timestamp: Utc::now(),
                        entity_key: None,
                    });
                }
            }
        }

        results
    }

    fn match_entity_cluster(&self, rule: &CorrelationRule) -> Vec<CorrelationResult> {
        let mut results = Vec::new();

        let mut entity_groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, ev) in self.events.iter().enumerate() {
            let key = ev
                .process
                .as_ref()
                .map(|p| p.pid.to_string())
                .unwrap_or_else(|| ev.source_detector.clone());
            entity_groups.entry(key).or_default().push(i);
        }

        for (entity_key, indices) in &entity_groups {
            if indices.len() >= rule.min_items {
                let base = self.events[indices[0]].timestamp;
                let within_window: Vec<ThreatEvent> = indices
                    .iter()
                    .filter(|&&i| {
                        self.events[i].timestamp - base
                            <= Duration::seconds(rule.time_window_seconds)
                    })
                    .map(|&i| self.events[i].clone())
                    .collect();

                if within_window.len() >= rule.min_items {
                    let combined_severity = within_window
                        .iter()
                        .map(|e| e.severity)
                        .max()
                        .unwrap_or(sentinelx_common::severity::Severity::Info);

                    let mut description = String::with_capacity(rule.description.len() + 20);
                    description.push_str(rule.description.as_str());
                    description.push_str(" - events: ");
                    for (idx, ev) in within_window.iter().enumerate() {
                        if idx > 0 {
                            description.push_str(", ");
                        }
                        description.push_str(ev.title.as_str());
                    }

                    results.push(CorrelationResult {
                        id: Uuid::new_v4(),
                        rule_name: rule.name.clone(),
                        kind: CorrelationKind::EntityCluster,
                        matched_events: within_window,
                        matched_evidence: Vec::new(),
                        combined_severity: combined_severity.as_str().to_string(),
                        title: format!("Multiple threats from entity {}", entity_key),
                        description,
                        timestamp: Utc::now(),
                        entity_key: Some(entity_key.clone()),
                    });
                }
            }
        }

        results
    }

    fn match_evidence_cluster(&self, rule: &CorrelationRule) -> Vec<CorrelationResult> {
        let mut results = Vec::new();

        let mut source_groups: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, ev) in self.evidence_items.iter().enumerate() {
            source_groups.entry(ev.source.as_str()).or_default().push(i);
        }

        for (source, indices) in &source_groups {
            let mut type_set: HashSet<&sentinelx_evidence::EvidenceType> = HashSet::new();
            for &i in indices {
                type_set.insert(&self.evidence_items[i].evidence_type);
            }

            if type_set.len() >= rule.min_items {
                let base = self.evidence_items[indices[0]].timestamp;
                let within_window_indices: Vec<usize> = indices
                    .iter()
                    .copied()
                    .filter(|&i| {
                        self.evidence_items[i].timestamp - base
                            <= Duration::seconds(rule.time_window_seconds)
                    })
                    .collect();

                if within_window_indices.len() >= rule.min_items {
                    let combined = within_window_indices
                        .iter()
                        .map(|&i| evidence_severity_rank(&self.evidence_items[i].severity))
                        .max()
                        .map(evidence_severity_name)
                        .unwrap_or_else(|| "info".to_string());

                    let summaries: Vec<EvidenceSummary> = within_window_indices
                        .iter()
                        .map(|&i| {
                            let e = &self.evidence_items[i];
                            EvidenceSummary {
                                id: e.id,
                                evidence_type: format!("{:?}", e.evidence_type),
                                severity: e.severity.as_str().to_string(),
                                source: e.source.clone(),
                                description: e.description.clone(),
                                confidence: e.confidence,
                            }
                        })
                        .collect();

                    let mut description = String::with_capacity(rule.description.len() + 20);
                    description.push_str(rule.description.as_str());
                    description.push_str(" - evidence: ");
                    for (idx, s) in summaries.iter().enumerate() {
                        if idx > 0 {
                            description.push_str("; ");
                        }
                        description.push_str(s.description.as_str());
                    }

                    results.push(CorrelationResult {
                        id: Uuid::new_v4(),
                        rule_name: rule.name.clone(),
                        kind: CorrelationKind::EvidenceCluster,
                        matched_events: Vec::new(),
                        matched_evidence: summaries,
                        combined_severity: combined,
                        title: format!("Cross-detector evidence from source {}", source),
                        description,
                        timestamp: Utc::now(),
                        entity_key: Some(source.to_string()),
                    });
                }
            }
        }

        results
    }

    fn match_time_window(&self, rule: &CorrelationRule) -> Vec<CorrelationResult> {
        let indices = self.sorted_event_indices();
        let mut results = Vec::new();

        for i in 0..indices.len() {
            let mut window_indices = vec![indices[i]];
            for j in (i + 1)..indices.len() {
                let diff = self.events[indices[j]].timestamp - self.events[indices[i]].timestamp;
                if diff <= Duration::seconds(rule.time_window_seconds) {
                    window_indices.push(indices[j]);
                } else {
                    break;
                }
            }

            if window_indices.len() >= rule.min_items {
                let combined_severity = window_indices
                    .iter()
                    .map(|&i| self.events[i].severity)
                    .max()
                    .unwrap_or(sentinelx_common::severity::Severity::Info);

                let window_events: Vec<ThreatEvent> = window_indices
                    .into_iter()
                    .map(|i| self.events[i].clone())
                    .collect();

                results.push(CorrelationResult {
                    id: Uuid::new_v4(),
                    rule_name: rule.name.clone(),
                    kind: CorrelationKind::TimeWindow,
                    matched_events: window_events,
                    matched_evidence: Vec::new(),
                    combined_severity: combined_severity.as_str().to_string(),
                    title: "Events within time window".to_string(),
                    description: rule.description.clone(),
                    timestamp: Utc::now(),
                    entity_key: None,
                });
            }
        }

        results
    }

    fn match_severity_escalation(&self, rule: &CorrelationRule) -> Vec<CorrelationResult> {
        let mut results = Vec::new();

        let mut category_groups: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, ev) in self.events.iter().enumerate() {
            category_groups
                .entry(ev.category.as_str())
                .or_default()
                .push(i);
        }

        for indices in category_groups.values() {
            let mut sorted_indices = indices.clone();
            sorted_indices.sort_by_key(|&i| self.events[i].timestamp);

            if sorted_indices.len() < rule.min_items {
                continue;
            }

            let mut escalation_indices: Vec<usize> = Vec::new();
            let mut prev_severity_rank = 0u8;

            for &i in &sorted_indices {
                let rank = severity_rank(&self.events[i].severity);
                if (rank >= prev_severity_rank && prev_severity_rank > 0)
                    || escalation_indices.is_empty()
                {
                    escalation_indices.push(i);
                    prev_severity_rank = rank;
                }
            }

            if escalation_indices.len() >= rule.min_items {
                let chain_events: Vec<ThreatEvent> = escalation_indices
                    .into_iter()
                    .map(|i| self.events[i].clone())
                    .collect();

                let combined = chain_events
                    .iter()
                    .map(|e| e.severity)
                    .max()
                    .unwrap_or(sentinelx_common::severity::Severity::Info);

                let category_str = chain_events
                    .first()
                    .map(|e| e.category.as_str().to_string())
                    .unwrap_or_default();

                results.push(CorrelationResult {
                    id: Uuid::new_v4(),
                    rule_name: rule.name.clone(),
                    kind: CorrelationKind::SeverityEscalation,
                    matched_events: chain_events,
                    matched_evidence: Vec::new(),
                    combined_severity: combined.as_str().to_string(),
                    title: format!("Severity escalation in {}", category_str),
                    description: rule.description.clone(),
                    timestamp: Utc::now(),
                    entity_key: None,
                });
            }
        }

        results
    }

    fn deduplicate_results(&mut self) {
        let mut seen: HashSet<Uuid> = HashSet::new();
        self.results.retain(|r| {
            let sig = dedup_signature(r);
            seen.insert(sig)
        });
    }

    pub fn clear(&mut self) {
        self.events.clear();
        self.evidence_items.clear();
        self.results.clear();
    }
}

fn severity_rank(severity: &sentinelx_common::severity::Severity) -> u8 {
    match severity {
        sentinelx_common::severity::Severity::Info => 0,
        sentinelx_common::severity::Severity::Low => 1,
        sentinelx_common::severity::Severity::Medium => 2,
        sentinelx_common::severity::Severity::High => 3,
        sentinelx_common::severity::Severity::Critical => 4,
    }
}

fn evidence_severity_rank(severity: &sentinelx_evidence::Severity) -> u8 {
    match severity {
        sentinelx_evidence::Severity::Info => 0,
        sentinelx_evidence::Severity::Low => 1,
        sentinelx_evidence::Severity::Medium => 2,
        sentinelx_evidence::Severity::High => 3,
        sentinelx_evidence::Severity::Critical => 4,
    }
}

fn evidence_severity_name(rank: u8) -> String {
    match rank {
        4 => "critical".to_string(),
        3 => "high".to_string(),
        2 => "medium".to_string(),
        1 => "low".to_string(),
        _ => "info".to_string(),
    }
}

fn dedup_signature(result: &CorrelationResult) -> Uuid {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    result.rule_name.hash(&mut hasher);
    for ev in &result.matched_events {
        ev.id.hash(&mut hasher);
    }
    for ev in &result.matched_evidence {
        ev.id.hash(&mut hasher);
    }
    let hash = hasher.finish();
    Uuid::from_u64_pair(hash, hash)
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinelx_common::pid::Pid;
    use sentinelx_common::severity::Severity;
    use sentinelx_common::types::{NamespaceInfo, ProcessInfo, ProcessStatus, ThreatCategory};
    use std::collections::HashMap;

    fn make_event(
        title: &str,
        severity: Severity,
        category: ThreatCategory,
        pid: Option<u32>,
    ) -> ThreatEvent {
        let process = pid.map(|p| ProcessInfo {
            pid: Pid::new(p),
            ppid: Pid::new(1),
            name: format!("proc_{}", p),
            binary_path: format!("/usr/bin/proc_{}", p),
            command_line: vec![format!("proc_{}", p)],
            user: "root".to_string(),
            uid: 0,
            gid: 0,
            start_time: Utc::now(),
            status: ProcessStatus::Running,
            hash: None,
            namespace: NamespaceInfo::default(),
            capabilities: vec![],
            threads: 1,
            memory_usage_kb: 1024,
        });

        ThreatEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category,
            title: title.to_string(),
            description: format!("Description of {}", title),
            evidence: vec![sentinelx_common::types::Evidence {
                description: "evidence".to_string(),
                data: HashMap::new(),
                confidence: 0.9,
            }],
            mitre_attack: vec![],
            source_detector: "test".to_string(),
            process,
            network: None,
            hash: None,
            tags: vec![],
        }
    }

    fn make_ev(
        evidence_type: sentinelx_evidence::EvidenceType,
        severity: sentinelx_evidence::Severity,
        source: &str,
        description: &str,
    ) -> Evidence {
        Evidence::new(
            evidence_type,
            severity,
            source.to_string(),
            description.to_string(),
        )
    }

    #[test]
    fn test_new_engine_has_default_rules() {
        let engine = CorrelationEngine::new();
        assert_eq!(engine.rules.len(), 6);
    }

    #[test]
    fn test_add_event_and_evidence() {
        let mut engine = CorrelationEngine::new();
        engine.add_event(make_event(
            "test",
            Severity::Low,
            ThreatCategory::HookDetected,
            None,
        ));
        assert_eq!(engine.events.len(), 1);

        engine.add_evidence(make_ev(
            sentinelx_evidence::EvidenceType::KernelIntegrity,
            sentinelx_evidence::Severity::High,
            "kernel",
            "hook detected",
        ));
        assert_eq!(engine.evidence_items.len(), 1);
    }

    #[test]
    fn test_multi_indicator_correlation() {
        let mut engine = CorrelationEngine::new();
        let now = Utc::now();

        for i in 0..5 {
            let mut ev = make_event(
                &format!("event_{}", i),
                Severity::High,
                ThreatCategory::HookDetected,
                Some(100 + i),
            );
            ev.timestamp = now + Duration::seconds(i as i64);
            engine.add_event(ev);
        }

        let results = engine.correlate();
        let multi_indicator: Vec<&CorrelationResult> = results
            .iter()
            .filter(|r| r.rule_name == "multi_indicator")
            .collect();
        assert!(!multi_indicator.is_empty());
    }

    #[test]
    fn test_privilege_escalation_chain() {
        let mut engine = CorrelationEngine::new();

        let mut pe_event = make_event(
            "priv esc",
            Severity::High,
            ThreatCategory::PrivilegeEscalation,
            Some(50),
        );
        pe_event.timestamp = Utc::now();
        engine.add_event(pe_event);

        let mut persist_event = make_event(
            "persistence",
            Severity::Critical,
            ThreatCategory::PersistenceMechanism,
            Some(50),
        );
        persist_event.timestamp = Utc::now() + Duration::seconds(30);
        engine.add_event(persist_event);

        let results = engine.correlate();
        let chain: Vec<&CorrelationResult> = results
            .iter()
            .filter(|r| r.rule_name == "privilege_escalation_chain")
            .collect();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].combined_severity, "critical");
    }

    #[test]
    fn test_rootkit_indicators() {
        let mut engine = CorrelationEngine::new();
        let now = Utc::now();

        let mut hook = make_event(
            "hook",
            Severity::High,
            ThreatCategory::HookDetected,
            Some(10),
        );
        hook.timestamp = now;
        engine.add_event(hook);

        let mut hidden = make_event(
            "hidden",
            Severity::High,
            ThreatCategory::HiddenProcess,
            Some(10),
        );
        hidden.timestamp = now + Duration::seconds(1);
        engine.add_event(hidden);

        let mut integrity = make_event(
            "integrity",
            Severity::Critical,
            ThreatCategory::IntegrityViolation,
            Some(10),
        );
        integrity.timestamp = now + Duration::seconds(2);
        engine.add_event(integrity);

        let results = engine.correlate();
        let rootkit: Vec<&CorrelationResult> = results
            .iter()
            .filter(|r| r.rule_name == "rootkit_indicators")
            .collect();
        assert_eq!(rootkit.len(), 1);
    }

    #[test]
    fn test_entity_cluster() {
        let mut engine = CorrelationEngine::new();
        let now = Utc::now();

        for i in 0..4 {
            let mut ev = make_event(
                &format!("threat_{}", i),
                Severity::Medium,
                ThreatCategory::HookDetected,
                Some(42),
            );
            ev.timestamp = now + Duration::seconds(i as i64);
            engine.add_event(ev);
        }

        let results = engine.correlate();
        let entity: Vec<&CorrelationResult> = results
            .iter()
            .filter(|r| r.rule_name == "process_anomaly_cluster")
            .collect();
        assert_eq!(entity.len(), 1);
        assert_eq!(entity[0].entity_key.as_deref(), Some("42"));
    }

    #[test]
    fn test_evidence_cluster() {
        let mut engine = CorrelationEngine::new();
        let now = Utc::now();

        let mut e1 = make_ev(
            sentinelx_evidence::EvidenceType::KernelIntegrity,
            sentinelx_evidence::Severity::High,
            "kernel_detector",
            "hook found",
        );
        e1.timestamp = now;

        let mut e2 = make_ev(
            sentinelx_evidence::EvidenceType::ModuleIntegrity,
            sentinelx_evidence::Severity::High,
            "kernel_detector",
            "module hidden",
        );
        e2.timestamp = now + Duration::seconds(1);

        let mut e3 = make_ev(
            sentinelx_evidence::EvidenceType::ProcessIntegrity,
            sentinelx_evidence::Severity::Critical,
            "kernel_detector",
            "process tampered",
        );
        e3.timestamp = now + Duration::seconds(2);

        engine.add_evidence_items(vec![e1, e2, e3]);

        let results = engine.correlate();
        let evidence_corr: Vec<&CorrelationResult> = results
            .iter()
            .filter(|r| r.rule_name == "cross_detector_evidence")
            .collect();
        assert_eq!(evidence_corr.len(), 1);
        assert_eq!(evidence_corr[0].matched_evidence.len(), 3);
    }

    #[test]
    fn test_severity_escalation() {
        let mut engine = CorrelationEngine::new();
        let now = Utc::now();

        let mut e1 = make_event(
            "low hook",
            Severity::Low,
            ThreatCategory::HookDetected,
            Some(20),
        );
        e1.timestamp = now;
        engine.add_event(e1);

        let mut e2 = make_event(
            "medium hook",
            Severity::Medium,
            ThreatCategory::HookDetected,
            Some(20),
        );
        e2.timestamp = now + Duration::seconds(10);
        engine.add_event(e2);

        let mut e3 = make_event(
            "high hook",
            Severity::High,
            ThreatCategory::HookDetected,
            Some(20),
        );
        e3.timestamp = now + Duration::seconds(20);
        engine.add_event(e3);

        let results = engine.correlate();
        let escalation: Vec<&CorrelationResult> = results
            .iter()
            .filter(|r| r.rule_name == "severity_escalation")
            .collect();
        assert_eq!(escalation.len(), 1);
        assert_eq!(escalation[0].matched_events.len(), 3);
    }

    #[test]
    fn test_empty_correlate() {
        let mut engine = CorrelationEngine::new();
        let results = engine.correlate();
        assert!(results.is_empty());
    }

    #[test]
    fn test_disabled_rule() {
        let mut engine = CorrelationEngine::new();
        engine.rules.push(CorrelationRule {
            name: "disabled_rule".to_string(),
            description: "should not fire".to_string(),
            kind: CorrelationKind::CoOccurrence,
            min_items: 1,
            time_window_seconds: 300,
            enabled: false,
        });

        let now = Utc::now();
        let mut ev = make_event(
            "test",
            Severity::High,
            ThreatCategory::HookDetected,
            Some(1),
        );
        ev.timestamp = now;
        engine.add_event(ev);

        let results = engine.correlate();
        let disabled: Vec<&CorrelationResult> = results
            .iter()
            .filter(|r| r.rule_name == "disabled_rule")
            .collect();
        assert!(disabled.is_empty());
    }

    #[test]
    fn test_stats() {
        let mut engine = CorrelationEngine::new();
        let now = Utc::now();

        for i in 0..5 {
            let mut ev = make_event(
                &format!("event_{}", i),
                Severity::High,
                ThreatCategory::HookDetected,
                Some(100 + i),
            );
            ev.timestamp = now + Duration::seconds(i as i64);
            engine.add_event(ev);
        }

        let results = engine.correlate();
        assert!(!results.is_empty());

        let stats = engine.stats();
        assert!(stats.total_correlations > 0);
    }

    #[test]
    fn test_clear() {
        let mut engine = CorrelationEngine::new();
        engine.add_event(make_event(
            "test",
            Severity::Low,
            ThreatCategory::HookDetected,
            Some(1),
        ));
        engine.add_evidence(make_ev(
            sentinelx_evidence::EvidenceType::KernelIntegrity,
            sentinelx_evidence::Severity::Low,
            "test",
            "test",
        ));

        engine.clear();
        assert!(engine.events.is_empty());
        assert!(engine.evidence_items.is_empty());
        assert!(engine.results.is_empty());
    }
}
