use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::types::{RiskScore, ThreatDecision, ThreatPriority, ThreatSeverity};
use sentinelx_incident::{Incident, IncidentSeverity};

pub struct ThreatEngine {
    decisions: RwLock<HashMap<uuid::Uuid, ThreatDecision>>,
    risk_weights: RiskWeights,
}

#[derive(Debug, Clone)]
pub struct RiskWeights {
    pub trust: f64,
    pub integrity: f64,
    pub risk: f64,
    pub reputation: f64,
    pub evidence_count: f64,
    pub incident_complexity: f64,
    pub rule_confidence: f64,
}

impl Default for RiskWeights {
    fn default() -> Self {
        Self {
            trust: 0.15,
            integrity: 0.20,
            risk: 0.25,
            reputation: 0.10,
            evidence_count: 0.10,
            incident_complexity: 0.10,
            rule_confidence: 0.10,
        }
    }
}

impl ThreatEngine {
    pub fn new() -> Self {
        Self {
            decisions: RwLock::new(HashMap::new()),
            risk_weights: RiskWeights::default(),
        }
    }

    pub fn with_weights(weights: RiskWeights) -> Self {
        Self {
            decisions: RwLock::new(HashMap::new()),
            risk_weights: weights,
        }
    }

    pub fn calculate_risk_score(
        &self,
        incident: &Incident,
        assessments: &[sentinelx_core::assessment::AssessmentResult],
    ) -> RiskScore {
        let mut score = RiskScore::new();

        if !assessments.is_empty() {
            let avg_trust: f64 = assessments
                .iter()
                .map(|a| match a.trust {
                    sentinelx_core::assessment::TrustLevel::Trusted => 20.0,
                    sentinelx_core::assessment::TrustLevel::Unknown => 50.0,
                    sentinelx_core::assessment::TrustLevel::Untrusted => 90.0,
                })
                .sum::<f64>()
                / assessments.len() as f64;

            let avg_integrity: f64 = assessments
                .iter()
                .map(|a| match a.integrity {
                    sentinelx_core::assessment::IntegrityLevel::Intact => 10.0,
                    sentinelx_core::assessment::IntegrityLevel::Unknown => 50.0,
                    sentinelx_core::assessment::IntegrityLevel::Tampered => 90.0,
                })
                .sum::<f64>()
                / assessments.len() as f64;

            let avg_risk: f64 = assessments
                .iter()
                .map(|a| match a.risk {
                    sentinelx_core::assessment::RiskLevel::None => 0.0,
                    sentinelx_core::assessment::RiskLevel::Low => 25.0,
                    sentinelx_core::assessment::RiskLevel::Medium => 50.0,
                    sentinelx_core::assessment::RiskLevel::High => 75.0,
                    sentinelx_core::assessment::RiskLevel::Critical => 100.0,
                })
                .sum::<f64>()
                / assessments.len() as f64;

            let avg_reputation: f64 = assessments
                .iter()
                .map(|a| match a.reputation {
                    sentinelx_core::assessment::ReputationLevel::Known => 10.0,
                    sentinelx_core::assessment::ReputationLevel::Unknown => 50.0,
                    sentinelx_core::assessment::ReputationLevel::Suspicious => 75.0,
                    sentinelx_core::assessment::ReputationLevel::Malicious => 100.0,
                })
                .sum::<f64>()
                / assessments.len() as f64;

            score.trust = avg_trust;
            score.integrity = avg_integrity;
            score.risk = avg_risk;
            score.reputation = avg_reputation;
        }

        score.evidence_count = (incident.evidence_ids.len() as f64 * 10.0).min(100.0);
        score.incident_complexity = (incident.attack_chain.len() as f64 * 20.0).min(100.0);
        score.rule_confidence = incident.confidence * 100.0;

        score.final_score = (score.trust * self.risk_weights.trust
            + score.integrity * self.risk_weights.integrity
            + score.risk * self.risk_weights.risk
            + score.reputation * self.risk_weights.reputation
            + score.evidence_count * self.risk_weights.evidence_count
            + score.incident_complexity * self.risk_weights.incident_complexity
            + score.rule_confidence * self.risk_weights.rule_confidence)
            .clamp(0.0, 100.0);

        score
    }

    pub fn severity_from_incident_severity(sev: &IncidentSeverity) -> ThreatSeverity {
        match sev {
            IncidentSeverity::Info => ThreatSeverity::Info,
            IncidentSeverity::Low => ThreatSeverity::Low,
            IncidentSeverity::Medium => ThreatSeverity::Medium,
            IncidentSeverity::High => ThreatSeverity::High,
            IncidentSeverity::Critical => ThreatSeverity::Critical,
        }
    }

    pub fn priority_from_score(score: f64) -> ThreatPriority {
        match score as u32 {
            80..=100 => ThreatPriority::Immediate,
            61..=79 => ThreatPriority::High,
            41..=60 => ThreatPriority::Normal,
            21..=40 => ThreatPriority::Low,
            _ => ThreatPriority::Informational,
        }
    }

    pub async fn evaluate_incident(
        &self,
        incident: &Incident,
        assessments: &[sentinelx_core::assessment::AssessmentResult],
    ) -> ThreatDecision {
        let risk_score = self.calculate_risk_score(incident, assessments);
        let severity = RiskScore::severity_from_score(risk_score.final_score);
        let priority = Self::priority_from_score(risk_score.final_score);

        let description = format!(
            "Security threat evaluated from incident '{}': {}",
            incident.title, incident.description
        );

        let recommendation = generate_recommendation(&severity, &risk_score);

        let mut decision =
            ThreatDecision::new(incident.id, severity, incident.confidence, &description)
                .with_risk_score(risk_score)
                .with_priority(priority)
                .with_recommendation(&recommendation);

        for mitre in &incident.mitre_mappings {
            decision =
                decision.with_mitre(&mitre.technique_id, &mitre.technique_name, &mitre.tactic);
        }

        for tag in &incident.tags {
            decision = decision.with_tag(tag.clone());
        }

        decision.metadata = serde_json::json!({
            "incident_title": incident.title,
            "evidence_count": incident.evidence_ids.len(),
            "object_count": incident.object_ids.len(),
            "attack_chain_length": incident.attack_chain.len(),
        });

        decision
    }

    pub async fn evaluate_and_store(
        &self,
        incident: &Incident,
        assessments: &[sentinelx_core::assessment::AssessmentResult],
    ) -> ThreatDecision {
        let decision = self.evaluate_incident(incident, assessments).await;
        let id = decision.id;
        let mut decisions = self.decisions.write().await;
        decisions.insert(id, decision.clone());
        debug!(threat_id = %id, severity = %decision.severity.as_str(), "Threat decision created");
        decision
    }

    pub async fn get_decision(&self, id: uuid::Uuid) -> Option<ThreatDecision> {
        let decisions = self.decisions.read().await;
        decisions.get(&id).cloned()
    }

    pub async fn list_decisions(&self) -> Vec<ThreatDecision> {
        let decisions = self.decisions.read().await;
        decisions.values().cloned().collect()
    }

    pub async fn list_by_severity(&self, min_severity: ThreatSeverity) -> Vec<ThreatDecision> {
        let decisions = self.decisions.read().await;
        decisions
            .values()
            .filter(|d| severity_rank(&d.severity) >= severity_rank(&min_severity))
            .cloned()
            .collect()
    }

    pub async fn list_by_priority(&self, min_priority: ThreatPriority) -> Vec<ThreatDecision> {
        let decisions = self.decisions.read().await;
        decisions
            .values()
            .filter(|d| priority_rank(&d.priority) >= priority_rank(&min_priority))
            .cloned()
            .collect()
    }

    pub async fn count(&self) -> usize {
        let decisions = self.decisions.read().await;
        decisions.len()
    }

    pub async fn count_by_severity(&self) -> HashMap<String, usize> {
        let decisions = self.decisions.read().await;
        let mut counts = HashMap::new();
        for d in decisions.values() {
            *counts.entry(d.severity.as_str().to_string()).or_insert(0) += 1;
        }
        counts
    }

    pub async fn clear(&self) {
        let mut decisions = self.decisions.write().await;
        decisions.clear();
        info!("Threat decisions cleared");
    }
}

impl Default for ThreatEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn severity_rank(s: &ThreatSeverity) -> u8 {
    match s {
        ThreatSeverity::Info => 0,
        ThreatSeverity::Low => 1,
        ThreatSeverity::Medium => 2,
        ThreatSeverity::High => 3,
        ThreatSeverity::Critical => 4,
    }
}

fn priority_rank(p: &ThreatPriority) -> u8 {
    match p {
        ThreatPriority::Informational => 0,
        ThreatPriority::Low => 1,
        ThreatPriority::Normal => 2,
        ThreatPriority::High => 3,
        ThreatPriority::Immediate => 4,
    }
}

fn generate_recommendation(severity: &ThreatSeverity, score: &RiskScore) -> String {
    match severity {
        ThreatSeverity::Critical => {
            format!(
                "CRITICAL: Immediate response required. Isolate affected systems. \
                 Risk score: {:.1}/100. Investigate related objects and evidence. \
                 Consider host isolation and forensic snapshot.",
                score.final_score
            )
        }
        ThreatSeverity::High => {
            format!(
                "HIGH: Prompt investigation required. Monitor affected systems closely. \
                 Risk score: {:.1}/100. Review related evidence and attack chain. \
                 Consider process termination if malicious.",
                score.final_score
            )
        }
        ThreatSeverity::Medium => {
            format!(
                "MEDIUM: Investigation recommended. Enhanced monitoring suggested. \
                 Risk score: {:.1}/100. Review assessment results and related evidence.",
                score.final_score
            )
        }
        ThreatSeverity::Low => {
            format!(
                "LOW: Awareness required. Standard monitoring sufficient. \
                 Risk score: {:.1}/100. Log for trend analysis.",
                score.final_score
            )
        }
        ThreatSeverity::Info => {
            format!(
                "INFO: Informational. No immediate action required. \
                 Risk score: {:.1}/100. Record for audit trail.",
                score.final_score
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_incident::{Incident, IncidentSeverity};

    fn make_incident(severity: IncidentSeverity, confidence: f64) -> Incident {
        Incident::new("Test", "Description", severity, confidence)
    }

    #[test]
    fn test_risk_score_calculation_no_assessments() {
        let engine = ThreatEngine::new();
        let incident = make_incident(IncidentSeverity::High, 0.8);
        let score = engine.calculate_risk_score(&incident, &[]);
        assert_eq!(score.trust, 0.0);
        assert_eq!(score.integrity, 0.0);
        assert!(score.final_score >= 0.0);
        assert!(score.final_score <= 100.0);
    }

    #[test]
    fn test_risk_score_with_assessments() {
        let engine = ThreatEngine::new();
        let incident = make_incident(IncidentSeverity::High, 0.8);
        let assessments =
            vec![
                sentinelx_core::assessment::AssessmentResult::new("test", "assessor")
                    .with_trust(sentinelx_core::assessment::TrustLevel::Untrusted)
                    .with_integrity(sentinelx_core::assessment::IntegrityLevel::Tampered)
                    .with_risk(sentinelx_core::assessment::RiskLevel::High)
                    .with_reputation(sentinelx_core::assessment::ReputationLevel::Malicious),
            ];
        let score = engine.calculate_risk_score(&incident, &assessments);
        assert!(score.final_score > 50.0);
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(
            ThreatEngine::severity_from_incident_severity(&IncidentSeverity::Critical),
            ThreatSeverity::Critical
        );
        assert_eq!(
            ThreatEngine::severity_from_incident_severity(&IncidentSeverity::Low),
            ThreatSeverity::Low
        );
    }

    #[test]
    fn test_priority_from_score() {
        assert_eq!(
            ThreatEngine::priority_from_score(90.0),
            ThreatPriority::Immediate
        );
        assert_eq!(
            ThreatEngine::priority_from_score(70.0),
            ThreatPriority::High
        );
        assert_eq!(
            ThreatEngine::priority_from_score(50.0),
            ThreatPriority::Normal
        );
        assert_eq!(ThreatEngine::priority_from_score(30.0), ThreatPriority::Low);
        assert_eq!(
            ThreatEngine::priority_from_score(10.0),
            ThreatPriority::Informational
        );
    }

    #[tokio::test]
    async fn test_evaluate_incident() {
        let engine = ThreatEngine::new();
        let incident = make_incident(IncidentSeverity::High, 0.85);
        let decision = engine.evaluate_incident(&incident, &[]).await;
        assert_eq!(decision.incident_id, incident.id);
        assert!(decision.confidence > 0.0);
        assert!(!decision.recommendation.is_empty());
    }

    #[tokio::test]
    async fn test_evaluate_and_store() {
        let engine = ThreatEngine::new();
        let incident = make_incident(IncidentSeverity::Critical, 0.95);
        let decision = engine.evaluate_and_store(&incident, &[]).await;
        assert_eq!(engine.count().await, 1);
        let found = engine.get_decision(decision.id).await;
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_count_by_severity() {
        let engine = ThreatEngine::new();
        let mut i1 = make_incident(IncidentSeverity::Critical, 0.9);
        i1 = i1
            .with_evidence("ev-001")
            .with_evidence("ev-002")
            .with_evidence("ev-003");
        i1.attack_chain.push(sentinelx_incident::AttackChainStep {
            order: 1,
            evidence_id: "ev-001".to_string(),
            object_id: "process:1".to_string(),
            description: "test".to_string(),
            timestamp: chrono::Utc::now(),
        });
        let mut i2 = make_incident(IncidentSeverity::Critical, 0.8);
        i2 = i2
            .with_evidence("ev-004")
            .with_evidence("ev-005")
            .with_evidence("ev-006");
        engine.evaluate_and_store(&i1, &[]).await;
        engine.evaluate_and_store(&i2, &[]).await;
        let counts = engine.count_by_severity().await;
        let total: usize = counts.values().sum();
        assert_eq!(total, 2);
    }

    #[test]
    fn test_recommendation_generation() {
        let score = RiskScore {
            final_score: 85.0,
            ..RiskScore::new()
        };
        let rec = generate_recommendation(&ThreatSeverity::Critical, &score);
        assert!(rec.contains("CRITICAL"));
        assert!(rec.contains("85.0"));
    }
}
