use sentinelx_common::types::ThreatEvent;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScore {
    pub threat_id: String,
    pub base_score: f64,
    pub evidence_score: f64,
    pub correlation_score: f64,
    pub rule_score: f64,
    pub final_score: f64,
    pub confidence: f64,
    pub factors: Vec<ScoreFactor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreFactor {
    pub name: String,
    pub weight: f64,
    pub contribution: f64,
    pub reason: String,
}

pub struct ThreatScorer {
    pub severity_weight: f64,
    pub evidence_weight: f64,
    pub correlation_weight: f64,
    pub rule_weight: f64,
    pub confidence_threshold: f64,
}

impl ThreatScorer {
    pub fn new() -> Self {
        Self {
            severity_weight: 0.3,
            evidence_weight: 0.3,
            correlation_weight: 0.2,
            rule_weight: 0.2,
            confidence_threshold: 0.5,
        }
    }

    pub fn score_threat(
        &self,
        threat: &ThreatEvent,
        evidence_confidence: f64,
        correlation_count: usize,
        rule_match_count: usize,
    ) -> ThreatScore {
        let mut factors = Vec::with_capacity(4);

        let base_score = severity_score(&threat.severity);
        factors.push(ScoreFactor {
            name: "severity".to_string(),
            weight: self.severity_weight,
            contribution: base_score * self.severity_weight,
            reason: format!("Severity is {}", threat.severity.as_str()),
        });

        let ev_score = (evidence_confidence * 100.0).round() / 100.0;
        factors.push(ScoreFactor {
            name: "evidence".to_string(),
            weight: self.evidence_weight,
            contribution: ev_score * self.evidence_weight,
            reason: format!("Evidence confidence: {:.2}", evidence_confidence),
        });

        let corr_score = correlation_score(correlation_count);
        factors.push(ScoreFactor {
            name: "correlation".to_string(),
            weight: self.correlation_weight,
            contribution: corr_score * self.correlation_weight,
            reason: format!("{} correlations found", correlation_count),
        });

        let rule_sc = rule_match_score(rule_match_count);
        factors.push(ScoreFactor {
            name: "rule_match".to_string(),
            weight: self.rule_weight,
            contribution: rule_sc * self.rule_weight,
            reason: format!("{} rule matches", rule_match_count),
        });

        let final_score = factors.iter().map(|f| f.contribution).sum::<f64>();
        let final_score = (final_score * 100.0).round() / 100.0;
        let confidence = calculate_confidence(&factors);

        ThreatScore {
            threat_id: threat.id.to_string(),
            base_score,
            evidence_score: ev_score,
            correlation_score: corr_score,
            rule_score: rule_sc,
            final_score,
            confidence,
            factors,
        }
    }

    pub fn score_threats(
        &self,
        threats: &[ThreatEvent],
        evidence_confidences: &[f64],
        correlation_counts: &[usize],
        rule_match_counts: &[usize],
    ) -> Vec<ThreatScore> {
        threats
            .iter()
            .enumerate()
            .map(|(i, threat)| {
                let ev_conf = evidence_confidences.get(i).copied().unwrap_or(0.0);
                let corr_count = correlation_counts.get(i).copied().unwrap_or(0);
                let rule_count = rule_match_counts.get(i).copied().unwrap_or(0);
                self.score_threat(threat, ev_conf, corr_count, rule_count)
            })
            .collect()
    }

    pub fn is_high_confidence(&self, score: &ThreatScore) -> bool {
        score.final_score >= self.confidence_threshold && score.confidence >= 0.5
    }
}

fn severity_score(severity: &sentinelx_common::severity::Severity) -> f64 {
    match severity {
        sentinelx_common::severity::Severity::Info => 0.1,
        sentinelx_common::severity::Severity::Low => 0.3,
        sentinelx_common::severity::Severity::Medium => 0.5,
        sentinelx_common::severity::Severity::High => 0.8,
        sentinelx_common::severity::Severity::Critical => 1.0,
    }
}

fn correlation_score(count: usize) -> f64 {
    match count {
        0 => 0.0,
        1 => 0.3,
        2 => 0.6,
        3 => 0.8,
        _ => 1.0,
    }
}

fn rule_match_score(count: usize) -> f64 {
    match count {
        0 => 0.0,
        1 => 0.4,
        2 => 0.7,
        _ => 1.0,
    }
}

fn calculate_confidence(factors: &[ScoreFactor]) -> f64 {
    if factors.is_empty() {
        return 0.0;
    }

    let total_weight: f64 = factors.iter().map(|f| f.weight).sum();
    let weight_variance = factors
        .iter()
        .map(|f| {
            let normalized = f.weight / total_weight;
            let deviation = normalized - (1.0 / factors.len() as f64);
            deviation * deviation
        })
        .sum::<f64>();

    let data_coverage =
        factors.iter().filter(|f| f.contribution > 0.0).count() as f64 / factors.len() as f64;

    let base_confidence = (1.0 - weight_variance.sqrt()) * 0.6 + data_coverage * 0.4;
    (base_confidence * 100.0).round() / 100.0
}

impl Default for ThreatScorer {
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
    use sentinelx_common::types::*;
    fn make_threat(severity: Severity, category: ThreatCategory) -> ThreatEvent {
        ThreatEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category,
            title: "test threat".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            mitre_attack: vec![],
            source_detector: "test".to_string(),
            process: Some(ProcessInfo {
                pid: Pid::new(100),
                ppid: Pid::new(1),
                name: "test_proc".to_string(),
                binary_path: "/usr/bin/test".to_string(),
                command_line: vec!["test".to_string()],
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
            }),
            network: None,
            hash: None,
            tags: vec![],
        }
    }

    #[test]
    fn test_basic_scoring() {
        let scorer = ThreatScorer::new();
        let threat = make_threat(Severity::High, ThreatCategory::HookDetected);
        let score = scorer.score_threat(&threat, 0.9, 2, 1);

        assert!(score.final_score > 0.0);
        assert!(score.final_score <= 1.0);
        assert_eq!(score.factors.len(), 4);
    }

    #[test]
    fn test_severity_scores() {
        let scorer = ThreatScorer::new();

        let critical = make_threat(Severity::Critical, ThreatCategory::HookDetected);
        let info = make_threat(Severity::Info, ThreatCategory::HookDetected);

        let s_crit = scorer.score_threat(&critical, 0.0, 0, 0);
        let s_info = scorer.score_threat(&info, 0.0, 0, 0);

        assert!(s_crit.base_score > s_info.base_score);
    }

    #[test]
    fn test_evidence_increases_score() {
        let scorer = ThreatScorer::new();
        let threat = make_threat(Severity::Medium, ThreatCategory::HookDetected);

        let s_low = scorer.score_threat(&threat, 0.1, 0, 0);
        let s_high = scorer.score_threat(&threat, 0.9, 0, 0);

        assert!(s_high.final_score > s_low.final_score);
    }

    #[test]
    fn test_correlation_increases_score() {
        let scorer = ThreatScorer::new();
        let threat = make_threat(Severity::Medium, ThreatCategory::HookDetected);

        let s_none = scorer.score_threat(&threat, 0.5, 0, 0);
        let s_some = scorer.score_threat(&threat, 0.5, 3, 0);

        assert!(s_some.final_score > s_none.final_score);
    }

    #[test]
    fn test_rule_match_increases_score() {
        let scorer = ThreatScorer::new();
        let threat = make_threat(Severity::Medium, ThreatCategory::HookDetected);

        let s_none = scorer.score_threat(&threat, 0.5, 0, 0);
        let s_some = scorer.score_threat(&threat, 0.5, 0, 2);

        assert!(s_some.final_score > s_none.final_score);
    }

    #[test]
    fn test_high_confidence() {
        let scorer = ThreatScorer::new();
        let threat = make_threat(Severity::Critical, ThreatCategory::HookDetected);
        let score = scorer.score_threat(&threat, 1.0, 4, 3);

        assert!(scorer.is_high_confidence(&score));
    }

    #[test]
    fn test_low_confidence() {
        let scorer = ThreatScorer::new();
        let threat = make_threat(Severity::Info, ThreatCategory::HookDetected);
        let score = scorer.score_threat(&threat, 0.0, 0, 0);

        assert!(!scorer.is_high_confidence(&score));
    }

    #[test]
    fn test_batch_scoring() {
        let scorer = ThreatScorer::new();
        let threats = vec![
            make_threat(Severity::High, ThreatCategory::HookDetected),
            make_threat(Severity::Low, ThreatCategory::HiddenProcess),
        ];

        let scores = scorer.score_threats(&threats, &[0.9, 0.3], &[2, 0], &[1, 0]);

        assert_eq!(scores.len(), 2);
        assert!(scores[0].final_score > scores[1].final_score);
    }
}
