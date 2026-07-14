use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceTrust {
    pub source_name: String,
    pub trust_score: f64,
    pub total_detections: u64,
    pub confirmed_positives: u64,
    pub false_positives: u64,
    pub total_events: u64,
    pub last_updated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvent {
    pub source_name: String,
    pub event_type: TrustEventType,
    pub details: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustEventType {
    ConfirmedPositive,
    FalsePositive,
    TrueNegative,
    FalseNegative,
    ManualAdjustment,
}

pub struct TrustEngine {
    sources: HashMap<String, SourceTrust>,
    history: Vec<TrustEvent>,
    prior_belief: f64,
    prior_weight: f64,
}

impl TrustEngine {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            history: Vec::new(),
            prior_belief: 0.5,
            prior_weight: 2.0,
        }
    }

    pub fn with_prior(prior_belief: f64, prior_weight: f64) -> Self {
        Self {
            sources: HashMap::new(),
            history: Vec::new(),
            prior_belief,
            prior_weight,
        }
    }

    pub fn register_source(&mut self, name: &str) {
        use std::collections::hash_map::Entry;
        if let Entry::Vacant(e) = self.sources.entry(name.to_string()) {
            e.insert(SourceTrust {
                source_name: name.to_string(),
                trust_score: self.prior_belief,
                total_detections: 0,
                confirmed_positives: 0,
                false_positives: 0,
                total_events: 0,
                last_updated: None,
            });
        }
    }

    pub fn record_confirmed_positive(&mut self, source: &str) {
        self.register_source(source);
        let prior_belief = self.prior_belief;
        let prior_weight = self.prior_weight;
        let (confirmed, false_pos) = {
            if let Some(s) = self.sources.get_mut(source) {
                s.total_detections += 1;
                s.confirmed_positives += 1;
                s.total_events += 1;
                s.last_updated = Some(chrono::Utc::now().to_rfc3339());
                (s.confirmed_positives, s.false_positives)
            } else {
                return;
            }
        };
        let alpha = prior_weight * prior_belief;
        let beta = prior_weight * (1.0 - prior_belief);
        let new_score = ((alpha + confirmed as f64)
            / (alpha + beta + confirmed as f64 + false_pos as f64)
            * 1000.0)
            .round()
            / 1000.0;
        if let Some(s) = self.sources.get_mut(source) {
            s.trust_score = new_score;
        }
        self.history.push(TrustEvent {
            source_name: source.to_string(),
            event_type: TrustEventType::ConfirmedPositive,
            details: "Detection confirmed as true positive".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    pub fn record_false_positive(&mut self, source: &str) {
        self.register_source(source);
        let prior_belief = self.prior_belief;
        let prior_weight = self.prior_weight;
        let (confirmed, false_pos) = {
            if let Some(s) = self.sources.get_mut(source) {
                s.total_detections += 1;
                s.false_positives += 1;
                s.total_events += 1;
                s.last_updated = Some(chrono::Utc::now().to_rfc3339());
                (s.confirmed_positives, s.false_positives)
            } else {
                return;
            }
        };
        let alpha = prior_weight * prior_belief;
        let beta = prior_weight * (1.0 - prior_belief);
        let new_score = ((alpha + confirmed as f64)
            / (alpha + beta + confirmed as f64 + false_pos as f64)
            * 1000.0)
            .round()
            / 1000.0;
        if let Some(s) = self.sources.get_mut(source) {
            s.trust_score = new_score;
        }
        self.history.push(TrustEvent {
            source_name: source.to_string(),
            event_type: TrustEventType::FalsePositive,
            details: "Detection reported as false positive".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    pub fn record_true_negative(&mut self, source: &str) {
        self.register_source(source);
        if let Some(s) = self.sources.get_mut(source) {
            s.total_events += 1;
            s.last_updated = Some(chrono::Utc::now().to_rfc3339());
        }
        self.history.push(TrustEvent {
            source_name: source.to_string(),
            event_type: TrustEventType::TrueNegative,
            details: "Correctly reported no threat".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    pub fn adjust_trust(&mut self, source: &str, adjustment: f64, reason: &str) {
        self.register_source(source);
        if let Some(s) = self.sources.get_mut(source) {
            s.trust_score = (s.trust_score + adjustment).clamp(0.0, 1.0);
            s.last_updated = Some(chrono::Utc::now().to_rfc3339());
        }
        self.history.push(TrustEvent {
            source_name: source.to_string(),
            event_type: TrustEventType::ManualAdjustment,
            details: reason.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    pub fn get_trust(&self, source: &str) -> f64 {
        self.sources
            .get(source)
            .map(|s| s.trust_score)
            .unwrap_or(self.prior_belief)
    }

    pub fn get_source(&self, source: &str) -> Option<&SourceTrust> {
        self.sources.get(source)
    }

    pub fn all_sources(&self) -> Vec<&SourceTrust> {
        self.sources.values().collect()
    }

    pub fn history(&self) -> &[TrustEvent] {
        &self.history
    }

    pub fn source_history(&self, source: &str) -> Vec<&TrustEvent> {
        self.history
            .iter()
            .filter(|e| e.source_name == source)
            .collect()
    }
}

impl Default for TrustEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_trust_engine() {
        let engine = TrustEngine::new();
        assert!(engine.sources.is_empty());
        assert_eq!(engine.get_trust("unknown"), 0.5);
    }

    #[test]
    fn test_register_source() {
        let mut engine = TrustEngine::new();
        engine.register_source("kernel_detector");
        assert!(engine.sources.contains_key("kernel_detector"));
        assert_eq!(engine.get_trust("kernel_detector"), 0.5);
    }

    #[test]
    fn test_confirmed_positive_increases_trust() {
        let mut engine = TrustEngine::new();
        let initial = engine.get_trust("test");
        engine.record_confirmed_positive("test");
        assert!(engine.get_trust("test") > initial);
    }

    #[test]
    fn test_false_positive_decreases_trust() {
        let mut engine = TrustEngine::new();
        let initial = engine.get_trust("test");
        engine.record_false_positive("test");
        assert!(engine.get_trust("test") < initial);
    }

    #[test]
    fn test_mixed_results() {
        let mut engine = TrustEngine::new();

        for _ in 0..9 {
            engine.record_confirmed_positive("detector_a");
        }
        for _ in 0..1 {
            engine.record_false_positive("detector_a");
        }

        assert!(engine.get_trust("detector_a") > 0.7);
    }

    #[test]
    fn test_manual_adjustment() {
        let mut engine = TrustEngine::new();
        engine.adjust_trust("test", 0.2, "manual override");
        assert!((engine.get_trust("test") - 0.7).abs() < 0.01);
    }

    #[test]
    fn test_trust_clamped() {
        let mut engine = TrustEngine::new();
        engine.adjust_trust("test", 10.0, "way too high");
        assert_eq!(engine.get_trust("test"), 1.0);

        engine.adjust_trust("test", -20.0, "way too low");
        assert_eq!(engine.get_trust("test"), 0.0);
    }

    #[test]
    fn test_source_info() {
        let mut engine = TrustEngine::new();
        engine.record_confirmed_positive("det");
        engine.record_confirmed_positive("det");
        engine.record_false_positive("det");

        let source = engine.get_source("det").unwrap();
        assert_eq!(source.total_detections, 3);
        assert_eq!(source.confirmed_positives, 2);
        assert_eq!(source.false_positives, 1);
    }

    #[test]
    fn test_history() {
        let mut engine = TrustEngine::new();
        engine.record_confirmed_positive("a");
        engine.record_false_positive("b");
        engine.record_confirmed_positive("a");

        assert_eq!(engine.history().len(), 3);
        assert_eq!(engine.source_history("a").len(), 2);
        assert_eq!(engine.source_history("b").len(), 1);
    }

    #[test]
    fn test_custom_prior() {
        let mut engine = TrustEngine::with_prior(0.8, 10.0);
        assert_eq!(engine.get_trust("new_source"), 0.8);

        engine.record_confirmed_positive("new_source");
        assert!(engine.get_trust("new_source") > 0.8);
    }

    #[test]
    fn test_all_sources() {
        let mut engine = TrustEngine::new();
        engine.register_source("a");
        engine.register_source("b");
        assert_eq!(engine.all_sources().len(), 2);
    }
}
