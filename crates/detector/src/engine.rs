use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

use sentinelx_common::event::{Event, EventKind, EventSource};
use sentinelx_common::types::ThreatEvent;
use sentinelx_config::Settings;
use sentinelx_correlation::{CorrelationEngine, CorrelationResult, CorrelationStats};
use sentinelx_database::repository::EvidenceRepository;
use sentinelx_database::Store;
use sentinelx_evidence::{Evidence, EvidenceStore};
use sentinelx_rule_engine::{RuleEngine, RuleMatch};
use sentinelx_telemetry::MetricsCollector;

use crate::event_bus::EventBus;
use crate::registry::DetectorRegistry;
use crate::scoring::{ThreatScore, ThreatScorer};
use crate::trust::TrustEngine;

pub struct DetectionEngine {
    registry: Arc<DetectorRegistry>,
    event_bus: EventBus,
    store: Arc<Store>,
    metrics: MetricsCollector,
    settings: Settings,
    running: Arc<RwLock<bool>>,
    evidence_store: Arc<RwLock<EvidenceStore>>,
    rule_engine: Arc<RwLock<RuleEngine>>,
    correlation_engine: Arc<RwLock<CorrelationEngine>>,
    scorer: ThreatScorer,
    trust_engine: Arc<RwLock<TrustEngine>>,
}

impl DetectionEngine {
    pub fn new(settings: Settings, store: Arc<Store>, metrics: MetricsCollector) -> Self {
        Self {
            registry: Arc::new(DetectorRegistry::new()),
            event_bus: EventBus::new(),
            store,
            metrics,
            settings,
            running: Arc::new(RwLock::new(false)),
            evidence_store: Arc::new(RwLock::new(EvidenceStore::new())),
            rule_engine: Arc::new(RwLock::new(RuleEngine::new())),
            correlation_engine: Arc::new(RwLock::new(CorrelationEngine::new())),
            scorer: ThreatScorer::new(),
            trust_engine: Arc::new(RwLock::new(TrustEngine::new())),
        }
    }

    pub fn registry(&self) -> &Arc<DetectorRegistry> {
        &self.registry
    }

    pub fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    pub fn evidence_store(&self) -> &Arc<RwLock<EvidenceStore>> {
        &self.evidence_store
    }

    pub fn rule_engine(&self) -> &Arc<RwLock<RuleEngine>> {
        &self.rule_engine
    }

    pub fn correlation_engine(&self) -> &Arc<RwLock<CorrelationEngine>> {
        &self.correlation_engine
    }

    pub fn trust_engine(&self) -> &Arc<RwLock<TrustEngine>> {
        &self.trust_engine
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    pub async fn start(&self) {
        {
            let mut running = self.running.write().await;
            *running = true;
        }

        let count = self.registry.count().await;
        self.metrics.set_active_detectors(count as u32);

        info!(
            detector_count = count,
            scan_interval = self.settings.general.scan_interval_seconds,
            "Detection engine starting"
        );

        let event = Event::new(
            EventKind::SystemStartup,
            EventSource::System,
            serde_json::json!({
                "detectors": count,
                "scan_interval": self.settings.general.scan_interval_seconds,
            }),
        );
        let _ = self.event_bus.publish(event).await;
    }

    pub async fn run_scan(&self) -> Vec<ThreatEvent> {
        info!("Starting detection scan");
        let threats = self.registry.run_all().await;

        for threat in &threats {
            self.metrics.record_threat();

            if let Err(e) = self
                .event_bus
                .publish(
                    Event::new(
                        EventKind::ThreatDetected,
                        EventSource::CorrelationEngine,
                        serde_json::to_value(threat).unwrap_or_default(),
                    )
                    .with_severity(threat.severity),
                )
                .await
            {
                error!("Failed to publish threat event: {}", e);
            }
        }

        self.metrics.record_scan();
        info!(threats_found = threats.len(), "Detection scan completed");
        threats
    }

    pub async fn run_evidence_collection(&self) {
        info!("Starting evidence collection");
        let evidence_collectors = self.registry.evidence_collectors().await;
        let mut evidence_store = self.evidence_store.write().await;

        for collector in &evidence_collectors {
            match collector.collect_evidence().await {
                Ok(evidence_items) => {
                    for evidence in evidence_items {
                        evidence_store.add_evidence(evidence);
                    }
                }
                Err(e) => {
                    error!("Failed to collect evidence: {}", e);
                }
            }
        }

        let evidence_count = evidence_store.len();
        let evidence_items: Vec<Evidence> = evidence_store.evidence.drain(..).collect();

        drop(evidence_store);

        let repo = EvidenceRepository::new(&self.store);
        if let Err(e) = repo.insert_batch(&evidence_items).await {
            error!("Failed to persist evidence to database: {}", e);
        }

        info!(
            evidence_count,
            "Evidence collection completed and persisted"
        );
    }

    pub async fn run_scan_with_evidence(&self) -> (Vec<ThreatEvent>, Vec<Evidence>) {
        let threats = self.run_scan().await;
        self.run_evidence_collection().await;

        let evidence_store = self.evidence_store.read().await;
        let evidence = evidence_store.evidence.clone();

        (threats, evidence)
    }

    pub async fn run_rule_engine(&self, threats: &[ThreatEvent]) -> Vec<RuleMatch> {
        let rule_engine = self.rule_engine.read().await;
        let mut all_matches = Vec::new();

        for threat in threats {
            let mut context = std::collections::HashMap::new();
            context.insert(
                "severity".to_string(),
                serde_json::Value::String(threat.severity.as_str().to_string()),
            );
            context.insert(
                "category".to_string(),
                serde_json::Value::String(threat.category.as_str().to_string()),
            );
            context.insert(
                "title".to_string(),
                serde_json::Value::String(threat.title.clone()),
            );
            context.insert(
                "source_detector".to_string(),
                serde_json::Value::String(threat.source_detector.clone()),
            );

            let matches = rule_engine.evaluate(&context).await;
            all_matches.extend(matches);
        }

        all_matches
    }

    pub async fn run_correlation(
        &self,
        threats: &[ThreatEvent],
        evidence: &[Evidence],
    ) -> Vec<CorrelationResult> {
        let mut correlation_engine = self.correlation_engine.write().await;
        correlation_engine.clear();
        correlation_engine.add_events(threats.to_vec());
        correlation_engine.add_evidence_items(evidence.to_vec());
        correlation_engine.correlate()
    }

    pub async fn correlation_stats(&self) -> CorrelationStats {
        let correlation_engine = self.correlation_engine.read().await;
        correlation_engine.stats()
    }

    pub async fn run_scoring(
        &self,
        threats: &[ThreatEvent],
        evidence: &[Evidence],
    ) -> Vec<ThreatScore> {
        let rule_engine = self.rule_engine.read().await;
        let correlation_engine = self.correlation_engine.read().await;

        let corr_stats = correlation_engine.stats();
        let total_correlations: usize = corr_stats.by_rule.values().copied().sum();
        let correlation_counts: Vec<usize> = vec![total_correlations; threats.len()];

        let mut rule_match_counts = Vec::with_capacity(threats.len());
        let mut context = std::collections::HashMap::with_capacity(4);
        for threat in threats {
            context.clear();
            context.insert(
                "severity".to_string(),
                serde_json::Value::String(threat.severity.as_str().to_string()),
            );
            context.insert(
                "category".to_string(),
                serde_json::Value::String(threat.category.as_str().to_string()),
            );
            let matches = rule_engine.evaluate(&context).await;
            rule_match_counts.push(matches.len());
        }

        let avg_confidence = if evidence.is_empty() {
            0.0
        } else {
            evidence.iter().map(|e| e.confidence).sum::<f64>() / evidence.len() as f64
        };
        let evidence_confidences = vec![avg_confidence; threats.len()];

        drop(rule_engine);
        drop(correlation_engine);

        self.scorer.score_threats(
            threats,
            &evidence_confidences,
            &correlation_counts,
            &rule_match_counts,
        )
    }

    pub async fn run_continuous(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let settings = this.settings.clone();

        tokio::spawn(async move {
            let mut scan_interval =
                interval(Duration::from_secs(settings.general.scan_interval_seconds));

            loop {
                scan_interval.tick().await;

                {
                    let is_running = this.running.read().await;
                    if !*is_running {
                        break;
                    }
                }

                let threats = this.registry.run_all().await;
                if !threats.is_empty() {
                    warn!(count = threats.len(), "Threats detected in continuous scan");
                }

                this.run_evidence_collection().await;
            }
        });
    }

    pub async fn stop(&self) {
        {
            let mut running = self.running.write().await;
            *running = false;
        }
        info!("Detection engine stopping");

        let event = Event::new(
            EventKind::SystemShutdown,
            EventSource::System,
            serde_json::json!({}),
        );
        let _ = self.event_bus.publish(event).await;
    }
}
