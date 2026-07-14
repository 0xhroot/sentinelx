use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

use sentinelx_common::traits::Detector;
use sentinelx_common::types::ThreatEvent;
use sentinelx_evidence::EvidenceCollector;

type DetectorMap = Arc<RwLock<HashMap<String, Arc<Box<dyn Detector>>>>>;
type EvidenceCollectorMap = Arc<RwLock<HashMap<String, Arc<Box<dyn EvidenceCollector>>>>>;

pub struct DetectorRegistry {
    detectors: DetectorMap,
    evidence_collectors: EvidenceCollectorMap,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            detectors: Arc::new(RwLock::new(HashMap::new())),
            evidence_collectors: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, detector: Box<dyn Detector>) {
        let name = detector.name().to_string();
        info!(detector = %name, "Registering detector");
        let mut detectors = self.detectors.write().await;
        detectors.insert(name, Arc::new(detector));
    }

    pub async fn register_evidence_collector(
        &self,
        name: String,
        collector: Box<dyn EvidenceCollector>,
    ) {
        info!(collector = %name, "Registering evidence collector");
        let mut collectors = self.evidence_collectors.write().await;
        collectors.insert(name, Arc::new(collector));
    }

    pub async fn run_all(&self) -> Vec<ThreatEvent> {
        let detectors = self.detectors.read().await;
        let mut all_threats = Vec::new();

        for (name, detector) in detectors.iter() {
            match detector.detect().await {
                Ok(threats) => {
                    info!(
                        detector = %name,
                        threats_found = threats.len(),
                        "Detector completed"
                    );
                    all_threats.extend(threats);
                }
                Err(e) => {
                    error!(
                        detector = %name,
                        error = %e,
                        "Detector failed"
                    );
                }
            }
        }

        all_threats
    }

    pub async fn run_detector(&self, name: &str) -> Result<Vec<ThreatEvent>, DetectorError> {
        let detectors = self.detectors.read().await;
        let detector = detectors
            .get(name)
            .ok_or_else(|| DetectorError::NotFound(name.to_string()))?;

        detector
            .detect()
            .await
            .map_err(|e| DetectorError::DetectionFailed(e.to_string()))
    }

    pub async fn evidence_collectors(&self) -> Vec<Arc<Box<dyn EvidenceCollector>>> {
        let collectors = self.evidence_collectors.read().await;
        collectors.values().cloned().collect()
    }

    pub async fn list_detectors(&self) -> Vec<DetectorInfo> {
        let detectors = self.detectors.read().await;
        detectors
            .iter()
            .map(|(name, d)| DetectorInfo {
                name: name.clone(),
                description: d.description().to_string(),
                category: format!("{:?}", d.category()),
                severity: d.severity().to_string(),
            })
            .collect()
    }

    pub async fn count(&self) -> usize {
        self.detectors.read().await.len()
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectorInfo {
    pub name: String,
    pub description: String,
    pub category: String,
    pub severity: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DetectorError {
    #[error("Detector not found: {0}")]
    NotFound(String),

    #[error("Detection failed: {0}")]
    DetectionFailed(String),

    #[error("Initialization failed: {0}")]
    InitFailed(String),
}
