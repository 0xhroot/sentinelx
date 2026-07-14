use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum EvidenceError {
    #[error("Evidence storage error: {0}")]
    StorageError(String),
    #[error("Evidence validation error: {0}")]
    ValidationError(String),
    #[error("Evidence serialization error: {0}")]
    SerializationError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EvidenceType {
    FileIntegrity,
    ProcessIntegrity,
    NetworkIntegrity,
    KernelIntegrity,
    MemoryIntegrity,
    ModuleIntegrity,
    PersistenceIntegrity,
    SystemIntegrity,
    UserActivity,
    SecurityEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_common(severity: &str) -> Self {
        match severity {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub evidence_type: EvidenceType,
    pub severity: Severity,
    pub source: String,
    pub description: String,
    pub data: HashMap<String, serde_json::Value>,
    pub tags: Vec<String>,
    pub confidence: f64,
    pub related_evidence: Vec<Uuid>,
}

impl Evidence {
    pub fn new(
        evidence_type: EvidenceType,
        severity: Severity,
        source: String,
        description: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            evidence_type,
            severity,
            source,
            description,
            data: HashMap::new(),
            tags: Vec::new(),
            confidence: 1.0,
            related_evidence: Vec::new(),
        }
    }

    pub fn with_data(mut self, key: String, value: serde_json::Value) -> Self {
        self.data.insert(key, value);
        self
    }

    pub fn with_tag(mut self, tag: String) -> Self {
        self.tags.push(tag);
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_related_evidence(mut self, evidence_id: Uuid) -> Self {
        self.related_evidence.push(evidence_id);
        self
    }
}

#[async_trait]
pub trait EvidenceCollector: Send + Sync {
    async fn collect_evidence(&self) -> Result<Vec<Evidence>, EvidenceError>;
    fn get_evidence_type(&self) -> EvidenceType;
    fn get_source(&self) -> String;
}

#[derive(Debug, Clone)]
pub struct EvidenceStore {
    pub evidence: Vec<Evidence>,
    by_type: HashMap<EvidenceType, Vec<usize>>,
    by_severity: HashMap<Severity, Vec<usize>>,
    by_source: HashMap<String, Vec<usize>>,
    by_tag: HashMap<String, Vec<usize>>,
}

impl Serialize for EvidenceStore {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.evidence.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EvidenceStore {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let evidence = Vec::<Evidence>::deserialize(deserializer)?;
        let mut store = Self {
            evidence,
            by_type: HashMap::new(),
            by_severity: HashMap::new(),
            by_source: HashMap::new(),
            by_tag: HashMap::new(),
        };
        store.rebuild_indices();
        Ok(store)
    }
}

impl EvidenceStore {
    pub fn new() -> Self {
        Self {
            evidence: Vec::new(),
            by_type: HashMap::new(),
            by_severity: HashMap::new(),
            by_source: HashMap::new(),
            by_tag: HashMap::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            evidence: Vec::with_capacity(capacity),
            by_type: HashMap::new(),
            by_severity: HashMap::new(),
            by_source: HashMap::new(),
            by_tag: HashMap::new(),
        }
    }

    fn rebuild_indices(&mut self) {
        self.by_type.clear();
        self.by_severity.clear();
        self.by_source.clear();
        self.by_tag.clear();
        for (idx, ev) in self.evidence.iter().enumerate() {
            self.by_type
                .entry(ev.evidence_type.clone())
                .or_default()
                .push(idx);
            self.by_severity
                .entry(ev.severity.clone())
                .or_default()
                .push(idx);
            self.by_source
                .entry(ev.source.clone())
                .or_default()
                .push(idx);
            for tag in &ev.tags {
                self.by_tag.entry(tag.clone()).or_default().push(idx);
            }
        }
    }

    fn add_to_indices(&mut self, idx: usize, evidence: &Evidence) {
        self.by_type
            .entry(evidence.evidence_type.clone())
            .or_default()
            .push(idx);
        self.by_severity
            .entry(evidence.severity.clone())
            .or_default()
            .push(idx);
        self.by_source
            .entry(evidence.source.clone())
            .or_default()
            .push(idx);
        for tag in &evidence.tags {
            self.by_tag.entry(tag.clone()).or_default().push(idx);
        }
    }

    pub fn add_evidence(&mut self, evidence: Evidence) {
        let idx = self.evidence.len();
        self.add_to_indices(idx, &evidence);
        self.evidence.push(evidence);
    }

    pub fn add_batch(&mut self, items: Vec<Evidence>) {
        for evidence in items {
            let idx = self.evidence.len();
            self.add_to_indices(idx, &evidence);
            self.evidence.push(evidence);
        }
    }

    pub fn get_evidence_by_type(&self, evidence_type: &EvidenceType) -> Vec<&Evidence> {
        self.by_type
            .get(evidence_type)
            .map(|indices| indices.iter().map(|&i| &self.evidence[i]).collect())
            .unwrap_or_default()
    }

    pub fn get_evidence_by_severity(&self, severity: &Severity) -> Vec<&Evidence> {
        self.by_severity
            .get(severity)
            .map(|indices| indices.iter().map(|&i| &self.evidence[i]).collect())
            .unwrap_or_default()
    }

    pub fn get_evidence_by_source(&self, source: &str) -> Vec<&Evidence> {
        self.by_source
            .get(source)
            .map(|indices| indices.iter().map(|&i| &self.evidence[i]).collect())
            .unwrap_or_default()
    }

    pub fn get_evidence_by_tag(&self, tag: &str) -> Vec<&Evidence> {
        self.by_tag
            .get(tag)
            .map(|indices| indices.iter().map(|&i| &self.evidence[i]).collect())
            .unwrap_or_default()
    }

    pub fn get_high_confidence_evidence(&self, threshold: f64) -> Vec<&Evidence> {
        self.evidence
            .iter()
            .filter(|e| e.confidence >= threshold)
            .collect()
    }

    pub fn get_related_evidence(&self, evidence_id: Uuid) -> Vec<&Evidence> {
        self.evidence
            .iter()
            .filter(|e| e.related_evidence.contains(&evidence_id))
            .collect()
    }

    pub fn unique_sources(&self) -> HashSet<&str> {
        self.by_source.keys().map(|s| s.as_str()).collect()
    }

    pub fn unique_tags(&self) -> HashSet<&str> {
        self.by_tag.keys().map(|s| s.as_str()).collect()
    }

    pub fn clear(&mut self) {
        self.evidence.clear();
        self.by_type.clear();
        self.by_severity.clear();
        self.by_source.clear();
        self.by_tag.clear();
    }

    pub fn len(&self) -> usize {
        self.evidence.len()
    }

    pub fn is_empty(&self) -> bool {
        self.evidence.is_empty()
    }
}

impl Default for EvidenceStore {
    fn default() -> Self {
        Self::new()
    }
}
