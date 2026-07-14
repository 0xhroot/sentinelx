use sqlx::Row;

use serde::Serialize;

use crate::error::{DatabaseError, Result};
use crate::store::Store;
use sentinelx_common::event::Event;
use sentinelx_common::severity::Severity;
use sentinelx_common::types::ThreatEvent;
use sentinelx_evidence::Evidence;

#[derive(Debug, Clone, Serialize)]
pub struct EventRow {
    pub id: String,
    pub timestamp: String,
    pub kind: String,
    pub source: String,
    pub severity: String,
    pub data: String,
}

#[derive(Debug, Clone)]
pub struct ThreatRow {
    pub id: String,
    pub timestamp: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub mitre_attack: String,
    pub source_detector: String,
    pub acknowledged: bool,
}

pub struct EventRepository<'a> {
    store: &'a Store,
}

impl<'a> EventRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, event: &Event) -> Result<()> {
        let data = serde_json::to_string(&event.data)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO events (id, timestamp, kind, source, severity, data) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(event.id.to_string())
        .bind(event.timestamp.to_rfc3339())
        .bind(format!("{:?}", event.kind))
        .bind(format!("{:?}", event.source))
        .bind(event.severity.as_str())
        .bind(data)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_severity(&self, severity: &Severity, limit: u32) -> Result<Vec<EventRow>> {
        let rows = sqlx::query(
            "SELECT id, timestamp, kind, source, severity, data FROM events WHERE severity = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(severity.as_str())
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| EventRow {
                id: r.get("id"),
                timestamp: r.get("timestamp"),
                kind: r.get("kind"),
                source: r.get("source"),
                severity: r.get("severity"),
                data: r.get("data"),
            })
            .collect())
    }

    pub async fn find_all(&self, limit: u32) -> Result<Vec<EventRow>> {
        let rows = sqlx::query(
            "SELECT id, timestamp, kind, source, severity, data FROM events ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| EventRow {
                id: r.get("id"),
                timestamp: r.get("timestamp"),
                kind: r.get("kind"),
                source: r.get("source"),
                severity: r.get("severity"),
                data: r.get("data"),
            })
            .collect())
    }

    pub async fn count_by_severity(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity ORDER BY cnt DESC",
        )
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.get("severity"), r.get("cnt")))
            .collect())
    }

    pub async fn cleanup_old(&self, retention_days: u32) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM events WHERE timestamp < datetime('now', '-' || ? || ' days')",
        )
        .bind(retention_days)
        .execute(self.store.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

pub struct ThreatRepository<'a> {
    store: &'a Store,
}

impl<'a> ThreatRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, threat: &ThreatEvent) -> Result<()> {
        let evidence = serde_json::to_string(&threat.evidence)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let mitre = serde_json::to_string(&threat.mitre_attack)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let tags = serde_json::to_string(&threat.tags)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        sqlx::query(
            r#"INSERT INTO threat_events
            (id, timestamp, severity, category, title, description, evidence, mitre_attack, source_detector, process_name, hash, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(threat.id.to_string())
        .bind(threat.timestamp.to_rfc3339())
        .bind(threat.severity.as_str())
        .bind(threat.category.as_str())
        .bind(&threat.title)
        .bind(&threat.description)
        .bind(evidence)
        .bind(mitre)
        .bind(&threat.source_detector)
        .bind(threat.process.as_ref().map(|p| &p.name))
        .bind(threat.hash.as_ref().map(|h| h.as_hex().to_string()))
        .bind(tags)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    fn severity_filter_clause(min_severity: &Severity) -> &'static str {
        match min_severity {
            Severity::Critical => "AND severity = 'critical'",
            Severity::High => "AND severity IN ('critical', 'high')",
            Severity::Medium => "AND severity IN ('critical', 'high', 'medium')",
            Severity::Low => "AND severity IN ('critical', 'high', 'medium', 'low')",
            Severity::Info => "",
        }
    }

    pub async fn find_unacknowledged(
        &self,
        min_severity: &Severity,
        limit: u32,
    ) -> Result<Vec<ThreatRow>> {
        let clause = Self::severity_filter_clause(min_severity);
        let query = format!(
            r#"SELECT id, timestamp, severity, category, title, description, evidence, mitre_attack, source_detector, acknowledged
            FROM threat_events
            WHERE acknowledged = 0 {}
            ORDER BY timestamp DESC LIMIT ?"#,
            clause
        );

        let rows = sqlx::query(&query)
            .bind(limit)
            .fetch_all(self.store.pool())
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| ThreatRow {
                id: r.get("id"),
                timestamp: r.get("timestamp"),
                severity: r.get("severity"),
                category: r.get("category"),
                title: r.get("title"),
                description: r.get("description"),
                evidence: r.get("evidence"),
                mitre_attack: r.get("mitre_attack"),
                source_detector: r.get("source_detector"),
                acknowledged: r.get::<i64, _>("acknowledged") != 0,
            })
            .collect())
    }

    pub async fn find_all(&self, min_severity: &Severity, limit: u32) -> Result<Vec<ThreatRow>> {
        let clause = Self::severity_filter_clause(min_severity);
        let query = format!(
            r#"SELECT id, timestamp, severity, category, title, description, evidence, mitre_attack, source_detector, acknowledged
            FROM threat_events
            WHERE 1=1 {}
            ORDER BY timestamp DESC LIMIT ?"#,
            clause
        );

        let rows = sqlx::query(&query)
            .bind(limit)
            .fetch_all(self.store.pool())
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| ThreatRow {
                id: r.get("id"),
                timestamp: r.get("timestamp"),
                severity: r.get("severity"),
                category: r.get("category"),
                title: r.get("title"),
                description: r.get("description"),
                evidence: r.get("evidence"),
                mitre_attack: r.get("mitre_attack"),
                source_detector: r.get("source_detector"),
                acknowledged: r.get::<i64, _>("acknowledged") != 0,
            })
            .collect())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<ThreatRow>> {
        let row = sqlx::query(
            r#"SELECT id, timestamp, severity, category, title, description, evidence, mitre_attack, source_detector, acknowledged
            FROM threat_events
            WHERE id = ?"#,
        )
        .bind(id)
        .fetch_optional(self.store.pool())
        .await?;

        Ok(row.map(|r| ThreatRow {
            id: r.get("id"),
            timestamp: r.get("timestamp"),
            severity: r.get("severity"),
            category: r.get("category"),
            title: r.get("title"),
            description: r.get("description"),
            evidence: r.get("evidence"),
            mitre_attack: r.get("mitre_attack"),
            source_detector: r.get("source_detector"),
            acknowledged: r.get::<i64, _>("acknowledged") != 0,
        }))
    }

    pub async fn acknowledge(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("UPDATE threat_events SET acknowledged = 1 WHERE id = ?")
            .bind(id)
            .execute(self.store.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn resolve(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("UPDATE threat_events SET acknowledged = 1 WHERE id = ?")
            .bind(id)
            .execute(self.store.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn count_by_category(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT category, COUNT(*) as cnt FROM threat_events GROUP BY category ORDER BY cnt DESC",
        )
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.get("category"), r.get("cnt")))
            .collect())
    }

    pub async fn stats(&self) -> Result<ThreatStats> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM threat_events")
            .fetch_one(self.store.pool())
            .await?;

        let unacknowledged: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM threat_events WHERE acknowledged = 0")
                .fetch_one(self.store.pool())
                .await?;

        let critical: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM threat_events WHERE severity = 'critical' AND acknowledged = 0",
        )
        .fetch_one(self.store.pool())
        .await?;

        let high: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM threat_events WHERE severity = 'high' AND acknowledged = 0",
        )
        .fetch_one(self.store.pool())
        .await?;

        Ok(ThreatStats {
            total: total.0,
            unacknowledged: unacknowledged.0,
            critical: critical.0,
            high: high.0,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ThreatStats {
    pub total: i64,
    pub unacknowledged: i64,
    pub critical: i64,
    pub high: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceRow {
    pub id: String,
    pub timestamp: String,
    pub evidence_type: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub data: String,
    pub tags: String,
    pub confidence: f64,
    pub related_evidence: String,
}

pub struct EvidenceRepository<'a> {
    store: &'a Store,
}

impl<'a> EvidenceRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, evidence: &Evidence) -> Result<()> {
        let data = serde_json::to_string(&evidence.data)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let tags = serde_json::to_string(&evidence.tags)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let related = serde_json::to_string(&evidence.related_evidence)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        sqlx::query(
            r#"INSERT OR REPLACE INTO evidence
            (id, timestamp, evidence_type, severity, source, description, data, tags, confidence, related_evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(evidence.id.to_string())
        .bind(evidence.timestamp.to_rfc3339())
        .bind(format!("{:?}", evidence.evidence_type))
        .bind(evidence.severity.as_str())
        .bind(&evidence.source)
        .bind(&evidence.description)
        .bind(data)
        .bind(tags)
        .bind(evidence.confidence)
        .bind(related)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn insert_batch(&self, evidence_list: &[Evidence]) -> Result<u64> {
        let mut total_inserted = 0;
        for evidence in evidence_list {
            self.insert(evidence).await?;
            total_inserted += 1;
        }
        Ok(total_inserted)
    }

    pub async fn find_all(&self, limit: u32) -> Result<Vec<EvidenceRow>> {
        let rows = sqlx::query(
            "SELECT id, timestamp, evidence_type, severity, source, description, data, tags, confidence, related_evidence FROM evidence ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| EvidenceRow {
                id: r.get("id"),
                timestamp: r.get("timestamp"),
                evidence_type: r.get("evidence_type"),
                severity: r.get("severity"),
                source: r.get("source"),
                description: r.get("description"),
                data: r.get("data"),
                tags: r.get("tags"),
                confidence: r.get("confidence"),
                related_evidence: r.get("related_evidence"),
            })
            .collect())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<EvidenceRow>> {
        let row = sqlx::query(
            "SELECT id, timestamp, evidence_type, severity, source, description, data, tags, confidence, related_evidence FROM evidence WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.store.pool())
        .await?;

        Ok(row.map(|r| EvidenceRow {
            id: r.get("id"),
            timestamp: r.get("timestamp"),
            evidence_type: r.get("evidence_type"),
            severity: r.get("severity"),
            source: r.get("source"),
            description: r.get("description"),
            data: r.get("data"),
            tags: r.get("tags"),
            confidence: r.get("confidence"),
            related_evidence: r.get("related_evidence"),
        }))
    }

    pub async fn find_by_type(&self, evidence_type: &str, limit: u32) -> Result<Vec<EvidenceRow>> {
        let rows = sqlx::query(
            "SELECT id, timestamp, evidence_type, severity, source, description, data, tags, confidence, related_evidence FROM evidence WHERE evidence_type = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(evidence_type)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| EvidenceRow {
                id: r.get("id"),
                timestamp: r.get("timestamp"),
                evidence_type: r.get("evidence_type"),
                severity: r.get("severity"),
                source: r.get("source"),
                description: r.get("description"),
                data: r.get("data"),
                tags: r.get("tags"),
                confidence: r.get("confidence"),
                related_evidence: r.get("related_evidence"),
            })
            .collect())
    }

    pub async fn find_by_severity(&self, severity: &str, limit: u32) -> Result<Vec<EvidenceRow>> {
        let rows = sqlx::query(
            "SELECT id, timestamp, evidence_type, severity, source, description, data, tags, confidence, related_evidence FROM evidence WHERE severity = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(severity)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| EvidenceRow {
                id: r.get("id"),
                timestamp: r.get("timestamp"),
                evidence_type: r.get("evidence_type"),
                severity: r.get("severity"),
                source: r.get("source"),
                description: r.get("description"),
                data: r.get("data"),
                tags: r.get("tags"),
                confidence: r.get("confidence"),
                related_evidence: r.get("related_evidence"),
            })
            .collect())
    }

    pub async fn find_by_source(&self, source: &str, limit: u32) -> Result<Vec<EvidenceRow>> {
        let rows = sqlx::query(
            "SELECT id, timestamp, evidence_type, severity, source, description, data, tags, confidence, related_evidence FROM evidence WHERE source = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(source)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| EvidenceRow {
                id: r.get("id"),
                timestamp: r.get("timestamp"),
                evidence_type: r.get("evidence_type"),
                severity: r.get("severity"),
                source: r.get("source"),
                description: r.get("description"),
                data: r.get("data"),
                tags: r.get("tags"),
                confidence: r.get("confidence"),
                related_evidence: r.get("related_evidence"),
            })
            .collect())
    }

    pub async fn stats(&self) -> Result<EvidenceStats> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM evidence")
            .fetch_one(self.store.pool())
            .await?;

        let by_type = sqlx::query(
            "SELECT evidence_type, COUNT(*) as cnt FROM evidence GROUP BY evidence_type ORDER BY cnt DESC",
        )
        .fetch_all(self.store.pool())
        .await?
        .into_iter()
        .map(|r| (r.get::<String, _>("evidence_type"), r.get::<i64, _>("cnt")))
        .collect();

        let by_severity = sqlx::query(
            "SELECT severity, COUNT(*) as cnt FROM evidence GROUP BY severity ORDER BY cnt DESC",
        )
        .fetch_all(self.store.pool())
        .await?
        .into_iter()
        .map(|r| (r.get::<String, _>("severity"), r.get::<i64, _>("cnt")))
        .collect();

        let by_source = sqlx::query(
            "SELECT source, COUNT(*) as cnt FROM evidence GROUP BY source ORDER BY cnt DESC",
        )
        .fetch_all(self.store.pool())
        .await?
        .into_iter()
        .map(|r| (r.get::<String, _>("source"), r.get::<i64, _>("cnt")))
        .collect();

        Ok(EvidenceStats {
            total: total.0,
            by_type,
            by_severity,
            by_source,
        })
    }

    pub async fn cleanup_old(&self, retention_days: u32) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM evidence WHERE timestamp < datetime('now', '-' || ? || ' days')",
        )
        .bind(retention_days)
        .execute(self.store.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceStats {
    pub total: i64,
    pub by_type: Vec<(String, i64)>,
    pub by_severity: Vec<(String, i64)>,
    pub by_source: Vec<(String, i64)>,
}

#[derive(Debug, Clone)]
pub struct AssessmentRow {
    pub id: String,
    pub object_id: String,
    pub timestamp: String,
    pub trust: u32,
    pub integrity: u32,
    pub risk: u32,
    pub reputation: u32,
    pub confidence: f64,
    pub reasons: String,
    pub warnings: String,
    pub metadata_references: String,
    pub version: u32,
}

pub struct AssessmentRepository<'a> {
    store: &'a Store,
}

impl<'a> AssessmentRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, assessment: &sentinelx_assessment::ObjectAssessment) -> Result<()> {
        let reasons = serde_json::to_string(&assessment.reasons)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let warnings = serde_json::to_string(&assessment.warnings)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let metadata_references = serde_json::to_string(&assessment.metadata_references)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        sqlx::query(
            r#"INSERT OR REPLACE INTO assessment_results
            (id, object_id, timestamp, trust, integrity, risk, reputation, confidence, reasons, warnings, metadata_references, version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(assessment.id.to_string())
        .bind(&assessment.object_id)
        .bind(assessment.timestamp.to_rfc3339())
        .bind(assessment.trust)
        .bind(assessment.integrity)
        .bind(assessment.risk)
        .bind(assessment.reputation)
        .bind(assessment.confidence)
        .bind(reasons)
        .bind(warnings)
        .bind(metadata_references)
        .bind(assessment.version)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn insert_batch(
        &self,
        assessments: &[sentinelx_assessment::ObjectAssessment],
    ) -> Result<u64> {
        let mut total = 0;
        for assessment in assessments {
            self.insert(assessment).await?;
            total += 1;
        }
        Ok(total)
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<AssessmentRow>> {
        let row = sqlx::query(
            "SELECT id, object_id, timestamp, trust, integrity, risk, reputation, confidence, reasons, warnings, metadata_references, version FROM assessment_results WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.store.pool())
        .await?;

        Ok(row.map(|r| AssessmentRow {
            id: r.get("id"),
            object_id: r.get("object_id"),
            timestamp: r.get("timestamp"),
            trust: r.get::<i64, _>("trust") as u32,
            integrity: r.get::<i64, _>("integrity") as u32,
            risk: r.get::<i64, _>("risk") as u32,
            reputation: r.get::<i64, _>("reputation") as u32,
            confidence: r.get("confidence"),
            reasons: r.get("reasons"),
            warnings: r.get("warnings"),
            metadata_references: r.get("metadata_references"),
            version: r.get::<i64, _>("version") as u32,
        }))
    }

    pub async fn find_by_object_id(
        &self,
        object_id: &str,
        limit: u32,
    ) -> Result<Vec<AssessmentRow>> {
        let rows = sqlx::query(
            "SELECT id, object_id, timestamp, trust, integrity, risk, reputation, confidence, reasons, warnings, metadata_references, version FROM assessment_results WHERE object_id = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(object_id)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| AssessmentRow {
                id: r.get("id"),
                object_id: r.get("object_id"),
                timestamp: r.get("timestamp"),
                trust: r.get::<i64, _>("trust") as u32,
                integrity: r.get::<i64, _>("integrity") as u32,
                risk: r.get::<i64, _>("risk") as u32,
                reputation: r.get::<i64, _>("reputation") as u32,
                confidence: r.get("confidence"),
                reasons: r.get("reasons"),
                warnings: r.get("warnings"),
                metadata_references: r.get("metadata_references"),
                version: r.get::<i64, _>("version") as u32,
            })
            .collect())
    }

    pub async fn find_latest_by_object_id(&self, object_id: &str) -> Result<Option<AssessmentRow>> {
        let rows = self.find_by_object_id(object_id, 1).await?;
        Ok(rows.into_iter().next())
    }

    pub async fn find_all(&self, limit: u32) -> Result<Vec<AssessmentRow>> {
        let rows = sqlx::query(
            "SELECT id, object_id, timestamp, trust, integrity, risk, reputation, confidence, reasons, warnings, metadata_references, version FROM assessment_results ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| AssessmentRow {
                id: r.get("id"),
                object_id: r.get("object_id"),
                timestamp: r.get("timestamp"),
                trust: r.get::<i64, _>("trust") as u32,
                integrity: r.get::<i64, _>("integrity") as u32,
                risk: r.get::<i64, _>("risk") as u32,
                reputation: r.get::<i64, _>("reputation") as u32,
                confidence: r.get("confidence"),
                reasons: r.get("reasons"),
                warnings: r.get("warnings"),
                metadata_references: r.get("metadata_references"),
                version: r.get::<i64, _>("version") as u32,
            })
            .collect())
    }

    pub async fn find_high_risk(&self, min_risk: u32, limit: u32) -> Result<Vec<AssessmentRow>> {
        let rows = sqlx::query(
            "SELECT id, object_id, timestamp, trust, integrity, risk, reputation, confidence, reasons, warnings, metadata_references, version FROM assessment_results WHERE risk >= ? ORDER BY risk DESC, timestamp DESC LIMIT ?",
        )
        .bind(min_risk)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| AssessmentRow {
                id: r.get("id"),
                object_id: r.get("object_id"),
                timestamp: r.get("timestamp"),
                trust: r.get::<i64, _>("trust") as u32,
                integrity: r.get::<i64, _>("integrity") as u32,
                risk: r.get::<i64, _>("risk") as u32,
                reputation: r.get::<i64, _>("reputation") as u32,
                confidence: r.get("confidence"),
                reasons: r.get("reasons"),
                warnings: r.get("warnings"),
                metadata_references: r.get("metadata_references"),
                version: r.get::<i64, _>("version") as u32,
            })
            .collect())
    }

    pub async fn delete_old(&self, retention_days: u32) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM assessment_results WHERE timestamp < datetime('now', '-' || ? || ' days')",
        )
        .bind(retention_days)
        .execute(self.store.pool())
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM assessment_results")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IncidentRow {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub severity: String,
    pub confidence: f64,
    pub created_at: String,
    pub updated_at: String,
    pub evidence_ids: String,
    pub object_ids: String,
    pub attack_chain: String,
    pub mitre_mappings: String,
    pub recommended_response: Option<String>,
    pub tags: String,
}

pub struct IncidentRepository<'a> {
    store: &'a Store,
}

impl<'a> IncidentRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, incident: &sentinelx_incident::Incident) -> Result<()> {
        let evidence_ids = serde_json::to_string(&incident.evidence_ids)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let object_ids = serde_json::to_string(&incident.object_ids)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let attack_chain = serde_json::to_string(&incident.attack_chain)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let mitre_mappings = serde_json::to_string(&incident.mitre_mappings)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let tags = serde_json::to_string(&incident.tags)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let metadata = serde_json::to_string(&incident.metadata)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        sqlx::query(
            r#"INSERT OR REPLACE INTO incidents
            (id, title, description, status, severity, confidence, created_at, updated_at,
             evidence_ids, object_ids, attack_chain, mitre_mappings, recommended_response, tags, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(incident.id.to_string())
        .bind(&incident.title)
        .bind(&incident.description)
        .bind(incident.status.as_str())
        .bind(incident.severity.as_str())
        .bind(incident.confidence)
        .bind(incident.created_at.to_rfc3339())
        .bind(incident.updated_at.to_rfc3339())
        .bind(evidence_ids)
        .bind(object_ids)
        .bind(attack_chain)
        .bind(mitre_mappings)
        .bind(&incident.recommended_response)
        .bind(tags)
        .bind(metadata)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<IncidentRow>> {
        let row = sqlx::query(
            "SELECT id, title, description, status, severity, confidence, created_at, updated_at,
             evidence_ids, object_ids, attack_chain, mitre_mappings, recommended_response, tags
             FROM incidents WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.store.pool())
        .await?;

        Ok(row.map(|r| IncidentRow {
            id: r.get("id"),
            title: r.get("title"),
            description: r.get("description"),
            status: r.get("status"),
            severity: r.get("severity"),
            confidence: r.get("confidence"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
            evidence_ids: r.get("evidence_ids"),
            object_ids: r.get("object_ids"),
            attack_chain: r.get("attack_chain"),
            mitre_mappings: r.get("mitre_mappings"),
            recommended_response: r.get("recommended_response"),
            tags: r.get("tags"),
        }))
    }

    pub async fn find_all(&self, limit: u32) -> Result<Vec<IncidentRow>> {
        let rows = sqlx::query(
            "SELECT id, title, description, status, severity, confidence, created_at, updated_at,
             evidence_ids, object_ids, attack_chain, mitre_mappings, recommended_response, tags
             FROM incidents ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| IncidentRow {
                id: r.get("id"),
                title: r.get("title"),
                description: r.get("description"),
                status: r.get("status"),
                severity: r.get("severity"),
                confidence: r.get("confidence"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
                evidence_ids: r.get("evidence_ids"),
                object_ids: r.get("object_ids"),
                attack_chain: r.get("attack_chain"),
                mitre_mappings: r.get("mitre_mappings"),
                recommended_response: r.get("recommended_response"),
                tags: r.get("tags"),
            })
            .collect())
    }

    pub async fn find_by_status(&self, status: &str, limit: u32) -> Result<Vec<IncidentRow>> {
        let rows = sqlx::query(
            "SELECT id, title, description, status, severity, confidence, created_at, updated_at,
             evidence_ids, object_ids, attack_chain, mitre_mappings, recommended_response, tags
             FROM incidents WHERE status = ? ORDER BY created_at DESC LIMIT ?",
        )
        .bind(status)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| IncidentRow {
                id: r.get("id"),
                title: r.get("title"),
                description: r.get("description"),
                status: r.get("status"),
                severity: r.get("severity"),
                confidence: r.get("confidence"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
                evidence_ids: r.get("evidence_ids"),
                object_ids: r.get("object_ids"),
                attack_chain: r.get("attack_chain"),
                mitre_mappings: r.get("mitre_mappings"),
                recommended_response: r.get("recommended_response"),
                tags: r.get("tags"),
            })
            .collect())
    }

    pub async fn update_status(&self, id: &str, status: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE incidents SET status = ?, updated_at = datetime('now') WHERE id = ?",
        )
        .bind(status)
        .bind(id)
        .execute(self.store.pool())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM incidents")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }

    pub async fn count_by_status(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT status, COUNT(*) as cnt FROM incidents GROUP BY status ORDER BY cnt DESC",
        )
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.get("status"), r.get("cnt")))
            .collect())
    }

    pub async fn count_by_severity(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT severity, COUNT(*) as cnt FROM incidents GROUP BY severity ORDER BY cnt DESC",
        )
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.get("severity"), r.get("cnt")))
            .collect())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatDecisionRow {
    pub id: String,
    pub incident_id: String,
    pub severity: String,
    pub risk_score_final: f64,
    pub confidence: f64,
    pub priority: String,
    pub description: String,
    pub recommendation: String,
    pub created_at: String,
    pub tags: String,
}

pub struct ThreatDecisionRepository<'a> {
    store: &'a Store,
}

impl<'a> ThreatDecisionRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, decision: &sentinelx_threat::ThreatDecision) -> Result<()> {
        let mitre = serde_json::to_string(&decision.mitre_mappings)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let tags = serde_json::to_string(&decision.tags)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let metadata = serde_json::to_string(&decision.metadata)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        sqlx::query(
            r#"INSERT OR REPLACE INTO threat_decisions
            (id, incident_id, severity, risk_score_trust, risk_score_integrity, risk_score_risk,
             risk_score_reputation, risk_score_evidence_count, risk_score_incident_complexity,
             risk_score_rule_confidence, risk_score_final, confidence, priority, mitre_mappings,
             description, recommendation, response_plan, created_at, tags, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(decision.id.to_string())
        .bind(decision.incident_id.to_string())
        .bind(decision.severity.as_str())
        .bind(decision.risk_score.trust)
        .bind(decision.risk_score.integrity)
        .bind(decision.risk_score.risk)
        .bind(decision.risk_score.reputation)
        .bind(decision.risk_score.evidence_count)
        .bind(decision.risk_score.incident_complexity)
        .bind(decision.risk_score.rule_confidence)
        .bind(decision.risk_score.final_score)
        .bind(decision.confidence)
        .bind(decision.priority.as_str())
        .bind(mitre)
        .bind(&decision.description)
        .bind(&decision.recommendation)
        .bind(&decision.response_plan)
        .bind(decision.created_at.to_rfc3339())
        .bind(tags)
        .bind(metadata)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<ThreatDecisionRow>> {
        let row = sqlx::query(
            "SELECT id, incident_id, severity, risk_score_final, confidence, priority,
             description, recommendation, created_at, tags
             FROM threat_decisions WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.store.pool())
        .await?;

        Ok(row.map(|r| ThreatDecisionRow {
            id: r.get("id"),
            incident_id: r.get("incident_id"),
            severity: r.get("severity"),
            risk_score_final: r.get("risk_score_final"),
            confidence: r.get("confidence"),
            priority: r.get("priority"),
            description: r.get("description"),
            recommendation: r.get("recommendation"),
            created_at: r.get("created_at"),
            tags: r.get("tags"),
        }))
    }

    pub async fn find_all(&self, limit: u32) -> Result<Vec<ThreatDecisionRow>> {
        let rows = sqlx::query(
            "SELECT id, incident_id, severity, risk_score_final, confidence, priority,
             description, recommendation, created_at, tags
             FROM threat_decisions ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ThreatDecisionRow {
                id: r.get("id"),
                incident_id: r.get("incident_id"),
                severity: r.get("severity"),
                risk_score_final: r.get("risk_score_final"),
                confidence: r.get("confidence"),
                priority: r.get("priority"),
                description: r.get("description"),
                recommendation: r.get("recommendation"),
                created_at: r.get("created_at"),
                tags: r.get("tags"),
            })
            .collect())
    }

    pub async fn find_by_severity(
        &self,
        severity: &str,
        limit: u32,
    ) -> Result<Vec<ThreatDecisionRow>> {
        let rows = sqlx::query(
            "SELECT id, incident_id, severity, risk_score_final, confidence, priority,
             description, recommendation, created_at, tags
             FROM threat_decisions WHERE severity = ? ORDER BY created_at DESC LIMIT ?",
        )
        .bind(severity)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ThreatDecisionRow {
                id: r.get("id"),
                incident_id: r.get("incident_id"),
                severity: r.get("severity"),
                risk_score_final: r.get("risk_score_final"),
                confidence: r.get("confidence"),
                priority: r.get("priority"),
                description: r.get("description"),
                recommendation: r.get("recommendation"),
                created_at: r.get("created_at"),
                tags: r.get("tags"),
            })
            .collect())
    }

    pub async fn find_by_incident_id(&self, incident_id: &str) -> Result<Vec<ThreatDecisionRow>> {
        let rows = sqlx::query(
            "SELECT id, incident_id, severity, risk_score_final, confidence, priority,
             description, recommendation, created_at, tags
             FROM threat_decisions WHERE incident_id = ? ORDER BY created_at DESC",
        )
        .bind(incident_id)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ThreatDecisionRow {
                id: r.get("id"),
                incident_id: r.get("incident_id"),
                severity: r.get("severity"),
                risk_score_final: r.get("risk_score_final"),
                confidence: r.get("confidence"),
                priority: r.get("priority"),
                description: r.get("description"),
                recommendation: r.get("recommendation"),
                created_at: r.get("created_at"),
                tags: r.get("tags"),
            })
            .collect())
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM threat_decisions")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }

    pub async fn count_by_severity(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT severity, COUNT(*) as cnt FROM threat_decisions GROUP BY severity ORDER BY cnt DESC",
        )
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.get("severity"), r.get("cnt")))
            .collect())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphEdgeRow {
    pub id: i64,
    pub source_id: String,
    pub target_id: String,
    pub edge_type: String,
    pub properties: String,
    pub created_at: String,
}

pub struct CorrelationGraphRepository<'a> {
    store: &'a Store,
}

impl<'a> CorrelationGraphRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert_edge(
        &self,
        source_id: &str,
        target_id: &str,
        edge_type: &str,
        properties: &serde_json::Value,
    ) -> Result<()> {
        let props = serde_json::to_string(properties)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO correlation_graph (source_id, target_id, edge_type, properties) VALUES (?, ?, ?, ?)",
        )
        .bind(source_id)
        .bind(target_id)
        .bind(edge_type)
        .bind(props)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_source(&self, source_id: &str) -> Result<Vec<GraphEdgeRow>> {
        let rows = sqlx::query(
            "SELECT id, source_id, target_id, edge_type, properties, created_at
             FROM correlation_graph WHERE source_id = ? ORDER BY created_at DESC",
        )
        .bind(source_id)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| GraphEdgeRow {
                id: r.get("id"),
                source_id: r.get("source_id"),
                target_id: r.get("target_id"),
                edge_type: r.get("edge_type"),
                properties: r.get("properties"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    pub async fn find_by_target(&self, target_id: &str) -> Result<Vec<GraphEdgeRow>> {
        let rows = sqlx::query(
            "SELECT id, source_id, target_id, edge_type, properties, created_at
             FROM correlation_graph WHERE target_id = ? ORDER BY created_at DESC",
        )
        .bind(target_id)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| GraphEdgeRow {
                id: r.get("id"),
                source_id: r.get("source_id"),
                target_id: r.get("target_id"),
                edge_type: r.get("edge_type"),
                properties: r.get("properties"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    pub async fn find_all(&self, limit: u32) -> Result<Vec<GraphEdgeRow>> {
        let rows = sqlx::query(
            "SELECT id, source_id, target_id, edge_type, properties, created_at
             FROM correlation_graph ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| GraphEdgeRow {
                id: r.get("id"),
                source_id: r.get("source_id"),
                target_id: r.get("target_id"),
                edge_type: r.get("edge_type"),
                properties: r.get("properties"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM correlation_graph")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }

    pub async fn clear(&self) -> Result<u64> {
        let result = sqlx::query("DELETE FROM correlation_graph")
            .execute(self.store.pool())
            .await?;
        Ok(result.rows_affected())
    }
}

#[derive(Debug, Clone)]
pub struct ResponseAuditRow {
    pub id: String,
    pub timestamp: String,
    pub threat_id: String,
    pub workflow_name: String,
    pub action_type: String,
    pub action_params: String,
    pub result: String,
    pub duration_ms: i64,
    pub errors: String,
    pub rollback_status: String,
    pub dry_run: bool,
    pub created_at: String,
}

pub struct ResponseAuditRepository<'a> {
    store: &'a Store,
}

impl<'a> ResponseAuditRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, record: &sentinelx_response::AuditRecord) -> Result<()> {
        let action_params = record.action.parameter_summary();
        let errors_json = serde_json::to_string(&record.errors)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let rollback_str = match record.rollback_status {
            sentinelx_response::RollbackStatus::None => "none",
            sentinelx_response::RollbackStatus::Applied => "applied",
            sentinelx_response::RollbackStatus::Failed => "failed",
            sentinelx_response::RollbackStatus::NotRequired => "not_required",
        };
        let result_str = match &record.result {
            sentinelx_response::WorkflowStepResult::Success => "success",
            sentinelx_response::WorkflowStepResult::Failed(_) => "failed",
            sentinelx_response::WorkflowStepResult::Skipped(_) => "skipped",
            sentinelx_response::WorkflowStepResult::RolledBack => "rolled_back",
        };

        sqlx::query(
            "INSERT INTO response_audit (id, timestamp, threat_id, workflow_name, action_type, action_params, result, duration_ms, errors, rollback_status, dry_run) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(record.id.to_string())
        .bind(record.timestamp.to_rfc3339())
        .bind(record.threat_id.to_string())
        .bind(&record.workflow_name)
        .bind(record.action.as_str())
        .bind(&action_params)
        .bind(result_str)
        .bind(record.duration_ms as i64)
        .bind(&errors_json)
        .bind(rollback_str)
        .bind(record.dry_run as i64)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_all(&self, limit: i64) -> Result<Vec<ResponseAuditRow>> {
        let rows = sqlx::query(
            "SELECT id, timestamp, threat_id, workflow_name, action_type, action_params, result, duration_ms, errors, rollback_status, dry_run, created_at FROM response_audit ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?
        .into_iter()
        .map(|r| ResponseAuditRow {
            id: r.get("id"),
            timestamp: r.get("timestamp"),
            threat_id: r.get("threat_id"),
            workflow_name: r.get("workflow_name"),
            action_type: r.get("action_type"),
            action_params: r.get("action_params"),
            result: r.get("result"),
            duration_ms: r.get("duration_ms"),
            errors: r.get("errors"),
            rollback_status: r.get("rollback_status"),
            dry_run: r.get::<i64, _>("dry_run") != 0,
            created_at: r.get("created_at"),
        })
        .collect();
        Ok(rows)
    }

    pub async fn find_by_threat_id(&self, threat_id: &str) -> Result<Vec<ResponseAuditRow>> {
        let rows = sqlx::query(
            "SELECT id, timestamp, threat_id, workflow_name, action_type, action_params, result, duration_ms, errors, rollback_status, dry_run, created_at FROM response_audit WHERE threat_id = ? ORDER BY timestamp DESC"
        )
        .bind(threat_id)
        .fetch_all(self.store.pool())
        .await?
        .into_iter()
        .map(|r| ResponseAuditRow {
            id: r.get("id"),
            timestamp: r.get("timestamp"),
            threat_id: r.get("threat_id"),
            workflow_name: r.get("workflow_name"),
            action_type: r.get("action_type"),
            action_params: r.get("action_params"),
            result: r.get("result"),
            duration_ms: r.get("duration_ms"),
            errors: r.get("errors"),
            rollback_status: r.get("rollback_status"),
            dry_run: r.get::<i64, _>("dry_run") != 0,
            created_at: r.get("created_at"),
        })
        .collect();
        Ok(rows)
    }

    pub async fn find_by_workflow(&self, workflow: &str) -> Result<Vec<ResponseAuditRow>> {
        let rows = sqlx::query(
            "SELECT id, timestamp, threat_id, workflow_name, action_type, action_params, result, duration_ms, errors, rollback_status, dry_run, created_at FROM response_audit WHERE workflow_name = ? ORDER BY timestamp DESC"
        )
        .bind(workflow)
        .fetch_all(self.store.pool())
        .await?
        .into_iter()
        .map(|r| ResponseAuditRow {
            id: r.get("id"),
            timestamp: r.get("timestamp"),
            threat_id: r.get("threat_id"),
            workflow_name: r.get("workflow_name"),
            action_type: r.get("action_type"),
            action_params: r.get("action_params"),
            result: r.get("result"),
            duration_ms: r.get("duration_ms"),
            errors: r.get("errors"),
            rollback_status: r.get("rollback_status"),
            dry_run: r.get::<i64, _>("dry_run") != 0,
            created_at: r.get("created_at"),
        })
        .collect();
        Ok(rows)
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM response_audit")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }

    pub async fn count_by_result(&self) -> Result<std::collections::HashMap<String, i64>> {
        let rows =
            sqlx::query("SELECT result, COUNT(*) as cnt FROM response_audit GROUP BY result")
                .fetch_all(self.store.pool())
                .await?;
        let mut map = std::collections::HashMap::new();
        for row in rows {
            let result: String = row.get("result");
            let cnt: i64 = row.get("cnt");
            map.insert(result, cnt);
        }
        Ok(map)
    }
}

pub struct TelemetryEventRepository<'a> {
    store: &'a Store,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TelemetryEventRow {
    pub id: String,
    pub timestamp: String,
    pub provider: String,
    pub category: String,
    pub event_type: String,
    pub pid: Option<i64>,
    pub uid: Option<i64>,
    pub namespace: Option<String>,
    pub container: Option<String>,
    pub object_id: Option<String>,
    pub metadata: String,
}

impl<'a> TelemetryEventRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, event: &sentinelx_telemetry::TelemetryEvent) -> Result<()> {
        let metadata_str = serde_json::to_string(&event.metadata).unwrap_or_default();

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO telemetry_events (id, timestamp, provider, category, event_type, pid, uid, namespace, container, object_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.id.to_string())
        .bind(event.timestamp.to_rfc3339())
        .bind(&event.provider)
        .bind(event.category.as_str())
        .bind(event.event_type.as_str())
        .bind(event.pid.map(|p| p as i64))
        .bind(event.uid.map(|u| u as i64))
        .bind(&event.namespace)
        .bind(&event.container)
        .bind(&event.object_id)
        .bind(&metadata_str)
        .execute(self.store.pool())
        .await?;

        Ok(())
    }

    pub async fn insert_batch(
        &self,
        events: &[sentinelx_telemetry::TelemetryEvent],
    ) -> Result<usize> {
        let mut count = 0;
        for event in events {
            if self.insert(event).await.is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }

    pub async fn find_all(&self, limit: i64) -> Result<Vec<TelemetryEventRow>> {
        let rows = sqlx::query_as::<_, TelemetryEventRow>(
            "SELECT id, timestamp, provider, category, event_type, pid, uid, namespace, container, object_id, metadata FROM telemetry_events ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn find_by_provider(
        &self,
        provider: &str,
        limit: i64,
    ) -> Result<Vec<TelemetryEventRow>> {
        let rows = sqlx::query_as::<_, TelemetryEventRow>(
            "SELECT id, timestamp, provider, category, event_type, pid, uid, namespace, container, object_id, metadata FROM telemetry_events WHERE provider = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(provider)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn find_by_category(
        &self,
        category: &str,
        limit: i64,
    ) -> Result<Vec<TelemetryEventRow>> {
        let rows = sqlx::query_as::<_, TelemetryEventRow>(
            "SELECT id, timestamp, provider, category, event_type, pid, uid, namespace, container, object_id, metadata FROM telemetry_events WHERE category = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(category)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn find_by_pid(&self, pid: u32, limit: i64) -> Result<Vec<TelemetryEventRow>> {
        let rows = sqlx::query_as::<_, TelemetryEventRow>(
            "SELECT id, timestamp, provider, category, event_type, pid, uid, namespace, container, object_id, metadata FROM telemetry_events WHERE pid = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(pid as i64)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM telemetry_events")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }

    pub async fn count_by_provider(&self) -> Result<std::collections::HashMap<String, i64>> {
        let rows =
            sqlx::query("SELECT provider, COUNT(*) as cnt FROM telemetry_events GROUP BY provider")
                .fetch_all(self.store.pool())
                .await?;
        let mut map = std::collections::HashMap::new();
        for row in rows {
            let provider: String = row.get("provider");
            let cnt: i64 = row.get("cnt");
            map.insert(provider, cnt);
        }
        Ok(map)
    }

    pub async fn count_by_category(&self) -> Result<std::collections::HashMap<String, i64>> {
        let rows =
            sqlx::query("SELECT category, COUNT(*) as cnt FROM telemetry_events GROUP BY category")
                .fetch_all(self.store.pool())
                .await?;
        let mut map = std::collections::HashMap::new();
        for row in rows {
            let category: String = row.get("category");
            let cnt: i64 = row.get("cnt");
            map.insert(category, cnt);
        }
        Ok(map)
    }

    pub async fn count_by_event_type(&self) -> Result<std::collections::HashMap<String, i64>> {
        let rows = sqlx::query(
            "SELECT event_type, COUNT(*) as cnt FROM telemetry_events GROUP BY event_type",
        )
        .fetch_all(self.store.pool())
        .await?;
        let mut map = std::collections::HashMap::new();
        for row in rows {
            let event_type: String = row.get("event_type");
            let cnt: i64 = row.get("cnt");
            map.insert(event_type, cnt);
        }
        Ok(map)
    }

    pub async fn cleanup_old(&self, days: i64) -> Result<i64> {
        let result = sqlx::query(
            "DELETE FROM telemetry_events WHERE timestamp < datetime('now', ? || ' days')",
        )
        .bind(-days)
        .execute(self.store.pool())
        .await?;
        Ok(result.rows_affected() as i64)
    }
}

pub struct BehaviorProfileRepository<'a> {
    store: &'a Store,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BehaviorProfileRow {
    pub id: String,
    pub object_id: String,
    pub first_seen: String,
    pub last_seen: String,
    pub execution_count: i64,
    pub connection_count: i64,
    pub privilege_changes: i64,
    pub persistence_events: i64,
    pub integrity_violations: i64,
    pub risk_trend: String,
    pub confidence_trend: String,
    pub historical_score: f64,
    pub categories: String,
    pub metadata: String,
}

impl<'a> BehaviorProfileRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, profile: &sentinelx_behavior::BehaviorProfile) -> Result<()> {
        let risk_trend = serde_json::to_string(&profile.risk_trend).unwrap_or_default();
        let confidence_trend = serde_json::to_string(&profile.confidence_trend).unwrap_or_default();
        let categories = serde_json::to_string(&profile.categories).unwrap_or_default();
        let metadata = serde_json::to_string(&profile.metadata).unwrap_or_default();

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO behavior_profiles (id, object_id, first_seen, last_seen, execution_count, connection_count, privilege_changes, persistence_events, integrity_violations, risk_trend, confidence_trend, historical_score, categories, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(profile.id.to_string())
        .bind(&profile.object_id)
        .bind(profile.first_seen.to_rfc3339())
        .bind(profile.last_seen.to_rfc3339())
        .bind(profile.execution_count as i64)
        .bind(profile.connection_count as i64)
        .bind(profile.privilege_changes as i64)
        .bind(profile.persistence_events as i64)
        .bind(profile.integrity_violations as i64)
        .bind(&risk_trend)
        .bind(&confidence_trend)
        .bind(profile.historical_score)
        .bind(&categories)
        .bind(&metadata)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_object_id(&self, object_id: &str) -> Result<Option<BehaviorProfileRow>> {
        let row = sqlx::query_as::<_, BehaviorProfileRow>(
            "SELECT id, object_id, first_seen, last_seen, execution_count, connection_count, privilege_changes, persistence_events, integrity_violations, risk_trend, confidence_trend, historical_score, categories, metadata FROM behavior_profiles WHERE object_id = ?",
        )
        .bind(object_id)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_all(&self, limit: i64) -> Result<Vec<BehaviorProfileRow>> {
        let rows = sqlx::query_as::<_, BehaviorProfileRow>(
            "SELECT id, object_id, first_seen, last_seen, execution_count, connection_count, privilege_changes, persistence_events, integrity_violations, risk_trend, confidence_trend, historical_score, categories, metadata FROM behavior_profiles ORDER BY last_seen DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM behavior_profiles")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }
}

pub struct IoCRepository<'a> {
    store: &'a Store,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IoCRow {
    pub id: String,
    pub ioc_type: String,
    pub value: String,
    pub severity: String,
    pub confidence: f64,
    pub source: String,
    pub description: String,
    pub tags: String,
    pub first_seen: String,
    pub last_seen: String,
    pub expiry: Option<String>,
    pub metadata: String,
}

impl<'a> IoCRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, ioc: &sentinelx_intelligence::IoC) -> Result<()> {
        let tags = serde_json::to_string(&ioc.tags).unwrap_or_default();
        let metadata = serde_json::to_string(&ioc.metadata).unwrap_or_default();

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO iocs (id, ioc_type, value, severity, confidence, source, description, tags, first_seen, last_seen, expiry, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(ioc.id.to_string())
        .bind(ioc.ioc_type.as_str())
        .bind(&ioc.value)
        .bind(&ioc.severity)
        .bind(ioc.confidence)
        .bind(&ioc.source)
        .bind(&ioc.description)
        .bind(&tags)
        .bind(ioc.first_seen.to_rfc3339())
        .bind(ioc.last_seen.to_rfc3339())
        .bind(ioc.expiry.map(|e| e.to_rfc3339()))
        .bind(&metadata)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_type(&self, ioc_type: &str) -> Result<Vec<IoCRow>> {
        let rows = sqlx::query_as::<_, IoCRow>(
            "SELECT id, ioc_type, value, severity, confidence, source, description, tags, first_seen, last_seen, expiry, metadata FROM iocs WHERE ioc_type = ? ORDER BY severity DESC",
        )
        .bind(ioc_type)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn find_by_value(&self, ioc_type: &str, value: &str) -> Result<Option<IoCRow>> {
        let row = sqlx::query_as::<_, IoCRow>(
            "SELECT id, ioc_type, value, severity, confidence, source, description, tags, first_seen, last_seen, expiry, metadata FROM iocs WHERE ioc_type = ? AND value = ?",
        )
        .bind(ioc_type)
        .bind(value)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_all(&self, limit: i64) -> Result<Vec<IoCRow>> {
        let rows = sqlx::query_as::<_, IoCRow>(
            "SELECT id, ioc_type, value, severity, confidence, source, description, tags, first_seen, last_seen, expiry, metadata FROM iocs ORDER BY last_seen DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM iocs")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }

    pub async fn count_by_type(&self) -> Result<std::collections::HashMap<String, i64>> {
        let rows = sqlx::query("SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type")
            .fetch_all(self.store.pool())
            .await?;
        let mut map = std::collections::HashMap::new();
        for row in rows {
            let ioc_type: String = row.get("ioc_type");
            let cnt: i64 = row.get("cnt");
            map.insert(ioc_type, cnt);
        }
        Ok(map)
    }

    pub async fn delete(&self, ioc_type: &str, value: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM iocs WHERE ioc_type = ? AND value = ?")
            .bind(ioc_type)
            .bind(value)
            .execute(self.store.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

pub struct YaraRuleRepository<'a> {
    store: &'a Store,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct YaraRuleRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub author: String,
    pub severity: String,
    pub tags: String,
    pub rule_content: String,
    pub enabled: i64,
}

impl<'a> YaraRuleRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, rule: &sentinelx_intelligence::YaraRule) -> Result<()> {
        let tags = serde_json::to_string(&rule.tags).unwrap_or_default();

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO yara_rules (id, name, description, author, severity, tags, rule_content, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(rule.id.to_string())
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(&rule.author)
        .bind(&rule.severity)
        .bind(&tags)
        .bind(&rule.rule_content)
        .bind(rule.enabled as i64)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_all(&self) -> Result<Vec<YaraRuleRow>> {
        let rows = sqlx::query_as::<_, YaraRuleRow>(
            "SELECT id, name, description, author, severity, tags, rule_content, enabled FROM yara_rules ORDER BY name",
        )
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Option<YaraRuleRow>> {
        let row = sqlx::query_as::<_, YaraRuleRow>(
            "SELECT id, name, description, author, severity, tags, rule_content, enabled FROM yara_rules WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row)
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM yara_rules")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }

    pub async fn delete(&self, name: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM yara_rules WHERE name = ?")
            .bind(name)
            .execute(self.store.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

pub struct SigmaRuleRepository<'a> {
    store: &'a Store,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SigmaRuleRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub author: String,
    pub severity: String,
    pub tags: String,
    pub logsource_category: Option<String>,
    pub logsource_product: Option<String>,
    pub logsource_service: Option<String>,
    pub detection_condition: String,
    pub detection_fields: String,
    pub falsepositives: String,
    pub enabled: i64,
}

impl<'a> SigmaRuleRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, rule: &sentinelx_intelligence::SigmaRule) -> Result<()> {
        let tags = serde_json::to_string(&rule.tags).unwrap_or_default();
        let detection_fields = serde_json::to_string(&rule.detection.fields).unwrap_or_default();
        let falsepositives = serde_json::to_string(&rule.falsepositives).unwrap_or_default();

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO sigma_rules (id, name, description, author, severity, tags, logsource_category, logsource_product, logsource_service, detection_condition, detection_fields, falsepositives, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(rule.id.to_string())
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(&rule.author)
        .bind(&rule.severity)
        .bind(&tags)
        .bind(&rule.logsource.category)
        .bind(&rule.logsource.product)
        .bind(&rule.logsource.service)
        .bind(&rule.detection.condition)
        .bind(&detection_fields)
        .bind(&falsepositives)
        .bind(rule.enabled as i64)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_all(&self) -> Result<Vec<SigmaRuleRow>> {
        let rows = sqlx::query_as::<_, SigmaRuleRow>(
            "SELECT id, name, description, author, severity, tags, logsource_category, logsource_product, logsource_service, detection_condition, detection_fields, falsepositives, enabled FROM sigma_rules ORDER BY name",
        )
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Option<SigmaRuleRow>> {
        let row = sqlx::query_as::<_, SigmaRuleRow>(
            "SELECT id, name, description, author, severity, tags, logsource_category, logsource_product, logsource_service, detection_condition, detection_fields, falsepositives, enabled FROM sigma_rules WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row)
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sigma_rules")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }

    pub async fn delete(&self, name: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM sigma_rules WHERE name = ?")
            .bind(name)
            .execute(self.store.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

pub struct CveRepository<'a> {
    store: &'a Store,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CveRow {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: f64,
    pub affected_products: String,
    pub published_at: String,
    pub references_list: String,
}

impl<'a> CveRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(&self, cve: &sentinelx_intelligence::CveEntry) -> Result<()> {
        let affected_products = serde_json::to_string(&cve.affected_products).unwrap_or_default();
        let references_list = serde_json::to_string(&cve.references).unwrap_or_default();

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO cves (id, description, severity, cvss_score, affected_products, published_at, references_list)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&cve.id)
        .bind(&cve.description)
        .bind(&cve.severity)
        .bind(cve.cvss_score)
        .bind(&affected_products)
        .bind(cve.published_at.to_rfc3339())
        .bind(&references_list)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<CveRow>> {
        let row = sqlx::query_as::<_, CveRow>(
            "SELECT id, description, severity, cvss_score, affected_products, published_at, references_list FROM cves WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_all(&self, limit: i64) -> Result<Vec<CveRow>> {
        let rows = sqlx::query_as::<_, CveRow>(
            "SELECT id, description, severity, cvss_score, affected_products, published_at, references_list FROM cves ORDER BY cvss_score DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM cves")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FleetAgentRow {
    pub id: String,
    pub hostname: String,
    pub version: String,
    pub kernel: String,
    pub distribution: String,
    pub architecture: String,
    pub status: String,
    pub registered_at: String,
    pub last_heartbeat: Option<String>,
    pub events_received: i64,
    pub incidents_received: i64,
    pub policies_sent: i64,
    pub actions_sent: i64,
    pub created_at: String,
}

pub struct FleetAgentRepository<'a> {
    store: &'a Store,
}

impl<'a> FleetAgentRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert(
        &self,
        id: &str,
        hostname: &str,
        version: &str,
        kernel: &str,
        distribution: &str,
        architecture: &str,
        registered_at: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO fleet_agents (id, hostname, version, kernel, distribution, architecture, registered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(id)
        .bind(hostname)
        .bind(version)
        .bind(kernel)
        .bind(distribution)
        .bind(architecture)
        .bind(registered_at)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<FleetAgentRow>> {
        let row = sqlx::query_as::<_, FleetAgentRow>(
            "SELECT id, hostname, version, kernel, distribution, architecture, status, registered_at, last_heartbeat, events_received, incidents_received, policies_sent, actions_sent, created_at FROM fleet_agents WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_all(&self) -> Result<Vec<FleetAgentRow>> {
        let rows = sqlx::query_as::<_, FleetAgentRow>(
            "SELECT id, hostname, version, kernel, distribution, architecture, status, registered_at, last_heartbeat, events_received, incidents_received, policies_sent, actions_sent, created_at FROM fleet_agents ORDER BY created_at DESC",
        )
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn find_by_status(&self, status: &str) -> Result<Vec<FleetAgentRow>> {
        let rows = sqlx::query_as::<_, FleetAgentRow>(
            "SELECT id, hostname, version, kernel, distribution, architecture, status, registered_at, last_heartbeat, events_received, incidents_received, policies_sent, actions_sent, created_at FROM fleet_agents WHERE status = ? ORDER BY created_at DESC",
        )
        .bind(status)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn update_heartbeat(&self, id: &str, timestamp: &str) -> Result<bool> {
        let result = sqlx::query("UPDATE fleet_agents SET last_heartbeat = ? WHERE id = ?")
            .bind(timestamp)
            .bind(id)
            .execute(self.store.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_stats(
        &self,
        id: &str,
        events_received: i64,
        incidents_received: i64,
        policies_sent: i64,
        actions_sent: i64,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE fleet_agents SET events_received = ?, incidents_received = ?, policies_sent = ?, actions_sent = ? WHERE id = ?",
        )
        .bind(events_received)
        .bind(incidents_received)
        .bind(policies_sent)
        .bind(actions_sent)
        .bind(id)
        .execute(self.store.pool())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM fleet_agents WHERE id = ?")
            .bind(id)
            .execute(self.store.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn count(&self) -> Result<i64> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM fleet_agents")
            .fetch_one(self.store.pool())
            .await?;
        Ok(total.0)
    }

    pub async fn count_by_status(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT status, COUNT(*) as cnt FROM fleet_agents GROUP BY status ORDER BY cnt DESC",
        )
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("status"), r.get("cnt")))
            .collect())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FleetHealthRow {
    pub id: i64,
    pub agent_id: String,
    pub timestamp: String,
    pub cpu_percent: f64,
    pub memory_used_bytes: i64,
    pub memory_total_bytes: i64,
    pub disk_used_bytes: i64,
    pub disk_total_bytes: i64,
    pub load_avg_1: f64,
    pub load_avg_5: f64,
    pub load_avg_15: f64,
    pub active_telemetry_providers: i64,
    pub total_events: i64,
    pub total_threats: i64,
    pub total_incidents: i64,
    pub created_at: String,
}

pub struct FleetHealthRepository<'a> {
    store: &'a Store,
}

impl<'a> FleetHealthRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert(
        &self,
        agent_id: &str,
        timestamp: &str,
        cpu_percent: f64,
        memory_used_bytes: i64,
        memory_total_bytes: i64,
        disk_used_bytes: i64,
        disk_total_bytes: i64,
        load_avg_1: f64,
        load_avg_5: f64,
        load_avg_15: f64,
        active_telemetry_providers: i64,
        total_events: i64,
        total_threats: i64,
        total_incidents: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO fleet_health (agent_id, timestamp, cpu_percent, memory_used_bytes, memory_total_bytes, disk_used_bytes, disk_total_bytes, load_avg_1, load_avg_5, load_avg_15, active_telemetry_providers, total_events, total_threats, total_incidents)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(agent_id)
        .bind(timestamp)
        .bind(cpu_percent)
        .bind(memory_used_bytes)
        .bind(memory_total_bytes)
        .bind(disk_used_bytes)
        .bind(disk_total_bytes)
        .bind(load_avg_1)
        .bind(load_avg_5)
        .bind(load_avg_15)
        .bind(active_telemetry_providers)
        .bind(total_events)
        .bind(total_threats)
        .bind(total_incidents)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_agent_id(
        &self,
        agent_id: &str,
        limit: i64,
    ) -> Result<Vec<FleetHealthRow>> {
        let rows = sqlx::query_as::<_, FleetHealthRow>(
            "SELECT id, agent_id, timestamp, cpu_percent, memory_used_bytes, memory_total_bytes, disk_used_bytes, disk_total_bytes, load_avg_1, load_avg_5, load_avg_15, active_telemetry_providers, total_events, total_threats, total_incidents, created_at FROM fleet_health WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(agent_id)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn find_recent(&self, limit: i64) -> Result<Vec<FleetHealthRow>> {
        let rows = sqlx::query_as::<_, FleetHealthRow>(
            "SELECT id, agent_id, timestamp, cpu_percent, memory_used_bytes, memory_total_bytes, disk_used_bytes, disk_total_bytes, load_avg_1, load_avg_5, load_avg_15, active_telemetry_providers, total_events, total_threats, total_incidents, created_at FROM fleet_health ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn cleanup_old(&self, retention_days: i64) -> Result<i64> {
        let result =
            sqlx::query("DELETE FROM fleet_health WHERE timestamp < datetime('now', ? || ' days')")
                .bind(-retention_days)
                .execute(self.store.pool())
                .await?;
        Ok(result.rows_affected() as i64)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FleetPolicyRow {
    pub id: String,
    pub name: String,
    pub policy_type: String,
    pub config: String,
    pub version: i64,
    pub enabled: i64,
    pub distributed_to: String,
    pub created_at: String,
}

pub struct FleetPolicyRepository<'a> {
    store: &'a Store,
}

impl<'a> FleetPolicyRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(
        &self,
        id: &str,
        name: &str,
        policy_type: &str,
        config: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO fleet_policies (id, name, policy_type, config)
            VALUES (?, ?, ?, ?)"#,
        )
        .bind(id)
        .bind(name)
        .bind(policy_type)
        .bind(config)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<FleetPolicyRow>> {
        let row = sqlx::query_as::<_, FleetPolicyRow>(
            "SELECT id, name, policy_type, config, version, enabled, distributed_to, created_at FROM fleet_policies WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_all(&self) -> Result<Vec<FleetPolicyRow>> {
        let rows = sqlx::query_as::<_, FleetPolicyRow>(
            "SELECT id, name, policy_type, config, version, enabled, distributed_to, created_at FROM fleet_policies ORDER BY created_at DESC",
        )
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn find_by_type(&self, policy_type: &str) -> Result<Vec<FleetPolicyRow>> {
        let rows = sqlx::query_as::<_, FleetPolicyRow>(
            "SELECT id, name, policy_type, config, version, enabled, distributed_to, created_at FROM fleet_policies WHERE policy_type = ? ORDER BY created_at DESC",
        )
        .bind(policy_type)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn update_enabled(&self, id: &str, enabled: bool) -> Result<bool> {
        let result = sqlx::query("UPDATE fleet_policies SET enabled = ? WHERE id = ?")
            .bind(enabled as i64)
            .bind(id)
            .execute(self.store.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM fleet_policies WHERE id = ?")
            .bind(id)
            .execute(self.store.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RemoteActionRow {
    pub id: String,
    pub agent_id: String,
    pub action_type: String,
    pub params: String,
    pub status: String,
    pub result: Option<String>,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

pub struct RemoteActionRepository<'a> {
    store: &'a Store,
}

impl<'a> RemoteActionRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub async fn insert(
        &self,
        id: &str,
        agent_id: &str,
        action_type: &str,
        params: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO remote_actions (id, agent_id, action_type, params)
            VALUES (?, ?, ?, ?)"#,
        )
        .bind(id)
        .bind(agent_id)
        .bind(action_type)
        .bind(params)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<RemoteActionRow>> {
        let row = sqlx::query_as::<_, RemoteActionRow>(
            "SELECT id, agent_id, action_type, params, status, result, error, duration_ms, created_at, completed_at FROM remote_actions WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row)
    }

    pub async fn find_by_agent_id(
        &self,
        agent_id: &str,
        limit: i64,
    ) -> Result<Vec<RemoteActionRow>> {
        let rows = sqlx::query_as::<_, RemoteActionRow>(
            "SELECT id, agent_id, action_type, params, status, result, error, duration_ms, created_at, completed_at FROM remote_actions WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?",
        )
        .bind(agent_id)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn find_by_status(&self, status: &str, limit: i64) -> Result<Vec<RemoteActionRow>> {
        let rows = sqlx::query_as::<_, RemoteActionRow>(
            "SELECT id, agent_id, action_type, params, status, result, error, duration_ms, created_at, completed_at FROM remote_actions WHERE status = ? ORDER BY created_at DESC LIMIT ?",
        )
        .bind(status)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn update_status(
        &self,
        id: &str,
        status: &str,
        result: Option<&str>,
        error: Option<&str>,
        duration_ms: Option<i64>,
        completed_at: Option<&str>,
    ) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE remote_actions SET status = ?, result = ?, error = ?, duration_ms = ?, completed_at = ? WHERE id = ?",
        )
        .bind(status)
        .bind(result)
        .bind(error)
        .bind(duration_ms)
        .bind(completed_at)
        .bind(id)
        .execute(self.store.pool())
        .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn cleanup_old(&self, retention_days: i64) -> Result<i64> {
        let result = sqlx::query(
            "DELETE FROM remote_actions WHERE created_at < datetime('now', ? || ' days')",
        )
        .bind(-retention_days)
        .execute(self.store.pool())
        .await?;
        Ok(result.rows_affected() as i64)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HeartbeatHistoryRow {
    pub id: i64,
    pub agent_id: String,
    pub timestamp: String,
    pub status: String,
    pub cpu_percent: f64,
    pub memory_used_bytes: i64,
    pub memory_total_bytes: i64,
    pub total_events: i64,
    pub total_threats: i64,
    pub total_incidents: i64,
    pub created_at: String,
}

pub struct HeartbeatHistoryRepository<'a> {
    store: &'a Store,
}

impl<'a> HeartbeatHistoryRepository<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert(
        &self,
        agent_id: &str,
        timestamp: &str,
        status: &str,
        cpu_percent: f64,
        memory_used_bytes: i64,
        memory_total_bytes: i64,
        total_events: i64,
        total_threats: i64,
        total_incidents: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO heartbeat_history (agent_id, timestamp, status, cpu_percent, memory_used_bytes, memory_total_bytes, total_events, total_threats, total_incidents)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(agent_id)
        .bind(timestamp)
        .bind(status)
        .bind(cpu_percent)
        .bind(memory_used_bytes)
        .bind(memory_total_bytes)
        .bind(total_events)
        .bind(total_threats)
        .bind(total_incidents)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn find_by_agent_id(
        &self,
        agent_id: &str,
        limit: i64,
    ) -> Result<Vec<HeartbeatHistoryRow>> {
        let rows = sqlx::query_as::<_, HeartbeatHistoryRow>(
            "SELECT id, agent_id, timestamp, status, cpu_percent, memory_used_bytes, memory_total_bytes, total_events, total_threats, total_incidents, created_at FROM heartbeat_history WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(agent_id)
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn find_recent(&self, limit: i64) -> Result<Vec<HeartbeatHistoryRow>> {
        let rows = sqlx::query_as::<_, HeartbeatHistoryRow>(
            "SELECT id, agent_id, timestamp, status, cpu_percent, memory_used_bytes, memory_total_bytes, total_events, total_threats, total_incidents, created_at FROM heartbeat_history ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows)
    }

    pub async fn cleanup_old(&self, retention_days: i64) -> Result<i64> {
        let result = sqlx::query(
            "DELETE FROM heartbeat_history WHERE timestamp < datetime('now', ? || ' days')",
        )
        .bind(-retention_days)
        .execute(self.store.pool())
        .await?;
        Ok(result.rows_affected() as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use chrono::Utc;
    use sentinelx_common::event::{Event, EventKind, EventSource};
    use sentinelx_common::severity::Severity;
    use sentinelx_common::types::{ThreatCategory, ThreatEvent};
    use uuid::Uuid;

    async fn test_store() -> Store {
        Store::new("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn event_insert_and_query() {
        let store = test_store().await;
        let repo = EventRepository::new(&store);

        let event = Event::new(
            EventKind::ProcessCreated,
            EventSource::ProcessMonitor,
            serde_json::json!({"pid": 1234}),
        )
        .with_severity(Severity::High);

        repo.insert(&event).await.unwrap();
        let events = repo.find_by_severity(&Severity::High, 10).await.unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn threat_insert_and_stats() {
        let store = test_store().await;
        let repo = ThreatRepository::new(&store);

        let threat = ThreatEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: Severity::Critical,
            category: ThreatCategory::Rootkit,
            title: "Test Rootkit".to_string(),
            description: "A test rootkit detection".to_string(),
            evidence: vec![],
            mitre_attack: vec![],
            source_detector: "test".to_string(),
            process: None,
            network: None,
            hash: None,
            tags: vec!["test".to_string()],
        };

        repo.insert(&threat).await.unwrap();
        let stats = repo.stats().await.unwrap();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.critical, 1);
    }

    #[tokio::test]
    async fn find_by_id_works() {
        let store = test_store().await;
        let repo = ThreatRepository::new(&store);

        let threat = ThreatEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: Severity::High,
            category: ThreatCategory::HookDetected,
            title: "Test Hook".to_string(),
            description: "Test".to_string(),
            evidence: vec![],
            mitre_attack: vec![],
            source_detector: "test".to_string(),
            process: None,
            network: None,
            hash: None,
            tags: vec![],
        };

        repo.insert(&threat).await.unwrap();
        let found = repo.find_by_id(&threat.id.to_string()).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().title, "Test Hook");

        let not_found = repo.find_by_id("nonexistent").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn acknowledge_returns_false_for_nonexistent() {
        let store = test_store().await;
        let repo = ThreatRepository::new(&store);

        let result = repo.acknowledge("nonexistent-id").await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn evidence_insert_and_query() {
        let store = test_store().await;
        let repo = EvidenceRepository::new(&store);

        let evidence = sentinelx_evidence::Evidence::new(
            sentinelx_evidence::EvidenceType::FileIntegrity,
            sentinelx_evidence::Severity::High,
            "test_source".to_string(),
            "Test evidence description".to_string(),
        )
        .with_tag("test_tag".to_string())
        .with_confidence(0.85);

        repo.insert(&evidence).await.unwrap();
        let found = repo.find_by_id(&evidence.id.to_string()).await.unwrap();
        assert!(found.is_some());

        let row = found.unwrap();
        assert_eq!(row.source, "test_source");
        assert_eq!(row.description, "Test evidence description");
        assert_eq!(row.confidence, 0.85);
    }

    #[tokio::test]
    async fn evidence_batch_insert() {
        let store = test_store().await;
        let repo = EvidenceRepository::new(&store);

        let evidence1 = sentinelx_evidence::Evidence::new(
            sentinelx_evidence::EvidenceType::KernelIntegrity,
            sentinelx_evidence::Severity::Critical,
            "kernel".to_string(),
            "Kernel evidence 1".to_string(),
        );
        let evidence2 = sentinelx_evidence::Evidence::new(
            sentinelx_evidence::EvidenceType::ProcessIntegrity,
            sentinelx_evidence::Severity::Medium,
            "process".to_string(),
            "Process evidence 2".to_string(),
        );

        let count = repo.insert_batch(&[evidence1, evidence2]).await.unwrap();
        assert_eq!(count, 2);

        let all = repo.find_all(10).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn evidence_stats() {
        let store = test_store().await;
        let repo = EvidenceRepository::new(&store);

        let e1 = sentinelx_evidence::Evidence::new(
            sentinelx_evidence::EvidenceType::FileIntegrity,
            sentinelx_evidence::Severity::High,
            "src1".to_string(),
            "desc1".to_string(),
        );
        let e2 = sentinelx_evidence::Evidence::new(
            sentinelx_evidence::EvidenceType::FileIntegrity,
            sentinelx_evidence::Severity::Critical,
            "src2".to_string(),
            "desc2".to_string(),
        );

        repo.insert(&e1).await.unwrap();
        repo.insert(&e2).await.unwrap();

        let stats = repo.stats().await.unwrap();
        assert_eq!(stats.total, 2);
    }

    #[tokio::test]
    async fn response_audit_insert_and_query() {
        let store = test_store().await;
        let repo = ResponseAuditRepository::new(&store);

        let record = sentinelx_response::AuditRecord {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            threat_id: Uuid::new_v4(),
            workflow_name: "critical_isolation".to_string(),
            action: sentinelx_response::ResponseAction::Alert,
            result: sentinelx_response::WorkflowStepResult::Success,
            duration_ms: 42,
            errors: vec![],
            rollback_status: sentinelx_response::RollbackStatus::None,
            dry_run: true,
        };

        repo.insert(&record).await.unwrap();
        let rows = repo.find_all(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].workflow_name, "critical_isolation");
        assert_eq!(rows[0].action_type, "alert");
        assert_eq!(rows[0].result, "success");
        assert_eq!(rows[0].duration_ms, 42);
        assert!(rows[0].dry_run);
    }

    #[tokio::test]
    async fn response_audit_count() {
        let store = test_store().await;
        let repo = ResponseAuditRepository::new(&store);

        assert_eq!(repo.count().await.unwrap(), 0);

        let record = sentinelx_response::AuditRecord {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            threat_id: Uuid::new_v4(),
            workflow_name: "low_monitoring".to_string(),
            action: sentinelx_response::ResponseAction::LogEvent,
            result: sentinelx_response::WorkflowStepResult::Success,
            duration_ms: 5,
            errors: vec![],
            rollback_status: sentinelx_response::RollbackStatus::None,
            dry_run: true,
        };
        repo.insert(&record).await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn telemetry_event_insert_and_query() {
        let store = test_store().await;
        let repo = TelemetryEventRepository::new(&store);

        let event = sentinelx_telemetry::TelemetryEvent::new(
            "test_provider",
            sentinelx_telemetry::TelemetryEventType::ProcessCreate,
        )
        .with_pid(1234)
        .with_uid(1000)
        .with_object_id("proc_1234");

        repo.insert(&event).await.unwrap();
        let rows = repo.find_all(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].provider, "test_provider");
        assert_eq!(rows[0].event_type, "process_create");
        assert_eq!(rows[0].category, "process");
        assert_eq!(rows[0].pid, Some(1234));
        assert_eq!(rows[0].uid, Some(1000));
        assert_eq!(rows[0].object_id, Some("proc_1234".to_string()));
    }

    #[tokio::test]
    async fn telemetry_event_count() {
        let store = test_store().await;
        let repo = TelemetryEventRepository::new(&store);

        assert_eq!(repo.count().await.unwrap(), 0);

        let event = sentinelx_telemetry::TelemetryEvent::new(
            "test",
            sentinelx_telemetry::TelemetryEventType::FileWrite,
        );
        repo.insert(&event).await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn telemetry_event_count_by_provider() {
        let store = test_store().await;
        let repo = TelemetryEventRepository::new(&store);

        let e1 = sentinelx_telemetry::TelemetryEvent::new(
            "provider_a",
            sentinelx_telemetry::TelemetryEventType::ProcessCreate,
        );
        let e2 = sentinelx_telemetry::TelemetryEvent::new(
            "provider_a",
            sentinelx_telemetry::TelemetryEventType::FileWrite,
        );
        let e3 = sentinelx_telemetry::TelemetryEvent::new(
            "provider_b",
            sentinelx_telemetry::TelemetryEventType::NetConnect,
        );

        repo.insert(&e1).await.unwrap();
        repo.insert(&e2).await.unwrap();
        repo.insert(&e3).await.unwrap();

        let counts = repo.count_by_provider().await.unwrap();
        assert_eq!(counts.get("provider_a"), Some(&2));
        assert_eq!(counts.get("provider_b"), Some(&1));
    }

    #[tokio::test]
    async fn telemetry_event_count_by_category() {
        let store = test_store().await;
        let repo = TelemetryEventRepository::new(&store);

        let e1 = sentinelx_telemetry::TelemetryEvent::new(
            "test",
            sentinelx_telemetry::TelemetryEventType::ProcessCreate,
        );
        let e2 = sentinelx_telemetry::TelemetryEvent::new(
            "test",
            sentinelx_telemetry::TelemetryEventType::FileWrite,
        );

        repo.insert(&e1).await.unwrap();
        repo.insert(&e2).await.unwrap();

        let counts = repo.count_by_category().await.unwrap();
        assert_eq!(counts.get("process"), Some(&1));
        assert_eq!(counts.get("filesystem"), Some(&1));
    }

    #[tokio::test]
    async fn telemetry_event_find_by_provider() {
        let store = test_store().await;
        let repo = TelemetryEventRepository::new(&store);

        let e1 = sentinelx_telemetry::TelemetryEvent::new(
            "ebpf",
            sentinelx_telemetry::TelemetryEventType::ProcessCreate,
        );
        let e2 = sentinelx_telemetry::TelemetryEvent::new(
            "auditd",
            sentinelx_telemetry::TelemetryEventType::FileWrite,
        );

        repo.insert(&e1).await.unwrap();
        repo.insert(&e2).await.unwrap();

        let rows = repo.find_by_provider("ebpf", 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].provider, "ebpf");
    }

    #[tokio::test]
    async fn telemetry_event_find_by_pid() {
        let store = test_store().await;
        let repo = TelemetryEventRepository::new(&store);

        let e1 = sentinelx_telemetry::TelemetryEvent::new(
            "test",
            sentinelx_telemetry::TelemetryEventType::ProcessCreate,
        )
        .with_pid(100);

        repo.insert(&e1).await.unwrap();

        let rows = repo.find_by_pid(100, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, Some(100));
    }

    #[tokio::test]
    async fn telemetry_event_batch_insert() {
        let store = test_store().await;
        let repo = TelemetryEventRepository::new(&store);

        let events: Vec<_> = (0..5)
            .map(|i| {
                sentinelx_telemetry::TelemetryEvent::new(
                    &format!("provider_{}", i),
                    sentinelx_telemetry::TelemetryEventType::ProcessCreate,
                )
            })
            .collect();

        let count = repo.insert_batch(&events).await.unwrap();
        assert_eq!(count, 5);
        assert_eq!(repo.count().await.unwrap(), 5);
    }

    #[tokio::test]
    async fn behavior_profile_insert_and_query() {
        let store = test_store().await;
        let repo = BehaviorProfileRepository::new(&store);

        let profile = sentinelx_behavior::BehaviorProfile::new("process:1234")
            .with_execution_count(10)
            .with_connection_count(5)
            .with_privilege_changes(2);

        repo.insert(&profile).await.unwrap();
        let found = repo.find_by_object_id("process:1234").await.unwrap();
        assert!(found.is_some());
        let row = found.unwrap();
        assert_eq!(row.object_id, "process:1234");
        assert_eq!(row.execution_count, 10);
        assert_eq!(row.connection_count, 5);
    }

    #[tokio::test]
    async fn behavior_profile_count() {
        let store = test_store().await;
        let repo = BehaviorProfileRepository::new(&store);
        assert_eq!(repo.count().await.unwrap(), 0);

        let profile = sentinelx_behavior::BehaviorProfile::new("process:1");
        repo.insert(&profile).await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn ioc_insert_and_query() {
        let store = test_store().await;
        let repo = IoCRepository::new(&store);

        let ioc = sentinelx_intelligence::IoC::new(
            sentinelx_intelligence::IoCType::Hash,
            "abc123def",
            "test_source",
        )
        .with_severity("high")
        .with_confidence(0.9);

        repo.insert(&ioc).await.unwrap();

        let found = repo.find_by_value("hash", "abc123def").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().severity, "high");
    }

    #[tokio::test]
    async fn ioc_count_by_type() {
        let store = test_store().await;
        let repo = IoCRepository::new(&store);

        repo.insert(&sentinelx_intelligence::IoC::new(
            sentinelx_intelligence::IoCType::Hash,
            "h1",
            "test",
        ))
        .await
        .unwrap();
        repo.insert(&sentinelx_intelligence::IoC::new(
            sentinelx_intelligence::IoCType::IpAddress,
            "1.2.3.4",
            "test",
        ))
        .await
        .unwrap();

        let counts = repo.count_by_type().await.unwrap();
        assert_eq!(counts.get("hash"), Some(&1));
        assert_eq!(counts.get("ip_address"), Some(&1));
    }

    #[tokio::test]
    async fn yara_rule_insert_and_query() {
        let store = test_store().await;
        let repo = YaraRuleRepository::new(&store);

        let rule =
            sentinelx_intelligence::YaraRule::new("test_rule", "rule test { condition: true }");
        repo.insert(&rule).await.unwrap();

        let found = repo.find_by_name("test_rule").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "test_rule");
    }

    #[tokio::test]
    async fn sigma_rule_insert_and_query() {
        let store = test_store().await;
        let repo = SigmaRuleRepository::new(&store);

        let rule = sentinelx_intelligence::SigmaRule::new("test_sigma");
        repo.insert(&rule).await.unwrap();

        let found = repo.find_by_name("test_sigma").await.unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn cve_insert_and_query() {
        let store = test_store().await;
        let repo = CveRepository::new(&store);

        let cve = sentinelx_intelligence::CveEntry::new("CVE-2024-1234", 9.5);
        repo.insert(&cve).await.unwrap();

        let found = repo.find_by_id("CVE-2024-1234").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().cvss_score, 9.5);
    }

    #[tokio::test]
    async fn ioc_delete() {
        let store = test_store().await;
        let repo = IoCRepository::new(&store);

        let ioc = sentinelx_intelligence::IoC::new(
            sentinelx_intelligence::IoCType::Hash,
            "to_delete",
            "test",
        );
        repo.insert(&ioc).await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 1);

        let deleted = repo.delete("hash", "to_delete").await.unwrap();
        assert!(deleted);
        assert_eq!(repo.count().await.unwrap(), 0);
    }
}
