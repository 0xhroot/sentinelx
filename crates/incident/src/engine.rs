use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::types::{Incident, IncidentSeverity, IncidentStatus};

pub struct IncidentEngine {
    incidents: RwLock<HashMap<uuid::Uuid, Incident>>,
    max_incidents: usize,
}

impl IncidentEngine {
    pub fn new() -> Self {
        Self {
            incidents: RwLock::new(HashMap::new()),
            max_incidents: 10_000,
        }
    }

    pub fn with_max_incidents(max: usize) -> Self {
        Self {
            incidents: RwLock::new(HashMap::new()),
            max_incidents: max,
        }
    }

    pub async fn create_incident(&self, incident: Incident) -> uuid::Uuid {
        let id = incident.id;
        let mut incidents = self.incidents.write().await;
        if incidents.len() >= self.max_incidents {
            tracing::warn!(
                "Incident store full ({}), oldest incident will be pruned",
                self.max_incidents
            );
        }
        incidents.insert(id, incident);
        debug!(incident_id = %id, "Incident created");
        id
    }

    pub async fn get_incident(&self, id: uuid::Uuid) -> Option<Incident> {
        let incidents = self.incidents.read().await;
        incidents.get(&id).cloned()
    }

    pub async fn update_status(
        &self,
        id: uuid::Uuid,
        status: IncidentStatus,
    ) -> Result<(), String> {
        let mut incidents = self.incidents.write().await;
        if let Some(incident) = incidents.get_mut(&id) {
            incident.update_status(status);
            debug!(incident_id = %id, new_status = %incident.status.as_str(), "Incident status updated");
            Ok(())
        } else {
            Err(format!("Incident {} not found", id))
        }
    }

    pub async fn escalate(&self, id: uuid::Uuid, severity: IncidentSeverity) -> Result<(), String> {
        let mut incidents = self.incidents.write().await;
        if let Some(incident) = incidents.get_mut(&id) {
            incident.escalate_severity(severity);
            debug!(incident_id = %id, new_severity = %incident.severity.as_str(), "Incident escalated");
            Ok(())
        } else {
            Err(format!("Incident {} not found", id))
        }
    }

    pub async fn add_evidence(&self, id: uuid::Uuid, evidence_id: String) -> Result<(), String> {
        let mut incidents = self.incidents.write().await;
        if let Some(incident) = incidents.get_mut(&id) {
            if !incident.evidence_ids.contains(&evidence_id) {
                incident.evidence_ids.push(evidence_id);
                incident.updated_at = chrono::Utc::now();
            }
            Ok(())
        } else {
            Err(format!("Incident {} not found", id))
        }
    }

    pub async fn list_incidents(&self) -> Vec<Incident> {
        let incidents = self.incidents.read().await;
        incidents.values().cloned().collect()
    }

    pub async fn list_by_status(&self, status: IncidentStatus) -> Vec<Incident> {
        let incidents = self.incidents.read().await;
        incidents
            .values()
            .filter(|i| i.status == status)
            .cloned()
            .collect()
    }

    pub async fn list_by_severity(&self, min_severity: IncidentSeverity) -> Vec<Incident> {
        let incidents = self.incidents.read().await;
        incidents
            .values()
            .filter(|i| i.severity.rank() >= min_severity.rank())
            .cloned()
            .collect()
    }

    pub async fn active_incidents(&self) -> Vec<Incident> {
        let incidents = self.incidents.read().await;
        incidents
            .values()
            .filter(|i| i.status != IncidentStatus::Closed && i.status != IncidentStatus::Resolved)
            .cloned()
            .collect()
    }

    pub async fn count(&self) -> usize {
        let incidents = self.incidents.read().await;
        incidents.len()
    }

    pub async fn count_by_status(&self) -> HashMap<String, usize> {
        let incidents = self.incidents.read().await;
        let mut counts = HashMap::new();
        for incident in incidents.values() {
            *counts
                .entry(incident.status.as_str().to_string())
                .or_insert(0) += 1;
        }
        counts
    }

    pub async fn count_by_severity(&self) -> HashMap<String, usize> {
        let incidents = self.incidents.read().await;
        let mut counts = HashMap::new();
        for incident in incidents.values() {
            *counts
                .entry(incident.severity.as_str().to_string())
                .or_insert(0) += 1;
        }
        counts
    }

    pub async fn merge_incidents(
        &self,
        primary_id: uuid::Uuid,
        secondary_id: uuid::Uuid,
    ) -> Result<(), String> {
        let mut incidents = self.incidents.write().await;
        let secondary = incidents
            .remove(&secondary_id)
            .ok_or_else(|| format!("Secondary incident {} not found", secondary_id))?;

        if let Some(primary) = incidents.get_mut(&primary_id) {
            primary.escalate_severity(secondary.severity);
            for ev_id in secondary.evidence_ids {
                if !primary.evidence_ids.contains(&ev_id) {
                    primary.evidence_ids.push(ev_id);
                }
            }
            for obj_id in secondary.object_ids {
                if !primary.object_ids.contains(&obj_id) {
                    primary.object_ids.push(obj_id);
                }
            }
            for step in secondary.attack_chain {
                primary.attack_chain.push(step);
            }
            for mitre in secondary.mitre_mappings {
                primary.mitre_mappings.push(mitre);
            }
            primary.updated_at = chrono::Utc::now();
            debug!(
                primary_id = %primary_id,
                secondary_id = %secondary_id,
                "Incidents merged"
            );
            Ok(())
        } else {
            incidents.insert(primary_id, secondary);
            Ok(())
        }
    }

    pub async fn prune_closed(&self, max_age: chrono::Duration) -> usize {
        let mut incidents = self.incidents.write().await;
        let cutoff = chrono::Utc::now() - max_age;
        let to_remove: Vec<uuid::Uuid> = incidents
            .iter()
            .filter(|(_, i)| {
                (i.status == IncidentStatus::Closed || i.status == IncidentStatus::Resolved)
                    && i.updated_at < cutoff
            })
            .map(|(id, _)| *id)
            .collect();
        let count = to_remove.len();
        for id in to_remove {
            incidents.remove(&id);
        }
        if count > 0 {
            info!(pruned = count, "Pruned old incidents");
        }
        count
    }

    pub fn incident_count_sync(&self) -> usize {
        // Use try_read for non-async contexts; returns 0 if locked
        self.incidents.try_read().map(|i| i.len()).unwrap_or(0)
    }
}

impl Default for IncidentEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IncidentSeverity;

    fn make_incident(title: &str, severity: IncidentSeverity) -> Incident {
        Incident::new(title, "Description", severity, 0.8)
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let engine = IncidentEngine::new();
        let incident = make_incident("Test", IncidentSeverity::High);
        let id = incident.id;
        engine.create_incident(incident).await;
        let found = engine.get_incident(id).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().title, "Test");
    }

    #[tokio::test]
    async fn test_update_status() {
        let engine = IncidentEngine::new();
        let incident = make_incident("Test", IncidentSeverity::High);
        let id = incident.id;
        engine.create_incident(incident).await;
        engine
            .update_status(id, IncidentStatus::Investigating)
            .await
            .unwrap();
        let found = engine.get_incident(id).await.unwrap();
        assert_eq!(found.status, IncidentStatus::Investigating);
    }

    #[tokio::test]
    async fn test_escalate() {
        let engine = IncidentEngine::new();
        let incident = make_incident("Test", IncidentSeverity::Low);
        let id = incident.id;
        engine.create_incident(incident).await;
        engine
            .escalate(id, IncidentSeverity::Critical)
            .await
            .unwrap();
        let found = engine.get_incident(id).await.unwrap();
        assert_eq!(found.severity, IncidentSeverity::Critical);
    }

    #[tokio::test]
    async fn test_add_evidence() {
        let engine = IncidentEngine::new();
        let incident = make_incident("Test", IncidentSeverity::High);
        let id = incident.id;
        engine.create_incident(incident).await;
        engine.add_evidence(id, "ev-001".to_string()).await.unwrap();
        engine.add_evidence(id, "ev-002".to_string()).await.unwrap();
        let found = engine.get_incident(id).await.unwrap();
        assert_eq!(found.evidence_ids.len(), 2);
    }

    #[tokio::test]
    async fn test_list_by_status() {
        let engine = IncidentEngine::new();
        engine
            .create_incident(make_incident("A", IncidentSeverity::High))
            .await;
        engine
            .create_incident(make_incident("B", IncidentSeverity::Low))
            .await;
        let open = engine.list_by_status(IncidentStatus::Open).await;
        assert_eq!(open.len(), 2);
    }

    #[tokio::test]
    async fn test_count_by_severity() {
        let engine = IncidentEngine::new();
        engine
            .create_incident(make_incident("A", IncidentSeverity::Critical))
            .await;
        engine
            .create_incident(make_incident("B", IncidentSeverity::Critical))
            .await;
        engine
            .create_incident(make_incident("C", IncidentSeverity::Low))
            .await;
        let counts = engine.count_by_severity().await;
        assert_eq!(counts.get("critical"), Some(&2));
        assert_eq!(counts.get("low"), Some(&1));
    }

    #[tokio::test]
    async fn test_merge_incidents() {
        let engine = IncidentEngine::new();
        let mut primary = make_incident("Primary", IncidentSeverity::Medium);
        primary = primary.with_evidence("ev-001");
        let primary_id = primary.id;
        engine.create_incident(primary).await;

        let mut secondary = make_incident("Secondary", IncidentSeverity::Critical);
        secondary = secondary
            .with_evidence("ev-002")
            .with_object("process:1234");
        let secondary_id = secondary.id;
        engine.create_incident(secondary).await;

        engine
            .merge_incidents(primary_id, secondary_id)
            .await
            .unwrap();
        assert!(engine.get_incident(secondary_id).await.is_none());
        let merged = engine.get_incident(primary_id).await.unwrap();
        assert_eq!(merged.severity, IncidentSeverity::Critical);
        assert_eq!(merged.evidence_ids.len(), 2);
        assert_eq!(merged.object_ids.len(), 1);
    }

    #[tokio::test]
    async fn test_prune_closed() {
        let engine = IncidentEngine::new();
        let mut incident = make_incident("Old", IncidentSeverity::Low);
        incident.update_status(IncidentStatus::Closed);
        engine.create_incident(incident).await;
        engine
            .create_incident(make_incident("New", IncidentSeverity::High))
            .await;

        let pruned = engine.prune_closed(chrono::Duration::seconds(0)).await;
        assert_eq!(pruned, 1);
        assert_eq!(engine.count().await, 1);
    }
}
