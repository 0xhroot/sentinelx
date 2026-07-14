use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::types::ObjectAssessment;

pub struct AssessmentStore {
    assessments: RwLock<HashMap<String, Vec<ObjectAssessment>>>,
}

impl AssessmentStore {
    pub fn new() -> Self {
        Self {
            assessments: RwLock::new(HashMap::new()),
        }
    }

    pub async fn store(&self, assessment: ObjectAssessment) {
        let mut store = self.assessments.write().await;
        store
            .entry(assessment.object_id.clone())
            .or_default()
            .push(assessment);
    }

    pub async fn store_batch(&self, assessments: Vec<ObjectAssessment>) {
        let mut store = self.assessments.write().await;
        for assessment in assessments {
            store
                .entry(assessment.object_id.clone())
                .or_default()
                .push(assessment);
        }
    }

    pub async fn get_latest(&self, object_id: &str) -> Option<ObjectAssessment> {
        let store = self.assessments.read().await;
        store.get(object_id).and_then(|v| v.last().cloned())
    }

    pub async fn get_history(&self, object_id: &str) -> Vec<ObjectAssessment> {
        let store = self.assessments.read().await;
        store.get(object_id).cloned().unwrap_or_default()
    }

    pub async fn get_by_id(&self, assessment_id: uuid::Uuid) -> Option<ObjectAssessment> {
        let store = self.assessments.read().await;
        for assessments in store.values() {
            if let Some(a) = assessments.iter().find(|a| a.id == assessment_id) {
                return Some(a.clone());
            }
        }
        None
    }

    pub async fn get_all_latest(&self) -> Vec<ObjectAssessment> {
        let store = self.assessments.read().await;
        store.values().filter_map(|v| v.last().cloned()).collect()
    }

    pub async fn search(&self, query: &str) -> Vec<ObjectAssessment> {
        let store = self.assessments.read().await;
        store
            .values()
            .flatten()
            .filter(|a| {
                a.object_id.contains(query)
                    || a.reasons.iter().any(|r| r.contains(query))
                    || a.warnings.iter().any(|w| w.contains(query))
            })
            .cloned()
            .collect()
    }

    pub async fn expire_old(&self, max_age: chrono::Duration) {
        let mut store = self.assessments.write().await;
        let cutoff = chrono::Utc::now() - max_age;
        for assessments in store.values_mut() {
            assessments.retain(|a| a.timestamp > cutoff);
        }
        store.retain(|_, v| !v.is_empty());
    }

    pub async fn count(&self) -> usize {
        let store = self.assessments.read().await;
        store.values().map(|v| v.len()).sum()
    }

    pub async fn object_count(&self) -> usize {
        let store = self.assessments.read().await;
        store.len()
    }
}

impl Default for AssessmentStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let store = AssessmentStore::new();
        let assessment = ObjectAssessment::new("process:1234").with_trust(80);
        store.store(assessment).await;

        let latest = store.get_latest("process:1234").await;
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().trust, 80);
    }

    #[tokio::test]
    async fn test_get_history() {
        let store = AssessmentStore::new();
        store
            .store(ObjectAssessment::new("process:1").with_trust(50))
            .await;
        store
            .store(ObjectAssessment::new("process:1").with_trust(70))
            .await;
        store
            .store(ObjectAssessment::new("process:1").with_trust(90))
            .await;

        let history = store.get_history("process:1").await;
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].trust, 50);
        assert_eq!(history[2].trust, 90);
    }

    #[tokio::test]
    async fn test_get_by_id() {
        let store = AssessmentStore::new();
        let assessment = ObjectAssessment::new("process:1").with_trust(80);
        let id = assessment.id;
        store.store(assessment).await;

        let found = store.get_by_id(id).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().trust, 80);
    }

    #[tokio::test]
    async fn test_get_all_latest() {
        let store = AssessmentStore::new();
        store
            .store(ObjectAssessment::new("process:1").with_trust(50))
            .await;
        store
            .store(ObjectAssessment::new("process:2").with_trust(70))
            .await;
        store
            .store(ObjectAssessment::new("process:1").with_trust(90))
            .await;

        let all = store.get_all_latest().await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_search() {
        let store = AssessmentStore::new();
        store
            .store(ObjectAssessment::new("process:1234").with_reason("Package verified"))
            .await;
        store
            .store(ObjectAssessment::new("file:/etc/passwd").with_warning("Modified"))
            .await;

        let results = store.search("Package").await;
        assert_eq!(results.len(), 1);

        let results = store.search("process").await;
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_count() {
        let store = AssessmentStore::new();
        assert_eq!(store.count().await, 0);

        store
            .store(ObjectAssessment::new("process:1").with_trust(50))
            .await;
        store
            .store(ObjectAssessment::new("process:1").with_trust(60))
            .await;
        store
            .store(ObjectAssessment::new("process:2").with_trust(70))
            .await;

        assert_eq!(store.count().await, 3);
        assert_eq!(store.object_count().await, 2);
    }

    #[tokio::test]
    async fn test_expire_old() {
        let store = AssessmentStore::new();
        store
            .store(ObjectAssessment::new("process:1").with_trust(50))
            .await;
        store
            .store(ObjectAssessment::new("process:2").with_trust(70))
            .await;

        store.expire_old(chrono::Duration::seconds(0)).await;
        assert_eq!(store.count().await, 0);
    }
}
