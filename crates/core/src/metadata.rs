use std::sync::Arc;

use crate::error::CoreError;
use crate::object::SentinelObject;

#[async_trait::async_trait]
pub trait MetadataCollector: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn enrich(&self, objects: &mut [SentinelObject]) -> Result<(), CoreError>;
}

pub struct MetadataEngine {
    collectors: Vec<Arc<dyn MetadataCollector>>,
}

impl MetadataEngine {
    pub fn new() -> Self {
        Self {
            collectors: Vec::new(),
        }
    }

    pub fn register(&mut self, collector: Arc<dyn MetadataCollector>) {
        tracing::info!(
            collector = collector.name(),
            "Registering metadata collector"
        );
        self.collectors.push(collector);
    }

    pub fn collector_count(&self) -> usize {
        self.collectors.len()
    }

    pub async fn enrich_all(&self, objects: &mut [SentinelObject]) -> Result<usize, CoreError> {
        let mut total_enriched = 0;

        for collector in &self.collectors {
            let before = count_enriched(objects);
            if let Err(e) = collector.enrich(objects).await {
                tracing::warn!(
                    collector = collector.name(),
                    error = %e,
                    "Metadata collector failed"
                );
            }
            let after = count_enriched(objects);
            total_enriched += after - before;
        }

        Ok(total_enriched)
    }
}

fn count_enriched(objects: &[SentinelObject]) -> usize {
    objects
        .iter()
        .filter(|o| {
            !o.metadata.properties.is_empty()
                || o.metadata.ownership.is_some()
                || o.metadata.permissions.is_some()
                || !o.metadata.hashes.is_empty()
                || o.metadata.package_info.is_some()
        })
        .count()
}

impl Default for MetadataEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{ObjectType, SentinelObject};

    struct MockMetadataCollector {
        name: String,
    }

    #[async_trait::async_trait]
    impl MetadataCollector for MockMetadataCollector {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "Mock metadata collector"
        }

        async fn enrich(&self, objects: &mut [SentinelObject]) -> Result<(), CoreError> {
            for obj in objects.iter_mut() {
                obj.metadata
                    .properties
                    .insert("enriched".to_string(), serde_json::Value::Bool(true));
            }
            Ok(())
        }
    }

    struct FailingMetadataCollector;

    #[async_trait::async_trait]
    impl MetadataCollector for FailingMetadataCollector {
        fn name(&self) -> &str {
            "failing_collector"
        }

        fn description(&self) -> &str {
            "Always fails"
        }

        async fn enrich(&self, _objects: &mut [SentinelObject]) -> Result<(), CoreError> {
            Err(CoreError::Metadata("simulated failure".to_string()))
        }
    }

    fn make_objects(count: usize) -> Vec<SentinelObject> {
        (0..count)
            .map(|i| SentinelObject::new(ObjectType::Process, "test", format!("obj_{}", i)))
            .collect()
    }

    #[test]
    fn test_engine_creation() {
        let engine = MetadataEngine::new();
        assert_eq!(engine.collector_count(), 0);
    }

    #[test]
    fn test_register_collector() {
        let mut engine = MetadataEngine::new();
        engine.register(Arc::new(MockMetadataCollector {
            name: "test_collector".to_string(),
        }));
        assert_eq!(engine.collector_count(), 1);
    }

    #[tokio::test]
    async fn test_enrich_all() {
        let mut engine = MetadataEngine::new();
        engine.register(Arc::new(MockMetadataCollector {
            name: "test".to_string(),
        }));

        let mut objects = make_objects(3);
        let enriched = engine.enrich_all(&mut objects).await.unwrap();
        assert_eq!(enriched, 3);

        for obj in &objects {
            assert_eq!(
                obj.metadata.properties.get("enriched"),
                Some(&serde_json::Value::Bool(true))
            );
        }
    }

    #[tokio::test]
    async fn test_enrich_with_failure() {
        let mut engine = MetadataEngine::new();
        engine.register(Arc::new(FailingMetadataCollector));

        let mut objects = make_objects(1);
        let enriched = engine.enrich_all(&mut objects).await.unwrap();
        assert_eq!(enriched, 0);
    }

    #[tokio::test]
    async fn test_multiple_collectors() {
        let mut engine = MetadataEngine::new();
        engine.register(Arc::new(MockMetadataCollector {
            name: "collector_1".to_string(),
        }));
        engine.register(Arc::new(MockMetadataCollector {
            name: "collector_2".to_string(),
        }));

        let mut objects = make_objects(2);
        let enriched = engine.enrich_all(&mut objects).await.unwrap();
        assert!(enriched >= 2);
    }
}
