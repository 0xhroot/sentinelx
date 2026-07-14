use chrono::{DateTime, Utc};
use std::sync::Arc;

use crate::error::CoreError;
use crate::object::{ObjectType, SentinelObject};

#[async_trait::async_trait]
pub trait DiscoveryProvider: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn supported_object_types(&self) -> Vec<ObjectType>;
    async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError>;
}

pub struct DiscoveryResult {
    pub provider: String,
    pub objects: Vec<SentinelObject>,
    pub timestamp: DateTime<Utc>,
    pub duration_ms: u64,
}

pub struct DiscoveryEngine {
    providers: Vec<Arc<Box<dyn DiscoveryProvider>>>,
}

impl DiscoveryEngine {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn register(&mut self, provider: Arc<Box<dyn DiscoveryProvider>>) {
        tracing::info!(provider = provider.name(), "Registering discovery provider");
        self.providers.push(provider);
    }

    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    pub async fn discover_all(&self) -> Vec<DiscoveryResult> {
        let mut results = Vec::with_capacity(self.providers.len());

        for provider in &self.providers {
            let start = std::time::Instant::now();
            let name = provider.name().to_string();

            match provider.discover().await {
                Ok(objects) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    tracing::info!(
                        provider = %name,
                        objects_found = objects.len(),
                        duration_ms,
                        "Discovery provider completed"
                    );
                    results.push(DiscoveryResult {
                        provider: name,
                        objects,
                        timestamp: Utc::now(),
                        duration_ms,
                    });
                }
                Err(e) => {
                    tracing::error!(
                        provider = %name,
                        error = %e,
                        "Discovery provider failed"
                    );
                }
            }
        }

        results
    }
}

impl Default for DiscoveryEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct MockProvider {
        name: String,
        objects: Vec<SentinelObject>,
    }

    impl MockProvider {
        fn new(name: &str, count: usize) -> Self {
            let objects: Vec<SentinelObject> = (0..count)
                .map(|i| SentinelObject::new(ObjectType::Process, name, format!("obj_{}", i)))
                .collect();
            Self {
                name: name.to_string(),
                objects,
            }
        }
    }

    #[async_trait::async_trait]
    impl DiscoveryProvider for MockProvider {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "Mock provider for testing"
        }

        fn supported_object_types(&self) -> Vec<ObjectType> {
            vec![ObjectType::Process]
        }

        async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError> {
            Ok(self.objects.clone())
        }
    }

    struct FailingProvider;

    #[async_trait::async_trait]
    impl DiscoveryProvider for FailingProvider {
        fn name(&self) -> &str {
            "failing_provider"
        }

        fn description(&self) -> &str {
            "Always fails"
        }

        fn supported_object_types(&self) -> Vec<ObjectType> {
            vec![ObjectType::File]
        }

        async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError> {
            Err(CoreError::Discovery("simulated failure".to_string()))
        }
    }

    fn make_provider(name: &str, count: usize) -> Arc<Box<dyn DiscoveryProvider>> {
        Arc::new(Box::new(MockProvider::new(name, count)))
    }

    #[test]
    fn test_engine_creation() {
        let engine = DiscoveryEngine::new();
        assert_eq!(engine.provider_count(), 0);
    }

    #[test]
    fn test_register_provider() {
        let mut engine = DiscoveryEngine::new();
        engine.register(make_provider("test", 3));
        assert_eq!(engine.provider_count(), 1);
    }

    #[tokio::test]
    async fn test_discover_all() {
        let mut engine = DiscoveryEngine::new();
        engine.register(make_provider("p1", 2));
        engine.register(make_provider("p2", 3));

        let results = engine.discover_all().await;
        assert_eq!(results.len(), 2);

        let total_objects: usize = results.iter().map(|r| r.objects.len()).sum();
        assert_eq!(total_objects, 5);
    }

    #[tokio::test]
    async fn test_discover_with_failure() {
        let mut engine = DiscoveryEngine::new();
        engine.register(make_provider("good", 1));
        engine.register(Arc::new(Box::new(FailingProvider)));

        let results = engine.discover_all().await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].objects.len(), 1);
    }

    #[tokio::test]
    async fn test_discover_result_metadata() {
        let mut engine = DiscoveryEngine::new();
        engine.register(make_provider("test", 1));

        let results = engine.discover_all().await;
        assert_eq!(results[0].provider, "test");
        assert!(!results[0].objects.is_empty());
    }
}
