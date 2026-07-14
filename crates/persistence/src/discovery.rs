use sentinelx_core::discovery::DiscoveryProvider;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::objects::PersistenceObject;
use crate::scanner::PersistenceScanner;

pub struct PersistenceDiscoveryProvider {
    scanner: PersistenceScanner,
}

impl PersistenceDiscoveryProvider {
    pub fn new() -> Self {
        Self {
            scanner: PersistenceScanner::new(),
        }
    }
}

impl Default for PersistenceDiscoveryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for PersistenceDiscoveryProvider {
    fn name(&self) -> &str {
        "persistence_discovery"
    }

    fn description(&self) -> &str {
        "Discovers persistence mechanisms (systemd, cron, rc.local, ld.so.preload, profiles, init)"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::Service]
    }

    async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError> {
        let entries = self.scanner.scan_all();
        let count = entries.len();
        let objects: Vec<SentinelObject> = entries
            .into_iter()
            .map(|e| PersistenceObject::from(e).to_sentinel_object("persistence_discovery"))
            .collect();

        tracing::debug!(discovered = count, "Persistence discovery completed");
        Ok(objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_persistence_discovery_provider_name() {
        let provider = PersistenceDiscoveryProvider::new();
        assert_eq!(provider.name(), "persistence_discovery");
    }

    #[tokio::test]
    async fn test_persistence_discovery_returns_objects() {
        let provider = PersistenceDiscoveryProvider::new();
        let objects = provider.discover().await.unwrap();
        for obj in &objects {
            assert_eq!(obj.object_type, ObjectType::Service);
            assert!(obj.metadata.properties.contains_key("name"));
            assert!(obj.metadata.properties.contains_key("entry_type"));
        }
    }

    #[tokio::test]
    async fn test_supported_types() {
        let provider = PersistenceDiscoveryProvider::new();
        let types = provider.supported_object_types();
        assert_eq!(types, vec![ObjectType::Service]);
    }
}
