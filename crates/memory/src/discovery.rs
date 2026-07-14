use sentinelx_core::discovery::DiscoveryProvider;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::objects::MemoryObject;

pub struct MemoryDiscoveryProvider;

impl MemoryDiscoveryProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MemoryDiscoveryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for MemoryDiscoveryProvider {
    fn name(&self) -> &str {
        "memory_discovery"
    }

    fn description(&self) -> &str {
        "Discovers memory integrity checks (kallsyms, self maps)"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::MemoryRegion]
    }

    async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError> {
        let mut objects = Vec::new();

        let kallsyms_obj = MemoryObject::new(
            "kallsyms_integrity",
            "/proc/kallsyms",
            "Kernel symbol table integrity check",
        );
        objects.push(kallsyms_obj.to_sentinel_object("memory_discovery"));

        let self_maps_obj = MemoryObject::new(
            "self_maps_integrity",
            "/proc/self/maps",
            "Process memory maps integrity check",
        );
        objects.push(self_maps_obj.to_sentinel_object("memory_discovery"));

        tracing::debug!(discovered = objects.len(), "Memory discovery completed");
        Ok(objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_discovery_provider_name() {
        let provider = MemoryDiscoveryProvider::new();
        assert_eq!(provider.name(), "memory_discovery");
    }

    #[tokio::test]
    async fn test_memory_discovery_returns_objects() {
        let provider = MemoryDiscoveryProvider::new();
        let objects = provider.discover().await.unwrap();
        assert!(!objects.is_empty());
        for obj in &objects {
            assert_eq!(obj.object_type, ObjectType::MemoryRegion);
            assert!(obj.metadata.properties.contains_key("name"));
        }
    }

    #[tokio::test]
    async fn test_supported_types() {
        let provider = MemoryDiscoveryProvider::new();
        let types = provider.supported_object_types();
        assert_eq!(types, vec![ObjectType::MemoryRegion]);
    }
}
