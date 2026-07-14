use sentinelx_core::discovery::DiscoveryProvider;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::objects::IntegrityObject;

const CRITICAL_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ld.so.preload",
    "/boot/grub/grub.cfg",
    "/etc/crontab",
];

pub struct IntegrityDiscoveryProvider;

impl IntegrityDiscoveryProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IntegrityDiscoveryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for IntegrityDiscoveryProvider {
    fn name(&self) -> &str {
        "integrity_discovery"
    }

    fn description(&self) -> &str {
        "Discovers critical system files for integrity monitoring"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::File]
    }

    async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError> {
        let mut objects = Vec::new();

        for path in CRITICAL_FILES {
            let obj = IntegrityObject::new(path);
            objects.push(obj.to_sentinel_object("integrity_discovery"));
        }

        tracing::debug!(discovered = objects.len(), "Integrity discovery completed");
        Ok(objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_integrity_discovery_provider_name() {
        let provider = IntegrityDiscoveryProvider::new();
        assert_eq!(provider.name(), "integrity_discovery");
    }

    #[tokio::test]
    async fn test_integrity_discovery_returns_objects() {
        let provider = IntegrityDiscoveryProvider::new();
        let objects = provider.discover().await.unwrap();
        assert!(!objects.is_empty());
        for obj in &objects {
            assert_eq!(obj.object_type, ObjectType::File);
            assert!(obj.metadata.properties.contains_key("path"));
        }
    }

    #[tokio::test]
    async fn test_supported_types() {
        let provider = IntegrityDiscoveryProvider::new();
        let types = provider.supported_object_types();
        assert_eq!(types, vec![ObjectType::File]);
    }
}
