use sentinelx_core::discovery::DiscoveryProvider;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::objects::ModuleObject;
use crate::scanner::ModuleScanner;

pub struct ModuleDiscoveryProvider {
    scanner: ModuleScanner,
}

impl ModuleDiscoveryProvider {
    pub fn new() -> Self {
        Self {
            scanner: ModuleScanner::new(),
        }
    }
}

impl Default for ModuleDiscoveryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for ModuleDiscoveryProvider {
    fn name(&self) -> &str {
        "module_discovery"
    }

    fn description(&self) -> &str {
        "Discovers kernel modules from /proc/modules"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::KernelModule]
    }

    async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError> {
        let modules = self.scanner.scan_proc_modules();
        let count = modules.len();
        let objects: Vec<SentinelObject> = modules
            .into_iter()
            .map(|m| ModuleObject::from(m).to_sentinel_object("module_discovery"))
            .collect();

        tracing::debug!(discovered = count, "Module discovery completed");
        Ok(objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_module_discovery_provider_name() {
        let provider = ModuleDiscoveryProvider::new();
        assert_eq!(provider.name(), "module_discovery");
    }

    #[tokio::test]
    async fn test_module_discovery_returns_module_objects() {
        let provider = ModuleDiscoveryProvider::new();
        let objects = provider.discover().await.unwrap();
        for obj in &objects {
            assert_eq!(obj.object_type, ObjectType::KernelModule);
            assert!(obj.metadata.properties.contains_key("name"));
            assert!(obj.metadata.properties.contains_key("size"));
        }
    }

    #[tokio::test]
    async fn test_supported_types() {
        let provider = ModuleDiscoveryProvider::new();
        let types = provider.supported_object_types();
        assert_eq!(types, vec![ObjectType::KernelModule]);
    }
}
