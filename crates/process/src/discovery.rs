use sentinelx_core::discovery::DiscoveryProvider;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::objects::ProcessObject;
use crate::scanner::ProcessScanner;

pub struct ProcessDiscoveryProvider {
    scanner: ProcessScanner,
}

impl ProcessDiscoveryProvider {
    pub fn new() -> Self {
        Self {
            scanner: ProcessScanner::new(),
        }
    }
}

impl Default for ProcessDiscoveryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for ProcessDiscoveryProvider {
    fn name(&self) -> &str {
        "process_discovery"
    }

    fn description(&self) -> &str {
        "Discovers running processes from /proc"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::Process]
    }

    async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError> {
        let processes = self.scanner.scan_all();
        let count = processes.len();
        let objects: Vec<SentinelObject> = processes
            .into_iter()
            .map(|p| ProcessObject::from(p).to_sentinel_object("process_discovery"))
            .collect();

        tracing::debug!(discovered = count, "Process discovery completed");
        Ok(objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_process_discovery_provider_name() {
        let provider = ProcessDiscoveryProvider::new();
        assert_eq!(provider.name(), "process_discovery");
    }

    #[tokio::test]
    async fn test_process_discovery_discovers_own_process() {
        let provider = ProcessDiscoveryProvider::new();
        let objects = provider.discover().await.unwrap();
        let self_pid = std::process::id();
        assert!(
            objects
                .iter()
                .any(|o| o.id == format!("process:{}", self_pid)),
            "Should discover own process"
        );
    }

    #[tokio::test]
    async fn test_process_discovery_returns_process_objects() {
        let provider = ProcessDiscoveryProvider::new();
        let objects = provider.discover().await.unwrap();
        assert!(!objects.is_empty());
        for obj in &objects {
            assert_eq!(obj.object_type, ObjectType::Process);
            assert!(obj.metadata.properties.contains_key("pid"));
            assert!(obj.metadata.properties.contains_key("name"));
        }
    }

    #[tokio::test]
    async fn test_supported_types() {
        let provider = ProcessDiscoveryProvider::new();
        let types = provider.supported_object_types();
        assert_eq!(types, vec![ObjectType::Process]);
    }
}
