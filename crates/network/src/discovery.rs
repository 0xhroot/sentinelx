use sentinelx_core::discovery::DiscoveryProvider;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::objects::NetworkObject;
use crate::scanner::NetworkScanner;

pub struct NetworkDiscoveryProvider {
    scanner: NetworkScanner,
}

impl NetworkDiscoveryProvider {
    pub fn new() -> Self {
        Self {
            scanner: NetworkScanner::new(),
        }
    }
}

impl Default for NetworkDiscoveryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for NetworkDiscoveryProvider {
    fn name(&self) -> &str {
        "network_discovery"
    }

    fn description(&self) -> &str {
        "Discovers network connections from /proc/net"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::NetworkConnection]
    }

    async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError> {
        let connections = self.scanner.scan_all();
        let count = connections.len();
        let objects: Vec<SentinelObject> = connections
            .into_iter()
            .map(|c| NetworkObject::from(c).to_sentinel_object("network_discovery"))
            .collect();

        tracing::debug!(discovered = count, "Network discovery completed");
        Ok(objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_discovery_provider_name() {
        let provider = NetworkDiscoveryProvider::new();
        assert_eq!(provider.name(), "network_discovery");
    }

    #[tokio::test]
    async fn test_network_discovery_returns_network_objects() {
        let provider = NetworkDiscoveryProvider::new();
        let objects = provider.discover().await.unwrap();
        for obj in &objects {
            assert_eq!(obj.object_type, ObjectType::NetworkConnection);
            assert!(obj.metadata.properties.contains_key("local_ip"));
            assert!(obj.metadata.properties.contains_key("inode"));
        }
    }

    #[tokio::test]
    async fn test_supported_types() {
        let provider = NetworkDiscoveryProvider::new();
        let types = provider.supported_object_types();
        assert_eq!(types, vec![ObjectType::NetworkConnection]);
    }
}
