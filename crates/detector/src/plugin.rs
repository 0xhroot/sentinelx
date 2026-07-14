use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use sentinelx_common::types::ThreatEvent;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PluginState {
    Registered,
    Initializing,
    Running,
    Stopped,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub enabled: bool,
    pub state: PluginState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginHealth {
    pub name: String,
    pub healthy: bool,
    pub message: String,
    pub last_check: String,
}

#[async_trait]
pub trait Plugin: Send + Sync {
    fn metadata(&self) -> PluginMetadata;
    async fn initialize(&mut self) -> Result<(), PluginError>;
    async fn start(&mut self) -> Result<(), PluginError>;
    async fn stop(&mut self) -> Result<(), PluginError>;
    async fn health_check(&self) -> PluginHealth;
    async fn run_scan(&self) -> Result<Vec<ThreatEvent>, PluginError>;
    fn set_enabled(&mut self, enabled: bool);
    fn as_any(&self) -> &dyn std::any::Any;
}

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Plugin initialization failed: {0}")]
    InitFailed(String),
    #[error("Plugin start failed: {0}")]
    StartFailed(String),
    #[error("Plugin stop failed: {0}")]
    StopFailed(String),
    #[error("Plugin scan failed: {0}")]
    ScanFailed(String),
    #[error("Plugin not found: {0}")]
    NotFound(String),
    #[error("Plugin already registered: {0}")]
    AlreadyRegistered(String),
}

pub struct PluginManager {
    plugins: HashMap<String, Arc<RwLock<dyn Plugin>>>,
    load_order: Vec<String>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            load_order: Vec::new(),
        }
    }

    pub async fn register(&mut self, plugin: Arc<RwLock<dyn Plugin>>) -> Result<(), PluginError> {
        let meta = {
            let p = plugin.read().await;
            p.metadata()
        };

        if self.plugins.contains_key(&meta.name) {
            return Err(PluginError::AlreadyRegistered(meta.name));
        }

        self.plugins.insert(meta.name.clone(), plugin);
        self.load_order.push(meta.name);
        Ok(())
    }

    pub async fn initialize_all(&mut self) -> Vec<PluginHealth> {
        let mut results = Vec::new();

        for name in self.load_order.clone() {
            if let Some(plugin) = self.plugins.get_mut(&name) {
                let mut p = plugin.write().await;
                match p.initialize().await {
                    Ok(()) => {
                        results.push(PluginHealth {
                            name: name.clone(),
                            healthy: true,
                            message: "Initialized successfully".to_string(),
                            last_check: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                    Err(e) => {
                        results.push(PluginHealth {
                            name: name.clone(),
                            healthy: false,
                            message: format!("Init failed: {}", e),
                            last_check: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        results
    }

    pub async fn start_all(&mut self) -> Vec<PluginHealth> {
        let mut results = Vec::new();

        for name in self.load_order.clone() {
            if let Some(plugin) = self.plugins.get_mut(&name) {
                let mut p = plugin.write().await;
                match p.start().await {
                    Ok(()) => {
                        results.push(PluginHealth {
                            name: name.clone(),
                            healthy: true,
                            message: "Started successfully".to_string(),
                            last_check: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                    Err(e) => {
                        results.push(PluginHealth {
                            name: name.clone(),
                            healthy: false,
                            message: format!("Start failed: {}", e),
                            last_check: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        results
    }

    pub async fn stop_all(&mut self) {
        for name in self.load_order.clone() {
            if let Some(plugin) = self.plugins.get_mut(&name) {
                let mut p = plugin.write().await;
                let _ = p.stop().await;
            }
        }
    }

    pub async fn run_all_scans(&self) -> Vec<Result<Vec<ThreatEvent>, PluginError>> {
        let mut results = Vec::new();

        for name in &self.load_order {
            if let Some(plugin) = self.plugins.get(name) {
                let p = plugin.read().await;
                results.push(p.run_scan().await);
            }
        }

        results
    }

    pub async fn health_check_all(&self) -> Vec<PluginHealth> {
        let mut results = Vec::new();

        for name in &self.load_order {
            if let Some(plugin) = self.plugins.get(name) {
                let p = plugin.read().await;
                results.push(p.health_check().await);
            }
        }

        results
    }

    pub async fn get_plugin(&self, name: &str) -> Option<Arc<RwLock<dyn Plugin>>> {
        self.plugins.get(name).cloned()
    }

    pub fn list_plugins(&self) -> Vec<String> {
        self.load_order.clone()
    }

    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    pub async fn enable_plugin(&mut self, name: &str) -> Result<(), PluginError> {
        if let Some(plugin) = self.plugins.get_mut(name) {
            let mut p = plugin.write().await;
            p.set_enabled(true);
            Ok(())
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }

    pub async fn disable_plugin(&mut self, name: &str) -> Result<(), PluginError> {
        if let Some(plugin) = self.plugins.get_mut(name) {
            let mut p = plugin.write().await;
            p.set_enabled(false);
            Ok(())
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    struct MockPlugin {
        metadata: PluginMetadata,
    }

    impl MockPlugin {
        fn new(name: &str) -> Self {
            Self {
                metadata: PluginMetadata {
                    name: name.to_string(),
                    version: "1.0.0".to_string(),
                    author: "test".to_string(),
                    description: format!("Mock plugin {}", name),
                    enabled: true,
                    state: PluginState::Registered,
                },
            }
        }
    }

    #[async_trait]
    impl Plugin for MockPlugin {
        fn metadata(&self) -> PluginMetadata {
            self.metadata.clone()
        }

        async fn initialize(&mut self) -> Result<(), PluginError> {
            self.metadata.state = PluginState::Initializing;
            Ok(())
        }

        async fn start(&mut self) -> Result<(), PluginError> {
            self.metadata.state = PluginState::Running;
            Ok(())
        }

        async fn stop(&mut self) -> Result<(), PluginError> {
            self.metadata.state = PluginState::Stopped;
            Ok(())
        }

        async fn health_check(&self) -> PluginHealth {
            PluginHealth {
                name: self.metadata.name.clone(),
                healthy: true,
                message: "OK".to_string(),
                last_check: chrono::Utc::now().to_rfc3339(),
            }
        }

        async fn run_scan(&self) -> Result<Vec<ThreatEvent>, PluginError> {
            Ok(vec![])
        }

        fn set_enabled(&mut self, enabled: bool) {
            self.metadata.enabled = enabled;
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_plugin_manager_new() {
        let mgr = PluginManager::new();
        assert_eq!(mgr.count(), 0);
    }

    #[tokio::test]
    async fn test_register_plugin() {
        let mut mgr = PluginManager::new();
        let plugin = Arc::new(RwLock::new(MockPlugin::new("test_plugin")));
        mgr.register(plugin).await.unwrap();
        assert_eq!(mgr.count(), 1);
        assert_eq!(mgr.list_plugins(), vec!["test_plugin".to_string()]);
    }

    #[tokio::test]
    async fn test_duplicate_register() {
        let mut mgr = PluginManager::new();
        let p1 = Arc::new(RwLock::new(MockPlugin::new("dup")));
        let p2 = Arc::new(RwLock::new(MockPlugin::new("dup")));
        mgr.register(p1).await.unwrap();
        assert!(mgr.register(p2).await.is_err());
    }

    #[tokio::test]
    async fn test_initialize_all() {
        let mut mgr = PluginManager::new();
        let plugin = Arc::new(RwLock::new(MockPlugin::new("init_test")));
        mgr.register(plugin).await.unwrap();
        let results = mgr.initialize_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].healthy);
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut mgr = PluginManager::new();
        let plugin = Arc::new(RwLock::new(MockPlugin::new("lifecycle")));
        mgr.register(plugin).await.unwrap();

        let init_results = mgr.initialize_all().await;
        assert!(init_results[0].healthy);

        let start_results = mgr.start_all().await;
        assert!(start_results[0].healthy);

        mgr.stop_all().await;
    }

    #[tokio::test]
    async fn test_health_check() {
        let mut mgr = PluginManager::new();
        let plugin = Arc::new(RwLock::new(MockPlugin::new("health")));
        mgr.register(plugin).await.unwrap();

        let results = mgr.health_check_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].healthy);
    }

    #[tokio::test]
    async fn test_run_scans() {
        let mut mgr = PluginManager::new();
        let plugin = Arc::new(RwLock::new(MockPlugin::new("scanner")));
        mgr.register(plugin).await.unwrap();

        let results = mgr.run_all_scans().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
    }

    #[tokio::test]
    async fn test_not_found() {
        let mut mgr = PluginManager::new();
        assert!(mgr.enable_plugin("nonexistent").await.is_err());
        assert!(mgr.disable_plugin("nonexistent").await.is_err());
    }
}
