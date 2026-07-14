use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{info, warn};

use crate::bus::{BusConfig, TelemetryBus};
use crate::normalizer::EventNormalizer;
use crate::proc_connector::{ProcConnector, ProcConnectorConfig};
use crate::provider::TelemetryProvider;
use crate::types::{ProviderInfo, TelemetryEvent, TelemetryEventType, TelemetryStats};

pub struct TelemetryConfig {
    pub bus: BusConfig,
    pub provider_configs: HashMap<String, ProviderConfig>,
}

#[derive(Clone)]
pub enum ProviderConfig {
    ProcConnector(ProcConnectorConfig),
    Stub,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        let mut provider_configs = HashMap::new();
        provider_configs.insert(
            "proc_connector".to_string(),
            ProviderConfig::ProcConnector(ProcConnectorConfig::default()),
        );

        Self {
            bus: BusConfig::default(),
            provider_configs,
        }
    }
}

pub struct TelemetryEngine {
    bus: Arc<TelemetryBus>,
    providers: Arc<RwLock<Vec<Box<dyn TelemetryProvider>>>>,
    normalizers: Arc<RwLock<HashMap<String, EventNormalizer>>>,
    event_tx: mpsc::Sender<TelemetryEvent>,
    event_rx: Arc<RwLock<mpsc::Receiver<TelemetryEvent>>>,
    total_events: Arc<AtomicU64>,
    config: TelemetryConfig,
}

impl TelemetryEngine {
    pub fn new(config: TelemetryConfig) -> Self {
        let bus = Arc::new(TelemetryBus::new(config.bus.clone()));
        let (event_tx, event_rx) = mpsc::channel(10000);

        Self {
            bus,
            providers: Arc::new(RwLock::new(Vec::new())),
            normalizers: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            event_rx: Arc::new(RwLock::new(event_rx)),
            total_events: Arc::new(AtomicU64::new(0)),
            config,
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(TelemetryConfig::default())
    }

    pub fn event_sender(&self) -> mpsc::Sender<TelemetryEvent> {
        self.event_tx.clone()
    }

    pub async fn register_provider(&self, provider: Box<dyn TelemetryProvider>) {
        let name = provider.name().to_string();
        info!("Registering telemetry provider: {}", name);

        let normalizer = EventNormalizer::new(&name);
        self.normalizers
            .write()
            .await
            .insert(name.clone(), normalizer);

        self.providers.write().await.push(provider);
    }

    pub async fn initialize_all(&self) {
        let mut providers = self.providers.write().await;
        for provider in providers.iter_mut() {
            let name = provider.name().to_string();
            match provider.initialize(self.event_tx.clone()).await {
                Ok(()) => {
                    info!("Provider '{}' initialized successfully", name);
                }
                Err(e) => {
                    warn!("Provider '{}' failed to initialize: {}", name, e);
                }
            }
        }
    }

    pub async fn shutdown_all(&self) {
        let mut providers = self.providers.write().await;
        for provider in providers.iter_mut() {
            let name = provider.name().to_string();
            if let Err(e) = provider.shutdown().await {
                warn!("Provider '{}' shutdown error: {}", name, e);
            }
        }
        info!("All telemetry providers shut down");
    }

    pub async fn process_events(&self) {
        let mut rx = self.event_rx.write().await;
        while let Some(event) = rx.recv().await {
            self.total_events.fetch_add(1, Ordering::Relaxed);
            self.bus.publish(event).await;
        }
    }

    pub fn bus(&self) -> &TelemetryBus {
        &self.bus
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TelemetryEvent> {
        self.bus.subscribe()
    }

    pub async fn recent_events(&self, count: usize) -> Vec<TelemetryEvent> {
        self.bus.recent_events(count).await
    }

    pub fn stats(&self) -> TelemetryStats {
        let mut stats = self.bus.stats();
        stats.total_events = self.total_events.load(Ordering::Relaxed);
        stats
    }

    pub async fn provider_infos(&self) -> Vec<ProviderInfo> {
        let providers = self.providers.read().await;
        providers.iter().map(|p| p.info()).collect()
    }

    pub async fn provider_names(&self) -> Vec<String> {
        let providers = self.providers.read().await;
        providers.iter().map(|p| p.name().to_string()).collect()
    }

    pub fn bus_stats(&self) -> crate::types::TelemetryStats {
        self.bus.stats()
    }

    pub async fn initialize_default_providers(&self) {
        for (name, config) in self.config.provider_configs.clone() {
            match config {
                ProviderConfig::ProcConnector(proc_config) => {
                    let connector = ProcConnector::new(proc_config);
                    self.register_provider(Box::new(connector)).await;
                }
                ProviderConfig::Stub => {
                    info!("Skipping stub provider: {}", name);
                }
            }
        }

        self.initialize_all().await;
    }
}

impl Default for TelemetryEngine {
    fn default() -> Self {
        Self::with_default_config()
    }
}

pub fn create_synthetic_event(provider: &str, event_type: TelemetryEventType) -> TelemetryEvent {
    let mut event = TelemetryEvent::new(provider, event_type.clone());

    match event_type {
        TelemetryEventType::ProcessCreate | TelemetryEventType::ProcessExec => {
            event = event
                .with_pid(1000 + (Utc::now().timestamp_millis() % 50000) as u32)
                .with_uid(1000)
                .with_metadata(serde_json::json!({
                    "comm": "synthetic_proc",
                    "ppid": 1,
                }));
        }
        TelemetryEventType::FileWrite | TelemetryEventType::FileOpen => {
            event = event
                .with_pid(1000)
                .with_object_id("/tmp/synthetic_file")
                .with_metadata(serde_json::json!({
                    "mode": "0644",
                }));
        }
        TelemetryEventType::NetConnect | TelemetryEventType::NetBind => {
            event = event.with_pid(1000).with_metadata(serde_json::json!({
                "dest_ip": "10.0.0.1",
                "dest_port": 443,
            }));
        }
        TelemetryEventType::KernelModuleLoad => {
            event = event
                .with_pid(0)
                .with_object_id("synthetic_module")
                .with_metadata(serde_json::json!({
                    "address": "0xffffffffc0000000",
                    "size": 65536,
                }));
        }
        _ => {
            event = event.with_metadata(serde_json::json!({
                "type": event_type.as_str(),
            }));
        }
    }

    event
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_default_config() {
        let engine = TelemetryEngine::with_default_config();
        assert!(engine
            .config
            .provider_configs
            .contains_key("proc_connector"));
    }

    #[test]
    fn engine_creation() {
        let engine = TelemetryEngine::default();
        let stats = engine.stats();
        assert_eq!(stats.total_events, 0);
    }

    #[tokio::test]
    async fn engine_register_provider() {
        let engine = TelemetryEngine::default();
        let connector = ProcConnector::new(ProcConnectorConfig {
            poll_interval_ms: 10000,
            scan_proc: false,
            scan_network: false,
        });
        engine.register_provider(Box::new(connector)).await;

        let names = engine.provider_names().await;
        assert!(names.contains(&"proc_connector".to_string()));
    }

    #[tokio::test]
    async fn engine_provider_infos() {
        let engine = TelemetryEngine::default();
        let connector = ProcConnector::new(ProcConnectorConfig {
            poll_interval_ms: 10000,
            scan_proc: false,
            scan_network: false,
        });
        engine.register_provider(Box::new(connector)).await;

        let infos = engine.provider_infos().await;
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].name, "proc_connector");
    }

    #[tokio::test]
    async fn engine_bus_subscribe() {
        let engine = TelemetryEngine::default();
        let mut rx = engine.subscribe();

        let event = create_synthetic_event("test", TelemetryEventType::ProcessCreate);
        engine.bus().publish(event.clone()).await;

        let received = rx.recv().await.unwrap();
        assert_eq!(received.id, event.id);
    }

    #[test]
    fn synthetic_event_process() {
        let event = create_synthetic_event("test", TelemetryEventType::ProcessCreate);
        assert_eq!(event.provider, "test");
        assert_eq!(event.event_type, TelemetryEventType::ProcessCreate);
        assert!(event.pid.is_some());
        assert!(event.metadata.is_object());
    }

    #[test]
    fn synthetic_event_file() {
        let event = create_synthetic_event("test", TelemetryEventType::FileWrite);
        assert_eq!(event.category, crate::types::TelemetryCategory::Filesystem);
        assert!(event.object_id.is_some());
    }

    #[test]
    fn synthetic_event_network() {
        let event = create_synthetic_event("test", TelemetryEventType::NetConnect);
        assert_eq!(event.category, crate::types::TelemetryCategory::Network);
    }

    #[test]
    fn synthetic_event_kernel() {
        let event = create_synthetic_event("test", TelemetryEventType::KernelModuleLoad);
        assert_eq!(event.category, crate::types::TelemetryCategory::Kernel);
    }

    #[tokio::test]
    async fn engine_initialize_default_providers() {
        let mut config = TelemetryConfig::default();
        config.provider_configs.insert(
            "proc_connector".to_string(),
            ProviderConfig::ProcConnector(ProcConnectorConfig {
                poll_interval_ms: 10000,
                scan_proc: false,
                scan_network: false,
            }),
        );

        let engine = TelemetryEngine::new(config);
        engine.initialize_default_providers().await;

        let infos = engine.provider_infos().await;
        assert_eq!(infos.len(), 1);

        engine.shutdown_all().await;
    }

    #[test]
    fn telemetry_config_default() {
        let config = TelemetryConfig::default();
        assert_eq!(config.bus.channel_capacity, 10000);
        assert_eq!(config.bus.broadcast_capacity, 256);
    }
}
