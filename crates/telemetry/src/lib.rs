pub mod bus;
pub mod collector;
pub mod engine;
pub mod normalizer;
pub mod proc_connector;
pub mod provider;
pub mod provider_manager;
pub mod subscriber;
pub mod types;

pub use bus::{BusConfig, TelemetryBus};
pub use collector::{MetricsCollector, MetricsSnapshot};
pub use engine::{create_synthetic_event, ProviderConfig, TelemetryConfig, TelemetryEngine};
pub use normalizer::EventNormalizer;
pub use proc_connector::{ProcConnector, ProcConnectorConfig};
pub use provider::{ProviderError, TelemetryProvider};
pub use provider_manager::{
    Capability, CapabilityReport, KernelLatencyReport, ProviderHealthReport, ProviderManager,
    TelemetryRateReport,
};
pub use subscriber::init_tracing;
pub use types::{
    ProviderInfo, ProviderStatus, TelemetryCategory, TelemetryEvent, TelemetryEventType,
    TelemetryStats,
};
