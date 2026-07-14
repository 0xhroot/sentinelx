pub mod behavior;
pub mod engine;
pub mod event_bus;
pub mod plugin;
pub mod registry;
pub mod scoring;
pub mod trust;

pub use behavior::{BehaviorGraph, BehaviorState, ProcessBehavior};
pub use engine::DetectionEngine;
pub use event_bus::EventBus;
pub use plugin::{Plugin, PluginError, PluginHealth, PluginManager, PluginMetadata, PluginState};
pub use registry::{DetectorInfo, DetectorRegistry};
pub use scoring::{ThreatScore, ThreatScorer};
pub use trust::{TrustEngine, TrustEvent, TrustEventType};
