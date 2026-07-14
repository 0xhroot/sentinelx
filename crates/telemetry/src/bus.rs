use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, RwLock};
use tracing::debug;

use crate::types::{TelemetryEvent, TelemetryStats};

#[derive(Clone)]
pub struct BusConfig {
    pub channel_capacity: usize,
    pub broadcast_capacity: usize,
    pub max_rate_per_second: u64,
    pub buffer_capacity: usize,
}

impl Default for BusConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 10000,
            broadcast_capacity: 256,
            max_rate_per_second: 50000,
            buffer_capacity: 50000,
        }
    }
}

pub struct TelemetryBus {
    broadcast_tx: broadcast::Sender<TelemetryEvent>,
    buffer: Arc<RwLock<VecDeque<TelemetryEvent>>>,
    config: BusConfig,
    total_events: AtomicU64,
    dropped_events: AtomicU64,
    events_this_second: AtomicU64,
    rate_window_start: RwLock<Instant>,
    enabled: AtomicBool,
}

impl TelemetryBus {
    pub fn new(config: BusConfig) -> Self {
        let (broadcast_tx, _) = broadcast::channel(config.broadcast_capacity);
        Self {
            broadcast_tx,
            buffer: Arc::new(RwLock::new(VecDeque::with_capacity(config.buffer_capacity))),
            config,
            total_events: AtomicU64::new(0),
            dropped_events: AtomicU64::new(0),
            events_this_second: AtomicU64::new(0),
            rate_window_start: RwLock::new(Instant::now()),
            enabled: AtomicBool::new(true),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TelemetryEvent> {
        self.broadcast_tx.subscribe()
    }

    pub async fn publish(&self, event: TelemetryEvent) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        if !self.check_rate_limit().await {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
            debug!("Event dropped due to rate limiting");
            return false;
        }

        self.total_events.fetch_add(1, Ordering::Relaxed);

        if self.broadcast_tx.receiver_count() > 0 && self.broadcast_tx.send(event.clone()).is_err()
        {
            debug!("No active broadcast subscribers");
        }

        let mut buffer = self.buffer.write().await;
        if buffer.len() >= self.config.buffer_capacity {
            buffer.pop_front();
        }
        buffer.push_back(event);

        true
    }

    async fn check_rate_limit(&self) -> bool {
        let mut window_start = self.rate_window_start.write().await;
        let now = Instant::now();

        if now.duration_since(*window_start) >= Duration::from_secs(1) {
            self.events_this_second.store(0, Ordering::Relaxed);
            *window_start = now;
            return true;
        }

        let current = self.events_this_second.fetch_add(1, Ordering::Relaxed);
        current < self.config.max_rate_per_second
    }

    pub async fn recent_events(&self, count: usize) -> Vec<TelemetryEvent> {
        let buffer = self.buffer.read().await;
        let len = buffer.len();
        let start = len.saturating_sub(count);
        buffer.range(start..).cloned().collect()
    }

    pub fn stats(&self) -> TelemetryStats {
        let total = self.total_events.load(Ordering::Relaxed);
        let dropped = self.dropped_events.load(Ordering::Relaxed);
        let buffer_size = self.buffer.try_read().map(|b| b.len()).unwrap_or(0);

        TelemetryStats {
            total_events: total,
            events_by_provider: std::collections::HashMap::new(),
            events_by_category: std::collections::HashMap::new(),
            dropped_events: dropped,
            active_providers: self.broadcast_tx.receiver_count() as u32,
            buffer_size,
            buffer_capacity: self.config.buffer_capacity,
            current_rate_per_second: 0.0,
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn config(&self) -> &BusConfig {
        &self.config
    }

    pub async fn clear_buffer(&self) {
        let mut buffer = self.buffer.write().await;
        buffer.clear();
    }

    pub fn total_events(&self) -> u64 {
        self.total_events.load(Ordering::Relaxed)
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }
}

impl Default for TelemetryBus {
    fn default() -> Self {
        Self::new(BusConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TelemetryEventType;

    fn make_event(name: &str) -> TelemetryEvent {
        TelemetryEvent::new(name, TelemetryEventType::ProcessCreate)
    }

    #[tokio::test]
    async fn bus_publish_and_subscribe() {
        let bus = TelemetryBus::default();
        let mut rx = bus.subscribe();

        let event = make_event("test");
        bus.publish(event.clone()).await;

        let received = rx.recv().await.unwrap();
        assert_eq!(received.id, event.id);
        assert_eq!(received.provider, "test");
    }

    #[tokio::test]
    async fn bus_multiple_subscribers() {
        let bus = TelemetryBus::default();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let event = make_event("test");
        bus.publish(event.clone()).await;

        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.id, r2.id);
    }

    #[tokio::test]
    async fn bus_recent_events() {
        let bus = TelemetryBus::default();

        for i in 0..5 {
            let event = TelemetryEvent::new(
                &format!("provider_{}", i),
                TelemetryEventType::ProcessCreate,
            );
            bus.publish(event).await;
        }

        let recent = bus.recent_events(3).await;
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].provider, "provider_2");
    }

    #[tokio::test]
    async fn bus_stats() {
        let bus = TelemetryBus::default();
        bus.publish(make_event("test")).await;
        bus.publish(make_event("test")).await;

        let stats = bus.stats();
        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.buffer_size, 2);
        assert_eq!(stats.buffer_capacity, 50000);
    }

    #[tokio::test]
    async fn bus_disabled_drops_events() {
        let bus = TelemetryBus::default();
        bus.set_enabled(false);

        let result = bus.publish(make_event("test")).await;
        assert!(!result);
        assert_eq!(bus.dropped_events(), 1);
        assert_eq!(bus.total_events(), 0);
    }

    #[tokio::test]
    async fn bus_rate_limiting() {
        let config = BusConfig {
            max_rate_per_second: 5,
            ..Default::default()
        };
        let bus = TelemetryBus::new(config);

        let mut published = 0;
        for _ in 0..10 {
            if bus.publish(make_event("test")).await {
                published += 1;
            }
        }

        assert!(published <= 6);
    }

    #[tokio::test]
    async fn bus_clear_buffer() {
        let bus = TelemetryBus::default();
        bus.publish(make_event("test")).await;
        assert_eq!(bus.stats().buffer_size, 1);

        bus.clear_buffer().await;
        assert_eq!(bus.stats().buffer_size, 0);
    }

    #[tokio::test]
    async fn bus_buffer_eviction() {
        let config = BusConfig {
            buffer_capacity: 3,
            ..Default::default()
        };
        let bus = TelemetryBus::new(config);

        for i in 0..5 {
            let event = TelemetryEvent::new(&format!("p{}", i), TelemetryEventType::ProcessCreate);
            bus.publish(event).await;
        }

        let recent = bus.recent_events(10).await;
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].provider, "p2");
    }

    #[tokio::test]
    async fn bus_default_config() {
        let bus = TelemetryBus::default();
        assert!(bus.is_enabled());
        assert_eq!(bus.config().channel_capacity, 10000);
        assert_eq!(bus.config().broadcast_capacity, 256);
    }
}
