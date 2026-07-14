use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info};

use sentinelx_common::event::{Event, EventKind};

const DEFAULT_CHANNEL_CAPACITY: usize = 10_000;
const DEFAULT_HISTORY_SIZE: usize = 1_000;

pub struct EventBus {
    sender: broadcast::Sender<Event>,
    history: Arc<RwLock<VecDeque<Event>>>,
    history_size: usize,
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        Self {
            sender,
            history: Arc::new(RwLock::new(VecDeque::new())),
            history_size: DEFAULT_HISTORY_SIZE,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            history: Arc::new(RwLock::new(VecDeque::new())),
            history_size: DEFAULT_HISTORY_SIZE,
        }
    }

    pub fn with_history_size(mut self, size: usize) -> Self {
        self.history_size = size;
        self
    }

    pub async fn publish(&self, event: Event) -> Result<(), EventBusError> {
        debug!(
            event_kind = ?event.kind,
            event_id = %event.id,
            "Publishing event"
        );

        {
            let mut history = self.history.write().await;
            if history.len() >= self.history_size {
                history.pop_front();
            }
            history.push_back(event.clone());
        }

        self.sender
            .send(event)
            .map_err(|e| EventBusError::PublishFailed(e.to_string()))?;
        Ok(())
    }

    pub fn subscribe(&self, name: &str) -> broadcast::Receiver<Event> {
        info!(subscriber = name, "New event bus subscriber");
        self.sender.subscribe()
    }

    pub fn subscribe_filtered(
        &self,
        name: &str,
        kinds: Vec<EventKind>,
    ) -> broadcast::Receiver<Event> {
        info!(
            subscriber = name,
            kinds = ?kinds,
            "New filtered event bus subscriber"
        );
        let _ = kinds;
        self.sender.subscribe()
    }

    pub fn sender(&self) -> broadcast::Sender<Event> {
        self.sender.clone()
    }

    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    pub async fn history(&self) -> Vec<Event> {
        let history = self.history.read().await;
        history.iter().cloned().collect()
    }

    pub async fn history_by_kind(&self, kind: EventKind) -> Vec<Event> {
        let history = self.history.read().await;
        history.iter().filter(|e| e.kind == kind).cloned().collect()
    }

    pub async fn history_count(&self) -> usize {
        let history = self.history.read().await;
        history.len()
    }

    pub async fn clear_history(&self) {
        let mut history = self.history.write().await;
        history.clear();
    }

    pub fn filtered_receiver(
        receiver: broadcast::Receiver<Event>,
        kinds: Vec<EventKind>,
    ) -> FilteredReceiver {
        FilteredReceiver {
            inner: receiver,
            kinds,
        }
    }
}

pub struct FilteredReceiver {
    inner: broadcast::Receiver<Event>,
    kinds: Vec<EventKind>,
}

impl FilteredReceiver {
    pub async fn recv(&mut self) -> Result<Event, EventBusError> {
        loop {
            let event = self
                .inner
                .recv()
                .await
                .map_err(|e| EventBusError::Lagged(e.to_string()))?;

            if self.kinds.is_empty() || self.kinds.contains(&event.kind) {
                return Ok(event);
            }
        }
    }
}

pub struct EventStats {
    pub total_published: u64,
    pub by_kind: HashMap<String, u64>,
    pub by_source: HashMap<String, u64>,
    pub history_size: usize,
    pub current_subscribers: usize,
}

pub struct EventStatsCollector {
    total_published: u64,
    by_kind: HashMap<String, u64>,
    by_source: HashMap<String, u64>,
}

impl EventStatsCollector {
    pub fn new() -> Self {
        Self {
            total_published: 0,
            by_kind: HashMap::new(),
            by_source: HashMap::new(),
        }
    }

    pub fn record(&mut self, event: &Event) {
        self.total_published += 1;
        let kind = format!("{:?}", event.kind);
        *self.by_kind.entry(kind).or_insert(0) += 1;

        let source = format!("{:?}", event.source);
        *self.by_source.entry(source).or_insert(0) += 1;
    }

    pub fn stats(&self, history_size: usize, current_subscribers: usize) -> EventStats {
        EventStats {
            total_published: self.total_published,
            by_kind: self.by_kind.clone(),
            by_source: self.by_source.clone(),
            history_size,
            current_subscribers,
        }
    }
}

impl Default for EventStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            history: Arc::clone(&self.history),
            history_size: self.history_size,
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EventBusError {
    #[error("Failed to publish event: {0}")]
    PublishFailed(String),

    #[error("Subscriber lagged: {0}")]
    Lagged(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_common::event::{EventKind, EventSource};
    use serde_json::json;

    fn make_event(kind: EventKind) -> Event {
        Event::new(kind, EventSource::System, json!({}))
    }

    #[tokio::test]
    async fn publish_and_receive() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe("test");

        let event = make_event(EventKind::ProcessCreated);
        bus.publish(event).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.kind, EventKind::ProcessCreated);
    }

    #[tokio::test]
    async fn multiple_subscribers_receive() {
        let bus = EventBus::new();
        let mut rx1 = bus.subscribe("sub1");
        let mut rx2 = bus.subscribe("sub2");

        let event = make_event(EventKind::ModuleLoaded);
        bus.publish(event).await.unwrap();

        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.kind, r2.kind);
    }

    #[tokio::test]
    async fn event_history() {
        let bus = EventBus::new().with_history_size(10);
        let _rx = bus.subscribe("history_test");

        for i in 0..5 {
            let kind = if i % 2 == 0 {
                EventKind::ProcessCreated
            } else {
                EventKind::ModuleLoaded
            };
            bus.publish(make_event(kind)).await.unwrap();
        }

        assert_eq!(bus.history_count().await, 5);

        let process_events = bus.history_by_kind(EventKind::ProcessCreated).await;
        assert_eq!(process_events.len(), 3);

        let module_events = bus.history_by_kind(EventKind::ModuleLoaded).await;
        assert_eq!(module_events.len(), 2);
    }

    #[tokio::test]
    async fn history_eviction() {
        let bus = EventBus::new().with_history_size(3);
        let _rx = bus.subscribe("eviction_test");

        for _ in 0..5 {
            bus.publish(make_event(EventKind::ProcessCreated))
                .await
                .unwrap();
        }

        assert_eq!(bus.history_count().await, 3);
    }

    #[tokio::test]
    async fn clear_history() {
        let bus = EventBus::new();
        let _rx = bus.subscribe("clear_test");
        bus.publish(make_event(EventKind::ProcessCreated))
            .await
            .unwrap();

        assert_eq!(bus.history_count().await, 1);
        bus.clear_history().await;
        assert_eq!(bus.history_count().await, 0);
    }

    #[tokio::test]
    async fn filtered_receiver() {
        let bus = EventBus::new();
        let rx = bus.subscribe("filtered");
        let mut filtered = EventBus::filtered_receiver(rx, vec![EventKind::HookDetected]);

        bus.publish(make_event(EventKind::ProcessCreated))
            .await
            .unwrap();
        bus.publish(make_event(EventKind::HookDetected))
            .await
            .unwrap();

        let event = filtered.recv().await.unwrap();
        assert_eq!(event.kind, EventKind::HookDetected);
    }

    #[tokio::test]
    async fn full_history() {
        let bus = EventBus::new();
        let _rx = bus.subscribe("full_history_test");
        bus.publish(make_event(EventKind::ProcessCreated))
            .await
            .unwrap();
        bus.publish(make_event(EventKind::ModuleLoaded))
            .await
            .unwrap();

        let history = bus.history().await;
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn stats_collector() {
        let mut collector = EventStatsCollector::new();
        let e1 = make_event(EventKind::ProcessCreated);
        let e2 = make_event(EventKind::HookDetected);

        collector.record(&e1);
        collector.record(&e2);
        collector.record(&e1);

        let stats = collector.stats(10, 2);
        assert_eq!(stats.total_published, 3);
        assert_eq!(stats.current_subscribers, 2);
        assert!(stats.by_kind.contains_key("ProcessCreated"));
    }

    #[test]
    fn subscriber_count() {
        let bus = EventBus::new();
        assert_eq!(bus.subscriber_count(), 0);
        let _rx = bus.subscribe("s1");
        assert_eq!(bus.subscriber_count(), 1);
        let _rx2 = bus.subscribe("s2");
        assert_eq!(bus.subscriber_count(), 2);
    }
}
