use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::types::{ProviderInfo, ProviderStatus, TelemetryEvent};

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("Provider not available: {0}")]
    NotAvailable(String),

    #[error("Provider initialization failed: {0}")]
    InitFailed(String),

    #[error("Provider runtime error: {0}")]
    Runtime(String),

    #[error("Provider shutdown error: {0}")]
    ShutdownFailed(String),
}

pub type Result<T> = std::result::Result<T, ProviderError>;

#[async_trait]
pub trait TelemetryProvider: Send + Sync {
    fn name(&self) -> &str;

    fn description(&self) -> &str;

    fn status(&self) -> ProviderStatus;

    async fn initialize(&mut self, event_tx: mpsc::Sender<TelemetryEvent>) -> Result<()>;

    async fn shutdown(&mut self) -> Result<()>;

    fn info(&self) -> ProviderInfo;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TelemetryEvent, TelemetryEventType};
    use tokio::sync::mpsc;

    struct MockProvider {
        name: String,
        status: ProviderStatus,
    }

    impl MockProvider {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                status: ProviderStatus::Stopped,
            }
        }
    }

    #[async_trait]
    impl TelemetryProvider for MockProvider {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "Mock telemetry provider for testing"
        }

        fn status(&self) -> ProviderStatus {
            self.status.clone()
        }

        async fn initialize(&mut self, event_tx: mpsc::Sender<TelemetryEvent>) -> Result<()> {
            self.status = ProviderStatus::Running;
            let event = TelemetryEvent::new(&self.name, TelemetryEventType::ProcessCreate);
            let _ = event_tx.send(event).await;
            Ok(())
        }

        async fn shutdown(&mut self) -> Result<()> {
            self.status = ProviderStatus::Stopped;
            Ok(())
        }

        fn info(&self) -> ProviderInfo {
            ProviderInfo {
                name: self.name.clone(),
                status: self.status.clone(),
                events_received: 100,
                events_dropped: 0,
                started_at: None,
            }
        }
    }

    #[tokio::test]
    async fn mock_provider_lifecycle() {
        let mut provider = MockProvider::new("mock_test");
        assert_eq!(provider.name(), "mock_test");
        assert_eq!(provider.status(), ProviderStatus::Stopped);

        let (tx, mut rx) = mpsc::channel(16);
        provider.initialize(tx).await.unwrap();
        assert_eq!(provider.status(), ProviderStatus::Running);

        let event = rx.recv().await.unwrap();
        assert_eq!(event.provider, "mock_test");
        assert_eq!(event.event_type, TelemetryEventType::ProcessCreate);

        provider.shutdown().await.unwrap();
        assert_eq!(provider.status(), ProviderStatus::Stopped);
    }

    #[tokio::test]
    async fn mock_provider_info() {
        let provider = MockProvider::new("test");
        let info = provider.info();
        assert_eq!(info.name, "test");
        assert_eq!(info.events_received, 100);
        assert_eq!(info.events_dropped, 0);
    }
}
