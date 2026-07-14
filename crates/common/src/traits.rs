use crate::error::Result;
use crate::event::Event;
use crate::severity::Severity;
use crate::types::{ThreatCategory, ThreatEvent};
use async_trait::async_trait;

#[async_trait]
pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn category(&self) -> ThreatCategory;
    fn severity(&self) -> Severity;
    async fn detect(&self) -> Result<Vec<ThreatEvent>>;
    async fn initialize(&mut self) -> Result<()> {
        Ok(())
    }
    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn scan(&self) -> Result<Vec<ThreatEvent>>;
}

pub trait EventProducer: Send + Sync {
    fn produce(&self, event: Event);
}

pub trait EventConsumer: Send + Sync {
    fn consume(&self, event: &Event);
}

#[async_trait]
pub trait IntegrityChecker: Send + Sync {
    fn name(&self) -> &str;
    async fn baseline(&self) -> Result<()>;
    async fn check(&self) -> Result<Vec<ThreatEvent>>;
}
