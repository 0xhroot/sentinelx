use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: DateTime<Utc>,
    pub events_processed: u64,
    pub threats_detected: u64,
    pub scans_completed: u64,
    pub errors: u64,
    pub active_detectors: u32,
    pub memory_usage_bytes: u64,
    pub cpu_usage_percent: f64,
}

#[derive(Debug, Clone)]
pub struct MetricsCollector {
    inner: Arc<MetricsInner>,
}

#[derive(Debug, Default)]
struct MetricsInner {
    events_processed: AtomicU64,
    threats_detected: AtomicU64,
    scans_completed: AtomicU64,
    errors: AtomicU64,
    active_detectors: AtomicU64,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MetricsInner::default()),
        }
    }

    pub fn record_event(&self) {
        self.inner.events_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_threat(&self) {
        self.inner.threats_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_scan(&self) {
        self.inner.scans_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.inner.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_active_detectors(&self, count: u32) {
        self.inner
            .active_detectors
            .store(count as u64, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            timestamp: Utc::now(),
            events_processed: self.inner.events_processed.load(Ordering::Relaxed),
            threats_detected: self.inner.threats_detected.load(Ordering::Relaxed),
            scans_completed: self.inner.scans_completed.load(Ordering::Relaxed),
            errors: self.inner.errors.load(Ordering::Relaxed),
            active_detectors: self.inner.active_detectors.load(Ordering::Relaxed) as u32,
            memory_usage_bytes: get_memory_usage(),
            cpu_usage_percent: 0.0,
        }
    }
}

fn get_memory_usage() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|kb| kb * 1024)
            })
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_counter_works() {
        let collector = MetricsCollector::new();
        collector.record_event();
        collector.record_event();
        collector.record_threat();

        let snap = collector.snapshot();
        assert_eq!(snap.events_processed, 2);
        assert_eq!(snap.threats_detected, 1);
    }

    #[test]
    fn metrics_snapshot_has_timestamp() {
        let collector = MetricsCollector::new();
        let snap = collector.snapshot();
        assert!(!snap.timestamp.to_rfc3339().is_empty());
    }
}
