use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::info;

use crate::provider::{Result, TelemetryProvider};
use crate::types::{ProviderInfo, ProviderStatus, TelemetryEvent, TelemetryEventType};

#[derive(Clone)]
pub struct ProcConnectorConfig {
    pub poll_interval_ms: u64,
    pub scan_proc: bool,
    pub scan_network: bool,
}

impl Default for ProcConnectorConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 1000,
            scan_proc: true,
            scan_network: true,
        }
    }
}

pub struct ProcConnector {
    name: String,
    config: ProcConnectorConfig,
    status: ProviderStatus,
    events_received: Arc<AtomicU64>,
    events_dropped: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    task_handle: Option<JoinHandle<()>>,
}

impl ProcConnector {
    pub fn new(config: ProcConnectorConfig) -> Self {
        Self {
            name: "proc_connector".to_string(),
            config,
            status: ProviderStatus::Stopped,
            events_received: Arc::new(AtomicU64::new(0)),
            events_dropped: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            task_handle: None,
        }
    }

    fn scan_proc_fs() -> Vec<TelemetryEvent> {
        let mut events = Vec::new();

        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if let Some(pid_str) = name.to_str() {
                    if pid_str.chars().all(|c| c.is_ascii_digit()) && pid_str != "self" {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            let proc_path = format!("/proc/{}", pid);
                            let mut event = TelemetryEvent::new(
                                "proc_connector",
                                TelemetryEventType::ProcessCreate,
                            )
                            .with_pid(pid);

                            if let Ok(status) =
                                std::fs::read_to_string(format!("{}/status", proc_path))
                            {
                                for line in status.lines() {
                                    if line.starts_with("Name:") {
                                        let name =
                                            line.split_whitespace().nth(1).unwrap_or("unknown");
                                        event = event.with_object_id(name);
                                    } else if line.starts_with("Uid:") {
                                        if let Some(uid_str) = line.split_whitespace().nth(1) {
                                            if let Ok(uid) = uid_str.parse::<u32>() {
                                                event = event.with_uid(uid);
                                            }
                                        }
                                    }
                                }
                            }

                            event = event.with_metadata(serde_json::json!({
                                "proc_path": proc_path,
                                "source": "procfs",
                            }));

                            events.push(event);
                        }
                    }
                }
            }
        }

        events
    }

    fn scan_net_connections() -> Vec<TelemetryEvent> {
        let mut events = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            for (idx, line) in content.lines().enumerate() {
                if idx == 0 {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Some(inode) = parts.get(9) {
                        let event =
                            TelemetryEvent::new("proc_connector", TelemetryEventType::NetConnect)
                                .with_metadata(serde_json::json!({
                                    "local_address": parts[1],
                                    "remote_address": parts[2],
                                    "state": parts[3],
                                    "inode": inode,
                                    "source": "procfs",
                                }));
                        events.push(event);
                    }
                }
            }
        }

        events
    }

    async fn run_polling_loop(
        config: ProcConnectorConfig,
        event_tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
        events_received: Arc<AtomicU64>,
    ) {
        let interval = std::time::Duration::from_millis(config.poll_interval_ms);
        let mut seen_pids: HashMap<u32, ()> = HashMap::new();

        while running.load(Ordering::Relaxed) {
            if config.scan_proc {
                let proc_events = Self::scan_proc_fs();
                for event in proc_events {
                    if let Some(pid) = event.pid {
                        if let std::collections::hash_map::Entry::Vacant(e) = seen_pids.entry(pid) {
                            e.insert(());
                            let _ = event_tx.send(event).await;
                            events_received.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        let _ = event_tx.send(event).await;
                        events_received.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            if config.scan_network {
                let net_events = Self::scan_net_connections();
                for event in net_events {
                    let _ = event_tx.send(event).await;
                    events_received.fetch_add(1, Ordering::Relaxed);
                }
            }

            tokio::time::sleep(interval).await;
        }
    }
}

#[async_trait]
impl TelemetryProvider for ProcConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Process connector using /proc filesystem (fallback provider)"
    }

    fn status(&self) -> ProviderStatus {
        self.status.clone()
    }

    async fn initialize(&mut self, event_tx: mpsc::Sender<TelemetryEvent>) -> Result<()> {
        info!("Initializing proc connector (fallback)");
        self.status = ProviderStatus::Running;
        self.running.store(true, Ordering::SeqCst);

        let config = self.config.clone_config();
        let running = Arc::clone(&self.running);
        let events_received = Arc::clone(&self.events_received);

        self.task_handle = Some(tokio::spawn(Self::run_polling_loop(
            config,
            event_tx,
            running,
            events_received,
        )));

        info!("Proc connector initialized (fallback mode)");
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down proc connector");
        self.running.store(false, Ordering::SeqCst);

        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }

        self.status = ProviderStatus::Stopped;
        info!("Proc connector shut down");
        Ok(())
    }

    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: self.name.clone(),
            status: self.status.clone(),
            events_received: self.events_received.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            started_at: None,
        }
    }
}

impl ProcConnectorConfig {
    fn clone_config(&self) -> Self {
        Self {
            poll_interval_ms: self.poll_interval_ms,
            scan_proc: self.scan_proc,
            scan_network: self.scan_network,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_connector_default_config() {
        let config = ProcConnectorConfig::default();
        assert_eq!(config.poll_interval_ms, 1000);
        assert!(config.scan_proc);
        assert!(config.scan_network);
    }

    #[test]
    fn proc_connector_creation() {
        let connector = ProcConnector::new(ProcConnectorConfig::default());
        assert_eq!(connector.name(), "proc_connector");
        assert_eq!(connector.status(), ProviderStatus::Stopped);
    }

    #[tokio::test]
    async fn proc_connector_initialize_and_shutdown() {
        let mut connector = ProcConnector::new(ProcConnectorConfig {
            poll_interval_ms: 10000,
            scan_proc: false,
            scan_network: false,
        });

        let (tx, _rx) = mpsc::channel(100);
        connector.initialize(tx).await.unwrap();
        assert_eq!(connector.status(), ProviderStatus::Running);

        connector.shutdown().await.unwrap();
        assert_eq!(connector.status(), ProviderStatus::Stopped);
    }

    #[test]
    fn proc_connector_info() {
        let connector = ProcConnector::new(ProcConnectorConfig::default());
        let info = connector.info();
        assert_eq!(info.name, "proc_connector");
        assert_eq!(info.events_received, 0);
    }

    #[test]
    fn scan_proc_fs_returns_events() {
        let events = ProcConnector::scan_proc_fs();
        assert!(!events.is_empty());
        for event in &events {
            assert_eq!(event.provider, "proc_connector");
            assert!(event.pid.is_some());
        }
    }

    #[test]
    fn scan_proc_fs_events_have_metadata() {
        let events = ProcConnector::scan_proc_fs();
        if let Some(event) = events.first() {
            assert!(event.metadata.is_object());
            assert!(event.metadata.get("source").is_some());
        }
    }
}
