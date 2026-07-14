use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{info, warn};

use sentinelx_telemetry::provider::{ProviderError, Result, TelemetryProvider};
use sentinelx_telemetry::types::{
    ProviderInfo, ProviderStatus, TelemetryEvent, TelemetryEventType,
};

use crate::engine::{BpfEvent, BpfEventType, EbpfEngine};

#[allow(dead_code)]
fn bpf_event_to_telemetry(event: &BpfEvent) -> Option<TelemetryEvent> {
    let event_type = match event.event_type {
        BpfEventType::ProcessExec => TelemetryEventType::ProcessExec,
        BpfEventType::ProcessExit => TelemetryEventType::ProcessExit,
        BpfEventType::ProcessFork => TelemetryEventType::ProcessFork,
        BpfEventType::ProcessClone => TelemetryEventType::ProcessClone,
        BpfEventType::ProcessSetuid => TelemetryEventType::ProcessSetuid,
        BpfEventType::ProcessSetgid => TelemetryEventType::ProcessSetgid,
        BpfEventType::ProcessPtrace => TelemetryEventType::ProcessPtrace,
        BpfEventType::ProcessCapChange => TelemetryEventType::ProcessCapChange,
        BpfEventType::FileOpen => TelemetryEventType::FileOpen,
        BpfEventType::FileWrite => TelemetryEventType::FileWrite,
        BpfEventType::FileDelete => TelemetryEventType::FileDelete,
        BpfEventType::FileRename => TelemetryEventType::FileRename,
        BpfEventType::FilePermChange => TelemetryEventType::FilePermChange,
        BpfEventType::FileExecute => TelemetryEventType::FileExecute,
        BpfEventType::NetConnect => TelemetryEventType::NetConnect,
        BpfEventType::NetBind => TelemetryEventType::NetBind,
        BpfEventType::KernelModuleLoad => TelemetryEventType::KernelModuleLoad,
        BpfEventType::KernelModuleUnload => TelemetryEventType::KernelModuleUnload,
        BpfEventType::KernelBpfLoad => TelemetryEventType::KernelBpfLoad,
        BpfEventType::KernelParamChange => TelemetryEventType::KernelParamChange,
    };

    let mut event_builder = TelemetryEvent::new("ebpf", event_type)
        .with_pid(event.pid)
        .with_uid(event.uid)
        .with_metadata(serde_json::json!({
            "comm": event.comm,
            "tgid": event.tgid,
            "ppid": event.ppid,
            "parent_pid": event.parent_pid,
            "flags": event.flags,
            "kernel_timestamp": event.timestamp,
        }));

    if let Some(obj) = match event.event_type {
        BpfEventType::FileOpen
        | BpfEventType::FileWrite
        | BpfEventType::FileDelete
        | BpfEventType::FileRename
        | BpfEventType::FilePermChange
        | BpfEventType::FileExecute => Some(format!("pid:{}", event.pid)),
        BpfEventType::NetConnect | BpfEventType::NetBind => Some(format!("pid:{}", event.pid)),
        BpfEventType::KernelModuleLoad | BpfEventType::KernelModuleUnload => {
            Some(event.comm.clone())
        }
        _ => None,
    } {
        event_builder = event_builder.with_object_id(&obj);
    }

    Some(event_builder)
}

pub struct EbpfTelemetryProvider {
    engine: EbpfEngine,
    status: ProviderStatus,
    events_received: Arc<AtomicU64>,
    events_dropped: Arc<AtomicU64>,
}

impl EbpfTelemetryProvider {
    pub fn new(engine: EbpfEngine) -> Self {
        Self {
            engine,
            status: ProviderStatus::Stopped,
            events_received: Arc::new(AtomicU64::new(0)),
            events_dropped: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[async_trait]
impl TelemetryProvider for EbpfTelemetryProvider {
    fn name(&self) -> &str {
        "ebpf"
    }

    fn description(&self) -> &str {
        "eBPF telemetry provider (real kernel instrumentation via Aya)"
    }

    fn status(&self) -> ProviderStatus {
        self.status.clone()
    }

    async fn initialize(&mut self, _event_tx: mpsc::Sender<TelemetryEvent>) -> Result<()> {
        info!("Initializing eBPF telemetry provider");

        self.status = ProviderStatus::Initializing;

        match self.engine.initialize().await {
            Ok(()) => {
                if self.engine.can_load_programs() {
                    let caps = self.engine.capabilities();
                    if caps.has_bpf || caps.has_sys_admin {
                        self.status = ProviderStatus::Running;
                        info!("eBPF telemetry provider initialized (kernel mode)");
                    } else {
                        self.status = ProviderStatus::Degraded;
                        info!("eBPF telemetry provider degraded (no CAP_BPF/CAP_SYS_ADMIN)");
                    }
                } else {
                    self.status = ProviderStatus::Degraded;
                    info!("eBPF telemetry provider degraded (capabilities not available)");
                }
                Ok(())
            }
            Err(e) => {
                warn!("eBPF engine init failed: {}, degrading", e);
                self.status = ProviderStatus::Degraded;
                Ok(())
            }
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down eBPF telemetry provider");

        match self.engine.shutdown().await {
            Ok(()) => {
                self.status = ProviderStatus::Stopped;
                info!("eBPF telemetry provider shut down");
                Ok(())
            }
            Err(e) => {
                self.status = ProviderStatus::Error;
                Err(ProviderError::ShutdownFailed(format!(
                    "eBPF shutdown failed: {}",
                    e
                )))
            }
        }
    }

    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: self.name().to_string(),
            status: self.status.clone(),
            events_received: self.events_received.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            started_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EbpfConfig;

    #[tokio::test]
    async fn ebpf_provider_creation() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        let provider = EbpfTelemetryProvider::new(engine);
        assert_eq!(provider.name(), "ebpf");
        assert_eq!(provider.status(), ProviderStatus::Stopped);
    }

    #[tokio::test]
    async fn ebpf_provider_initialize_and_shutdown() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        let mut provider = EbpfTelemetryProvider::new(engine);

        let (tx, _rx) = mpsc::channel(16);
        provider.initialize(tx).await.unwrap();
        let s = provider.status();
        assert!(
            s == ProviderStatus::Running || s == ProviderStatus::Degraded,
            "expected Running or Degraded, got {:?}",
            s
        );

        provider.shutdown().await.unwrap();
        assert_eq!(provider.status(), ProviderStatus::Stopped);
    }

    #[test]
    fn ebpf_provider_info() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        let provider = EbpfTelemetryProvider::new(engine);
        let info = provider.info();
        assert_eq!(info.name, "ebpf");
        assert_eq!(info.events_received, 0);
    }

    #[test]
    fn ebpf_provider_description() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        let provider = EbpfTelemetryProvider::new(engine);
        assert!(provider.description().contains("kernel instrumentation"));
    }

    #[test]
    fn bpf_event_to_telemetry_mapping_process() {
        let event = BpfEvent {
            event_type: BpfEventType::ProcessExec,
            pid: 100,
            tgid: 100,
            uid: 0,
            comm: "bash".to_string(),
            timestamp: 12345,
            flags: 0,
            parent_pid: 99,
            ppid: 99,
        };
        let telemetry = bpf_event_to_telemetry(&event).unwrap();
        assert_eq!(telemetry.provider, "ebpf");
        assert_eq!(telemetry.event_type, TelemetryEventType::ProcessExec);
        assert_eq!(telemetry.pid, Some(100));
        assert_eq!(telemetry.uid, Some(0));
    }

    #[test]
    fn bpf_event_to_telemetry_mapping_file() {
        let event = BpfEvent {
            event_type: BpfEventType::FileOpen,
            pid: 200,
            tgid: 200,
            uid: 1000,
            comm: "cat".to_string(),
            timestamp: 99999,
            flags: 0,
            parent_pid: 199,
            ppid: 199,
        };
        let telemetry = bpf_event_to_telemetry(&event).unwrap();
        assert_eq!(telemetry.event_type, TelemetryEventType::FileOpen);
        assert!(telemetry.object_id.is_some());
    }

    #[test]
    fn bpf_event_to_telemetry_mapping_network() {
        let event = BpfEvent {
            event_type: BpfEventType::NetConnect,
            pid: 300,
            tgid: 300,
            uid: 1000,
            comm: "curl".to_string(),
            timestamp: 55555,
            flags: 0,
            parent_pid: 299,
            ppid: 299,
        };
        let telemetry = bpf_event_to_telemetry(&event).unwrap();
        assert_eq!(telemetry.event_type, TelemetryEventType::NetConnect);
    }

    #[test]
    fn bpf_event_to_telemetry_mapping_kernel() {
        let event = BpfEvent {
            event_type: BpfEventType::KernelModuleLoad,
            pid: 0,
            tgid: 0,
            uid: 0,
            comm: "nvidia".to_string(),
            timestamp: 11111,
            flags: 0,
            parent_pid: 0,
            ppid: 0,
        };
        let telemetry = bpf_event_to_telemetry(&event).unwrap();
        assert_eq!(telemetry.event_type, TelemetryEventType::KernelModuleLoad);
        assert_eq!(telemetry.object_id, Some("nvidia".to_string()));
    }

    #[test]
    fn provider_starts_stopped() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        let provider = EbpfTelemetryProvider::new(engine);
        assert_eq!(provider.status(), ProviderStatus::Stopped);
    }
}
