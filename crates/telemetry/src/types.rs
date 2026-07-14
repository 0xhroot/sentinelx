use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TelemetryCategory {
    Process,
    Filesystem,
    Network,
    Kernel,
    Persistence,
}

impl TelemetryCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Filesystem => "filesystem",
            Self::Network => "network",
            Self::Kernel => "kernel",
            Self::Persistence => "persistence",
        }
    }

    pub fn parse_from(s: &str) -> Option<Self> {
        match s {
            "process" => Some(Self::Process),
            "filesystem" => Some(Self::Filesystem),
            "network" => Some(Self::Network),
            "kernel" => Some(Self::Kernel),
            "persistence" => Some(Self::Persistence),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TelemetryEventType {
    // Process
    ProcessCreate,
    ProcessFork,
    ProcessClone,
    ProcessExec,
    ProcessExit,
    ProcessSetuid,
    ProcessSetgid,
    ProcessPtrace,
    ProcessCapChange,
    // Filesystem
    FileOpen,
    FileClose,
    FileRead,
    FileWrite,
    FileRename,
    FileDelete,
    FileExecute,
    FilePermChange,
    FileOwnChange,
    FileMount,
    FileUnmount,
    // Network
    NetConnect,
    NetAccept,
    NetBind,
    NetListen,
    NetClose,
    NetDnsLookup,
    // Kernel
    KernelModuleLoad,
    KernelModuleUnload,
    KernelBpfLoad,
    KernelParamChange,
    // Persistence
    PersistenceServiceCreate,
    PersistenceCronModify,
    PersistenceRcLocalModify,
    PersistenceLdPreloadModify,
}

impl TelemetryEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessCreate => "process_create",
            Self::ProcessFork => "process_fork",
            Self::ProcessClone => "process_clone",
            Self::ProcessExec => "process_exec",
            Self::ProcessExit => "process_exit",
            Self::ProcessSetuid => "process_setuid",
            Self::ProcessSetgid => "process_setgid",
            Self::ProcessPtrace => "process_ptrace",
            Self::ProcessCapChange => "process_cap_change",
            Self::FileOpen => "file_open",
            Self::FileClose => "file_close",
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::FileRename => "file_rename",
            Self::FileDelete => "file_delete",
            Self::FileExecute => "file_execute",
            Self::FilePermChange => "file_perm_change",
            Self::FileOwnChange => "file_own_change",
            Self::FileMount => "file_mount",
            Self::FileUnmount => "file_unmount",
            Self::NetConnect => "net_connect",
            Self::NetAccept => "net_accept",
            Self::NetBind => "net_bind",
            Self::NetListen => "net_listen",
            Self::NetClose => "net_close",
            Self::NetDnsLookup => "net_dns_lookup",
            Self::KernelModuleLoad => "kernel_module_load",
            Self::KernelModuleUnload => "kernel_module_unload",
            Self::KernelBpfLoad => "kernel_bpf_load",
            Self::KernelParamChange => "kernel_param_change",
            Self::PersistenceServiceCreate => "persistence_service_create",
            Self::PersistenceCronModify => "persistence_cron_modify",
            Self::PersistenceRcLocalModify => "persistence_rc_local_modify",
            Self::PersistenceLdPreloadModify => "persistence_ld_preload_modify",
        }
    }

    pub fn parse_from(s: &str) -> Option<Self> {
        match s {
            "process_create" => Some(Self::ProcessCreate),
            "process_fork" => Some(Self::ProcessFork),
            "process_clone" => Some(Self::ProcessClone),
            "process_exec" => Some(Self::ProcessExec),
            "process_exit" => Some(Self::ProcessExit),
            "process_setuid" => Some(Self::ProcessSetuid),
            "process_setgid" => Some(Self::ProcessSetgid),
            "process_ptrace" => Some(Self::ProcessPtrace),
            "process_cap_change" => Some(Self::ProcessCapChange),
            "file_open" => Some(Self::FileOpen),
            "file_close" => Some(Self::FileClose),
            "file_read" => Some(Self::FileRead),
            "file_write" => Some(Self::FileWrite),
            "file_rename" => Some(Self::FileRename),
            "file_delete" => Some(Self::FileDelete),
            "file_execute" => Some(Self::FileExecute),
            "file_perm_change" => Some(Self::FilePermChange),
            "file_own_change" => Some(Self::FileOwnChange),
            "file_mount" => Some(Self::FileMount),
            "file_unmount" => Some(Self::FileUnmount),
            "net_connect" => Some(Self::NetConnect),
            "net_accept" => Some(Self::NetAccept),
            "net_bind" => Some(Self::NetBind),
            "net_listen" => Some(Self::NetListen),
            "net_close" => Some(Self::NetClose),
            "net_dns_lookup" => Some(Self::NetDnsLookup),
            "kernel_module_load" => Some(Self::KernelModuleLoad),
            "kernel_module_unload" => Some(Self::KernelModuleUnload),
            "kernel_bpf_load" => Some(Self::KernelBpfLoad),
            "kernel_param_change" => Some(Self::KernelParamChange),
            "persistence_service_create" => Some(Self::PersistenceServiceCreate),
            "persistence_cron_modify" => Some(Self::PersistenceCronModify),
            "persistence_rc_local_modify" => Some(Self::PersistenceRcLocalModify),
            "persistence_ld_preload_modify" => Some(Self::PersistenceLdPreloadModify),
            _ => None,
        }
    }

    pub fn category(&self) -> TelemetryCategory {
        match self {
            Self::ProcessCreate
            | Self::ProcessFork
            | Self::ProcessClone
            | Self::ProcessExec
            | Self::ProcessExit
            | Self::ProcessSetuid
            | Self::ProcessSetgid
            | Self::ProcessPtrace
            | Self::ProcessCapChange => TelemetryCategory::Process,
            Self::FileOpen
            | Self::FileClose
            | Self::FileRead
            | Self::FileWrite
            | Self::FileRename
            | Self::FileDelete
            | Self::FileExecute
            | Self::FilePermChange
            | Self::FileOwnChange
            | Self::FileMount
            | Self::FileUnmount => TelemetryCategory::Filesystem,
            Self::NetConnect
            | Self::NetAccept
            | Self::NetBind
            | Self::NetListen
            | Self::NetClose
            | Self::NetDnsLookup => TelemetryCategory::Network,
            Self::KernelModuleLoad
            | Self::KernelModuleUnload
            | Self::KernelBpfLoad
            | Self::KernelParamChange => TelemetryCategory::Kernel,
            Self::PersistenceServiceCreate
            | Self::PersistenceCronModify
            | Self::PersistenceRcLocalModify
            | Self::PersistenceLdPreloadModify => TelemetryCategory::Persistence,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProviderStatus {
    Initializing,
    Running,
    Degraded,
    Stopped,
    Error,
}

impl ProviderStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Running => "running",
            Self::Degraded => "degraded",
            Self::Stopped => "stopped",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub provider: String,
    pub category: TelemetryCategory,
    pub event_type: TelemetryEventType,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub namespace: Option<String>,
    pub container: Option<String>,
    pub object_id: Option<String>,
    pub metadata: serde_json::Value,
}

impl TelemetryEvent {
    pub fn new(provider: &str, event_type: TelemetryEventType) -> Self {
        let category = event_type.category();
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            provider: provider.to_string(),
            category,
            event_type,
            pid: None,
            uid: None,
            namespace: None,
            container: None,
            object_id: None,
            metadata: serde_json::Value::Null,
        }
    }

    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn with_namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_string());
        self
    }

    pub fn with_container(mut self, container: &str) -> Self {
        self.container = Some(container.to_string());
        self
    }

    pub fn with_object_id(mut self, object_id: &str) -> Self {
        self.object_id = Some(object_id.to_string());
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub name: String,
    pub status: ProviderStatus,
    pub events_received: u64,
    pub events_dropped: u64,
    pub started_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryStats {
    pub total_events: u64,
    pub events_by_provider: std::collections::HashMap<String, u64>,
    pub events_by_category: std::collections::HashMap<String, u64>,
    pub dropped_events: u64,
    pub active_providers: u32,
    pub buffer_size: usize,
    pub buffer_capacity: usize,
    pub current_rate_per_second: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_category_as_str() {
        assert_eq!(TelemetryCategory::Process.as_str(), "process");
        assert_eq!(TelemetryCategory::Filesystem.as_str(), "filesystem");
        assert_eq!(TelemetryCategory::Network.as_str(), "network");
        assert_eq!(TelemetryCategory::Kernel.as_str(), "kernel");
        assert_eq!(TelemetryCategory::Persistence.as_str(), "persistence");
    }

    #[test]
    fn telemetry_category_parse() {
        assert_eq!(
            TelemetryCategory::parse_from("process"),
            Some(TelemetryCategory::Process)
        );
        assert_eq!(
            TelemetryCategory::parse_from("filesystem"),
            Some(TelemetryCategory::Filesystem)
        );
        assert_eq!(
            TelemetryCategory::parse_from("network"),
            Some(TelemetryCategory::Network)
        );
        assert_eq!(
            TelemetryCategory::parse_from("kernel"),
            Some(TelemetryCategory::Kernel)
        );
        assert_eq!(
            TelemetryCategory::parse_from("persistence"),
            Some(TelemetryCategory::Persistence)
        );
        assert_eq!(TelemetryCategory::parse_from("invalid"), None);
    }

    #[test]
    fn event_type_as_str() {
        assert_eq!(TelemetryEventType::ProcessCreate.as_str(), "process_create");
        assert_eq!(TelemetryEventType::FileOpen.as_str(), "file_open");
        assert_eq!(TelemetryEventType::NetConnect.as_str(), "net_connect");
        assert_eq!(
            TelemetryEventType::KernelModuleLoad.as_str(),
            "kernel_module_load"
        );
        assert_eq!(
            TelemetryEventType::PersistenceCronModify.as_str(),
            "persistence_cron_modify"
        );
    }

    #[test]
    fn event_type_parse() {
        assert_eq!(
            TelemetryEventType::parse_from("process_create"),
            Some(TelemetryEventType::ProcessCreate)
        );
        assert_eq!(
            TelemetryEventType::parse_from("file_write"),
            Some(TelemetryEventType::FileWrite)
        );
        assert_eq!(TelemetryEventType::parse_from("invalid"), None);
    }

    #[test]
    fn event_type_category_mapping() {
        assert_eq!(
            TelemetryEventType::ProcessCreate.category(),
            TelemetryCategory::Process
        );
        assert_eq!(
            TelemetryEventType::FileWrite.category(),
            TelemetryCategory::Filesystem
        );
        assert_eq!(
            TelemetryEventType::NetConnect.category(),
            TelemetryCategory::Network
        );
        assert_eq!(
            TelemetryEventType::KernelModuleLoad.category(),
            TelemetryCategory::Kernel
        );
        assert_eq!(
            TelemetryEventType::PersistenceCronModify.category(),
            TelemetryCategory::Persistence
        );
    }

    #[test]
    fn provider_status_as_str() {
        assert_eq!(ProviderStatus::Running.as_str(), "running");
        assert_eq!(ProviderStatus::Degraded.as_str(), "degraded");
        assert_eq!(ProviderStatus::Error.as_str(), "error");
    }

    #[test]
    fn telemetry_event_creation() {
        let event = TelemetryEvent::new("test_provider", TelemetryEventType::ProcessCreate)
            .with_pid(1234)
            .with_uid(0)
            .with_object_id("proc_1234")
            .with_metadata(serde_json::json!({"ppid": 1}));

        assert_eq!(event.provider, "test_provider");
        assert_eq!(event.event_type, TelemetryEventType::ProcessCreate);
        assert_eq!(event.category, TelemetryCategory::Process);
        assert_eq!(event.pid, Some(1234));
        assert_eq!(event.uid, Some(0));
        assert_eq!(event.object_id, Some("proc_1234".to_string()));
        assert!(event.metadata.is_object());
    }

    #[test]
    fn telemetry_event_builder_chains() {
        let event = TelemetryEvent::new("provider", TelemetryEventType::FileWrite)
            .with_pid(100)
            .with_uid(1000)
            .with_namespace("ns1")
            .with_container("container1")
            .with_object_id("/etc/passwd");

        assert_eq!(event.namespace, Some("ns1".to_string()));
        assert_eq!(event.container, Some("container1".to_string()));
    }

    #[test]
    fn telemetry_event_serialization() {
        let event = TelemetryEvent::new("test", TelemetryEventType::ProcessExec);
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: TelemetryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.id, deserialized.id);
        assert_eq!(event.event_type, deserialized.event_type);
    }

    #[test]
    fn provider_info_serialization() {
        let info = ProviderInfo {
            name: "ebpf".to_string(),
            status: ProviderStatus::Running,
            events_received: 1000,
            events_dropped: 5,
            started_at: Some(Utc::now()),
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: ProviderInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info.name, deserialized.name);
        assert_eq!(info.events_received, deserialized.events_received);
    }

    #[test]
    fn all_event_types_parse_roundtrip() {
        let types = vec![
            TelemetryEventType::ProcessCreate,
            TelemetryEventType::ProcessFork,
            TelemetryEventType::ProcessClone,
            TelemetryEventType::ProcessExec,
            TelemetryEventType::ProcessExit,
            TelemetryEventType::ProcessSetuid,
            TelemetryEventType::ProcessSetgid,
            TelemetryEventType::ProcessPtrace,
            TelemetryEventType::ProcessCapChange,
            TelemetryEventType::FileOpen,
            TelemetryEventType::FileClose,
            TelemetryEventType::FileRead,
            TelemetryEventType::FileWrite,
            TelemetryEventType::FileRename,
            TelemetryEventType::FileDelete,
            TelemetryEventType::FileExecute,
            TelemetryEventType::FilePermChange,
            TelemetryEventType::FileOwnChange,
            TelemetryEventType::FileMount,
            TelemetryEventType::FileUnmount,
            TelemetryEventType::NetConnect,
            TelemetryEventType::NetAccept,
            TelemetryEventType::NetBind,
            TelemetryEventType::NetListen,
            TelemetryEventType::NetClose,
            TelemetryEventType::NetDnsLookup,
            TelemetryEventType::KernelModuleLoad,
            TelemetryEventType::KernelModuleUnload,
            TelemetryEventType::KernelBpfLoad,
            TelemetryEventType::KernelParamChange,
            TelemetryEventType::PersistenceServiceCreate,
            TelemetryEventType::PersistenceCronModify,
            TelemetryEventType::PersistenceRcLocalModify,
            TelemetryEventType::PersistenceLdPreloadModify,
        ];
        for et in &types {
            let s = et.as_str();
            let parsed = TelemetryEventType::parse_from(s);
            assert_eq!(parsed.as_ref(), Some(et), "Failed roundtrip for {}", s);
        }
    }
}
