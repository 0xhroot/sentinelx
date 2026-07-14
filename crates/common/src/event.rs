use crate::pid::Pid;
use crate::severity::Severity;
use crate::types::ThreatCategory;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub kind: EventKind,
    pub source: EventSource,
    pub severity: Severity,
    pub data: serde_json::Value,
}

impl Event {
    pub fn new(kind: EventKind, source: EventSource, data: serde_json::Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            kind,
            source,
            severity: Severity::Info,
            data,
        }
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventKind {
    ProcessCreated,
    ProcessTerminated,
    ProcessModified,
    ModuleLoaded,
    ModuleUnloaded,
    ModuleTampered,
    ConnectionOpened,
    ConnectionClosed,
    HookDetected,
    IntegrityViolation,
    SyscallHooked,
    MemoryModified,
    PersistenceDetected,
    PrivilegeEscalation,
    ContainerEscape,
    ThreatDetected,
    ScanStarted,
    ScanCompleted,
    SystemStartup,
    SystemShutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventSource {
    Detector(String),
    Ebpf(String),
    Kernel(String),
    ProcessMonitor,
    NetworkMonitor,
    ModuleMonitor,
    IntegrityMonitor,
    PersistenceScanner,
    CorrelationEngine,
    User,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid: Pid,
    pub ppid: Pid,
    pub name: String,
    pub binary_path: String,
    pub uid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEvent {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub loaded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetectedEvent {
    pub category: ThreatCategory,
    pub severity: Severity,
    pub title: String,
    pub description: String,
}
