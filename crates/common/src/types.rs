use crate::hash::HashValue;
use crate::pid::Pid;
use crate::severity::Severity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: Pid,
    pub ppid: Pid,
    pub name: String,
    pub binary_path: String,
    pub command_line: Vec<String>,
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    pub start_time: DateTime<Utc>,
    pub status: ProcessStatus,
    pub hash: Option<HashValue>,
    pub namespace: NamespaceInfo,
    pub capabilities: Vec<String>,
    pub threads: u32,
    pub memory_usage_kb: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProcessStatus {
    #[default]
    Unknown,
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Dead,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamespaceInfo {
    pub pid_ns: Option<u64>,
    pub net_ns: Option<u64>,
    pub mnt_ns: Option<u64>,
    pub user_ns: Option<u64>,
    pub uts_ns: Option<u64>,
    pub ipc_ns: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelModuleInfo {
    pub name: String,
    pub size: u64,
    pub ref_count: u32,
    pub load_address: u64,
    pub state: ModuleState,
    pub version: Option<String>,
    pub license: Option<String>,
    pub hash: Option<HashValue>,
    pub signature_valid: Option<bool>,
    pub source: ModuleSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModuleState {
    Live,
    Coming,
    Going,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModuleSource {
    ProcModules,
    Sysfs,
    KernelList,
    Memory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub local_addr: SocketAddr,
    pub remote_addr: Option<SocketAddr>,
    pub protocol: Protocol,
    pub state: ConnectionState,
    pub pid: Option<Pid>,
    pub inode: u64,
    pub uid: u32,
    pub process_name: Option<String>,
    pub process_hash: Option<HashValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketAddr {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
    Unix,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallInfo {
    pub number: u64,
    pub name: String,
    pub args: Vec<u64>,
    pub return_value: i64,
    pub pid: Pid,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookInfo {
    pub hook_type: HookType,
    pub address: u64,
    pub target_address: u64,
    pub symbol: Option<String>,
    pub module: Option<String>,
    pub is_inline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HookType {
    SyscallTable,
    Inline,
    Ftrace,
    Kprobe,
    Kretprobe,
    Upsrobe,
    Tracepoint,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub module: Option<String>,
    pub is_function: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrityRecord {
    pub path: String,
    pub hash: HashValue,
    pub size: u64,
    pub permissions: u32,
    pub owner: u32,
    pub group: u32,
    pub modified_at: DateTime<Utc>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub entry_type: PersistenceType,
    pub name: String,
    pub path: String,
    pub content: Option<String>,
    pub enabled: bool,
    pub hash: Option<HashValue>,
    pub user: Option<String>,
    #[serde(default)]
    pub owner_uid: Option<u32>,
    #[serde(default)]
    pub group_uid: Option<u32>,
    #[serde(default)]
    pub permissions: Option<u32>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub is_symlink: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PersistenceType {
    SystemdService,
    SystemdTimer,
    CronJob,
    AtJob,
    RcLocal,
    BashProfile,
    LdPreload,
    KernelModule,
    Initramfs,
    GrubConfig,
    Uefi,
    InitScript,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: uuid::Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub category: ThreatCategory,
    pub title: String,
    pub description: String,
    pub evidence: Vec<Evidence>,
    pub mitre_attack: Vec<MitreAttackMapping>,
    pub source_detector: String,
    pub process: Option<ProcessInfo>,
    pub network: Option<NetworkConnection>,
    pub hash: Option<HashValue>,
    pub tags: Vec<String>,
}

impl ThreatEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn from_evidence_data(
        severity: Severity,
        category: ThreatCategory,
        title: String,
        description: String,
        evidence_data: HashMap<String, serde_json::Value>,
        evidence_confidence: f64,
        mitre: Vec<MitreAttackMapping>,
        source: String,
        tags: Vec<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category,
            title,
            description: description.clone(),
            evidence: vec![Evidence {
                description,
                data: evidence_data,
                confidence: evidence_confidence,
            }],
            mitre_attack: mitre,
            source_detector: source,
            process: None,
            network: None,
            hash: None,
            tags,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatCategory {
    Rootkit,
    HiddenProcess,
    HiddenModule,
    HiddenConnection,
    HookDetected,
    MemoryTampering,
    IntegrityViolation,
    PrivilegeEscalation,
    PersistenceMechanism,
    SuspiciousSyscall,
    ContainerEscape,
    ReverseShell,
    FilelessMalware,
    DkomAttack,
    LivepatchAbuse,
    EbpfAbuse,
    Unknown,
}

impl ThreatCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatCategory::Rootkit => "rootkit",
            ThreatCategory::HiddenProcess => "hidden_process",
            ThreatCategory::HiddenModule => "hidden_module",
            ThreatCategory::HiddenConnection => "hidden_connection",
            ThreatCategory::HookDetected => "hook_detected",
            ThreatCategory::MemoryTampering => "memory_tampering",
            ThreatCategory::IntegrityViolation => "integrity_violation",
            ThreatCategory::PrivilegeEscalation => "privilege_escalation",
            ThreatCategory::PersistenceMechanism => "persistence_mechanism",
            ThreatCategory::SuspiciousSyscall => "suspicious_syscall",
            ThreatCategory::ContainerEscape => "container_escape",
            ThreatCategory::ReverseShell => "reverse_shell",
            ThreatCategory::FilelessMalware => "fileless_malware",
            ThreatCategory::DkomAttack => "dkom_attack",
            ThreatCategory::LivepatchAbuse => "livepatch_abuse",
            ThreatCategory::EbpfAbuse => "ebpf_abuse",
            ThreatCategory::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub description: String,
    pub data: HashMap<String, serde_json::Value>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreAttackMapping {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub event: ThreatEvent,
    pub related_pids: Vec<Pid>,
    pub related_inodes: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicSnapshot {
    pub id: uuid::Uuid,
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub kernel_version: String,
    pub processes: Vec<ProcessInfo>,
    pub modules: Vec<KernelModuleInfo>,
    pub connections: Vec<NetworkConnection>,
    pub hooks: Vec<HookInfo>,
    pub threats: Vec<ThreatEvent>,
    pub memory_hashes: HashMap<String, HashValue>,
    pub open_files: Vec<String>,
    pub env_vars: HashMap<String, String>,
}
