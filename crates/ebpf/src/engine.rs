use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use aya::programs::Program;
use aya::Ebpf;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum EbpfError {
    #[error("eBPF not available: {0}")]
    NotAvailable(String),

    #[error("eBPF configuration error: {0}")]
    Config(String),

    #[error("eBPF program error: {0}")]
    Program(String),

    #[error("eBPF map error: {0}")]
    Map(String),

    #[error("eBPF syscall error: {0}")]
    Syscall(String),
}

pub type Result<T> = std::result::Result<T, EbpfError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfConfig {
    pub map_size: u32,
    pub perf_buffer_pages: u32,
    pub max_events_per_second: u32,
    pub programs: Vec<EbpfProgramDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfProgramDef {
    pub name: String,
    pub program_type: EbpfProgramType,
    pub attach_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EbpfProgramType {
    Tracepoint,
    Kprobe,
    Xdp,
    PerfEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfStats {
    pub events_received: u64,
    pub events_dropped: u64,
    pub maps_active: u32,
    pub programs_loaded: u32,
    pub programs_failed: u32,
    pub ring_buffer_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfProgramInfo {
    pub name: String,
    pub type_str: String,
    pub attached: bool,
    pub id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCapabilities {
    pub has_bpf: bool,
    pub has_sys_admin: bool,
    pub has_perf_event: bool,
    pub kernel_version: String,
    pub btf_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfEvent {
    pub event_type: BpfEventType,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub comm: String,
    pub timestamp: u64,
    pub flags: u32,
    pub parent_pid: u32,
    pub ppid: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BpfEventType {
    ProcessExec,
    ProcessExit,
    ProcessFork,
    ProcessClone,
    ProcessSetuid,
    ProcessSetgid,
    ProcessPtrace,
    ProcessCapChange,
    FileOpen,
    FileWrite,
    FileDelete,
    FileRename,
    FilePermChange,
    FileExecute,
    NetConnect,
    NetBind,
    KernelModuleLoad,
    KernelModuleUnload,
    KernelBpfLoad,
    KernelParamChange,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            map_size: 1024,
            perf_buffer_pages: 64,
            max_events_per_second: 10000,
            programs: default_programs(),
        }
    }
}

pub fn default_programs() -> Vec<EbpfProgramDef> {
    vec![
        EbpfProgramDef {
            name: "trace_exec".to_string(),
            program_type: EbpfProgramType::Tracepoint,
            attach_point: "sched:sched_process_exec".to_string(),
        },
        EbpfProgramDef {
            name: "trace_exit".to_string(),
            program_type: EbpfProgramType::Tracepoint,
            attach_point: "sched:sched_process_exit".to_string(),
        },
        EbpfProgramDef {
            name: "trace_fork".to_string(),
            program_type: EbpfProgramType::Tracepoint,
            attach_point: "sched:sched_process_fork".to_string(),
        },
        EbpfProgramDef {
            name: "kprobe_security_bprm_check".to_string(),
            program_type: EbpfProgramType::Kprobe,
            attach_point: "security_bprm_check".to_string(),
        },
        EbpfProgramDef {
            name: "kprobe_do_init_module".to_string(),
            program_type: EbpfProgramType::Kprobe,
            attach_point: "do_init_module".to_string(),
        },
        EbpfProgramDef {
            name: "kprobe_security_socket_connect".to_string(),
            program_type: EbpfProgramType::Kprobe,
            attach_point: "security_socket_connect".to_string(),
        },
    ]
}

const CAP_BPF: i32 = 39;
const CAP_SYS_ADMIN: i32 = 21;
const CAP_PERFMON: i32 = 38;

#[repr(C)]
#[derive(Clone, Copy)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn detect_capabilities() -> KernelCapabilities {
    let kernel_version = get_kernel_version();
    let has_bpf = check_cap_effective(CAP_BPF);
    let has_sys_admin = check_cap_effective(CAP_SYS_ADMIN);
    let has_perf_event = check_cap_effective(CAP_PERFMON);
    let btf_available = check_btf_available();

    KernelCapabilities {
        has_bpf,
        has_sys_admin,
        has_perf_event,
        kernel_version,
        btf_available,
    }
}

fn get_kernel_version() -> String {
    let mut uname: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: uname() writes to the uname struct. The pointer is valid and
    // the struct is stack-allocated with proper alignment.
    let rc = unsafe { libc::uname(&mut uname) };
    if rc == 0 {
        // SAFETY: uname.sysname is a fixed-size char array [c_char; 65].
        // We copy it to a String immediately, so the lifetime is bounded.
        let sysname = unsafe {
            std::ffi::CStr::from_ptr(uname.sysname.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        let release = unsafe {
            std::ffi::CStr::from_ptr(uname.release.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        format!("{} {}", sysname, release)
    } else {
        "unknown".to_string()
    }
}

fn check_cap_effective(cap: i32) -> bool {
    // SAFETY: We use the capget syscall via libc::syscall to check capabilities.
    // CapHeader and CapData are plain repr(C) structs that the kernel writes to.
    let mut header = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let mut data: [CapData; 2] = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];

    // SAFETY: SYS_capget syscall. header and data are valid stack-allocated
    // structs with repr(C) layout matching what the kernel expects.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return false;
    }

    let cap_idx = cap as usize / 32;
    let cap_bit = 1u32 << (cap as u32 % 32);

    if cap_idx < 2 {
        (data[cap_idx].effective & cap_bit) != 0
    } else {
        false
    }
}

fn check_btf_available() -> bool {
    std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
}

pub struct EbpfEngine {
    config: EbpfConfig,
    capabilities: KernelCapabilities,
    loaded: Arc<AtomicBool>,
    events_received: Arc<AtomicU64>,
    events_dropped: Arc<AtomicU64>,
    programs_loaded: Arc<AtomicU32>,
    programs_failed: Arc<AtomicU32>,
    has_ring_buffer: Arc<AtomicBool>,
}

impl EbpfEngine {
    pub fn new(config: EbpfConfig) -> Self {
        let capabilities = detect_capabilities();
        Self {
            config,
            capabilities,
            loaded: Arc::new(AtomicBool::new(false)),
            events_received: Arc::new(AtomicU64::new(0)),
            events_dropped: Arc::new(AtomicU64::new(0)),
            programs_loaded: Arc::new(AtomicU32::new(0)),
            programs_failed: Arc::new(AtomicU32::new(0)),
            has_ring_buffer: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn capabilities(&self) -> &KernelCapabilities {
        &self.capabilities
    }

    pub fn can_load_programs(&self) -> bool {
        self.capabilities.has_bpf || self.capabilities.has_sys_admin
    }

    pub async fn initialize(&self) -> Result<()> {
        info!(
            kernel_version = %self.capabilities.kernel_version,
            has_bpf = self.capabilities.has_bpf,
            has_sys_admin = self.capabilities.has_sys_admin,
            btf = self.capabilities.btf_available,
            "Initializing eBPF engine"
        );

        if !self.can_load_programs() {
            warn!(
                "eBPF engine: insufficient capabilities (need CAP_BPF or CAP_SYS_ADMIN). \
                 Running in degraded mode."
            );
            self.loaded.store(true, Ordering::SeqCst);
            return Ok(());
        }

        match self.try_load_programs() {
            Ok(count) => {
                self.programs_loaded.store(count, Ordering::SeqCst);
                self.loaded.store(true, Ordering::SeqCst);
                info!(
                    programs_loaded = count,
                    "eBPF engine initialized with {} programs", count
                );
            }
            Err(e) => {
                warn!(
                    "eBPF engine failed to load programs: {}. Running in degraded mode.",
                    e
                );
                self.loaded.store(true, Ordering::SeqCst);
            }
        }

        Ok(())
    }

    pub fn load_programs_from_bytes(&self, bytecode: &[u8]) -> Result<u32> {
        let mut bpf = Ebpf::load(bytecode)
            .map_err(|e| EbpfError::Program(format!("Failed to load eBPF bytecode: {}", e)))?;

        let mut loaded = 0u32;

        for prog_def in &self.config.programs {
            match self.try_attach_program(&mut bpf, prog_def) {
                Ok(true) => {
                    loaded += 1;
                    debug!("Attached eBPF program: {}", prog_def.name);
                }
                Ok(false) => {
                    debug!("Skipped eBPF program (not found): {}", prog_def.name);
                }
                Err(e) => {
                    self.programs_failed.fetch_add(1, Ordering::Relaxed);
                    warn!("Failed to attach eBPF program {}: {}", prog_def.name, e);
                }
            }
        }

        Ok(loaded)
    }

    fn try_load_programs(&self) -> Result<u32> {
        let programs_count = self.config.programs.len() as u32;
        debug!(
            "eBPF engine: {} programs configured, \
             but no compiled bytecode loaded. \
             Use load_programs_from_bytes() at runtime.",
            programs_count
        );
        Ok(0)
    }

    fn try_attach_program(&self, bpf: &mut Ebpf, prog_def: &EbpfProgramDef) -> Result<bool> {
        let program: &mut Program = match bpf.program_mut(&prog_def.name) {
            Some(p) => p,
            None => {
                debug!("eBPF program {} not found in loaded objects", prog_def.name);
                return Ok(false);
            }
        };

        match prog_def.program_type {
            EbpfProgramType::Tracepoint => {
                let parts: Vec<&str> = prog_def.attach_point.splitn(2, ':').collect();
                if parts.len() != 2 {
                    return Err(EbpfError::Config(format!(
                        "Invalid tracepoint format: {} (expected category:name)",
                        prog_def.attach_point
                    )));
                }

                // SAFETY: We are converting from &mut Program to &mut TracePoint via
                // aya's TryFrom implementation, which validates the program type at runtime.
                let tp: &mut aya::programs::TracePoint = program.try_into().map_err(|e| {
                    EbpfError::Program(format!(
                        "Program {} is not a tracepoint: {}",
                        prog_def.name, e
                    ))
                })?;
                tp.load().map_err(|e| {
                    EbpfError::Program(format!("Load tracepoint {}: {}", prog_def.name, e))
                })?;
                tp.attach(parts[0], parts[1]).map_err(|e| {
                    EbpfError::Program(format!("Attach tracepoint {}: {}", prog_def.name, e))
                })?;
                Ok(true)
            }
            EbpfProgramType::Kprobe => {
                // SAFETY: Converting &mut Program to &mut KProbe via aya's TryFrom.
                let kp: &mut aya::programs::KProbe = program.try_into().map_err(|e| {
                    EbpfError::Program(format!("Program {} is not a kprobe: {}", prog_def.name, e))
                })?;
                kp.load().map_err(|e| {
                    EbpfError::Program(format!("Load kprobe {}: {}", prog_def.name, e))
                })?;
                kp.attach(&prog_def.attach_point, 0).map_err(|e| {
                    EbpfError::Program(format!("Attach kprobe {}: {}", prog_def.name, e))
                })?;
                Ok(true)
            }
            EbpfProgramType::Xdp => {
                // SAFETY: Converting &mut Program to &mut Xdp via aya's TryFrom.
                let xdp: &mut aya::programs::Xdp = program.try_into().map_err(|e| {
                    EbpfError::Program(format!("Program {} is not XDP: {}", prog_def.name, e))
                })?;
                xdp.load().map_err(|e| {
                    EbpfError::Program(format!("Load XDP {}: {}", prog_def.name, e))
                })?;
                xdp.attach(&prog_def.attach_point, aya::programs::xdp::XdpMode::Skb)
                    .map_err(|e| {
                        EbpfError::Program(format!("Attach XDP {}: {}", prog_def.name, e))
                    })?;
                Ok(true)
            }
            EbpfProgramType::PerfEvent => {
                // SAFETY: Converting &mut Program to &mut PerfEvent via aya's TryFrom.
                let pe: &mut aya::programs::PerfEvent = program.try_into().map_err(|e| {
                    EbpfError::Program(format!(
                        "Program {} is not a perf event: {}",
                        prog_def.name, e
                    ))
                })?;
                pe.load().map_err(|e| {
                    EbpfError::Program(format!("Load perf event {}: {}", prog_def.name, e))
                })?;
                Ok(true)
            }
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down eBPF engine");
        self.loaded.store(false, Ordering::SeqCst);
        self.has_ring_buffer.store(false, Ordering::SeqCst);
        self.events_received.store(0, Ordering::SeqCst);
        self.events_dropped.store(0, Ordering::SeqCst);
        self.programs_loaded.store(0, Ordering::SeqCst);
        self.programs_failed.store(0, Ordering::SeqCst);
        info!("eBPF engine shut down");
        Ok(())
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::SeqCst)
    }

    pub fn get_stats(&self) -> EbpfStats {
        EbpfStats {
            events_received: self.events_received.load(Ordering::SeqCst),
            events_dropped: self.events_dropped.load(Ordering::SeqCst),
            maps_active: if self.has_ring_buffer.load(Ordering::SeqCst) {
                1
            } else {
                0
            },
            programs_loaded: self.programs_loaded.load(Ordering::SeqCst),
            programs_failed: self.programs_failed.load(Ordering::SeqCst),
            ring_buffer_size: self.config.map_size,
        }
    }

    pub fn get_loaded_programs(&self) -> Vec<EbpfProgramInfo> {
        if !self.is_loaded() {
            return Vec::new();
        }

        let loaded = self.programs_loaded.load(Ordering::SeqCst);
        self.config
            .programs
            .iter()
            .enumerate()
            .map(|(i, p)| EbpfProgramInfo {
                name: p.name.clone(),
                type_str: format!("{:?}", p.program_type),
                attached: (i as u32) < loaded,
                id: (i as u32) + 1,
            })
            .collect()
    }

    pub fn increment_received(&self, count: u64) {
        self.events_received.fetch_add(count, Ordering::Relaxed);
    }

    pub fn increment_dropped(&self, count: u64) {
        self.events_dropped.fetch_add(count, Ordering::Relaxed);
    }
}

impl Default for EbpfEngine {
    fn default() -> Self {
        Self::new(EbpfConfig::default())
    }
}

pub fn parse_bpf_event_from_bytes(data: &[u8]) -> Option<BpfEvent> {
    if data.len() < std::mem::size_of::<BpfRawEvent>() {
        return None;
    }

    // SAFETY: We verified data has enough bytes. BpfRawEvent is repr(C) with
    // only integer fields and a fixed-size byte array, so read_unaligned is safe.
    let raw: BpfRawEvent = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const BpfRawEvent) };

    let event_type = match raw.event_type {
        1 => BpfEventType::ProcessExec,
        2 => BpfEventType::ProcessExit,
        3 => BpfEventType::ProcessFork,
        4 => BpfEventType::ProcessClone,
        5 => BpfEventType::ProcessSetuid,
        6 => BpfEventType::ProcessSetgid,
        7 => BpfEventType::ProcessPtrace,
        8 => BpfEventType::ProcessCapChange,
        9 => BpfEventType::FileOpen,
        10 => BpfEventType::FileWrite,
        11 => BpfEventType::FileDelete,
        12 => BpfEventType::FileRename,
        13 => BpfEventType::FilePermChange,
        14 => BpfEventType::FileExecute,
        15 => BpfEventType::NetConnect,
        16 => BpfEventType::NetBind,
        17 => BpfEventType::KernelModuleLoad,
        18 => BpfEventType::KernelModuleUnload,
        19 => BpfEventType::KernelBpfLoad,
        20 => BpfEventType::KernelParamChange,
        _ => return None,
    };

    let comm_len = std::cmp::min(raw.comm.len(), 15);
    let comm = String::from_utf8_lossy(&raw.comm[..comm_len])
        .trim_end_matches('\0')
        .to_string();

    Some(BpfEvent {
        event_type,
        pid: raw.pid,
        tgid: raw.tgid,
        uid: raw.uid,
        comm,
        timestamp: raw.timestamp,
        flags: raw.flags,
        parent_pid: raw.parent_pid,
        ppid: raw.ppid,
    })
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfRawEvent {
    pub event_type: u32,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub timestamp: u64,
    pub flags: u32,
    pub parent_pid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let config = EbpfConfig::default();
        assert_eq!(config.map_size, 1024);
        assert_eq!(config.perf_buffer_pages, 64);
        assert_eq!(config.max_events_per_second, 10000);
        assert!(!config.programs.is_empty());
    }

    #[test]
    fn custom_config() {
        let config = EbpfConfig {
            map_size: 2048,
            perf_buffer_pages: 128,
            max_events_per_second: 50000,
            programs: vec![],
        };
        assert_eq!(config.map_size, 2048);
        assert_eq!(config.perf_buffer_pages, 128);
        assert_eq!(config.max_events_per_second, 50000);
    }

    #[test]
    fn engine_creates_with_default_config() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        assert!(!engine.is_loaded());
    }

    #[tokio::test]
    async fn initialize_sets_loaded() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        assert!(!engine.is_loaded());
        let result = engine.initialize().await;
        assert!(result.is_ok());
        assert!(engine.is_loaded());
    }

    #[tokio::test]
    async fn shutdown_clears_loaded() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        engine.initialize().await.unwrap();
        assert!(engine.is_loaded());
        let result = engine.shutdown().await;
        assert!(result.is_ok());
        assert!(!engine.is_loaded());
    }

    #[test]
    fn stats_before_loading() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        let stats = engine.get_stats();
        assert_eq!(stats.events_received, 0);
        assert_eq!(stats.events_dropped, 0);
        assert_eq!(stats.maps_active, 0);
    }

    #[test]
    fn loaded_programs_when_not_loaded() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        let programs = engine.get_loaded_programs();
        assert!(programs.is_empty());
    }

    #[test]
    fn loaded_programs_when_loaded() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        engine.loaded.store(true, Ordering::SeqCst);
        engine.programs_loaded.store(2, Ordering::SeqCst);
        let programs = engine.get_loaded_programs();
        assert_eq!(programs.len(), 6);
        assert_eq!(programs[0].name, "trace_exec");
        assert_eq!(programs[0].type_str, "Tracepoint");
        assert!(programs[0].attached);
        assert_eq!(programs[1].name, "trace_exit");
        assert!(programs[1].attached);
        assert!(!programs[3].attached);
    }

    #[test]
    fn default_programs_count() {
        let programs = default_programs();
        assert_eq!(programs.len(), 6);
    }

    #[test]
    fn detect_capabilities_does_not_panic() {
        let caps = detect_capabilities();
        assert!(!caps.kernel_version.is_empty());
    }

    #[test]
    fn bpf_event_type_roundtrip() {
        let event = BpfEvent {
            event_type: BpfEventType::ProcessExec,
            pid: 100,
            tgid: 100,
            uid: 0,
            comm: "bash".to_string(),
            timestamp: 12345,
            flags: 0,
            parent_pid: 50,
            ppid: 50,
        };
        assert_eq!(event.event_type, BpfEventType::ProcessExec);
        assert_eq!(event.pid, 100);
    }

    #[test]
    fn ebpf_config_serialization() {
        let config = EbpfConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: EbpfConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.map_size, deserialized.map_size);
        assert_eq!(
            config.max_events_per_second,
            deserialized.max_events_per_second
        );
    }

    #[test]
    fn ebpf_stats_serialization() {
        let stats = EbpfStats {
            events_received: 100,
            events_dropped: 5,
            maps_active: 2,
            programs_loaded: 4,
            programs_failed: 1,
            ring_buffer_size: 1024,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: EbpfStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats.events_received, deserialized.events_received);
        assert_eq!(stats.programs_loaded, deserialized.programs_loaded);
    }

    #[test]
    fn ebpf_error_display() {
        let err = EbpfError::NotAvailable("missing capabilities".to_string());
        assert_eq!(err.to_string(), "eBPF not available: missing capabilities");

        let err = EbpfError::Config("bad map size".to_string());
        assert_eq!(err.to_string(), "eBPF configuration error: bad map size");

        let err = EbpfError::Program("load failed".to_string());
        assert_eq!(err.to_string(), "eBPF program error: load failed");

        let err = EbpfError::Map("map not found".to_string());
        assert_eq!(err.to_string(), "eBPF map error: map not found");

        let err = EbpfError::Syscall("EPERM".to_string());
        assert_eq!(err.to_string(), "eBPF syscall error: EPERM");
    }

    #[test]
    fn increment_counters() {
        let engine = EbpfEngine::new(EbpfConfig::default());
        assert_eq!(engine.get_stats().events_received, 0);
        engine.increment_received(10);
        assert_eq!(engine.get_stats().events_received, 10);
        engine.increment_received(5);
        assert_eq!(engine.get_stats().events_received, 15);
        engine.increment_dropped(3);
        assert_eq!(engine.get_stats().events_dropped, 3);
    }

    #[test]
    fn parse_bpf_event_short_buffer() {
        assert!(parse_bpf_event_from_bytes(&[0u8; 5]).is_none());
        assert!(parse_bpf_event_from_bytes(&[]).is_none());
    }

    fn make_raw_event(event_type: u32, pid: u32, tgid: u32, uid: u32, comm: &[u8; 16]) -> Vec<u8> {
        let raw = BpfRawEvent {
            event_type,
            pid,
            tgid,
            uid,
            timestamp: 99999,
            flags: 0,
            parent_pid: pid.saturating_sub(1),
            ppid: pid.saturating_sub(1),
            comm: *comm,
        };
        // SAFETY: BpfRawEvent is repr(C) with only integer and fixed-size fields.
        unsafe {
            std::slice::from_raw_parts(
                &raw as *const BpfRawEvent as *const u8,
                std::mem::size_of::<BpfRawEvent>(),
            )
            .to_vec()
        }
    }

    #[test]
    fn parse_bpf_event_valid() {
        let mut comm = [0u8; 16];
        comm[..10].copy_from_slice(b"test_proc\0");
        let bytes = make_raw_event(1, 42, 42, 1000, &comm);

        let event = parse_bpf_event_from_bytes(&bytes).unwrap();
        assert_eq!(event.event_type, BpfEventType::ProcessExec);
        assert_eq!(event.pid, 42);
        assert_eq!(event.uid, 1000);
        assert_eq!(event.comm, "test_proc");
    }

    #[test]
    fn parse_bpf_event_invalid_type() {
        let comm = [0u8; 16];
        let bytes = make_raw_event(999, 1, 1, 0, &comm);
        assert!(parse_bpf_event_from_bytes(&bytes).is_none());
    }

    #[test]
    fn parse_bpf_event_all_types() {
        let comm = [0u8; 16];
        let type_map: Vec<(u32, BpfEventType)> = vec![
            (1, BpfEventType::ProcessExec),
            (2, BpfEventType::ProcessExit),
            (3, BpfEventType::ProcessFork),
            (4, BpfEventType::ProcessClone),
            (9, BpfEventType::FileOpen),
            (10, BpfEventType::FileWrite),
            (15, BpfEventType::NetConnect),
            (16, BpfEventType::NetBind),
            (17, BpfEventType::KernelModuleLoad),
            (20, BpfEventType::KernelParamChange),
        ];

        for (raw_type, expected) in type_map {
            let bytes = make_raw_event(raw_type, 1, 1, 0, &comm);
            let event = parse_bpf_event_from_bytes(&bytes).unwrap();
            assert_eq!(event.event_type, expected);
        }
    }

    #[test]
    fn kernel_capabilities_serialization() {
        let caps = KernelCapabilities {
            has_bpf: true,
            has_sys_admin: false,
            has_perf_event: true,
            kernel_version: "Linux 6.1.0".to_string(),
            btf_available: true,
        };
        let json = serde_json::to_string(&caps).unwrap();
        let deserialized: KernelCapabilities = serde_json::from_str(&json).unwrap();
        assert!(deserialized.has_bpf);
        assert!(!deserialized.has_sys_admin);
        assert!(deserialized.btf_available);
    }
}
