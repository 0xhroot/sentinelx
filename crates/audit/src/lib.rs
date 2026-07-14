use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use sentinelx_telemetry::provider::{Result, TelemetryProvider};
use sentinelx_telemetry::types::{
    ProviderInfo, ProviderStatus, TelemetryEvent, TelemetryEventType,
};

const NETLINK_AUDIT: i32 = 9;

const AUDIT_GET: u16 = 1000;
const AUDIT_SET: u16 = 1001;
const AUDIT_FIRST_USER_MSG: u16 = 1100;
const AUDIT_USER_MSG: u16 = 1105;

const AUDIT_STATUS_ENABLED: u32 = 1;

const EVENT_BUFFER_SIZE: usize = 8192;

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditStatus {
    mask: u32,
    enabled: u32,
    failure: u32,
    pid: u32,
    rate_limit: u32,
    backlog_limit: u32,
    lost: u32,
    backlog: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub enabled: bool,
    pub backlog_limit: u32,
    pub rate_limit: u32,
    pub add_rules: bool,
    pub buffer_size: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backlog_limit: 8192,
            rate_limit: 0,
            add_rules: false,
            buffer_size: EVENT_BUFFER_SIZE as u32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    X86,
    Arm,
    Aarch64,
}

impl Arch {
    pub fn detect() -> Self {
        // SAFETY: uname() writes to a stack-allocated struct.
        let mut uname: libc::utsname = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::uname(&mut uname) };
        if rc == 0 {
            let machine = unsafe {
                std::ffi::CStr::from_ptr(uname.machine.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            };
            match machine.as_str() {
                "x86_64" | "amd64" => Arch::X86_64,
                "i386" | "i686" | "i586" => Arch::X86,
                "aarch64" | "arm64" => Arch::Aarch64,
                "armv7l" | "armv6l" => Arch::Arm,
                _ => Arch::X86_64,
            }
        } else {
            Arch::X86_64
        }
    }
}

fn x86_64_syscall_to_event_type(syscall: i32) -> Option<TelemetryEventType> {
    match syscall {
        59 => Some(TelemetryEventType::ProcessExec),
        322 => Some(TelemetryEventType::ProcessExec),
        57 => Some(TelemetryEventType::ProcessFork),
        58 => Some(TelemetryEventType::ProcessFork),
        56 => Some(TelemetryEventType::ProcessClone),
        231 => Some(TelemetryEventType::ProcessExit),
        60 => Some(TelemetryEventType::ProcessExit),
        105 => Some(TelemetryEventType::ProcessSetuid),
        113 => Some(TelemetryEventType::ProcessSetuid),
        106 => Some(TelemetryEventType::ProcessSetgid),
        114 => Some(TelemetryEventType::ProcessSetgid),
        126 => Some(TelemetryEventType::ProcessPtrace),
        125 => Some(TelemetryEventType::ProcessCapChange),
        2 => Some(TelemetryEventType::FileOpen),
        257 => Some(TelemetryEventType::FileOpen),
        85 => Some(TelemetryEventType::FileOpen),
        87 => Some(TelemetryEventType::FileDelete),
        263 => Some(TelemetryEventType::FileDelete),
        82 => Some(TelemetryEventType::FileRename),
        264 => Some(TelemetryEventType::FileRename),
        90 => Some(TelemetryEventType::FilePermChange),
        91 => Some(TelemetryEventType::FilePermChange),
        92 => Some(TelemetryEventType::FilePermChange),
        93 => Some(TelemetryEventType::FilePermChange),
        94 => Some(TelemetryEventType::FileOwnChange),
        95 => Some(TelemetryEventType::FileOwnChange),
        96 => Some(TelemetryEventType::FileOwnChange),
        49 => Some(TelemetryEventType::NetConnect),
        50 => Some(TelemetryEventType::NetConnect),
        43 => Some(TelemetryEventType::NetConnect),
        174 => Some(TelemetryEventType::NetConnect),
        41 => Some(TelemetryEventType::KernelModuleLoad),
        175 => Some(TelemetryEventType::KernelModuleLoad),
        313 => Some(TelemetryEventType::KernelBpfLoad),
        _ => None,
    }
}

fn nl_msg_hdr_from_bytes(buf: &[u8], offset: usize) -> Option<NlMsgHdr> {
    if offset + std::mem::size_of::<NlMsgHdr>() > buf.len() {
        return None;
    }
    // SAFETY: We verified bounds. NlMsgHdr is repr(C).
    Some(unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const NlMsgHdr) })
}

fn create_audit_socket() -> std::io::Result<RawFd> {
    // SAFETY: Creating a NETLINK_AUDIT socket for audit event subscription.
    let fd = unsafe {
        libc::socket(
            libc::PF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_AUDIT,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = 0;

    // SAFETY: Binding to the kernel audit netlink socket.
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };

    if rc < 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: fd is valid.
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    Ok(fd)
}

fn send_audit_request(fd: RawFd, msg_type: u16) -> std::io::Result<()> {
    let mut nl_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    nl_addr.nl_family = libc::AF_NETLINK as u16;
    nl_addr.nl_pid = 0;
    nl_addr.nl_groups = 0;

    let hdr = NlMsgHdr {
        nlmsg_len: std::mem::size_of::<NlMsgHdr>() as u32,
        nlmsg_type: msg_type,
        nlmsg_flags: libc::NLM_F_REQUEST as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    // SAFETY: Sending a properly formatted netlink audit request.
    let rc = unsafe {
        libc::sendto(
            fd,
            &hdr as *const NlMsgHdr as *const libc::c_void,
            std::mem::size_of::<NlMsgHdr>(),
            0,
            &nl_addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };

    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: F_GETFL/F_SETFL are standard POSIX operations.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn parse_audit_msg<'a>(buf: &'a [u8], offset: usize, hdr: &NlMsgHdr) -> Option<AuditMsg<'a>> {
    let msg_len = hdr.nlmsg_len as usize;
    if msg_len <= std::mem::size_of::<NlMsgHdr>() {
        return None;
    }

    let data_offset = offset + std::mem::size_of::<NlMsgHdr>();
    let data_len = msg_len - std::mem::size_of::<NlMsgHdr>();

    if data_offset + data_len > buf.len() {
        return None;
    }

    let data = &buf[data_offset..data_offset + data_len];

    let msg_type = hdr.nlmsg_type;
    if (AUDIT_FIRST_USER_MSG..=AUDIT_USER_MSG).contains(&msg_type) {
        let msg = std::str::from_utf8(data).ok()?;
        Some(AuditMsg::UserMessage(msg))
    } else {
        let msg = std::str::from_utf8(data).ok()?;
        Some(AuditMsg::Other {
            msg_type,
            data: msg,
        })
    }
}

enum AuditMsg<'a> {
    UserMessage(&'a str),
    #[allow(dead_code)]
    Other {
        msg_type: u16,
        data: &'a str,
    },
}

fn parse_user_message(msg: &str) -> Option<(TelemetryEventType, serde_json::Value)> {
    if msg.starts_with("SYSCALL") {
        return parse_syscall_record(msg);
    }
    if msg.starts_with("EXECVE") || msg.starts_with("EXECVE ") {
        return Some((
            TelemetryEventType::ProcessExec,
            serde_json::json!({
                "audit_type": "EXECVE",
                "raw": msg,
            }),
        ));
    }
    if msg.starts_with("CRED") {
        return parse_cred_record(msg);
    }
    if msg.starts_with("PATH") {
        return parse_path_record(msg);
    }

    None
}

fn parse_syscall_record(msg: &str) -> Option<(TelemetryEventType, serde_json::Value)> {
    let syscall_num =
        extract_key_int(msg, "syscall").or_else(|| extract_key_int(msg, "SYSCALL"))?;
    let pid = extract_key_int(msg, "pid");
    let uid = extract_key_int(msg, "uid");
    let exe = extract_key_string(msg, "exe");
    let comm = extract_key_string(msg, "comm");
    let success = extract_key_string(msg, "success");

    let arch = Arch::detect();
    let event_type = match arch {
        Arch::X86_64 | Arch::X86 => x86_64_syscall_to_event_type(syscall_num as i32),
        _ => None,
    };

    let event_type = event_type.unwrap_or(TelemetryEventType::ProcessExec);

    Some((
        event_type,
        serde_json::json!({
            "audit_type": "SYSCALL",
            "syscall": syscall_num,
            "arch": format!("{:?}", arch),
            "pid": pid,
            "uid": uid,
            "exe": exe,
            "comm": comm,
            "success": success,
        }),
    ))
}

fn parse_cred_record(msg: &str) -> Option<(TelemetryEventType, serde_json::Value)> {
    let op = extract_key_string(msg, "op");
    let pid = extract_key_int(msg, "pid");

    let event_type = match op.as_deref() {
        Some("setuid") | Some("setreuid") | Some("setresuid") => TelemetryEventType::ProcessSetuid,
        Some("setgid") | Some("setregid") | Some("setresgid") => TelemetryEventType::ProcessSetgid,
        _ => TelemetryEventType::ProcessCapChange,
    };

    Some((
        event_type,
        serde_json::json!({
            "audit_type": "CRED",
            "op": op,
            "pid": pid,
            "raw": msg,
        }),
    ))
}

fn parse_path_record(msg: &str) -> Option<(TelemetryEventType, serde_json::Value)> {
    let name = extract_key_string(msg, "name");
    let item = extract_key_string(msg, "item");

    let event_type = match item.as_deref() {
        Some("0") => TelemetryEventType::FileOpen,
        Some("1") => TelemetryEventType::FileOpen,
        _ => TelemetryEventType::FileOpen,
    };

    Some((
        event_type,
        serde_json::json!({
            "audit_type": "PATH",
            "name": name,
            "item": item,
            "raw": msg,
        }),
    ))
}

fn clean_value(val: &str) -> String {
    let clean = val.trim_matches(|c: char| {
        c == '\'' || c == '"' || c == ',' || c == ')' || c == '(' || c == ';'
    });
    clean.to_string()
}

fn extract_key_int(msg: &str, key: &str) -> Option<i64> {
    let prefix = format!("{}=", key);
    for part in msg.split_whitespace() {
        if let Some(idx) = part.find(&prefix) {
            if idx > 0 {
                let prev = part.as_bytes()[idx - 1];
                if prev != b'(' && prev != b',' {
                    continue;
                }
            }
            let val = &part[idx + prefix.len()..];
            let clean: String = val
                .chars()
                .filter(|c| *c == '-' || c.is_ascii_digit())
                .collect();
            return clean.parse().ok();
        }
    }
    None
}

fn extract_key_string(msg: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    for part in msg.split_whitespace() {
        if let Some(idx) = part.find(&prefix) {
            if idx > 0 {
                let prev = part.as_bytes()[idx - 1];
                if prev != b'(' && prev != b',' {
                    continue;
                }
            }
            let val = &part[idx + prefix.len()..];
            return Some(clean_value(val));
        }
    }
    None
}

fn run_read_loop(
    fd: RawFd,
    running: Arc<AtomicBool>,
    event_tx: mpsc::Sender<TelemetryEvent>,
    events_received: Arc<AtomicU64>,
    events_dropped: Arc<AtomicU64>,
    config: AuditConfig,
) {
    let mut buf = vec![0u8; config.buffer_size as usize];

    while running.load(Ordering::Relaxed) {
        // SAFETY: fd is a valid NETLINK_AUDIT socket. buf is writable.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

        if n < 0 {
            let errno = nix::errno::Errno::last();
            match errno {
                nix::errno::Errno::EAGAIN => {
                    thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                nix::errno::Errno::EINTR => continue,
                _ => {
                    debug!("audit recv error ({}), exiting read loop", errno);
                    break;
                }
            }
        }

        if n == 0 {
            break;
        }

        let total = n as usize;
        let mut offset = 0usize;

        while offset + std::mem::size_of::<NlMsgHdr>() <= total {
            let hdr = match nl_msg_hdr_from_bytes(&buf, offset) {
                Some(h) => h,
                None => break,
            };

            let msg_len = hdr.nlmsg_len as usize;
            if msg_len < std::mem::size_of::<NlMsgHdr>() || offset + msg_len > total {
                break;
            }

            if let Some(audit_msg) = parse_audit_msg(&buf, offset, &hdr) {
                match audit_msg {
                    AuditMsg::UserMessage(msg) => {
                        if let Some((event_type, metadata)) = parse_user_message(msg) {
                            let event = TelemetryEvent::new("auditd", event_type)
                                .with_metadata(metadata)
                                .with_pid(extract_key_int(msg, "pid").unwrap_or(0) as u32);

                            if event_tx.blocking_send(event).is_ok() {
                                events_received.fetch_add(1, Ordering::Relaxed);
                            } else {
                                events_dropped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    AuditMsg::Other {
                        msg_type: _,
                        data: _,
                    } => {}
                }
            }

            let aligned = (msg_len + 3) & !3;
            offset += aligned;
        }
    }
}

pub struct AuditdProvider {
    config: AuditConfig,
    status: ProviderStatus,
    events_received: Arc<AtomicU64>,
    events_dropped: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    audit_fd: Arc<AtomicI32>,
    task_handle: Option<JoinHandle<()>>,
}

impl AuditdProvider {
    pub fn new(config: AuditConfig) -> Self {
        Self {
            config,
            status: ProviderStatus::Stopped,
            events_received: Arc::new(AtomicU64::new(0)),
            events_dropped: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            audit_fd: Arc::new(AtomicI32::new(-1)),
            task_handle: None,
        }
    }
}

#[async_trait]
impl TelemetryProvider for AuditdProvider {
    fn name(&self) -> &str {
        "auditd"
    }

    fn description(&self) -> &str {
        "Audit telemetry provider (real NETLINK_AUDIT socket)"
    }

    fn status(&self) -> ProviderStatus {
        self.status.clone()
    }

    async fn initialize(&mut self, event_tx: mpsc::Sender<TelemetryEvent>) -> Result<()> {
        info!("Initializing auditd provider");
        self.status = ProviderStatus::Initializing;

        let fd = match create_audit_socket() {
            Ok(fd) => fd,
            Err(e) => {
                warn!(
                    "Failed to create audit netlink socket: {}, degrading gracefully",
                    e
                );
                self.status = ProviderStatus::Degraded;
                return Ok(());
            }
        };

        if let Err(e) = set_nonblocking(fd) {
            warn!("Failed to set nonblocking on audit fd: {}", e);
        }

        match send_audit_request(fd, AUDIT_GET) {
            Ok(()) => {
                debug!("Sent AUDIT_GET request to kernel");
            }
            Err(e) => {
                warn!("Failed to send AUDIT_GET: {}", e);
            }
        }

        if self.config.enabled {
            let status = AuditStatus {
                mask: AUDIT_STATUS_ENABLED,
                enabled: 1,
                failure: 0,
                pid: 0,
                rate_limit: self.config.rate_limit,
                backlog_limit: self.config.backlog_limit,
                lost: 0,
                backlog: 0,
            };

            let mut msg_buf =
                vec![0u8; std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<AuditStatus>()];

            let hdr = NlMsgHdr {
                nlmsg_len: msg_buf.len() as u32,
                nlmsg_type: AUDIT_SET,
                nlmsg_flags: libc::NLM_F_REQUEST as u16,
                nlmsg_seq: 2,
                nlmsg_pid: 0,
            };

            // SAFETY: Writing NlMsgHdr and AuditStatus into a properly-sized buffer.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &hdr as *const NlMsgHdr as *const u8,
                    msg_buf.as_mut_ptr(),
                    std::mem::size_of::<NlMsgHdr>(),
                );
                std::ptr::copy_nonoverlapping(
                    &status as *const AuditStatus as *const u8,
                    msg_buf.as_mut_ptr().add(std::mem::size_of::<NlMsgHdr>()),
                    std::mem::size_of::<AuditStatus>(),
                );
            }

            let mut nl_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            nl_addr.nl_family = libc::AF_NETLINK as u16;

            // SAFETY: Sending AUDIT_SET to configure audit subsystem.
            let rc = unsafe {
                libc::sendto(
                    fd,
                    msg_buf.as_ptr() as *const libc::c_void,
                    msg_buf.len(),
                    0,
                    &nl_addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };

            if rc < 0 {
                warn!(
                    "Failed to send AUDIT_SET (need root): {}",
                    std::io::Error::last_os_error()
                );
            } else {
                info!("Sent AUDIT_SET to enable audit subsystem");
            }
        }

        self.audit_fd.store(fd, Ordering::SeqCst);
        self.running.store(true, Ordering::SeqCst);
        self.status = ProviderStatus::Running;

        let running = Arc::clone(&self.running);
        let events_received = Arc::clone(&self.events_received);
        let events_dropped = Arc::clone(&self.events_dropped);
        let config = self.config.clone();

        self.task_handle = Some(tokio::task::spawn_blocking(move || {
            run_read_loop(
                fd,
                running,
                event_tx,
                events_received,
                events_dropped,
                config,
            );
        }));

        info!("auditd provider initialized (fd={})", fd);
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down auditd provider");
        self.running.store(false, Ordering::SeqCst);

        let fd = self.audit_fd.swap(-1, Ordering::SeqCst);
        if fd >= 0 {
            // SAFETY: fd is the audit netlink socket we own.
            unsafe {
                libc::close(fd);
            }
        }

        if let Some(handle) = self.task_handle.take() {
            if let Err(e) = handle.await {
                if !e.is_cancelled() {
                    warn!("audit read-loop task panicked: {}", e);
                }
            }
        }

        self.status = ProviderStatus::Stopped;
        info!("auditd provider shut down");
        Ok(())
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

    #[test]
    fn audit_config_default() {
        let config = AuditConfig::default();
        assert!(config.enabled);
        assert_eq!(config.backlog_limit, 8192);
        assert_eq!(config.rate_limit, 0);
        assert!(!config.add_rules);
    }

    #[test]
    fn audit_config_custom() {
        let config = AuditConfig {
            enabled: false,
            backlog_limit: 4096,
            rate_limit: 100,
            add_rules: true,
            buffer_size: 16384,
        };
        assert!(!config.enabled);
        assert_eq!(config.backlog_limit, 4096);
        assert_eq!(config.rate_limit, 100);
        assert!(config.add_rules);
    }

    #[test]
    fn audit_provider_creation() {
        let provider = AuditdProvider::new(AuditConfig::default());
        assert_eq!(provider.name(), "auditd");
        assert_eq!(provider.status(), ProviderStatus::Stopped);
    }

    #[tokio::test]
    async fn audit_provider_degrades_without_root() {
        let mut provider = AuditdProvider::new(AuditConfig::default());
        let (tx, _rx) = mpsc::channel(16);
        let result = provider.initialize(tx).await;
        assert!(result.is_ok());
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
    fn audit_provider_info() {
        let provider = AuditdProvider::new(AuditConfig::default());
        let info = provider.info();
        assert_eq!(info.name, "auditd");
        assert_eq!(info.events_received, 0);
        assert_eq!(info.events_dropped, 0);
    }

    #[test]
    fn arch_detect() {
        let arch = Arch::detect();
        match arch {
            Arch::X86_64 | Arch::X86 | Arch::Arm | Arch::Aarch64 => {}
        }
    }

    #[test]
    fn x86_64_syscall_exec() {
        assert_eq!(
            x86_64_syscall_to_event_type(59),
            Some(TelemetryEventType::ProcessExec)
        );
        assert_eq!(
            x86_64_syscall_to_event_type(322),
            Some(TelemetryEventType::ProcessExec)
        );
    }

    #[test]
    fn x86_64_syscall_fork() {
        assert_eq!(
            x86_64_syscall_to_event_type(57),
            Some(TelemetryEventType::ProcessFork)
        );
        assert_eq!(
            x86_64_syscall_to_event_type(58),
            Some(TelemetryEventType::ProcessFork)
        );
    }

    #[test]
    fn x86_64_syscall_setuid() {
        assert_eq!(
            x86_64_syscall_to_event_type(105),
            Some(TelemetryEventType::ProcessSetuid)
        );
        assert_eq!(
            x86_64_syscall_to_event_type(113),
            Some(TelemetryEventType::ProcessSetuid)
        );
    }

    #[test]
    fn x86_64_syscall_file_ops() {
        assert_eq!(
            x86_64_syscall_to_event_type(87),
            Some(TelemetryEventType::FileDelete)
        );
        assert_eq!(
            x86_64_syscall_to_event_type(82),
            Some(TelemetryEventType::FileRename)
        );
        assert_eq!(
            x86_64_syscall_to_event_type(90),
            Some(TelemetryEventType::FilePermChange)
        );
        assert_eq!(
            x86_64_syscall_to_event_type(49),
            Some(TelemetryEventType::NetConnect)
        );
        assert_eq!(
            x86_64_syscall_to_event_type(41),
            Some(TelemetryEventType::KernelModuleLoad)
        );
        assert_eq!(
            x86_64_syscall_to_event_type(313),
            Some(TelemetryEventType::KernelBpfLoad)
        );
    }

    #[test]
    fn x86_64_syscall_unknown() {
        assert_eq!(x86_64_syscall_to_event_type(9999), None);
    }

    #[test]
    fn extract_key_int_test() {
        let msg = "SYSCALL(a0=59, a1=0, a2=0, ppid=100, pid=200, uid=0, exe='/bin/bash')";
        assert_eq!(extract_key_int(msg, "pid"), Some(200));
        assert_eq!(extract_key_int(msg, "ppid"), Some(100));
        assert_eq!(extract_key_int(msg, "uid"), Some(0));
        assert_eq!(extract_key_int(msg, "missing"), None);
    }

    #[test]
    fn extract_key_string_test() {
        let msg = "SYSCALL(exe='/usr/bin/bash', comm='bash', success=yes)";
        assert_eq!(
            extract_key_string(msg, "exe"),
            Some("/usr/bin/bash".to_string())
        );
        assert_eq!(extract_key_string(msg, "comm"), Some("bash".to_string()));
        assert_eq!(extract_key_string(msg, "success"), Some("yes".to_string()));
    }

    #[test]
    fn parse_user_message_syscall() {
        let msg = "SYSCALL syscall=59 ppid=1 pid=100 uid=0 exe=/bin/bash comm=bash success=yes";
        let result = parse_user_message(msg);
        assert!(result.is_some());
        let (event_type, _metadata) = result.unwrap();
        assert_eq!(event_type, TelemetryEventType::ProcessExec);
    }

    #[test]
    fn parse_user_message_execve() {
        let msg = "EXECVE(argc=2, argv[0]=\"/bin/bash\")";
        let result = parse_user_message(msg);
        assert!(result.is_some());
        let (event_type, _metadata) = result.unwrap();
        assert_eq!(event_type, TelemetryEventType::ProcessExec);
    }

    #[test]
    fn parse_user_message_path() {
        let msg = "PATH(name='/etc/passwd', item=0)";
        let result = parse_user_message(msg);
        assert!(result.is_some());
        let (event_type, metadata) = result.unwrap();
        assert_eq!(event_type, TelemetryEventType::FileOpen);
        assert!(metadata.is_object());
    }

    #[test]
    fn parse_user_message_unknown() {
        let msg = "UNKNOWN_TYPE(some=data)";
        let result = parse_user_message(msg);
        assert!(result.is_none());
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = AuditConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let de: AuditConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.enabled, de.enabled);
        assert_eq!(config.backlog_limit, de.backlog_limit);
    }

    #[test]
    fn audit_constants() {
        assert_eq!(NETLINK_AUDIT, 9);
        assert_eq!(AUDIT_GET, 1000);
        assert_eq!(AUDIT_SET, 1001);
        assert_eq!(AUDIT_FIRST_USER_MSG, 1100);
    }
}
