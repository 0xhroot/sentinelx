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

// ── fanotify UAPI constants ───────────────────────────────────────────

const FAN_ACCESS: u64 = 0x0000_0001;
const FAN_MODIFY: u64 = 0x0000_0002;
const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
const FAN_OPEN: u64 = 0x0000_0020;
const FAN_DELETE: u64 = 0x0000_0400;
const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
const FAN_OPEN_PERM: u64 = 0x0001_0000;
const FAN_ATTRIB: u64 = 0x0000_0004;

const FAN_MARK_ADD: i32 = 0x0000_0001;
const FAN_MARK_MOUNT: i32 = 0x0000_0010;

const MIN_EVENT_METADATA_SIZE: usize = 28;
const EVENT_BUFFER_SIZE: usize = 4096;

// ── packed representation of `struct fanotify_event_metadata` ─────────
//
// The kernel struct (include/uapi/linux/fanotify.h):
//   __u32  event_len;
//   __u8   vers;
//   __u8   reserved;
//   __u16  metadata_len;
//   __u64  mask;
//   __u64  fd;
//   __u32  pid;
//
// Total content: 28 bytes.  With `__attribute__((aligned(8)))` the kernel
// pads to 32, but `event_len` carries the real advance width, so we use
// the packed 28-byte layout for reading.

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: u64,
    pid: u32,
}

// ── FanotifyConfig ────────────────────────────────────────────────────

/// Configuration for the fanotify telemetry provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanotifyConfig {
    /// Absolute directory paths to monitor.  fanotify_mark watches the
    /// entire mount-point that contains each path.
    pub monitor_paths: Vec<String>,

    /// Bitmask of fanotify event flags (e.g. `FAN_ACCESS | FAN_OPEN`).
    pub event_mask: u64,

    /// Flags passed to `fanotify_init` (e.g. `O_CLOEXEC | O_NONBLOCK`).
    pub flags: i32,

    /// Mark flags passed to `fanotify_mark` (e.g. `FAN_MARK_ADD | FAN_MARK_MOUNT`).
    pub mount_flags: i32,
}

impl Default for FanotifyConfig {
    fn default() -> Self {
        Self {
            monitor_paths: vec!["/etc".to_string(), "/usr".to_string(), "/boot".to_string()],
            event_mask: FAN_ACCESS
                | FAN_OPEN
                | FAN_MODIFY
                | FAN_CLOSE_WRITE
                | FAN_DELETE
                | FAN_EVENT_ON_CHILD,
            flags: libc::O_CLOEXEC | libc::O_NONBLOCK,
            mount_flags: FAN_MARK_ADD | FAN_MARK_MOUNT,
        }
    }
}

// ── internal helpers ──────────────────────────────────────────────────

/// Read a [`FanotifyEventMetadata`] from `buf` at `offset`.
/// Returns `None` when there are not enough bytes.
fn read_event_metadata(buf: &[u8], offset: usize) -> Option<FanotifyEventMetadata> {
    let sz = std::mem::size_of::<FanotifyEventMetadata>();
    if offset + sz > buf.len() {
        return None;
    }
    // SAFETY: we verified `buf` has at least `offset + sz` bytes.
    // The struct is `#[repr(C, packed)]`, so there are no alignment
    // requirements and `read_unaligned` is always sound.
    Some(unsafe {
        std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const FanotifyEventMetadata)
    })
}

/// Try to resolve a file descriptor to a path via `/proc/self/fd/N`.
fn resolve_fd_path(fd: RawFd) -> Option<String> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd))
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
}

/// Map a fanotify event mask to the corresponding [`TelemetryEventType`].
fn map_event_type(mask: u64) -> Option<TelemetryEventType> {
    if mask & FAN_ACCESS != 0 {
        Some(TelemetryEventType::FileRead)
    } else if mask & FAN_OPEN != 0 {
        Some(TelemetryEventType::FileOpen)
    } else if mask & FAN_MODIFY != 0 {
        Some(TelemetryEventType::FileWrite)
    } else if mask & FAN_CLOSE_WRITE != 0 {
        Some(TelemetryEventType::FileClose)
    } else if mask & FAN_DELETE != 0 {
        Some(TelemetryEventType::FileDelete)
    } else if mask & FAN_OPEN_PERM != 0 {
        Some(TelemetryEventType::FileExecute)
    } else if mask & FAN_ATTRIB != 0 {
        Some(TelemetryEventType::FilePermChange)
    } else {
        None
    }
}

// ── read loop (runs on a dedicated OS thread) ─────────────────────────

/// Drain fanotify events from `fd` and forward them as [`TelemetryEvent`]s.
///
/// The loop exits when `running` becomes `false`, `fd` is closed (EBADF),
/// or a fatal read error occurs.
fn run_read_loop(
    fd: RawFd,
    running: Arc<AtomicBool>,
    event_tx: mpsc::Sender<TelemetryEvent>,
    events_received: Arc<AtomicU64>,
    events_dropped: Arc<AtomicU64>,
) {
    let mut buf = vec![0u8; EVENT_BUFFER_SIZE];

    while running.load(Ordering::Relaxed) {
        // SAFETY: `fd` is a valid fanotify descriptor opened by
        // `fanotify_init`.  `buf` is a non-null, writable region of
        // `buf.len()` bytes.  The fd was opened with O_NONBLOCK so
        // this never blocks the thread permanently.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if n < 0 {
            let errno = nix::errno::Errno::last();
            match errno {
                nix::errno::Errno::EAGAIN => {
                    thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                nix::errno::Errno::EINTR => continue,
                _ => {
                    debug!("fanotify read error ({}), exiting read loop", errno);
                    break;
                }
            }
        }

        if n == 0 {
            break;
        }

        let total = n as usize;
        let mut offset = 0usize;

        while offset + MIN_EVENT_METADATA_SIZE <= total {
            let meta = match read_event_metadata(&buf, offset) {
                Some(m) => m,
                None => break,
            };

            let event_len = meta.event_len as usize;
            if event_len < MIN_EVENT_METADATA_SIZE {
                warn!(
                    "fanotify event_len {} smaller than minimum {}, aborting parse",
                    event_len, MIN_EVENT_METADATA_SIZE
                );
                break;
            }
            if offset + event_len > total {
                break;
            }

            let fanotify_fd = meta.fd as RawFd;

            // Copy fields out of the packed struct before use to avoid
            // creating misaligned references (UB).
            let mask = meta.mask;
            let pid = meta.pid;

            if let Some(event_type) = map_event_type(mask) {
                let path = if fanotify_fd >= 0 {
                    resolve_fd_path(fanotify_fd).unwrap_or_else(|| format!("fd:{}", fanotify_fd))
                } else {
                    format!("fd:{}", fanotify_fd)
                };

                let telemetry_event = TelemetryEvent::new("fanotify", event_type)
                    .with_pid(pid)
                    .with_object_id(&path)
                    .with_metadata(serde_json::json!({
                        "path": path,
                        "fd": fanotify_fd,
                        "fanotify_mask": mask,
                    }));

                if event_tx.blocking_send(telemetry_event).is_ok() {
                    events_received.fetch_add(1, Ordering::Relaxed);
                } else {
                    events_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }

            // SAFETY: `fanotify_fd` is a kernel-provided file descriptor
            // that must be closed after processing each event (fanotify API
            // contract).  The fd is valid for the lifetime of this event.
            if fanotify_fd >= 0 {
                unsafe {
                    libc::close(fanotify_fd);
                }
            }

            offset += event_len;
        }
    }
}

// ── FanotifyProvider ──────────────────────────────────────────────────

pub struct FanotifyProvider {
    config: FanotifyConfig,
    status: ProviderStatus,
    events_received: Arc<AtomicU64>,
    events_dropped: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    fanotify_fd: Arc<AtomicI32>,
    task_handle: Option<JoinHandle<()>>,
}

impl FanotifyProvider {
    pub fn new(config: FanotifyConfig) -> Self {
        Self {
            config,
            status: ProviderStatus::Stopped,
            events_received: Arc::new(AtomicU64::new(0)),
            events_dropped: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            fanotify_fd: Arc::new(AtomicI32::new(-1)),
            task_handle: None,
        }
    }
}

#[async_trait]
impl TelemetryProvider for FanotifyProvider {
    fn name(&self) -> &str {
        "fanotify"
    }

    fn description(&self) -> &str {
        "fanotify filesystem monitoring provider (Linux syscalls)"
    }

    fn status(&self) -> ProviderStatus {
        self.status.clone()
    }

    async fn initialize(&mut self, event_tx: mpsc::Sender<TelemetryEvent>) -> Result<()> {
        info!(
            "Initializing fanotify provider for paths: {:?}",
            self.config.monitor_paths
        );
        self.status = ProviderStatus::Initializing;

        // ── fanotify_init ──────────────────────────────────────────────
        // SAFETY: fanotify_init(2) is a Linux syscall that allocates a
        // new fanotify group.  We pass the user-configured flags and
        // event mask.  The return value is a valid fd ≥ 0 on success or
        // −1 on failure (checked immediately below).
        let fd = unsafe {
            libc::fanotify_init(
                self.config.flags as libc::c_uint,
                self.config.event_mask as libc::c_uint,
            )
        };

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            warn!(
                "fanotify_init failed (need CAP_SYS_ADMIN or root): {}, degrading gracefully",
                err
            );
            self.status = ProviderStatus::Degraded;
            return Ok(());
        }

        self.fanotify_fd.store(fd, Ordering::SeqCst);

        // ── fanotify_mark for each configured path ────────────────────
        for path in &self.config.monitor_paths {
            let c_path = match std::ffi::CString::new(path.as_str()) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Skipping invalid path '{}': {}", path, e);
                    continue;
                }
            };

            // SAFETY: `fd` is a valid fanotify descriptor.  `c_path` is a
            // Nul-terminated C string.  `mount_flags` and `event_mask` are
            // valid fanotify constants.  `AT_FDCWD` means interpret the
            // path relative to the working directory (it is absolute here).
            let rc = unsafe {
                libc::fanotify_mark(
                    fd,
                    self.config.mount_flags as libc::c_uint,
                    self.config.event_mask,
                    libc::AT_FDCWD,
                    c_path.as_ptr(),
                )
            };

            if rc < 0 {
                let err = std::io::Error::last_os_error();
                warn!("fanotify_mark failed for '{}': {}", path, err);
            } else {
                info!("fanotify_mark watching '{}'", path);
            }
        }

        self.running.store(true, Ordering::SeqCst);
        self.status = ProviderStatus::Running;

        let running = Arc::clone(&self.running);
        let events_received = Arc::clone(&self.events_received);
        let events_dropped = Arc::clone(&self.events_dropped);

        // Spawn a blocking OS thread for the read loop so we never pin
        // an async-runtime thread on a potentially long read.
        self.task_handle = Some(tokio::task::spawn_blocking(move || {
            run_read_loop(fd, running, event_tx, events_received, events_dropped);
        }));

        info!("fanotify provider initialized (fd={})", fd);
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down fanotify provider");

        self.running.store(false, Ordering::SeqCst);

        let fd = self.fanotify_fd.swap(-1, Ordering::SeqCst);
        if fd >= 0 {
            // SAFETY: `fd` is the fanotify group descriptor we own.
            // Closing it causes any blocking/pending read to return
            // EBADF, which makes the read-loop thread exit.
            unsafe {
                libc::close(fd);
            }
        }

        if let Some(handle) = self.task_handle.take() {
            if let Err(e) = handle.await {
                if !e.is_cancelled() {
                    warn!("fanotify read-loop task panicked: {}", e);
                }
            }
        }

        self.status = ProviderStatus::Stopped;
        info!("fanotify provider shut down");
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

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── config ─────────────────────────────────────────────────────

    #[test]
    fn config_defaults() {
        let cfg = FanotifyConfig::default();
        assert_eq!(cfg.monitor_paths.len(), 3);
        assert!(cfg.monitor_paths.contains(&"/etc".to_string()));
        assert!(cfg.monitor_paths.contains(&"/usr".to_string()));
        assert!(cfg.monitor_paths.contains(&"/boot".to_string()));
        assert_eq!(
            cfg.event_mask,
            FAN_ACCESS | FAN_OPEN | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_DELETE | FAN_EVENT_ON_CHILD
        );
        assert_ne!(cfg.flags & libc::O_NONBLOCK, 0);
        assert_ne!(cfg.flags & libc::O_CLOEXEC, 0);
        assert_eq!(cfg.mount_flags, FAN_MARK_ADD | FAN_MARK_MOUNT);
    }

    #[test]
    fn config_custom() {
        let cfg = FanotifyConfig {
            monitor_paths: vec!["/var".to_string()],
            event_mask: FAN_OPEN,
            flags: libc::O_CLOEXEC,
            mount_flags: FAN_MARK_ADD,
        };
        assert_eq!(cfg.monitor_paths, vec!["/var"]);
        assert_eq!(cfg.event_mask, FAN_OPEN);
        assert_eq!(cfg.flags, libc::O_CLOEXEC);
        assert_eq!(cfg.mount_flags, FAN_MARK_ADD);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let cfg = FanotifyConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let de: FanotifyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg.monitor_paths, de.monitor_paths);
        assert_eq!(cfg.event_mask, de.event_mask);
        assert_eq!(cfg.flags, de.flags);
        assert_eq!(cfg.mount_flags, de.mount_flags);
    }

    // ── event type mapping ─────────────────────────────────────────

    #[test]
    fn map_access_to_file_read() {
        assert_eq!(
            map_event_type(FAN_ACCESS),
            Some(TelemetryEventType::FileRead)
        );
    }

    #[test]
    fn map_open_to_file_open() {
        assert_eq!(map_event_type(FAN_OPEN), Some(TelemetryEventType::FileOpen));
    }

    #[test]
    fn map_modify_to_file_write() {
        assert_eq!(
            map_event_type(FAN_MODIFY),
            Some(TelemetryEventType::FileWrite)
        );
    }

    #[test]
    fn map_close_write_to_file_close() {
        assert_eq!(
            map_event_type(FAN_CLOSE_WRITE),
            Some(TelemetryEventType::FileClose)
        );
    }

    #[test]
    fn map_delete_to_file_delete() {
        assert_eq!(
            map_event_type(FAN_DELETE),
            Some(TelemetryEventType::FileDelete)
        );
    }

    #[test]
    fn map_open_perm_to_file_execute() {
        assert_eq!(
            map_event_type(FAN_OPEN_PERM),
            Some(TelemetryEventType::FileExecute)
        );
    }

    #[test]
    fn map_attrib_to_file_perm_change() {
        assert_eq!(
            map_event_type(FAN_ATTRIB),
            Some(TelemetryEventType::FilePermChange)
        );
    }

    #[test]
    fn map_unknown_mask_to_none() {
        assert_eq!(map_event_type(0), None);
        // 0x8000_0000 is not any of our monitored fanotify flags
        assert_eq!(map_event_type(0x8000_0000), None);
    }

    // ── metadata parsing ───────────────────────────────────────────

    #[test]
    fn read_metadata_valid_buffer() {
        let meta = FanotifyEventMetadata {
            event_len: 32,
            vers: 3,
            reserved: 0,
            metadata_len: 0,
            mask: FAN_OPEN,
            fd: 7,
            pid: 42,
        };
        let mut buf = vec![0u8; 64];
        // SAFETY: writing a small, packed struct into a properly-sized buffer.
        unsafe {
            std::ptr::copy_nonoverlapping(
                &meta as *const FanotifyEventMetadata as *const u8,
                buf.as_mut_ptr(),
                std::mem::size_of::<FanotifyEventMetadata>(),
            );
        }
        let got = read_event_metadata(&buf, 0).unwrap();
        // Copy out of packed struct to avoid misaligned-reference UB.
        let (event_len, vers, mask, fd, pid) = (got.event_len, got.vers, got.mask, got.fd, got.pid);
        assert_eq!(event_len, 32);
        assert_eq!(vers, 3);
        assert_eq!(mask, FAN_OPEN);
        assert_eq!(fd, 7);
        assert_eq!(pid, 42);
    }

    #[test]
    fn read_metadata_at_offset() {
        let meta = FanotifyEventMetadata {
            event_len: 28,
            vers: 3,
            reserved: 0,
            metadata_len: 0,
            mask: FAN_DELETE,
            fd: 3,
            pid: 999,
        };
        let mut buf = vec![0u8; 64];
        let offset = 8usize;
        unsafe {
            std::ptr::copy_nonoverlapping(
                &meta as *const FanotifyEventMetadata as *const u8,
                buf.as_mut_ptr().add(offset),
                std::mem::size_of::<FanotifyEventMetadata>(),
            );
        }
        let got = read_event_metadata(&buf, offset).unwrap();
        let (mask, fd, pid) = (got.mask, got.fd, got.pid);
        assert_eq!(mask, FAN_DELETE);
        assert_eq!(fd, 3);
        assert_eq!(pid, 999);
    }

    #[test]
    fn read_metadata_too_short() {
        let buf = vec![0u8; 10];
        assert!(read_event_metadata(&buf, 0).is_none());
    }

    #[test]
    fn read_metadata_offset_exceeds_buffer() {
        let buf = vec![0u8; 64];
        assert!(read_event_metadata(&buf, 60).is_none());
    }

    // ── fd path resolution ─────────────────────────────────────────

    #[test]
    fn resolve_fd_path_stdin() {
        // fd 0 (stdin) should resolve to something under /dev or a pipe.
        match resolve_fd_path(0) {
            Some(p) => assert!(!p.is_empty()),
            None => {
                // stdin may not be open in some test harnesses
            }
        }
    }

    #[test]
    fn resolve_fd_path_invalid() {
        assert!(resolve_fd_path(999_999).is_none());
    }

    // ── provider lifecycle ─────────────────────────────────────────

    #[test]
    fn provider_creation() {
        let p = FanotifyProvider::new(FanotifyConfig::default());
        assert_eq!(p.name(), "fanotify");
        assert_eq!(p.status(), ProviderStatus::Stopped);
        assert!(p.description().contains("Linux syscalls"));
    }

    #[tokio::test]
    async fn provider_degrades_without_root() {
        let mut p = FanotifyProvider::new(FanotifyConfig {
            monitor_paths: vec!["/tmp".to_string()],
            event_mask: FAN_ACCESS | FAN_OPEN,
            flags: libc::O_CLOEXEC | libc::O_NONBLOCK,
            mount_flags: FAN_MARK_ADD | FAN_MARK_MOUNT,
        });

        let (tx, _rx) = mpsc::channel(16);
        p.initialize(tx).await.unwrap();

        // Without privileges the provider must degrade, not crash.
        let s = p.status();
        assert!(
            s == ProviderStatus::Running || s == ProviderStatus::Degraded,
            "expected Running or Degraded, got {:?}",
            s
        );

        p.shutdown().await.unwrap();
        assert_eq!(p.status(), ProviderStatus::Stopped);
    }

    #[test]
    fn provider_info_initial() {
        let p = FanotifyProvider::new(FanotifyConfig::default());
        let info = p.info();
        assert_eq!(info.name, "fanotify");
        assert_eq!(info.events_received, 0);
        assert_eq!(info.events_dropped, 0);
        assert_eq!(info.status, ProviderStatus::Stopped);
        assert!(info.started_at.is_none());
    }

    // ── constants sanity ───────────────────────────────────────────

    #[test]
    fn fanotify_constant_values() {
        assert_eq!(FAN_ACCESS, 0x1);
        assert_eq!(FAN_MODIFY, 0x2);
        assert_eq!(FAN_ATTRIB, 0x4);
        assert_eq!(FAN_CLOSE_WRITE, 0x8);
        assert_eq!(FAN_OPEN, 0x20);
        assert_eq!(FAN_DELETE, 0x400);
        assert_eq!(FAN_OPEN_PERM, 0x1_0000);
        assert_eq!(FAN_EVENT_ON_CHILD, 0x0800_0000);
        assert_eq!(FAN_MARK_ADD, 0x1);
        assert_eq!(FAN_MARK_MOUNT, 0x10);
    }

    #[test]
    fn metadata_struct_size() {
        assert_eq!(
            std::mem::size_of::<FanotifyEventMetadata>(),
            MIN_EVENT_METADATA_SIZE
        );
    }
}
