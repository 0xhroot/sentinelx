use sentinelx_common::hash::HashValue;
use sentinelx_common::pid::Pid;
use sentinelx_common::types::{NamespaceInfo, ProcessInfo, ProcessStatus};

pub struct ProcessScanner;

impl ProcessScanner {
    pub fn new() -> Self {
        Self
    }

    pub fn scan_all(&self) -> Vec<ProcessInfo> {
        let mut processes = Vec::new();

        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if let Some(pid_str) = name.to_str() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        if let Some(info) = self.read_process_info(pid) {
                            processes.push(info);
                        }
                    }
                }
            }
        }

        processes
    }

    pub fn read_process_info(&self, pid: u32) -> Option<ProcessInfo> {
        let status = self.parse_status(pid);
        let cmdline = self.parse_cmdline(pid);
        let stat = self.parse_stat(pid);
        let hash = self.compute_exe_hash(pid);

        let ppid = stat
            .as_ref()
            .map(|s| Pid::new(s.ppid))
            .unwrap_or_else(|| Pid::new(0));

        let (start_ticks, threads) = stat
            .as_ref()
            .map(|s| (s.start_time, s.threads))
            .unwrap_or((0, 0));

        let start_time = stat_time_to_utc(start_ticks);

        let exe_path = format!("/proc/{}/exe", pid);
        let binary_path = std::fs::read_link(&exe_path)
            .ok()
            .and_then(|p| p.into_os_string().into_string().ok())
            .unwrap_or_default();

        let namespace = self.read_namespaces(pid);
        let capabilities = self.read_capabilities(pid);
        let memory_usage_kb = status.as_ref().map(|s| s.vmrss_kb).unwrap_or(0);

        Some(ProcessInfo {
            pid: Pid::new(pid),
            ppid,
            name: status
                .as_ref()
                .map(|s| s.name.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            binary_path,
            command_line: cmdline,
            user: status
                .as_ref()
                .map(|s| s.user.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            uid: status.as_ref().map(|s| s.uid).unwrap_or(0),
            gid: status.as_ref().map(|s| s.gid).unwrap_or(0),
            start_time,
            status: status
                .as_ref()
                .map(|s| s.state.clone())
                .unwrap_or(ProcessStatus::Unknown),
            hash,
            namespace,
            capabilities,
            threads,
            memory_usage_kb,
        })
    }

    fn parse_status(&self, pid: u32) -> Option<ProcessStatusInfo> {
        let path = format!("/proc/{}/status", pid);
        let content = std::fs::read_to_string(path).ok()?;

        let mut info = ProcessStatusInfo::default();

        for line in content.lines() {
            if let Some(val) = line.strip_prefix("Name:") {
                info.name = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("State:") {
                info.state = match val.trim().as_bytes() {
                    b if b.starts_with(b"R") => ProcessStatus::Running,
                    b if b.starts_with(b"S") => ProcessStatus::Sleeping,
                    b if b.starts_with(b"T") => ProcessStatus::Stopped,
                    b if b.starts_with(b"Z") => ProcessStatus::Zombie,
                    b if b.starts_with(b"D") => ProcessStatus::Sleeping,
                    b if b.starts_with(b"X") => ProcessStatus::Dead,
                    _ => ProcessStatus::Unknown,
                };
            } else if let Some(val) = line.strip_prefix("Uid:") {
                let uids: Vec<u32> = val
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if let Some(&uid) = uids.first() {
                    info.uid = uid;
                }
            } else if let Some(val) = line.strip_prefix("Gid:") {
                let gids: Vec<u32> = val
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if let Some(&gid) = gids.first() {
                    info.gid = gid;
                }
            } else if let Some(val) = line.strip_prefix("VmRSS:") {
                info.vmrss_kb = val
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }

        info.user = uid_to_name(info.uid);

        Some(info)
    }

    fn parse_cmdline(&self, pid: u32) -> Vec<String> {
        let path = format!("/proc/{}/cmdline", pid);
        std::fs::read(&path)
            .ok()
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn parse_stat(&self, pid: u32) -> Option<ProcessStat> {
        let path = format!("/proc/{}/stat", pid);
        let content = std::fs::read_to_string(path).ok()?;

        let open_paren = content.find('(')?;
        let close_paren = content.rfind(')')?;

        let _comm = &content[open_paren + 1..close_paren];
        let rest = &content[close_paren + 2..];
        let fields: Vec<&str> = rest.split_whitespace().collect();

        if fields.len() >= 20 {
            Some(ProcessStat {
                ppid: fields[1].parse().unwrap_or(0),
                threads: fields[17].parse().unwrap_or(1),
                start_time: fields[19].parse().unwrap_or(0),
            })
        } else {
            None
        }
    }

    fn compute_exe_hash(&self, pid: u32) -> Option<HashValue> {
        let path = format!("/proc/{}/exe", pid);
        let data = std::fs::read(&path).ok()?;
        Some(HashValue::new(&data))
    }

    fn read_namespaces(&self, pid: u32) -> NamespaceInfo {
        NamespaceInfo {
            pid_ns: self.read_ns_inode(pid, "pid"),
            net_ns: self.read_ns_inode(pid, "net"),
            mnt_ns: self.read_ns_inode(pid, "mnt"),
            user_ns: self.read_ns_inode(pid, "user"),
            uts_ns: self.read_ns_inode(pid, "uts"),
            ipc_ns: self.read_ns_inode(pid, "ipc"),
        }
    }

    fn read_ns_inode(&self, pid: u32, ns_type: &str) -> Option<u64> {
        let path = format!("/proc/{}/ns/{}", pid, ns_type);
        let link = std::fs::read_link(&path).ok()?;
        let link_str = link.to_str()?;
        let inode_str = link_str.strip_prefix("_inode:")?;
        inode_str.parse().ok()
    }

    fn read_capabilities(&self, pid: u32) -> Vec<String> {
        let path = format!("/proc/{}/status", pid);
        std::fs::read_to_string(path)
            .ok()
            .and_then(|content| {
                for line in content.lines() {
                    if let Some(val) = line.strip_prefix("CapEff:") {
                        let cap_hex = val.trim();
                        if let Ok(cap_val) = u64::from_str_radix(cap_hex, 16) {
                            return Some(decode_capabilities(cap_val));
                        }
                    }
                }
                None
            })
            .unwrap_or_default()
    }
}

impl Default for ProcessScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
struct ProcessStatusInfo {
    name: String,
    state: ProcessStatus,
    uid: u32,
    gid: u32,
    vmrss_kb: u64,
    user: String,
}

#[derive(Debug)]
struct ProcessStat {
    ppid: u32,
    threads: u32,
    start_time: u64,
}

fn uid_to_name(uid: u32) -> String {
    // SAFETY: getpwuid returns a pointer to a statically-allocated passwd struct.
    // The pointer is null-checked before dereference. pw_name is NUL-terminated
    // per POSIX. Note: not thread-safe (uses static buffer); acceptable for
    // single-threaded process scanning context.
    unsafe {
        let passwd = libc::getpwuid(uid);
        if !passwd.is_null() {
            let name = std::ffi::CStr::from_ptr((*passwd).pw_name);
            return name.to_string_lossy().to_string();
        }
    }
    uid.to_string()
}

fn decode_capabilities(cap: u64) -> Vec<String> {
    let mut caps = Vec::new();
    let cap_names: &[(&str, u64)] = &[
        ("CAP_CHOWN", 1 << 0),
        ("CAP_DAC_OVERRIDE", 1 << 1),
        ("CAP_DAC_READ_SEARCH", 1 << 2),
        ("CAP_FOWNER", 1 << 3),
        ("CAP_FSETID", 1 << 4),
        ("CAP_KILL", 1 << 5),
        ("CAP_SETGID", 1 << 6),
        ("CAP_SETUID", 1 << 7),
        ("CAP_SETPCAP", 1 << 8),
        ("CAP_LINUX_IMMUTABLE", 1 << 9),
        ("CAP_NET_BIND_SERVICE", 1 << 10),
        ("CAP_NET_BROADCAST", 1 << 11),
        ("CAP_NET_ADMIN", 1 << 12),
        ("CAP_NET_RAW", 1 << 13),
        ("CAP_IPC_LOCK", 1 << 14),
        ("CAP_IPC_OWNER", 1 << 15),
        ("CAP_SYS_MODULE", 1 << 16),
        ("CAP_SYS_RAWIO", 1 << 17),
        ("CAP_SYS_CHROOT", 1 << 18),
        ("CAP_SYS_PTRACE", 1 << 19),
        ("CAP_SYS_PACCT", 1 << 20),
        ("CAP_SYS_ADMIN", 1 << 21),
        ("CAP_SYS_BOOT", 1 << 22),
        ("CAP_SYS_NICE", 1 << 23),
        ("CAP_SYS_RESOURCE", 1 << 24),
        ("CAP_SYS_TIME", 1 << 25),
        ("CAP_SYS_TTY_CONFIG", 1 << 26),
        ("CAP_MKNOD", 1 << 27),
        ("CAP_LEASE", 1 << 28),
        ("CAP_AUDIT_WRITE", 1 << 29),
        ("CAP_AUDIT_CONTROL", 1 << 30),
        ("CAP_SETFCAP", 1 << 31),
    ];

    for &(name, bit) in cap_names {
        if cap & bit != 0 {
            caps.push(name.to_string());
        }
    }
    caps
}

fn stat_time_to_utc(_start_ticks: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_all_finds_own_process() {
        let scanner = ProcessScanner::new();
        let processes = scanner.scan_all();
        let self_pid = std::process::id();
        assert!(processes.iter().any(|p| p.pid.as_u32() == self_pid));
    }

    #[test]
    fn decode_capabilities_works() {
        let caps = decode_capabilities(0x80);
        assert!(caps.contains(&"CAP_SETUID".to_string()));
    }
}
