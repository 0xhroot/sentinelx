use chrono::Utc;
use sentinelx_common::types::*;
use sentinelx_common::Pid;
use std::collections::HashMap;
use std::fs;

const CAPABILITY_NAMES: &[(u32, &str)] = &[
    (0, "chown"),
    (1, "dac_override"),
    (2, "dac_read_search"),
    (3, "fowner"),
    (4, "fsetid"),
    (5, "kill"),
    (6, "setgid"),
    (7, "setuid"),
    (8, "setpcap"),
    (9, "linux_immutable"),
    (10, "net_bind_service"),
    (11, "net_broadcast"),
    (12, "net_admin"),
    (13, "net_raw"),
    (14, "ipc_lock"),
    (15, "ipc_owner"),
    (16, "sys_module"),
    (17, "sys_rawio"),
    (18, "sys_chroot"),
    (19, "sys_ptrace"),
    (20, "sys_pacct"),
    (21, "sys_admin"),
    (22, "sys_boot"),
    (23, "sys_nice"),
    (24, "sys_resource"),
    (25, "sys_time"),
    (26, "sys_tty_config"),
    (27, "mknod"),
    (28, "lease"),
    (29, "audit_write"),
    (30, "audit_control"),
    (31, "setfcap"),
    (32, "mac_override"),
    (33, "mac_admin"),
    (34, "syslog"),
    (35, "wake_alarm"),
    (36, "block_suspend"),
    (37, "audit_read"),
    (38, "perfmon"),
    (39, "bpf"),
    (40, "checkpoint_restore"),
];

pub struct ForensicsCollector;

impl Default for ForensicsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsCollector {
    pub fn new() -> Self {
        Self
    }

    pub fn collect_process_tree(&self) -> Vec<ProcessInfo> {
        let mut processes = Vec::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if let Some(s) = name.to_str() {
                    if let Ok(pid) = s.parse::<u32>() {
                        if let Some(info) = self.parse_process(pid) {
                            processes.push(info);
                        }
                    }
                }
            }
        }
        processes
    }

    fn parse_process(&self, pid: u32) -> Option<ProcessInfo> {
        let status_text = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
        let stat_text = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;

        let mut name = String::new();
        let mut state_char = ' ';
        let mut ppid = 0u32;
        let mut uid = 0u32;
        let mut gid = 0u32;
        let mut threads = 0u32;
        let mut vm_rss = 0u64;
        let mut cap_hex = String::new();

        for line in status_text.lines() {
            if let Some(v) = line.strip_prefix("Name:") {
                name = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("State:") {
                state_char = v.trim().chars().next().unwrap_or(' ');
            } else if let Some(v) = line.strip_prefix("PPid:") {
                ppid = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Uid:") {
                uid = v
                    .split_whitespace()
                    .next()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Gid:") {
                gid = v
                    .split_whitespace()
                    .next()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Threads:") {
                threads = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("VmRSS:") {
                vm_rss = v
                    .split_whitespace()
                    .next()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("CapEff:") {
                cap_hex = v.trim().to_string();
            }
        }

        let open = stat_text.find('(')?;
        let close = stat_text[open..].rfind(')')? + open;
        let after_paren = close.checked_add(2)?;
        if after_paren >= stat_text.len() {
            return None;
        }
        let fields: Vec<&str> = stat_text[after_paren..].split_whitespace().collect();
        let start_ticks: u64 = fields.get(19).and_then(|s| s.parse().ok()).unwrap_or(0);

        let uptime = fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .unwrap_or(0.0);
        let ticks_per_sec: u64 = 100;
        let process_age_secs = start_ticks / ticks_per_sec;
        let boot_offset = chrono::Duration::seconds((uptime as i64) - (process_age_secs as i64));
        let start_time = Utc::now() - boot_offset;

        let command_line: Vec<String> = fs::read_to_string(format!("/proc/{}/cmdline", pid))
            .unwrap_or_default()
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        let binary_path = fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let user = lookup_uid(uid);

        let proc_status = match state_char {
            'R' => ProcessStatus::Running,
            'S' => ProcessStatus::Sleeping,
            'T' => ProcessStatus::Stopped,
            'Z' => ProcessStatus::Zombie,
            'D' | 'X' => ProcessStatus::Dead,
            _ => ProcessStatus::Unknown,
        };

        let cap_val = u64::from_str_radix(&cap_hex, 16).unwrap_or(0);
        let capabilities: Vec<String> = CAPABILITY_NAMES
            .iter()
            .filter(|&&(bit, _)| cap_val & (1 << bit) != 0)
            .map(|&(_, name)| name.to_string())
            .collect();

        let namespace = NamespaceInfo {
            pid_ns: read_ns(pid, "pid"),
            net_ns: read_ns(pid, "net"),
            mnt_ns: read_ns(pid, "mnt"),
            user_ns: read_ns(pid, "user"),
            uts_ns: read_ns(pid, "uts"),
            ipc_ns: read_ns(pid, "ipc"),
        };

        Some(ProcessInfo {
            pid: Pid::new(pid),
            ppid: Pid::new(ppid),
            name,
            binary_path,
            command_line,
            user,
            uid,
            gid,
            start_time,
            status: proc_status,
            hash: None,
            namespace,
            capabilities,
            threads,
            memory_usage_kb: vm_rss,
        })
    }

    pub fn collect_network_state(&self) -> Vec<NetworkConnection> {
        let mut connections = Vec::new();
        let inode_map = self.build_inode_map();

        let proto_files: &[(&str, Protocol)] = &[
            ("/proc/net/tcp", Protocol::Tcp),
            ("/proc/net/tcp6", Protocol::Tcp6),
            ("/proc/net/udp", Protocol::Udp),
            ("/proc/net/udp6", Protocol::Udp6),
        ];

        for &(file, ref proto) in proto_files {
            if let Ok(content) = fs::read_to_string(file) {
                for line in content.lines().skip(1) {
                    if let Some(conn) = parse_net_line(line, proto.clone(), &inode_map) {
                        connections.push(conn);
                    }
                }
            }
        }

        connections
    }

    fn build_inode_map(&self) -> HashMap<u64, u32> {
        let mut map = HashMap::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Some(s) = entry.file_name().to_str() {
                    if let Ok(pid) = s.parse::<u32>() {
                        let fd_dir = format!("/proc/{}/fd", pid);
                        if let Ok(fds) = fs::read_dir(&fd_dir) {
                            for fd in fds.flatten() {
                                if let Ok(target) = fs::read_link(fd.path()) {
                                    let t = target.to_string_lossy();
                                    if let Some(inode) = t
                                        .strip_prefix("socket:[")
                                        .and_then(|s| s.strip_suffix(']'))
                                        .and_then(|s| s.parse::<u64>().ok())
                                    {
                                        map.insert(inode, pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        map
    }

    pub fn collect_kernel_modules(&self) -> Vec<KernelModuleInfo> {
        let mut modules = Vec::new();
        if let Ok(content) = fs::read_to_string("/proc/modules") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 6 {
                    continue;
                }
                let name = parts[0].to_string();
                let size = parts[1].parse::<u64>().unwrap_or(0);
                let ref_count = parts[2].parse::<u32>().unwrap_or(0);
                let load_addr =
                    u64::from_str_radix(parts[3].trim_start_matches("0x"), 16).unwrap_or(0);

                let state = match parts[4] {
                    "Live" => ModuleState::Live,
                    "Coming" => ModuleState::Coming,
                    "Going" => ModuleState::Going,
                    _ => ModuleState::Unknown,
                };

                modules.push(KernelModuleInfo {
                    name,
                    size,
                    ref_count,
                    load_address: load_addr,
                    state,
                    version: None,
                    license: None,
                    hash: None,
                    signature_valid: None,
                    source: ModuleSource::ProcModules,
                });
            }
        }
        modules
    }

    pub fn collect_open_files(&self) -> Vec<String> {
        let mut files = Vec::new();
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Some(s) = entry.file_name().to_str() {
                    if s.parse::<u32>().is_ok() {
                        let fd_dir = entry.path().join("fd");
                        if let Ok(fds) = fs::read_dir(&fd_dir) {
                            for fd in fds.flatten() {
                                if let Ok(target) = fs::read_link(fd.path()) {
                                    files.push(target.to_string_lossy().to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        files.sort();
        files.dedup();
        files
    }

    pub fn collect_environment(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();
        if let Ok(content) = fs::read_to_string("/proc/self/environ") {
            for entry in content.split('\0') {
                if let Some((key, value)) = entry.split_once('=') {
                    env.insert(key.to_string(), value.to_string());
                }
            }
        }
        env
    }

    pub fn collect_system_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();

        if let Ok(v) = fs::read_to_string("/proc/version") {
            info.insert("kernel_version".to_string(), v.trim().to_string());
        }

        if let Ok(h) = fs::read_to_string("/proc/sys/kernel/hostname") {
            info.insert("hostname".to_string(), h.trim().to_string());
        }

        if let Ok(content) = fs::read_to_string("/proc/uptime") {
            if let Some(val) = content.split_whitespace().next() {
                info.insert("uptime".to_string(), format!("{}s", val));
            }
        }

        info
    }

    pub fn collect_all(&self) -> ForensicSnapshot {
        let sys_info = self.collect_system_info();

        ForensicSnapshot {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            hostname: sys_info.get("hostname").cloned().unwrap_or_default(),
            kernel_version: sys_info.get("kernel_version").cloned().unwrap_or_default(),
            processes: self.collect_process_tree(),
            modules: self.collect_kernel_modules(),
            connections: self.collect_network_state(),
            hooks: Vec::new(),
            threats: Vec::new(),
            memory_hashes: HashMap::new(),
            open_files: self.collect_open_files(),
            env_vars: self.collect_environment(),
        }
    }
}

fn lookup_uid(uid: u32) -> String {
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(file_uid) = parts[2].parse::<u32>() {
                    if file_uid == uid {
                        return parts[0].to_string();
                    }
                }
            }
        }
    }
    format!("uid:{}", uid)
}

fn read_ns(pid: u32, ns_type: &str) -> Option<u64> {
    let target = fs::read_link(format!("/proc/{}/ns/{}", pid, ns_type)).ok()?;
    let s = target.to_str()?;
    let start = s.find('[')?.checked_add(1)?;
    let end = s.rfind(']')?;
    s[start..end].parse().ok()
}

fn parse_hex_ip(hex_str: &str) -> Option<String> {
    let val = u32::from_str_radix(hex_str, 16).ok()?;
    Some(format!(
        "{}.{}.{}.{}",
        val & 0xFF,
        (val >> 8) & 0xFF,
        (val >> 16) & 0xFF,
        (val >> 24) & 0xFF,
    ))
}

fn parse_hex_ipv6(hex_str: &str) -> Option<String> {
    if hex_str.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let chunk = &hex_str[i * 8..(i + 1) * 8];
        let val = u32::from_str_radix(chunk, 16).ok()?;
        let b = val.to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&b);
    }
    Some(format!(
        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    ))
}

fn parse_conn_state(hex: &str) -> ConnectionState {
    match hex {
        "01" => ConnectionState::Established,
        "02" => ConnectionState::SynSent,
        "03" => ConnectionState::SynRecv,
        "04" => ConnectionState::FinWait1,
        "05" => ConnectionState::FinWait2,
        "06" => ConnectionState::TimeWait,
        "07" => ConnectionState::Close,
        "08" => ConnectionState::CloseWait,
        "09" => ConnectionState::LastAck,
        "0A" => ConnectionState::Listen,
        "0B" => ConnectionState::Closing,
        _ => ConnectionState::Unknown,
    }
}

fn parse_addr_port(addr_str: &str) -> Option<(String, u16)> {
    let (ip_hex, port_hex) = addr_str.split_once(':')?;
    let ip = match ip_hex.len() {
        8 => parse_hex_ip(ip_hex)?,
        32 => parse_hex_ipv6(ip_hex)?,
        _ => return None,
    };
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((ip, port))
}

fn parse_net_line(
    line: &str,
    protocol: Protocol,
    inode_map: &HashMap<u64, u32>,
) -> Option<NetworkConnection> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let local = parts[1];
    let remote = parts[2];
    let state_hex = parts[3];
    let uid: u32 = parts[7].parse().ok()?;
    let inode: u64 = parts[9].parse().ok()?;

    let (local_ip, local_port) = parse_addr_port(local)?;
    let (remote_ip, remote_port) = parse_addr_port(remote)?;

    let state = parse_conn_state(state_hex);

    let pid = inode_map.get(&inode).copied().map(Pid::new);
    let process_name = pid.and_then(|p| {
        fs::read_to_string(format!("/proc/{}/comm", p.as_u32()))
            .ok()
            .map(|s| s.trim().to_string())
    });

    Some(NetworkConnection {
        local_addr: SocketAddr {
            ip: local_ip,
            port: local_port,
        },
        remote_addr: Some(SocketAddr {
            ip: remote_ip,
            port: remote_port,
        }),
        protocol,
        state,
        pid,
        inode,
        uid,
        process_name,
        process_hash: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_process_tree() {
        let collector = ForensicsCollector::new();
        let procs = collector.collect_process_tree();
        assert!(!procs.is_empty());
        assert!(procs.iter().any(|p| p.pid.as_u32() == 1));
    }

    #[test]
    fn test_collect_process_tree_has_root() {
        let collector = ForensicsCollector::new();
        let procs = collector.collect_process_tree();
        let init = procs.iter().find(|p| p.pid.as_u32() == 1).unwrap();
        assert_eq!(init.name, "systemd");
        assert_eq!(init.ppid.as_u32(), 0);
    }

    #[test]
    fn test_collect_network_state() {
        let collector = ForensicsCollector::new();
        let _conns = collector.collect_network_state();
    }

    #[test]
    fn test_collect_network_state_parses_tcp() {
        let hex_ip = parse_hex_ip("0100007F");
        assert_eq!(hex_ip.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn test_collect_network_state_parses_port() {
        let result = parse_addr_port("0100007F:0050");
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_collect_kernel_modules() {
        let collector = ForensicsCollector::new();
        let _modules = collector.collect_kernel_modules();
    }

    #[test]
    fn test_collect_open_files() {
        let collector = ForensicsCollector::new();
        let files = collector.collect_open_files();
        assert!(!files.is_empty());
    }

    #[test]
    fn test_collect_environment() {
        let collector = ForensicsCollector::new();
        let env = collector.collect_environment();
        assert!(!env.is_empty());
    }

    #[test]
    fn test_collect_system_info() {
        let collector = ForensicsCollector::new();
        let info = collector.collect_system_info();
        assert!(info.contains_key("kernel_version"));
        assert!(info.contains_key("hostname"));
        assert!(info.contains_key("uptime"));
    }

    #[test]
    fn test_collect_all() {
        let collector = ForensicsCollector::new();
        let snapshot = collector.collect_all();
        assert!(!snapshot.hostname.is_empty());
        assert!(!snapshot.kernel_version.is_empty());
        assert!(!snapshot.processes.is_empty());
    }

    #[test]
    fn test_capability_decode() {
        let collector = ForensicsCollector::new();
        let procs = collector.collect_process_tree();
        let root_proc = procs.iter().find(|p| p.uid == 0 && p.pid.as_u32() == 1);
        assert!(root_proc.is_some());
        let caps = &root_proc.unwrap().capabilities;
        assert!(caps.contains(&"sys_admin".to_string()));
    }

    #[test]
    fn test_hex_ip_parsing() {
        assert_eq!(parse_hex_ip("00000000").as_deref(), Some("0.0.0.0"));
        assert_eq!(parse_hex_ip("FFFFFFFF").as_deref(), Some("255.255.255.255"));
    }

    #[test]
    fn test_connection_state_parsing() {
        assert_eq!(parse_conn_state("01"), ConnectionState::Established);
        assert_eq!(parse_conn_state("0A"), ConnectionState::Listen);
        assert_eq!(parse_conn_state("06"), ConnectionState::TimeWait);
        assert_eq!(parse_conn_state("FF"), ConnectionState::Unknown);
    }
}
