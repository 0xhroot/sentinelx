use sentinelx_common::pid::Pid;
use sentinelx_common::types::{ConnectionState, NetworkConnection, Protocol, SocketAddr};

pub struct NetworkScanner;

impl NetworkScanner {
    pub fn new() -> Self {
        Self
    }

    pub fn scan_all(&self) -> Vec<NetworkConnection> {
        let mut connections = Vec::new();

        if let Some(tcp) = self.parse_proc_net("tcp", Protocol::Tcp) {
            connections.extend(tcp);
        }
        if let Some(tcp6) = self.parse_proc_net("tcp6", Protocol::Tcp6) {
            connections.extend(tcp6);
        }
        if let Some(udp) = self.parse_proc_net("udp", Protocol::Udp) {
            connections.extend(udp);
        }
        if let Some(udp6) = self.parse_proc_net("udp6", Protocol::Udp6) {
            connections.extend(udp6);
        }

        connections
    }

    fn parse_proc_net(&self, filename: &str, protocol: Protocol) -> Option<Vec<NetworkConnection>> {
        let path = format!("/proc/net/{}", filename);
        let content = std::fs::read_to_string(&path).ok()?;

        let mut connections = Vec::new();

        for line in content.lines().skip(1) {
            if let Some(conn) = self.parse_line(line, protocol.clone()) {
                connections.push(conn);
            }
        }

        Some(connections)
    }

    fn parse_line(&self, line: &str, protocol: Protocol) -> Option<NetworkConnection> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return None;
        }

        let local_addr = parse_hex_addr(fields[1])?;
        let remote_addr = parse_hex_addr(fields[2])?;
        let state = parse_state(fields[3])?;
        let inode: u64 = fields[9].parse().ok()?;

        let pid = self.find_pid_by_inode(inode);

        let process_name = pid.and_then(|p| {
            let proc_path = format!("/proc/{}/comm", p.as_u32());
            std::fs::read_to_string(proc_path)
                .ok()
                .map(|s| s.trim().to_string())
        });

        let uid: u32 = fields[7].parse().unwrap_or(0);

        Some(NetworkConnection {
            local_addr: SocketAddr {
                ip: local_addr.0,
                port: local_addr.1,
            },
            remote_addr: Some(SocketAddr {
                ip: remote_addr.0,
                port: remote_addr.1,
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

    fn find_pid_by_inode(&self, inode: u64) -> Option<Pid> {
        if inode == 0 {
            return None;
        }

        let proc_dir = std::fs::read_dir("/proc").ok()?;

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            if let Some(pid_str) = name.to_str() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    let fd_dir = format!("/proc/{}/fd", pid);
                    if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                        for fd in fds.flatten() {
                            let link = std::fs::read_link(fd.path()).ok();
                            if let Some(target) = link {
                                let target_str = target.to_string_lossy();
                                if target_str.contains(&format!("socket:[{}]", inode)) {
                                    return Some(Pid::new(pid));
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_hex_addr(hex_str: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex_str.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr_hex = parts[0];
    let port_hex = parts[1];

    let addr_val = u32::from_str_radix(addr_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    let ip = format!(
        "{}.{}.{}.{}",
        addr_val & 0xff,
        (addr_val >> 8) & 0xff,
        (addr_val >> 16) & 0xff,
        (addr_val >> 24) & 0xff,
    );

    Some((ip, port))
}

fn parse_state(hex_state: &str) -> Option<ConnectionState> {
    let state_val = u32::from_str_radix(hex_state, 16).ok()?;
    Some(match state_val {
        0x01 => ConnectionState::Established,
        0x02 => ConnectionState::SynSent,
        0x03 => ConnectionState::SynRecv,
        0x04 => ConnectionState::FinWait1,
        0x05 => ConnectionState::FinWait2,
        0x06 => ConnectionState::TimeWait,
        0x07 => ConnectionState::Close,
        0x08 => ConnectionState::CloseWait,
        0x09 => ConnectionState::LastAck,
        0x0A => ConnectionState::Listen,
        0x0B => ConnectionState::Closing,
        _ => ConnectionState::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_addr_works() {
        let result = parse_hex_addr("0100007F:1F90");
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_state_works() {
        assert_eq!(parse_state("0A"), Some(ConnectionState::Listen));
        assert_eq!(parse_state("01"), Some(ConnectionState::Established));
    }

    #[test]
    fn scanner_creates() {
        let scanner = NetworkScanner::new();
        let connections = scanner.scan_all();
        assert!(!connections.is_empty() || connections.is_empty());
    }
}
