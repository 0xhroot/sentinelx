use sentinelx_common::types::ForensicSnapshot;
use sentinelx_common::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct ForensicReport {
    snapshot: ForensicSnapshot,
}

impl ForensicReport {
    pub fn new(snapshot: ForensicSnapshot) -> Self {
        Self { snapshot }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.snapshot).unwrap_or_default()
    }

    pub fn to_summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Forensic Report: {}", self.snapshot.id));
        lines.push(format!("Timestamp: {}", self.snapshot.timestamp));
        lines.push(format!("Hostname: {}", self.snapshot.hostname));
        lines.push(format!("Kernel: {}", self.snapshot.kernel_version));
        lines.push(format!("Processes: {}", self.snapshot.processes.len()));
        lines.push(format!("Kernel Modules: {}", self.snapshot.modules.len()));
        lines.push(format!(
            "Network Connections: {}",
            self.snapshot.connections.len()
        ));
        lines.push(format!("Open Files: {}", self.snapshot.open_files.len()));
        lines.push(format!(
            "Environment Variables: {}",
            self.snapshot.env_vars.len()
        ));

        let mut state_counts: HashMap<String, u32> = HashMap::new();
        for p in &self.snapshot.processes {
            *state_counts.entry(format!("{:?}", p.status)).or_insert(0) += 1;
        }
        lines.push("Process States:".to_string());
        let mut state_vec: Vec<_> = state_counts.into_iter().collect();
        state_vec.sort_by_key(|b| std::cmp::Reverse(b.1));
        for (state, count) in &state_vec {
            lines.push(format!("  {}: {}", state, count));
        }

        let mut proto_counts: HashMap<String, u32> = HashMap::new();
        for c in &self.snapshot.connections {
            *proto_counts.entry(format!("{:?}", c.protocol)).or_insert(0) += 1;
        }
        lines.push("Connections by Protocol:".to_string());
        let mut proto_vec: Vec<_> = proto_counts.into_iter().collect();
        proto_vec.sort_by_key(|b| std::cmp::Reverse(b.1));
        for (proto, count) in &proto_vec {
            lines.push(format!("  {}: {}", proto, count));
        }

        lines.push(format!("Hooks Detected: {}", self.snapshot.hooks.len()));
        lines.push(format!("Threats Detected: {}", self.snapshot.threats.len()));
        lines.push(format!(
            "Memory Hashes: {}",
            self.snapshot.memory_hashes.len()
        ));

        lines.join("\n")
    }

    pub fn save_to_dir(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;

        let report_json = self.to_json();
        fs::write(dir.join("report.json"), report_json)?;

        fs::write(
            dir.join("processes.json"),
            serde_json::to_string_pretty(&self.snapshot.processes).unwrap_or_default(),
        )?;

        fs::write(
            dir.join("modules.json"),
            serde_json::to_string_pretty(&self.snapshot.modules).unwrap_or_default(),
        )?;

        fs::write(
            dir.join("connections.json"),
            serde_json::to_string_pretty(&self.snapshot.connections).unwrap_or_default(),
        )?;

        fs::write(
            dir.join("open_files.json"),
            serde_json::to_string_pretty(&self.snapshot.open_files).unwrap_or_default(),
        )?;

        fs::write(
            dir.join("environment.json"),
            serde_json::to_string_pretty(&self.snapshot.env_vars).unwrap_or_default(),
        )?;

        Ok(())
    }

    pub fn compute_iocs(&self) -> Vec<String> {
        let mut iocs = Vec::new();

        for conn in &self.snapshot.connections {
            if !conn.local_addr.ip.is_empty()
                && conn.local_addr.ip != "0.0.0.0"
                && conn.local_addr.ip != "::"
            {
                iocs.push(conn.local_addr.ip.clone());
            }
            if let Some(remote) = &conn.remote_addr {
                if !remote.ip.is_empty() && remote.ip != "0.0.0.0" && remote.ip != "::" {
                    iocs.push(remote.ip.clone());
                }
            }
        }

        for proc in &self.snapshot.processes {
            if let Some(ref hash) = proc.hash {
                iocs.push(hash.as_hex().to_string());
            }
        }

        for (path, hash) in &self.snapshot.memory_hashes {
            iocs.push(format!("{}:{}", path, hash.as_hex()));
        }

        for file in &self.snapshot.open_files {
            if is_suspicious_path(file) {
                iocs.push(file.clone());
            }
        }

        for proc in &self.snapshot.processes {
            if is_suspicious_path(&proc.binary_path) {
                iocs.push(proc.binary_path.clone());
            }
        }

        for module in &self.snapshot.modules {
            if module.name.starts_with('.')
                || module.name.contains("rootkit")
                || module.name.contains("hide")
            {
                iocs.push(module.name.clone());
            }
        }

        iocs.sort();
        iocs.dedup();
        iocs
    }
}

fn is_suspicious_path(path: &str) -> bool {
    path.starts_with("/tmp/")
        || path.starts_with("/dev/shm/")
        || path.starts_with("/var/tmp/")
        || path.contains("/..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinelx_common::types::*;
    use sentinelx_common::{HashValue, Pid};
    use std::collections::HashMap;

    fn make_test_snapshot() -> ForensicSnapshot {
        ForensicSnapshot {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            hostname: "test-host".to_string(),
            kernel_version: "6.1.0-test".to_string(),
            processes: vec![ProcessInfo {
                pid: Pid::new(1),
                ppid: Pid::new(0),
                name: "systemd".to_string(),
                binary_path: "/usr/lib/systemd/systemd".to_string(),
                command_line: vec!["/usr/lib/systemd/systemd".to_string()],
                user: "root".to_string(),
                uid: 0,
                gid: 0,
                start_time: Utc::now(),
                status: ProcessStatus::Sleeping,
                hash: Some(HashValue::new(b"test-binary")),
                namespace: NamespaceInfo::default(),
                capabilities: vec!["sys_admin".to_string()],
                threads: 1,
                memory_usage_kb: 10240,
            }],
            modules: vec![KernelModuleInfo {
                name: "test_module".to_string(),
                size: 4096,
                ref_count: 1,
                load_address: 0xffffffffc0000000,
                state: ModuleState::Live,
                version: None,
                license: None,
                hash: None,
                signature_valid: None,
                source: ModuleSource::ProcModules,
            }],
            connections: vec![NetworkConnection {
                local_addr: SocketAddr {
                    ip: "127.0.0.1".to_string(),
                    port: 8080,
                },
                remote_addr: Some(SocketAddr {
                    ip: "10.0.0.1".to_string(),
                    port: 443,
                }),
                protocol: Protocol::Tcp,
                state: ConnectionState::Established,
                pid: Some(Pid::new(1234)),
                inode: 5678,
                uid: 0,
                process_name: Some("test_proc".to_string()),
                process_hash: None,
            }],
            hooks: Vec::new(),
            threats: Vec::new(),
            memory_hashes: HashMap::from([(
                "/test/binary".to_string(),
                HashValue::new(b"test_hash"),
            )]),
            open_files: vec![
                "/tmp/suspicious_file".to_string(),
                "/usr/lib/test.so".to_string(),
                "/proc/1/fd/0".to_string(),
            ],
            env_vars: HashMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]),
        }
    }

    #[test]
    fn test_to_json() {
        let report = ForensicReport::new(make_test_snapshot());
        let json = report.to_json();
        assert!(!json.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
        assert_eq!(parsed["hostname"], "test-host");
        assert_eq!(parsed["kernel_version"], "6.1.0-test");
    }

    #[test]
    fn test_to_json_contains_processes() {
        let report = ForensicReport::new(make_test_snapshot());
        let json = report.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let procs = parsed["processes"].as_array().unwrap();
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0]["name"], "systemd");
    }

    #[test]
    fn test_to_summary() {
        let report = ForensicReport::new(make_test_snapshot());
        let summary = report.to_summary();
        assert!(summary.contains("test-host"));
        assert!(summary.contains("6.1.0-test"));
        assert!(summary.contains("Processes: 1"));
        assert!(summary.contains("Kernel Modules: 1"));
        assert!(summary.contains("Network Connections: 1"));
        assert!(summary.contains("Open Files: 3"));
        assert!(summary.contains("Sleeping: 1"));
        assert!(summary.contains("Tcp: 1"));
    }

    #[test]
    fn test_save_to_dir() {
        let report = ForensicReport::new(make_test_snapshot());
        let dir = std::env::temp_dir().join("sentinelx_forensics_test_save");
        let _ = fs::remove_dir_all(&dir);

        report.save_to_dir(&dir).unwrap();

        assert!(dir.join("report.json").exists());
        assert!(dir.join("processes.json").exists());
        assert!(dir.join("modules.json").exists());
        assert!(dir.join("connections.json").exists());
        assert!(dir.join("open_files.json").exists());
        assert!(dir.join("environment.json").exists());

        let report_content = fs::read_to_string(dir.join("report.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&report_content).unwrap();
        assert_eq!(parsed["hostname"], "test-host");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_save_to_dir_creates_parent_dirs() {
        let report = ForensicReport::new(make_test_snapshot());
        let dir = std::env::temp_dir()
            .join("sentinelx_test")
            .join("nested")
            .join("dir");
        let _ = fs::remove_dir_all(std::env::temp_dir().join("sentinelx_test"));

        report.save_to_dir(&dir).unwrap();
        assert!(dir.join("report.json").exists());

        let _ = fs::remove_dir_all(std::env::temp_dir().join("sentinelx_test"));
    }

    #[test]
    fn test_compute_iocs() {
        let report = ForensicReport::new(make_test_snapshot());
        let iocs = report.compute_iocs();
        assert!(iocs.contains(&"127.0.0.1".to_string()));
        assert!(iocs.contains(&"10.0.0.1".to_string()));
        assert!(iocs.contains(&"/tmp/suspicious_file".to_string()));
    }

    #[test]
    fn test_compute_iocs_excludes_zero_addr() {
        let mut snapshot = make_test_snapshot();
        snapshot.connections.push(NetworkConnection {
            local_addr: SocketAddr {
                ip: "0.0.0.0".to_string(),
                port: 0,
            },
            remote_addr: Some(SocketAddr {
                ip: "0.0.0.0".to_string(),
                port: 0,
            }),
            protocol: Protocol::Udp,
            state: ConnectionState::Close,
            pid: None,
            inode: 9999,
            uid: 0,
            process_name: None,
            process_hash: None,
        });
        let report = ForensicReport::new(snapshot);
        let iocs = report.compute_iocs();
        assert!(!iocs.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn test_compute_iocs_deduplicates() {
        let mut snapshot = make_test_snapshot();
        snapshot.connections.push(NetworkConnection {
            local_addr: SocketAddr {
                ip: "10.0.0.1".to_string(),
                port: 80,
            },
            remote_addr: Some(SocketAddr {
                ip: "127.0.0.1".to_string(),
                port: 9090,
            }),
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            pid: Some(Pid::new(5678)),
            inode: 1111,
            uid: 0,
            process_name: None,
            process_hash: None,
        });
        let report = ForensicReport::new(snapshot);
        let iocs = report.compute_iocs();
        let count_10_0_0_1 = iocs.iter().filter(|i| **i == "10.0.0.1").count();
        assert_eq!(count_10_0_0_1, 1);
    }

    #[test]
    fn test_compute_iocs_finds_hash() {
        let snapshot = make_test_snapshot();
        let report = ForensicReport::new(snapshot);
        let iocs = report.compute_iocs();
        let expected = HashValue::new(b"test-binary");
        assert!(iocs.contains(&expected.as_hex().to_string()));
    }

    #[test]
    fn test_is_suspicious_path() {
        assert!(is_suspicious_path("/tmp/malware"));
        assert!(is_suspicious_path("/dev/shm/payload"));
        assert!(is_suspicious_path("/var/tmp/.hidden"));
        assert!(is_suspicious_path("/usr/lib/../bin/evil"));
        assert!(!is_suspicious_path("/usr/lib/test.so"));
        assert!(!is_suspicious_path("/home/user/file.txt"));
    }
}
