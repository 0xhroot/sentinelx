use std::fs;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub exists: bool,
    pub is_symlink: bool,
    pub is_file: bool,
    pub is_dir: bool,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub size: u64,
    pub dev: u64,
    pub ino: u64,
}

impl FileMetadata {
    pub fn analyze(path: &str) -> Self {
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => {
                return Self {
                    exists: false,
                    is_symlink: false,
                    is_file: false,
                    is_dir: false,
                    uid: 0,
                    gid: 0,
                    permissions: 0,
                    size: 0,
                    dev: 0,
                    ino: 0,
                };
            }
        };

        Self {
            exists: true,
            is_symlink: meta.file_type().is_symlink(),
            is_file: meta.file_type().is_file(),
            is_dir: meta.file_type().is_dir(),
            uid: meta.uid(),
            gid: meta.gid(),
            permissions: meta.mode() & 0o7777,
            size: meta.size(),
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }

    pub fn is_world_writable(&self) -> bool {
        self.permissions & 0o002 != 0
    }

    pub fn is_setuid(&self) -> bool {
        self.permissions & 0o4000 != 0
    }

    pub fn is_setgid(&self) -> bool {
        self.permissions & 0o2000 != 0
    }

    pub fn standard_permissions(&self) -> bool {
        !self.is_world_writable() && !self.is_setuid() && !self.is_setgid()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExecRisk {
    Trusted,
    Verified,
    Suspicious,
    Critical,
}

#[derive(Debug, Clone)]
pub struct ExecAnalysis {
    pub raw: String,
    pub command: String,
    pub args: Vec<String>,
    pub risk: ExecRisk,
    pub confidence: f64,
}

const TRUSTED_DIRS: &[&str] = &[
    "/usr/lib/systemd/system",
    "/usr/lib/systemd/user",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/run/systemd/generator",
];

const VERIFIED_DIRS: &[&str] = &["/etc", "/opt", "/usr/local/bin", "/usr/local/sbin", "/run"];

const CRITICAL_DIRS: &[&str] = &["/tmp", "/dev/shm", "/var/tmp", "/var/run/user"];

const SUSPICIOUS_DIRS: &[&str] = &["/home", "/root", "/var/tmp", "/run/user"];

pub fn classify_exec_path(path: &str) -> ExecRisk {
    if CRITICAL_DIRS.iter().any(|d| path.starts_with(d)) {
        return ExecRisk::Critical;
    }
    if SUSPICIOUS_DIRS.iter().any(|d| path.starts_with(d)) {
        return ExecRisk::Suspicious;
    }
    if TRUSTED_DIRS.iter().any(|d| path.starts_with(d)) {
        return ExecRisk::Trusted;
    }
    if VERIFIED_DIRS.iter().any(|d| path.starts_with(d)) {
        return ExecRisk::Verified;
    }
    ExecRisk::Suspicious
}

pub fn parse_exec_fields(unit_content: &str) -> Vec<ExecAnalysis> {
    let mut results = Vec::new();

    for line in unit_content.lines() {
        let trimmed = line.trim();
        for prefix in &[
            "ExecStart=",
            "ExecStartPre=",
            "ExecStartPost=",
            "ExecStop=",
            "ExecStopPost=",
        ] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let raw = rest.trim().to_string();
                if raw.is_empty() {
                    continue;
                }

                let (raw_value, _has_at) = if let Some(stripped) = raw.strip_prefix('@') {
                    (stripped.to_string(), true)
                } else {
                    (raw.clone(), false)
                };

                let raw_value = if let Some(stripped) = raw_value.strip_prefix('!') {
                    stripped.to_string()
                } else {
                    raw_value
                };

                let raw_value = if let Some(stripped) = raw_value.strip_prefix('-') {
                    stripped.to_string()
                } else {
                    raw_value
                };

                let parts: Vec<&str> = raw_value.split_whitespace().collect();
                let command = parts.first().unwrap_or(&"").to_string();
                let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

                let risk = classify_exec_path(&command);
                let confidence = match risk {
                    ExecRisk::Trusted => 0.95,
                    ExecRisk::Verified => 0.80,
                    ExecRisk::Suspicious => 0.50,
                    ExecRisk::Critical => 0.30,
                };

                results.push(ExecAnalysis {
                    raw,
                    command,
                    args,
                    risk,
                    confidence,
                });
            }
        }
    }

    results
}

pub fn analyze_exec_start_for_path(path: &str) -> Vec<ExecAnalysis> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_exec_fields(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_metadata_nonexistent() {
        let meta = FileMetadata::analyze("/nonexistent/path");
        assert!(!meta.exists);
        assert_eq!(meta.uid, 0);
    }

    #[test]
    fn test_file_metadata_root() {
        let meta = FileMetadata::analyze("/etc/hostname");
        assert!(meta.exists);
        assert!(meta.is_file);
    }

    #[test]
    fn test_classify_exec_path_trusted() {
        assert_eq!(
            classify_exec_path("/usr/lib/systemd/system/systemd-journald"),
            ExecRisk::Trusted
        );
        assert_eq!(classify_exec_path("/usr/bin/bash"), ExecRisk::Trusted);
    }

    #[test]
    fn test_classify_exec_path_critical() {
        assert_eq!(
            classify_exec_path("/tmp/.hidden_script"),
            ExecRisk::Critical
        );
        assert_eq!(
            classify_exec_path("/dev/shm/x86_64-linux-gnu/libc.so.6"),
            ExecRisk::Critical
        );
    }

    #[test]
    fn test_classify_exec_path_suspicious() {
        assert_eq!(
            classify_exec_path("/home/user/.config/evil"),
            ExecRisk::Suspicious
        );
    }

    #[test]
    fn test_classify_exec_path_verified() {
        assert_eq!(classify_exec_path("/etc/init.d/custom"), ExecRisk::Verified);
    }

    #[test]
    fn test_parse_exec_fields() {
        let unit = "\
[Service]
ExecStart=/usr/lib/systemd/systemd-journald
ExecStartPre=/usr/bin/mkdir -p /run/journal
ExecStop=/usr/bin/kill -TERM $MAINPID
";
        let results = parse_exec_fields(unit);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].command, "/usr/lib/systemd/systemd-journald");
        assert_eq!(results[0].risk, ExecRisk::Trusted);
        assert_eq!(results[1].command, "/usr/bin/mkdir");
        assert_eq!(results[1].args, vec!["-p", "/run/journal"]);
        assert_eq!(results[1].risk, ExecRisk::Trusted);
        assert_eq!(results[2].command, "/usr/bin/kill");
    }

    #[test]
    fn test_parse_exec_fields_negative() {
        let unit = "ExecStartPre=-/usr/bin/modprobe kvm\n";
        let results = parse_exec_fields(unit);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "/usr/bin/modprobe");
    }

    #[test]
    fn test_parse_exec_fields_at_prefix() {
        let unit = "ExecStart=@/usr/bin/cool cool --config /etc/cool.toml\n";
        let results = parse_exec_fields(unit);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "/usr/bin/cool");
    }

    #[test]
    fn test_parse_exec_fields_empty() {
        let unit = "ExecStart=\n";
        let results = parse_exec_fields(unit);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_exec_fields_critical_path() {
        let unit = "ExecStart=/tmp/.exploit\n";
        let results = parse_exec_fields(unit);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].risk, ExecRisk::Critical);
    }

    #[test]
    fn test_world_writable() {
        let meta = FileMetadata {
            exists: true,
            is_symlink: false,
            is_file: true,
            is_dir: false,
            uid: 0,
            gid: 0,
            permissions: 0o666,
            size: 100,
            dev: 0,
            ino: 0,
        };
        assert!(meta.is_world_writable());
        assert!(!meta.standard_permissions());
    }

    #[test]
    fn test_setuid() {
        let meta = FileMetadata {
            exists: true,
            is_symlink: false,
            is_file: true,
            is_dir: false,
            uid: 0,
            gid: 0,
            permissions: 0o4755,
            size: 100,
            dev: 0,
            ino: 0,
        };
        assert!(meta.is_setuid());
        assert!(!meta.standard_permissions());
    }
}
