use std::collections::HashMap;
use std::process::Command;

use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
}

pub trait PackageManager: Send + Sync {
    fn name(&self) -> &str;
    fn query_owner(&self, path: &str) -> Option<PackageInfo>;
    fn list_foreign_packages(&self) -> Vec<ForeignPackage>;
}

pub struct ForeignPackage {
    pub name: String,
    pub version: String,
}

pub struct PacmanProvider {
    foreign_packages: HashMap<String, PackageInfo>,
}

impl Default for PacmanProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PacmanProvider {
    pub fn new() -> Self {
        let foreign_packages = Self::load_foreign_packages();
        info!(
            "Loaded {} foreign packages from pacman",
            foreign_packages.len()
        );
        Self { foreign_packages }
    }

    fn load_foreign_packages() -> HashMap<String, PackageInfo> {
        let mut map = HashMap::new();

        let output = match Command::new("pacman").args(["-Qm"]).output() {
            Ok(o) => o,
            Err(e) => {
                warn!("Failed to run pacman -Qm: {}", e);
                return map;
            }
        };

        if !output.status.success() {
            warn!(
                "pacman -Qm failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return map;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();
                map.insert(name.clone(), PackageInfo { name, version });
            }
        }

        map
    }
}

impl PackageManager for PacmanProvider {
    fn name(&self) -> &str {
        "pacman"
    }

    fn query_owner(&self, path: &str) -> Option<PackageInfo> {
        let output = Command::new("pacman").args(["-Qo", path]).output().ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(pos) = line.find(" is owned by ") {
                let pkg_part = &line[pos + " is owned by ".len()..];
                let parts: Vec<&str> = pkg_part.splitn(2, ' ').collect();
                if parts.len() >= 2 {
                    return Some(PackageInfo {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                    });
                }
            }
        }

        None
    }

    fn list_foreign_packages(&self) -> Vec<ForeignPackage> {
        self.foreign_packages
            .values()
            .map(|p| ForeignPackage {
                name: p.name.clone(),
                version: p.version.clone(),
            })
            .collect()
    }
}

pub struct DpkgProvider;

impl Default for DpkgProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DpkgProvider {
    pub fn new() -> Self {
        Self
    }
}

impl PackageManager for DpkgProvider {
    fn name(&self) -> &str {
        "dpkg"
    }

    fn query_owner(&self, path: &str) -> Option<PackageInfo> {
        let output = Command::new("dpkg").args(["-S", path]).output().ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(colon_pos) = line.find(':') {
                let pkg_part = line[..colon_pos].trim();
                if let Some(paren_start) = pkg_part.find('(') {
                    if let Some(paren_end) = pkg_part.find(')') {
                        return Some(PackageInfo {
                            name: pkg_part[paren_start + 1..paren_end].to_string(),
                            version: String::new(),
                        });
                    }
                }
            }
        }

        None
    }

    fn list_foreign_packages(&self) -> Vec<ForeignPackage> {
        Vec::new()
    }
}

pub struct RpmProvider;

impl Default for RpmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl RpmProvider {
    pub fn new() -> Self {
        Self
    }
}

impl PackageManager for RpmProvider {
    fn name(&self) -> &str {
        "rpm"
    }

    fn query_owner(&self, path: &str) -> Option<PackageInfo> {
        let output = Command::new("rpm")
            .args([
                "-qf",
                "--queryformat",
                "%{NAME} %{VERSION}-%{RELEASE}",
                path,
            ])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout.trim();
        if line.starts_with("not owned by") {
            return None;
        }

        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() >= 2 {
            return Some(PackageInfo {
                name: parts[0].to_string(),
                version: parts[1].to_string(),
            });
        }

        None
    }

    fn list_foreign_packages(&self) -> Vec<ForeignPackage> {
        Vec::new()
    }
}

pub fn detect_package_manager() -> Option<Box<dyn PackageManager>> {
    if Command::new("pacman")
        .args(["--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        debug!("Detected pacman package manager");
        return Some(Box::new(PacmanProvider::new()));
    }

    if Command::new("dpkg")
        .args(["--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        debug!("Detected dpkg package manager");
        return Some(Box::new(DpkgProvider::new()));
    }

    if Command::new("rpm")
        .args(["--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        debug!("Detected rpm package manager");
        return Some(Box::new(RpmProvider::new()));
    }

    warn!("No supported package manager detected");
    None
}

const SYSTEM_DIRS: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/usr/bin",
    "/usr/sbin",
    "/usr/share",
    "/usr/lib/modules",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc/systemd",
    "/run/systemd",
];

pub fn is_system_directory(path: &str) -> bool {
    SYSTEM_DIRS.iter().any(|d| path.starts_with(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_system_directory() {
        assert!(is_system_directory("/usr/lib/systemd/system/ssh.service"));
        assert!(is_system_directory("/usr/bin/bash"));
        assert!(is_system_directory("/etc/systemd/system/custom.service"));
        assert!(!is_system_directory("/home/user/script.sh"));
        assert!(!is_system_directory("/tmp/exploit"));
        assert!(!is_system_directory("/root/.bashrc"));
    }

    #[test]
    fn test_detect_package_manager() {
        if let Some(pm) = detect_package_manager() {
            assert!(!pm.name().is_empty());
        }
    }
}
