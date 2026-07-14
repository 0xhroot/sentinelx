use sentinelx_core::discovery::DiscoveryProvider;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::{ObjectType, SentinelObject};

use crate::objects::KernelObject;

pub struct KernelDiscoveryProvider;

impl KernelDiscoveryProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KernelDiscoveryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for KernelDiscoveryProvider {
    fn name(&self) -> &str {
        "kernel_discovery"
    }

    fn description(&self) -> &str {
        "Discovers kernel integrity checks and hardening status"
    }

    fn supported_object_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::MemoryRegion]
    }

    async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError> {
        let mut objects = Vec::new();

        // Hardening checks
        let checks = vec![
            check_kptr_restrict(),
            check_dmesg_restrict(),
            check_modules_disabled(),
            check_secure_boot(),
        ];

        for c in checks.into_iter().flatten() {
            let obj =
                KernelObject::from_hardening_check(&c.name, &c.expected, &c.actual, &c.severity);
            objects.push(obj.to_sentinel_object("kernel_discovery"));
        }

        tracing::debug!(discovered = objects.len(), "Kernel discovery completed");
        Ok(objects)
    }
}

struct HardeningCheck {
    name: String,
    expected: String,
    actual: String,
    severity: String,
}

fn read_sysctl_int(key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn check_kptr_restrict() -> Option<HardeningCheck> {
    let val = read_sysctl_int("kptr_restrict")?;
    if val != "1" && val != "2" {
        Some(HardeningCheck {
            name: "kptr_restrict".to_string(),
            expected: "1 or 2".to_string(),
            actual: val,
            severity: "Medium".to_string(),
        })
    } else {
        None
    }
}

fn check_dmesg_restrict() -> Option<HardeningCheck> {
    let val = read_sysctl_int("dmesg_restrict")?;
    if val != "1" {
        Some(HardeningCheck {
            name: "dmesg_restrict".to_string(),
            expected: "1".to_string(),
            actual: val,
            severity: "Low".to_string(),
        })
    } else {
        None
    }
}

fn check_modules_disabled() -> Option<HardeningCheck> {
    let val = read_sysctl_int("modules_disabled")?;
    if val != "1" {
        Some(HardeningCheck {
            name: "modules_disabled".to_string(),
            expected: "1 (modules loading disabled)".to_string(),
            actual: val,
            severity: "Info".to_string(),
        })
    } else {
        None
    }
}

fn check_secure_boot() -> Option<HardeningCheck> {
    if std::path::Path::new("/sys/firmware/efi").exists() {
        let secure_boot = std::fs::read_to_string(
            "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
        );
        match secure_boot {
            Ok(data) => {
                if let Some(&last_byte) = data.as_bytes().last() {
                    if last_byte != 1 {
                        return Some(HardeningCheck {
                            name: "secure_boot".to_string(),
                            expected: "enabled".to_string(),
                            actual: "disabled".to_string(),
                            severity: "Medium".to_string(),
                        });
                    }
                }
                None
            }
            Err(_) => Some(HardeningCheck {
                name: "secure_boot".to_string(),
                expected: "present".to_string(),
                actual: "unreadable".to_string(),
                severity: "Low".to_string(),
            }),
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_kernel_discovery_provider_name() {
        let provider = KernelDiscoveryProvider::new();
        assert_eq!(provider.name(), "kernel_discovery");
    }

    #[tokio::test]
    async fn test_kernel_discovery_returns_objects() {
        let provider = KernelDiscoveryProvider::new();
        let objects = provider.discover().await.unwrap();
        for obj in &objects {
            assert_eq!(obj.object_type, ObjectType::MemoryRegion);
            assert!(obj.metadata.properties.contains_key("name"));
            assert!(obj.metadata.properties.contains_key("kernel_obj_type"));
        }
    }

    #[tokio::test]
    async fn test_supported_types() {
        let provider = KernelDiscoveryProvider::new();
        let types = provider.supported_object_types();
        assert_eq!(types, vec![ObjectType::MemoryRegion]);
    }
}
