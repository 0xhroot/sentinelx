use sentinelx_common::hash::HashValue;
use sentinelx_common::types::HookInfo;
use sentinelx_core::object::{ObjectMetadata, ObjectType, SentinelObject};

#[derive(Debug, Clone)]
pub struct KernelObject {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub obj_type: KernelObjectType,
    pub hash: Option<HashValue>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelObjectType {
    HookDetection,
    IntegrityViolation,
    HardeningCheck,
}

impl KernelObject {
    pub fn from_hook(hook: &HookInfo) -> Self {
        Self {
            name: format!("{:?}_hook", hook.hook_type),
            description: format!("Detected {:?} hook at 0x{:x}", hook.hook_type, hook.address),
            severity: "Critical".to_string(),
            obj_type: KernelObjectType::HookDetection,
            hash: None,
            risk_score: 0.9,
        }
    }

    pub fn from_integrity_violation(
        path: &str,
        _baseline_hash: &HashValue,
        current_hash: &HashValue,
    ) -> Self {
        Self {
            name: format!("integrity_{}", path.replace('/', "_")),
            description: format!("Kernel integrity violation: {}", path),
            severity: "Critical".to_string(),
            obj_type: KernelObjectType::IntegrityViolation,
            hash: Some(current_hash.clone()),
            risk_score: 0.95,
        }
    }

    pub fn from_hardening_check(name: &str, expected: &str, actual: &str, severity: &str) -> Self {
        Self {
            name: format!("hardening_{}", name),
            description: format!(
                "Kernel hardening check {}: expected {}, got {}",
                name, expected, actual
            ),
            severity: severity.to_string(),
            obj_type: KernelObjectType::HardeningCheck,
            hash: None,
            risk_score: match severity {
                "Critical" => 0.9,
                "High" => 0.8,
                "Medium" => 0.6,
                _ => 0.3,
            },
        }
    }

    pub fn to_sentinel_object(&self, source: &str) -> SentinelObject {
        let mut metadata = ObjectMetadata::new()
            .with_property("name", serde_json::json!(self.name))
            .with_property("description", serde_json::json!(self.description))
            .with_property("severity", serde_json::json!(self.severity))
            .with_property(
                "kernel_obj_type",
                serde_json::json!(format!("{:?}", self.obj_type)),
            )
            .with_property("risk_score", serde_json::json!(self.risk_score));

        if let Some(ref h) = self.hash {
            metadata
                .hashes
                .insert("kernel_hash".to_string(), h.as_hex().to_string());
        }

        metadata.tags.push(self.severity.to_lowercase());

        SentinelObject::new(ObjectType::MemoryRegion, source, &self.name).with_metadata(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_common::types::HookType;

    #[test]
    fn test_kernel_object_from_hook() {
        let hook = HookInfo {
            hook_type: HookType::SyscallTable,
            address: 0xffffffff81000000,
            target_address: 0,
            symbol: Some("sys_read".to_string()),
            module: None,
            is_inline: false,
        };
        let obj = KernelObject::from_hook(&hook);
        assert_eq!(obj.name, "SyscallTable_hook");
        assert_eq!(obj.severity, "Critical");
        assert_eq!(obj.obj_type, KernelObjectType::HookDetection);
    }

    #[test]
    fn test_to_sentinel_object() {
        let obj = KernelObject::from_hardening_check("kptr_restrict", "1 or 2", "0", "Medium");
        let sentinel = obj.to_sentinel_object("kernel_discovery");

        assert_eq!(sentinel.object_type, ObjectType::MemoryRegion);
        assert_eq!(sentinel.source, "kernel_discovery");
        assert!(sentinel.id.starts_with("memory_region:"));
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("name")
                .and_then(|v| v.as_str()),
            Some("hardening_kptr_restrict")
        );
    }
}
