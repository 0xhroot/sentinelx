use sentinelx_common::hash::HashValue;
use sentinelx_common::types::{KernelModuleInfo, ModuleSource, ModuleState};
use sentinelx_core::object::{ObjectMetadata, ObjectType, SentinelObject};

#[derive(Debug, Clone)]
pub struct ModuleObject {
    pub name: String,
    pub size: u64,
    pub ref_count: u32,
    pub load_address: u64,
    pub state: ModuleState,
    pub version: Option<String>,
    pub license: Option<String>,
    pub hash: Option<HashValue>,
    pub signature_valid: Option<bool>,
    pub source: ModuleSource,
    pub is_builtin: bool,
    pub trust_score: f64,
}

impl From<KernelModuleInfo> for ModuleObject {
    fn from(info: KernelModuleInfo) -> Self {
        Self {
            name: info.name,
            size: info.size,
            ref_count: info.ref_count,
            load_address: info.load_address,
            state: info.state,
            version: info.version,
            license: info.license,
            hash: info.hash,
            signature_valid: info.signature_valid,
            source: info.source,
            is_builtin: false,
            trust_score: 0.5,
        }
    }
}

impl ModuleObject {
    pub fn to_sentinel_object(&self, source: &str) -> SentinelObject {
        let mut metadata = ObjectMetadata::new()
            .with_property("name", serde_json::json!(self.name))
            .with_property("size", serde_json::json!(self.size))
            .with_property("ref_count", serde_json::json!(self.ref_count))
            .with_property(
                "load_address",
                serde_json::json!(format!("0x{:x}", self.load_address)),
            )
            .with_property("state", serde_json::json!(format!("{:?}", self.state)))
            .with_property("source", serde_json::json!(format!("{:?}", self.source)))
            .with_property("is_builtin", serde_json::json!(self.is_builtin))
            .with_property("trust_score", serde_json::json!(self.trust_score));

        if let Some(ref v) = self.version {
            metadata = metadata.with_property("version", serde_json::json!(v));
        }
        if let Some(ref l) = self.license {
            metadata = metadata.with_property("license", serde_json::json!(l));
        }
        if let Some(ref h) = self.hash {
            metadata
                .hashes
                .insert("module_sha256".to_string(), h.as_hex().to_string());
        }
        metadata =
            metadata.with_property("signature_valid", serde_json::json!(self.signature_valid));

        SentinelObject::new(ObjectType::KernelModule, source, &self.name).with_metadata(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_module_info(name: &str) -> KernelModuleInfo {
        KernelModuleInfo {
            name: name.to_string(),
            size: 123456,
            ref_count: 1,
            load_address: 0xffffffffc0000000,
            state: ModuleState::Live,
            version: Some("3.2.6-k".to_string()),
            license: Some("GPL".to_string()),
            hash: None,
            signature_valid: Some(true),
            source: ModuleSource::ProcModules,
        }
    }

    #[test]
    fn test_module_object_from_info() {
        let info = make_module_info("e1000e");
        let obj = ModuleObject::from(info);
        assert_eq!(obj.name, "e1000e");
        assert_eq!(obj.size, 123456);
        assert_eq!(obj.ref_count, 1);
        assert_eq!(obj.load_address, 0xffffffffc0000000);
        assert_eq!(obj.state, ModuleState::Live);
        assert_eq!(obj.version, Some("3.2.6-k".to_string()));
        assert_eq!(obj.license, Some("GPL".to_string()));
        assert_eq!(obj.signature_valid, Some(true));
    }

    #[test]
    fn test_to_sentinel_object() {
        let info = make_module_info("e1000e");
        let obj = ModuleObject::from(info);
        let sentinel = obj.to_sentinel_object("module_discovery");

        assert_eq!(sentinel.id, "kernel_module:e1000e");
        assert_eq!(sentinel.object_type, ObjectType::KernelModule);
        assert_eq!(sentinel.source, "module_discovery");
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("name")
                .and_then(|v| v.as_str()),
            Some("e1000e")
        );
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("size")
                .and_then(|v| v.as_u64()),
            Some(123456)
        );
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("license")
                .and_then(|v| v.as_str()),
            Some("GPL")
        );
    }

    #[test]
    fn test_to_sentinel_object_with_tags() {
        let info = make_module_info("kvm");
        let mut obj = ModuleObject::from(info);
        obj.is_builtin = true;
        obj.trust_score = 0.9;
        let sentinel = obj.to_sentinel_object("test");

        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("is_builtin")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(
            (sentinel
                .metadata
                .properties
                .get("trust_score")
                .and_then(|v| v.as_f64())
                .unwrap()
                - 0.9)
                .abs()
                < f64::EPSILON
        );
    }
}
