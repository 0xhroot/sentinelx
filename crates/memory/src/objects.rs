use sentinelx_common::hash::HashValue;
use sentinelx_core::object::{ObjectMetadata, ObjectType, SentinelObject};

#[derive(Debug, Clone)]
pub struct MemoryObject {
    pub name: String,
    pub description: String,
    pub resource_path: String,
    pub baseline_hash: Option<HashValue>,
    pub current_hash: Option<HashValue>,
    pub is_modified: bool,
    pub risk_score: f64,
}

impl MemoryObject {
    pub fn new(name: &str, resource_path: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            resource_path: resource_path.to_string(),
            baseline_hash: None,
            current_hash: None,
            is_modified: false,
            risk_score: 0.5,
        }
    }

    pub fn to_sentinel_object(&self, source: &str) -> SentinelObject {
        let mut metadata = ObjectMetadata::new()
            .with_property("name", serde_json::json!(self.name))
            .with_property("description", serde_json::json!(self.description))
            .with_property("resource_path", serde_json::json!(self.resource_path))
            .with_property("is_modified", serde_json::json!(self.is_modified))
            .with_property("risk_score", serde_json::json!(self.risk_score));

        if let Some(ref h) = self.baseline_hash {
            metadata
                .hashes
                .insert("baseline_sha256".to_string(), h.as_hex().to_string());
        }
        if let Some(ref h) = self.current_hash {
            metadata
                .hashes
                .insert("current_sha256".to_string(), h.as_hex().to_string());
        }

        if self.is_modified {
            metadata.tags.push("tampering".to_string());
            metadata.tags.push("critical".to_string());
        }

        SentinelObject::new(ObjectType::MemoryRegion, source, &self.name).with_metadata(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_object_new() {
        let obj = MemoryObject::new(
            "kallsyms_check",
            "/proc/kallsyms",
            "Kernel symbol table integrity",
        );
        assert_eq!(obj.name, "kallsyms_check");
        assert_eq!(obj.resource_path, "/proc/kallsyms");
        assert!(!obj.is_modified);
    }

    #[test]
    fn test_to_sentinel_object() {
        let obj = MemoryObject::new("test", "/proc/self/maps", "test");
        let sentinel = obj.to_sentinel_object("memory_discovery");

        assert_eq!(sentinel.object_type, ObjectType::MemoryRegion);
        assert_eq!(sentinel.source, "memory_discovery");
        assert!(sentinel.id.starts_with("memory_region:"));
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("name")
                .and_then(|v| v.as_str()),
            Some("test")
        );
    }

    #[test]
    fn test_to_sentinel_object_modified() {
        let mut obj = MemoryObject::new("modified", "/proc/kallsyms", "modified");
        obj.is_modified = true;
        obj.risk_score = 0.95;
        let sentinel = obj.to_sentinel_object("test");
        assert!(sentinel.metadata.tags.contains(&"tampering".to_string()));
    }
}
