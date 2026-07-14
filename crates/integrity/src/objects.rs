use sentinelx_common::hash::HashValue;
use sentinelx_core::object::{ObjectMetadata, ObjectType, SentinelObject};

#[derive(Debug, Clone)]
pub struct IntegrityObject {
    pub path: String,
    pub baseline_hash: Option<HashValue>,
    pub current_hash: Option<HashValue>,
    pub is_modified: bool,
    pub is_readable: bool,
    pub risk_score: f64,
}

impl IntegrityObject {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            baseline_hash: None,
            current_hash: None,
            is_modified: false,
            is_readable: true,
            risk_score: 0.5,
        }
    }

    pub fn to_sentinel_object(&self, source: &str) -> SentinelObject {
        let identifier = self.path.replace('/', "_");
        let mut metadata = ObjectMetadata::new()
            .with_property("path", serde_json::json!(self.path))
            .with_property("is_modified", serde_json::json!(self.is_modified))
            .with_property("is_readable", serde_json::json!(self.is_readable))
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
            metadata.tags.push("modified".to_string());
            metadata.tags.push("critical".to_string());
        }
        if !self.is_readable {
            metadata.tags.push("unreadable".to_string());
        }

        SentinelObject::new(ObjectType::File, source, &identifier).with_metadata(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrity_object_new() {
        let obj = IntegrityObject::new("/etc/passwd");
        assert_eq!(obj.path, "/etc/passwd");
        assert!(!obj.is_modified);
        assert!(obj.is_readable);
    }

    #[test]
    fn test_to_sentinel_object() {
        let obj = IntegrityObject::new("/etc/passwd");
        let sentinel = obj.to_sentinel_object("integrity_discovery");

        assert_eq!(sentinel.object_type, ObjectType::File);
        assert_eq!(sentinel.source, "integrity_discovery");
        assert!(sentinel.id.starts_with("file:"));
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("path")
                .and_then(|v| v.as_str()),
            Some("/etc/passwd")
        );
    }

    #[test]
    fn test_to_sentinel_object_modified() {
        let mut obj = IntegrityObject::new("/etc/shadow");
        obj.is_modified = true;
        let sentinel = obj.to_sentinel_object("test");
        assert!(sentinel.metadata.tags.contains(&"modified".to_string()));
    }
}
