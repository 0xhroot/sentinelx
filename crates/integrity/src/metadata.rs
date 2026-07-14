use sentinelx_common::hash::HashValue;
use sentinelx_core::error::CoreError;
use sentinelx_core::metadata::MetadataCollector;
use sentinelx_core::object::SentinelObject;

pub struct IntegrityMetadataCollector;

impl IntegrityMetadataCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IntegrityMetadataCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_file(path: &str) -> Option<HashValue> {
    let metadata = std::fs::metadata(path).ok()?;
    let mut file = std::fs::File::open(path).ok()?;
    let mut data = Vec::new();
    data.resize_with(metadata.len() as usize, Default::default);
    std::io::Read::read_exact(&mut file, &mut data).ok()?;
    Some(HashValue::new(&data))
}

#[async_trait::async_trait]
impl MetadataCollector for IntegrityMetadataCollector {
    fn name(&self) -> &str {
        "integrity_metadata"
    }

    fn description(&self) -> &str {
        "Enriches file objects with current hash and readability status"
    }

    async fn enrich(&self, objects: &mut [SentinelObject]) -> Result<(), CoreError> {
        for obj in objects.iter_mut() {
            if obj.object_type != sentinelx_core::object::ObjectType::File {
                continue;
            }

            let path = obj
                .metadata
                .properties
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if path.is_empty() {
                continue;
            }

            let is_readable = std::fs::metadata(&path).is_ok();
            obj.metadata
                .properties
                .insert("is_readable".to_string(), serde_json::json!(is_readable));

            if is_readable {
                if let Some(current_hash) = hash_file(&path) {
                    obj.metadata.hashes.insert(
                        "current_sha256".to_string(),
                        current_hash.as_hex().to_string(),
                    );
                }
            } else {
                obj.metadata.tags.push("unreadable".to_string());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_core::object::{ObjectMetadata, ObjectType};

    fn make_file_object(path: &str) -> SentinelObject {
        let metadata = ObjectMetadata::new()
            .with_property("path", serde_json::json!(path))
            .with_property("is_modified", serde_json::json!(false))
            .with_property("risk_score", serde_json::json!(0.5));

        SentinelObject::new(ObjectType::File, "test", path.replace('/', "_"))
            .with_metadata(metadata)
    }

    #[tokio::test]
    async fn test_enrich_populates_readable() {
        let collector = IntegrityMetadataCollector::new();
        let mut objects = vec![make_file_object("/etc/passwd")];
        collector.enrich(&mut objects).await.unwrap();

        assert!(objects[0].metadata.properties.contains_key("is_readable"));
    }

    #[tokio::test]
    async fn test_enrich_skips_non_file_objects() {
        let collector = IntegrityMetadataCollector::new();
        let obj = SentinelObject::new(ObjectType::Process, "test", "1234");
        let mut objects = vec![obj];
        collector.enrich(&mut objects).await.unwrap();
    }
}
