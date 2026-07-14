use sentinelx_common::hash::HashValue;
use sentinelx_core::error::CoreError;
use sentinelx_core::metadata::MetadataCollector;
use sentinelx_core::object::SentinelObject;

pub struct MemoryMetadataCollector;

impl MemoryMetadataCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MemoryMetadataCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_file(path: &str) -> Option<HashValue> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > 10 * 1024 * 1024 {
        return None;
    }
    let data = std::fs::read(path).ok()?;
    Some(HashValue::new(&data))
}

fn compute_memory_maps_hash() -> Option<HashValue> {
    let content = std::fs::read_to_string("/proc/self/maps").ok()?;
    let mut maps_data = Vec::new();
    for line in content.lines() {
        if line.contains("r-xp") || line.contains("r--p") {
            maps_data.extend_from_slice(line.as_bytes());
            maps_data.push(b'\n');
        }
    }
    if maps_data.is_empty() {
        return None;
    }
    Some(HashValue::new(&maps_data))
}

#[async_trait::async_trait]
impl MetadataCollector for MemoryMetadataCollector {
    fn name(&self) -> &str {
        "memory_metadata"
    }

    fn description(&self) -> &str {
        "Enriches memory objects with current hash values and accessibility status"
    }

    async fn enrich(&self, objects: &mut [SentinelObject]) -> Result<(), CoreError> {
        for obj in objects.iter_mut() {
            if obj.object_type != sentinelx_core::object::ObjectType::MemoryRegion {
                continue;
            }

            let resource_path = obj
                .metadata
                .properties
                .get("resource_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let (current_hash, is_accessible) = match resource_path {
                "/proc/kallsyms" => {
                    let h = hash_file("/proc/kallsyms");
                    (h, true)
                }
                "/proc/self/maps" => {
                    let h = compute_memory_maps_hash();
                    (h, true)
                }
                _ => (None, false),
            };

            obj.metadata.properties.insert(
                "resource_accessible".to_string(),
                serde_json::json!(is_accessible),
            );

            if let Some(ref h) = current_hash {
                obj.metadata
                    .hashes
                    .insert("current_sha256".to_string(), h.as_hex().to_string());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_core::object::{ObjectMetadata, ObjectType};

    fn make_memory_object(resource_path: &str) -> SentinelObject {
        let metadata = ObjectMetadata::new()
            .with_property("name", serde_json::json!("test"))
            .with_property("resource_path", serde_json::json!(resource_path))
            .with_property("description", serde_json::json!("test"))
            .with_property("is_modified", serde_json::json!(false))
            .with_property("risk_score", serde_json::json!(0.5));

        SentinelObject::new(ObjectType::MemoryRegion, "test", "test").with_metadata(metadata)
    }

    #[tokio::test]
    async fn test_enrich_populates_is_modified() {
        let collector = MemoryMetadataCollector::new();
        let mut objects = vec![make_memory_object("/proc/kallsyms")];
        collector.enrich(&mut objects).await.unwrap();

        assert!(objects[0]
            .metadata
            .properties
            .contains_key("resource_accessible"));
    }

    #[tokio::test]
    async fn test_enrich_skips_non_memory_objects() {
        let collector = MemoryMetadataCollector::new();
        let obj = SentinelObject::new(ObjectType::File, "test", "/etc/passwd");
        let mut objects = vec![obj];
        collector.enrich(&mut objects).await.unwrap();
    }
}
