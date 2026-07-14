use sentinelx_core::error::CoreError;
use sentinelx_core::metadata::MetadataCollector;
use sentinelx_core::object::SentinelObject;

pub struct PersistenceMetadataCollector;

impl PersistenceMetadataCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PersistenceMetadataCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl MetadataCollector for PersistenceMetadataCollector {
    fn name(&self) -> &str {
        "persistence_metadata"
    }

    fn description(&self) -> &str {
        "Enriches persistence objects with trust classification"
    }

    async fn enrich(&self, objects: &mut [SentinelObject]) -> Result<(), CoreError> {
        for obj in objects.iter_mut() {
            if obj.object_type != sentinelx_core::object::ObjectType::Service {
                continue;
            }

            let entry_type = obj
                .metadata
                .properties
                .get("entry_type")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let enabled = obj
                .metadata
                .properties
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let owner_uid = obj
                .metadata
                .properties
                .get("owner_uid")
                .and_then(|v| v.as_u64());

            let is_symlink = obj
                .metadata
                .properties
                .get("is_symlink")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let classification = if is_symlink {
                "Suspicious"
            } else if owner_uid == Some(0) && enabled {
                "TrustedOS"
            } else if entry_type == "BashProfile" || entry_type == "RcLocal" {
                "Unknown"
            } else {
                "TrustedPackage"
            };

            let trust_score = match classification {
                "TrustedOS" => 0.9,
                "TrustedPackage" => 0.8,
                "Unknown" => 0.5,
                "Suspicious" => 0.2,
                _ => 0.5,
            };

            obj.metadata.properties.insert(
                "classification".to_string(),
                serde_json::json!(classification),
            );
            obj.metadata
                .properties
                .insert("trust_score".to_string(), serde_json::json!(trust_score));
            obj.metadata.tags.push(classification.to_lowercase());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_core::object::{ObjectMetadata, ObjectType};

    fn make_persistence_object(
        entry_type: &str,
        is_symlink: bool,
        owner_uid: u64,
    ) -> SentinelObject {
        let metadata = ObjectMetadata::new()
            .with_property("entry_type", serde_json::json!(entry_type))
            .with_property("name", serde_json::json!("test"))
            .with_property(
                "path",
                serde_json::json!("/etc/systemd/system/test.service"),
            )
            .with_property("enabled", serde_json::json!(true))
            .with_property("is_symlink", serde_json::json!(is_symlink))
            .with_property("owner_uid", serde_json::json!(owner_uid));

        SentinelObject::new(ObjectType::Service, "test", "test").with_metadata(metadata)
    }

    #[tokio::test]
    async fn test_enrich_classifies_trusted_os() {
        let collector = PersistenceMetadataCollector::new();
        let mut objects = vec![make_persistence_object("SystemdService", false, 0)];
        collector.enrich(&mut objects).await.unwrap();

        let classification = objects[0]
            .metadata
            .properties
            .get("classification")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(classification, "TrustedOS");
    }

    #[tokio::test]
    async fn test_enrich_classifies_symlink_as_suspicious() {
        let collector = PersistenceMetadataCollector::new();
        let mut objects = vec![make_persistence_object("SystemdService", true, 0)];
        collector.enrich(&mut objects).await.unwrap();

        let classification = objects[0]
            .metadata
            .properties
            .get("classification")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(classification, "Suspicious");
    }

    #[tokio::test]
    async fn test_enrich_skips_non_service_objects() {
        let collector = PersistenceMetadataCollector::new();
        let obj = SentinelObject::new(ObjectType::File, "test", "/etc/passwd");
        let mut objects = vec![obj];
        collector.enrich(&mut objects).await.unwrap();
    }
}
