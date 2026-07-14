use sentinelx_core::error::CoreError;
use sentinelx_core::metadata::MetadataCollector;
use sentinelx_core::object::SentinelObject;

pub struct KernelMetadataCollector;

impl KernelMetadataCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KernelMetadataCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl MetadataCollector for KernelMetadataCollector {
    fn name(&self) -> &str {
        "kernel_metadata"
    }

    fn description(&self) -> &str {
        "Enriches kernel objects with risk classification"
    }

    async fn enrich(&self, objects: &mut [SentinelObject]) -> Result<(), CoreError> {
        for obj in objects.iter_mut() {
            if obj.object_type != sentinelx_core::object::ObjectType::MemoryRegion {
                continue;
            }

            let kernel_obj_type = obj
                .metadata
                .properties
                .get("kernel_obj_type")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let severity = obj
                .metadata
                .properties
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("Info");

            let _risk_score = obj
                .metadata
                .properties
                .get("risk_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.5);

            let is_hardening = kernel_obj_type == "HardeningCheck";
            let is_critical = severity == "Critical";

            obj.metadata.properties.insert(
                "is_critical_finding".to_string(),
                serde_json::json!(is_critical),
            );
            obj.metadata.properties.insert(
                "requires_immediate_attention".to_string(),
                serde_json::json!(is_critical && !is_hardening),
            );

            if is_critical {
                obj.metadata.tags.push("critical".to_string());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_core::object::{ObjectMetadata, ObjectType};

    fn make_kernel_object(name: &str, kernel_obj_type: &str, severity: &str) -> SentinelObject {
        let metadata = ObjectMetadata::new()
            .with_property("name", serde_json::json!(name))
            .with_property("kernel_obj_type", serde_json::json!(kernel_obj_type))
            .with_property("severity", serde_json::json!(severity))
            .with_property("risk_score", serde_json::json!(0.9))
            .with_property("description", serde_json::json!("test"));

        SentinelObject::new(ObjectType::MemoryRegion, "test", name).with_metadata(metadata)
    }

    #[tokio::test]
    async fn test_enrich_marks_critical() {
        let collector = KernelMetadataCollector::new();
        let mut objects = vec![make_kernel_object("test_hook", "HookDetection", "Critical")];
        collector.enrich(&mut objects).await.unwrap();

        let is_critical = objects[0]
            .metadata
            .properties
            .get("is_critical_finding")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert!(is_critical);
    }

    #[tokio::test]
    async fn test_enrich_skips_non_kernel_objects() {
        let collector = KernelMetadataCollector::new();
        let obj = SentinelObject::new(ObjectType::File, "test", "/etc/passwd");
        let mut objects = vec![obj];
        collector.enrich(&mut objects).await.unwrap();
    }
}
