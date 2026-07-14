use sentinelx_core::error::CoreError;
use sentinelx_core::metadata::MetadataCollector;
use sentinelx_core::object::SentinelObject;

pub struct NetworkMetadataCollector;

impl NetworkMetadataCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NetworkMetadataCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl MetadataCollector for NetworkMetadataCollector {
    fn name(&self) -> &str {
        "network_metadata"
    }

    fn description(&self) -> &str {
        "Enriches network connection objects with hidden connection detection"
    }

    async fn enrich(&self, objects: &mut [SentinelObject]) -> Result<(), CoreError> {
        let all_pids: std::collections::HashSet<u32> = objects
            .iter()
            .filter(|o| o.object_type == sentinelx_core::object::ObjectType::Process)
            .filter_map(|o| o.metadata.properties.get("pid")?.as_u64().map(|p| p as u32))
            .collect();

        for obj in objects.iter_mut() {
            if obj.object_type != sentinelx_core::object::ObjectType::NetworkConnection {
                continue;
            }

            let has_pid = obj
                .metadata
                .properties
                .get("pid")
                .and_then(|v| v.as_u64())
                .map(|p| p as u32);

            let inode = obj
                .metadata
                .properties
                .get("inode")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let is_hidden = has_pid.is_none() && inode > 0;
            obj.metadata
                .properties
                .insert("is_hidden".to_string(), serde_json::json!(is_hidden));

            if is_hidden {
                obj.metadata.tags.push("hidden_connection".to_string());
                obj.metadata.tags.push("orphaned".to_string());
            }

            if let Some(pid) = has_pid {
                if !all_pids.contains(&pid) {
                    obj.metadata
                        .properties
                        .insert("orphaned".to_string(), serde_json::Value::Bool(true));
                    obj.metadata.tags.push("orphaned".to_string());
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_core::object::{ObjectMetadata, ObjectType};

    fn make_network_object(inode: u64, pid: Option<u64>) -> SentinelObject {
        let mut metadata = ObjectMetadata::new()
            .with_property("local_ip", serde_json::json!("127.0.0.1"))
            .with_property("local_port", serde_json::json!(8080))
            .with_property("inode", serde_json::json!(inode))
            .with_property("protocol", serde_json::json!("Tcp"))
            .with_property("state", serde_json::json!("Established"))
            .with_property("uid", serde_json::json!(0));

        if let Some(p) = pid {
            metadata = metadata.with_property("pid", serde_json::json!(p));
        }

        SentinelObject::new(ObjectType::NetworkConnection, "test", inode.to_string())
            .with_metadata(metadata)
    }

    #[tokio::test]
    async fn test_enrich_marks_hidden_connection() {
        let collector = NetworkMetadataCollector::new();
        let mut objects = vec![make_network_object(12345, None)];
        collector.enrich(&mut objects).await.unwrap();

        let is_hidden = objects[0]
            .metadata
            .properties
            .get("is_hidden")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert!(is_hidden, "Connection without PID should be hidden");
        assert!(objects[0]
            .metadata
            .tags
            .contains(&"hidden_connection".to_string()));
    }

    #[tokio::test]
    async fn test_enrich_does_not_mark_connection_with_pid() {
        let collector = NetworkMetadataCollector::new();
        let mut objects = vec![make_network_object(12345, Some(1234))];
        collector.enrich(&mut objects).await.unwrap();

        let is_hidden = objects[0]
            .metadata
            .properties
            .get("is_hidden")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        assert!(!is_hidden, "Connection with PID should not be hidden");
    }

    #[tokio::test]
    async fn test_enrich_skips_non_network_objects() {
        let collector = NetworkMetadataCollector::new();
        let obj = SentinelObject::new(ObjectType::File, "test", "/etc/passwd");
        let mut objects = vec![obj];
        collector.enrich(&mut objects).await.unwrap();
    }
}
