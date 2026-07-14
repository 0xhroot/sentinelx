use std::collections::HashSet;

use sentinelx_core::error::CoreError;
use sentinelx_core::metadata::MetadataCollector;
use sentinelx_core::object::{ObjectType, SentinelObject};

pub struct ProcessMetadataCollector;

#[async_trait::async_trait]
impl MetadataCollector for ProcessMetadataCollector {
    fn name(&self) -> &str {
        "process_metadata"
    }

    fn description(&self) -> &str {
        "Enriches process objects with DKOM hidden detection and orphan detection"
    }

    async fn enrich(&self, objects: &mut [SentinelObject]) -> Result<(), CoreError> {
        let all_pids: HashSet<u32> = objects
            .iter()
            .filter(|o| o.object_type == ObjectType::Process)
            .filter_map(|o| o.metadata.properties.get("pid")?.as_u64().map(|p| p as u32))
            .collect();

        let accessible_pids = get_accessible_pids();

        for object in objects.iter_mut() {
            if object.object_type != ObjectType::Process {
                continue;
            }

            let pid = match object
                .metadata
                .properties
                .get("pid")
                .and_then(|v| v.as_u64())
            {
                Some(p) => p as u32,
                None => continue,
            };

            let is_hidden = !accessible_pids.contains(&pid);
            if is_hidden {
                object
                    .metadata
                    .properties
                    .insert("hidden_dkom".to_string(), serde_json::Value::Bool(true));
                object.metadata.tags.push("hidden".to_string());
                object.metadata.tags.push("dkom".to_string());
            }

            let ppid = object
                .metadata
                .properties
                .get("ppid")
                .and_then(|v| v.as_u64())
                .map(|p| p as u32)
                .unwrap_or(0);

            if ppid > 1 && !all_pids.contains(&ppid) {
                object
                    .metadata
                    .properties
                    .insert("orphaned".to_string(), serde_json::Value::Bool(true));
                object.metadata.properties.insert(
                    "orphan_reason".to_string(),
                    serde_json::Value::String("Parent PID not in process list".to_string()),
                );
                object.metadata.tags.push("orphaned".to_string());
            }
        }

        Ok(())
    }
}

fn get_accessible_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    let status_path = format!("/proc/{}/status", pid);
                    if std::fs::metadata(&status_path).is_ok() {
                        pids.insert(pid);
                    }
                }
            }
        }
    }
    pids
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_core::object::ObjectMetadata;

    fn make_process_object(pid: u32, ppid: u32) -> SentinelObject {
        let metadata = ObjectMetadata::new()
            .with_property("pid", serde_json::json!(pid))
            .with_property("ppid", serde_json::json!(ppid))
            .with_property("name", serde_json::json!("test"))
            .with_property("binary_path", serde_json::json!("/usr/bin/test"))
            .with_property("user", serde_json::json!("root"))
            .with_property("uid", serde_json::json!(0))
            .with_property("gid", serde_json::json!(0))
            .with_property("status", serde_json::json!("Running"))
            .with_property("threads", serde_json::json!(1))
            .with_property("memory_usage_kb", serde_json::json!(1024));

        SentinelObject::new(ObjectType::Process, "test", pid.to_string()).with_metadata(metadata)
    }

    #[tokio::test]
    async fn test_enrich_marks_own_process_not_hidden() {
        let self_pid = std::process::id();
        let mut objects = vec![make_process_object(self_pid, 1)];

        let collector = ProcessMetadataCollector;
        collector.enrich(&mut objects).await.unwrap();

        let hidden = objects[0]
            .metadata
            .properties
            .get("hidden_dkom")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert!(!hidden, "Own process should not be marked as hidden");
    }

    #[tokio::test]
    async fn test_enrich_marks_orphaned_process() {
        let self_pid = std::process::id();
        let mut objects = vec![make_process_object(self_pid, 99999)];

        let collector = ProcessMetadataCollector;
        collector.enrich(&mut objects).await.unwrap();

        let orphaned = objects[0]
            .metadata
            .properties
            .get("orphaned")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert!(
            orphaned,
            "Process with non-existent parent should be orphaned"
        );
    }

    #[tokio::test]
    async fn test_enrich_skips_non_process_objects() {
        let obj =
            sentinelx_core::object::SentinelObject::new(ObjectType::File, "test", "/etc/passwd");
        let collector = ProcessMetadataCollector;
        let mut objects = vec![obj];
        collector.enrich(&mut objects).await.unwrap();
    }
}
