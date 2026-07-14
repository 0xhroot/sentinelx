use sentinelx_common::hash::HashValue;
use sentinelx_common::types::{NamespaceInfo, ProcessInfo, ProcessStatus};
use sentinelx_core::object::{ObjectMetadata, ObjectType, OwnershipInfo, SentinelObject};

#[derive(Debug, Clone)]
pub struct ProcessObject {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub binary_path: String,
    pub command_line: Vec<String>,
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    pub status: ProcessStatus,
    pub hash: Option<HashValue>,
    pub namespace: NamespaceInfo,
    pub capabilities: Vec<String>,
    pub threads: u32,
    pub memory_usage_kb: u64,
}

impl ProcessObject {
    pub fn to_sentinel_object(&self, source: &str) -> SentinelObject {
        let mut metadata = ObjectMetadata::new()
            .with_property("pid", serde_json::json!(self.pid))
            .with_property("ppid", serde_json::json!(self.ppid))
            .with_property("name", serde_json::json!(self.name))
            .with_property("binary_path", serde_json::json!(self.binary_path))
            .with_property("command_line", serde_json::json!(self.command_line))
            .with_property("user", serde_json::json!(self.user))
            .with_property("uid", serde_json::json!(self.uid))
            .with_property("gid", serde_json::json!(self.gid))
            .with_property("status", serde_json::json!(format!("{:?}", self.status)))
            .with_property("threads", serde_json::json!(self.threads))
            .with_property("memory_usage_kb", serde_json::json!(self.memory_usage_kb))
            .with_property("pid_ns", serde_json::json!(self.namespace.pid_ns))
            .with_property("net_ns", serde_json::json!(self.namespace.net_ns))
            .with_property("mnt_ns", serde_json::json!(self.namespace.mnt_ns));

        metadata = metadata.with_ownership(OwnershipInfo {
            uid: self.uid,
            gid: self.gid,
            user: self.user.clone(),
            group: String::new(),
        });

        if let Some(ref hash) = self.hash {
            metadata
                .hashes
                .insert("exe_sha256".to_string(), hash.as_hex().to_string());
        }

        for cap in &self.capabilities {
            metadata.tags.push(cap.clone());
        }

        SentinelObject::new(ObjectType::Process, source, self.pid.to_string())
            .with_metadata(metadata)
    }
}

impl From<ProcessInfo> for ProcessObject {
    fn from(info: ProcessInfo) -> Self {
        Self {
            pid: info.pid.as_u32(),
            ppid: info.ppid.as_u32(),
            name: info.name,
            binary_path: info.binary_path,
            command_line: info.command_line,
            user: info.user,
            uid: info.uid,
            gid: info.gid,
            status: info.status,
            hash: info.hash,
            namespace: info.namespace,
            capabilities: info.capabilities,
            threads: info.threads,
            memory_usage_kb: info.memory_usage_kb,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_common::pid::Pid;

    fn make_process_info(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::new(pid),
            ppid: Pid::new(1),
            name: "test".to_string(),
            binary_path: "/usr/bin/test".to_string(),
            command_line: vec!["/usr/bin/test".to_string()],
            user: "root".to_string(),
            uid: 0,
            gid: 0,
            start_time: chrono::Utc::now(),
            status: ProcessStatus::Running,
            hash: None,
            namespace: NamespaceInfo::default(),
            capabilities: vec![],
            threads: 1,
            memory_usage_kb: 1024,
        }
    }

    #[test]
    fn test_process_object_from_info() {
        let info = make_process_info(1234);
        let obj = ProcessObject::from(info);
        assert_eq!(obj.pid, 1234);
        assert_eq!(obj.ppid, 1);
        assert_eq!(obj.name, "test");
    }

    #[test]
    fn test_to_sentinel_object() {
        let info = make_process_info(5678);
        let obj = ProcessObject::from(info);
        let sentinel = obj.to_sentinel_object("test_source");

        assert_eq!(sentinel.id, "process:5678");
        assert_eq!(sentinel.object_type, ObjectType::Process);
        assert_eq!(sentinel.source, "test_source");
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("pid")
                .and_then(|v| v.as_u64()),
            Some(5678)
        );
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("binary_path")
                .and_then(|v| v.as_str()),
            Some("/usr/bin/test")
        );
        assert!(sentinel.metadata.ownership.is_some());
        assert_eq!(sentinel.metadata.ownership.as_ref().unwrap().uid, 0);
    }

    #[test]
    fn test_to_sentinel_object_preserves_capabilities() {
        let mut info = make_process_info(100);
        info.capabilities = vec!["CAP_NET_RAW".to_string(), "CAP_SYS_ADMIN".to_string()];
        let obj = ProcessObject::from(info);
        let sentinel = obj.to_sentinel_object("test");

        assert!(sentinel.metadata.tags.contains(&"CAP_NET_RAW".to_string()));
        assert!(sentinel
            .metadata
            .tags
            .contains(&"CAP_SYS_ADMIN".to_string()));
    }
}
