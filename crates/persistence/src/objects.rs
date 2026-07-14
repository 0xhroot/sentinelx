use sentinelx_common::hash::HashValue;
use sentinelx_common::types::{PersistenceEntry, PersistenceType};
use sentinelx_core::object::{ObjectMetadata, ObjectType, SentinelObject};

#[derive(Debug, Clone)]
pub struct PersistenceObject {
    pub entry_type: PersistenceType,
    pub name: String,
    pub path: String,
    pub content: Option<String>,
    pub enabled: bool,
    pub hash: Option<HashValue>,
    pub user: Option<String>,
    pub owner_uid: Option<u32>,
    pub group_uid: Option<u32>,
    pub permissions: Option<u32>,
    pub size: Option<u64>,
    pub is_symlink: bool,
    pub trust_score: f64,
    pub classification: Option<String>,
}

impl From<PersistenceEntry> for PersistenceObject {
    fn from(entry: PersistenceEntry) -> Self {
        Self {
            entry_type: entry.entry_type,
            name: entry.name,
            path: entry.path,
            content: entry.content,
            enabled: entry.enabled,
            hash: entry.hash,
            user: entry.user,
            owner_uid: entry.owner_uid,
            group_uid: entry.group_uid,
            permissions: entry.permissions,
            size: entry.size,
            is_symlink: entry.is_symlink,
            trust_score: 0.5,
            classification: None,
        }
    }
}

impl PersistenceObject {
    pub fn to_sentinel_object(&self, source: &str) -> SentinelObject {
        let identifier = format!(
            "{}:{}",
            format!("{:?}", self.entry_type).to_lowercase(),
            self.path
        );
        let mut metadata = ObjectMetadata::new()
            .with_property(
                "entry_type",
                serde_json::json!(format!("{:?}", self.entry_type)),
            )
            .with_property("name", serde_json::json!(self.name))
            .with_property("path", serde_json::json!(self.path))
            .with_property("enabled", serde_json::json!(self.enabled))
            .with_property("is_symlink", serde_json::json!(self.is_symlink))
            .with_property("trust_score", serde_json::json!(self.trust_score));

        if let Some(ref h) = self.hash {
            metadata
                .hashes
                .insert("content_sha256".to_string(), h.as_hex().to_string());
        }
        if let Some(uid) = self.owner_uid {
            metadata = metadata.with_property("owner_uid", serde_json::json!(uid));
        }
        if let Some(gid) = self.group_uid {
            metadata = metadata.with_property("group_uid", serde_json::json!(gid));
        }
        if let Some(perms) = self.permissions {
            metadata = metadata.with_property("permissions", serde_json::json!(perms));
        }
        if let Some(sz) = self.size {
            metadata = metadata.with_property("size", serde_json::json!(sz));
        }
        if let Some(ref user) = self.user {
            metadata = metadata.with_property("user", serde_json::json!(user));
        }
        if let Some(ref classification) = self.classification {
            metadata = metadata.with_property("classification", serde_json::json!(classification));
        }
        if let Some(ref content) = self.content {
            let preview: String = content.chars().take(256).collect();
            metadata = metadata.with_property("content_preview", serde_json::json!(preview));
        }

        SentinelObject::new(ObjectType::Service, source, &identifier).with_metadata(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, path: &str, entry_type: PersistenceType) -> PersistenceEntry {
        PersistenceEntry {
            entry_type,
            name: name.to_string(),
            path: path.to_string(),
            content: Some(
                "[Unit]\nDescription=Test\n[Service]\nExecStart=/usr/bin/test\n".to_string(),
            ),
            enabled: true,
            hash: None,
            user: None,
            owner_uid: Some(0),
            group_uid: Some(0),
            permissions: Some(0o644),
            size: Some(1024),
            is_symlink: false,
        }
    }

    #[test]
    fn test_persistence_object_from_entry() {
        let entry = make_entry(
            "test.service",
            "/etc/systemd/system/test.service",
            PersistenceType::SystemdService,
        );
        let obj = PersistenceObject::from(entry);
        assert_eq!(obj.name, "test.service");
        assert_eq!(obj.path, "/etc/systemd/system/test.service");
        assert!(obj.enabled);
        assert_eq!(obj.owner_uid, Some(0));
    }

    #[test]
    fn test_to_sentinel_object() {
        let entry = make_entry("cron.d/test", "/etc/cron.d/test", PersistenceType::CronJob);
        let obj = PersistenceObject::from(entry);
        let sentinel = obj.to_sentinel_object("persistence_discovery");

        assert_eq!(sentinel.object_type, ObjectType::Service);
        assert_eq!(sentinel.source, "persistence_discovery");
        assert!(sentinel.id.starts_with("service:"));
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("name")
                .and_then(|v| v.as_str()),
            Some("cron.d/test")
        );
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("entry_type")
                .and_then(|v| v.as_str()),
            Some("CronJob")
        );
    }

    #[test]
    fn test_to_sentinel_object_with_classification() {
        let entry = make_entry("test", "/tmp/test", PersistenceType::InitScript);
        let mut obj = PersistenceObject::from(entry);
        obj.classification = Some("TrustedOS".to_string());
        obj.trust_score = 0.9;
        let sentinel = obj.to_sentinel_object("test");
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("classification")
                .and_then(|v| v.as_str()),
            Some("TrustedOS")
        );
    }
}
