use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::assessment::AssessmentResult;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Process,
    KernelModule,
    NetworkConnection,
    Service,
    Socket,
    File,
    MemoryRegion,
    User,
    Namespace,
    Container,
}

impl ObjectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectType::Process => "process",
            ObjectType::KernelModule => "kernel_module",
            ObjectType::NetworkConnection => "network_connection",
            ObjectType::Service => "service",
            ObjectType::Socket => "socket",
            ObjectType::File => "file",
            ObjectType::MemoryRegion => "memory_region",
            ObjectType::User => "user",
            ObjectType::Namespace => "namespace",
            ObjectType::Container => "container",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RelationshipType {
    Parent,
    Child,
    DependsOn,
    ConnectsTo,
    Loads,
    Executes,
    Modifies,
    Owns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRelationship {
    pub relationship_type: RelationshipType,
    pub target_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipInfo {
    pub uid: u32,
    pub gid: u32,
    pub user: String,
    pub group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionInfo {
    pub mode: u32,
    pub is_executable: bool,
    pub is_world_writable: bool,
    pub is_setuid: bool,
    pub is_setgid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub manager: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    pub properties: HashMap<String, serde_json::Value>,
    pub ownership: Option<OwnershipInfo>,
    pub permissions: Option<PermissionInfo>,
    pub hashes: HashMap<String, String>,
    pub package_info: Option<PackageInfo>,
    pub tags: Vec<String>,
}

impl ObjectMetadata {
    pub fn new() -> Self {
        Self {
            properties: HashMap::new(),
            ownership: None,
            permissions: None,
            hashes: HashMap::new(),
            package_info: None,
            tags: Vec::new(),
        }
    }

    pub fn with_property(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.properties.insert(key.into(), value);
        self
    }

    pub fn with_ownership(mut self, ownership: OwnershipInfo) -> Self {
        self.ownership = Some(ownership);
        self
    }

    pub fn with_permissions(mut self, permissions: PermissionInfo) -> Self {
        self.permissions = Some(permissions);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

impl Default for ObjectMetadata {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelObject {
    pub id: String,
    pub object_type: ObjectType,
    pub metadata: ObjectMetadata,
    pub relationships: Vec<ObjectRelationship>,
    pub created_at: DateTime<Utc>,
    pub source: String,
    pub assessments: Vec<AssessmentResult>,
    pub evidence_refs: Vec<uuid::Uuid>,
}

impl SentinelObject {
    pub fn new(
        object_type: ObjectType,
        source: impl Into<String>,
        identifier: impl Into<String>,
    ) -> Self {
        let id = format!("{}:{}", object_type.as_str(), identifier.into());
        Self {
            id,
            object_type,
            metadata: ObjectMetadata::new(),
            relationships: Vec::new(),
            created_at: Utc::now(),
            source: source.into(),
            assessments: Vec::new(),
            evidence_refs: Vec::new(),
        }
    }

    pub fn with_metadata(mut self, metadata: ObjectMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_relationship(mut self, rel: ObjectRelationship) -> Self {
        self.relationships.push(rel);
        self
    }

    pub fn with_evidence_ref(mut self, evidence_id: uuid::Uuid) -> Self {
        self.evidence_refs.push(evidence_id);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_type_as_str() {
        assert_eq!(ObjectType::Process.as_str(), "process");
        assert_eq!(ObjectType::KernelModule.as_str(), "kernel_module");
        assert_eq!(ObjectType::File.as_str(), "file");
        assert_eq!(ObjectType::Container.as_str(), "container");
    }

    #[test]
    fn test_create_object() {
        let obj = SentinelObject::new(ObjectType::Process, "process_scanner", "1234");
        assert_eq!(obj.id, "process:1234");
        assert_eq!(obj.object_type, ObjectType::Process);
        assert_eq!(obj.source, "process_scanner");
        assert!(obj.relationships.is_empty());
        assert!(obj.assessments.is_empty());
        assert!(obj.evidence_refs.is_empty());
    }

    #[test]
    fn test_object_with_metadata() {
        let meta = ObjectMetadata::new()
            .with_property("name", serde_json::json!("bash"))
            .with_tag("shell");
        let obj = SentinelObject::new(ObjectType::Process, "test", "1").with_metadata(meta);

        assert_eq!(
            obj.metadata.properties.get("name").unwrap(),
            &serde_json::json!("bash")
        );
        assert!(obj.metadata.tags.contains(&"shell".to_string()));
    }

    #[test]
    fn test_object_with_relationships() {
        let obj = SentinelObject::new(ObjectType::Process, "test", "1").with_relationship(
            ObjectRelationship {
                relationship_type: RelationshipType::Parent,
                target_id: "process:0".to_string(),
            },
        );
        assert_eq!(obj.relationships.len(), 1);
        assert_eq!(obj.relationships[0].target_id, "process:0");
    }

    #[test]
    fn test_object_with_ownership() {
        let meta = ObjectMetadata::new().with_ownership(OwnershipInfo {
            uid: 0,
            gid: 0,
            user: "root".to_string(),
            group: "root".to_string(),
        });
        let obj = SentinelObject::new(ObjectType::File, "test", "/etc/passwd").with_metadata(meta);
        assert!(obj.metadata.ownership.is_some());
        assert_eq!(obj.metadata.ownership.as_ref().unwrap().user, "root");
    }

    #[test]
    fn test_object_with_permissions() {
        let meta = ObjectMetadata::new().with_permissions(PermissionInfo {
            mode: 0o4755,
            is_executable: true,
            is_world_writable: false,
            is_setuid: true,
            is_setgid: false,
        });
        let obj = SentinelObject::new(ObjectType::File, "test", "/usr/bin/su").with_metadata(meta);
        let perms = obj.metadata.permissions.as_ref().unwrap();
        assert!(perms.is_setuid);
        assert!(perms.is_executable);
    }

    #[test]
    fn test_metadata_default() {
        let meta = ObjectMetadata::new();
        assert!(meta.properties.is_empty());
        assert!(meta.ownership.is_none());
        assert!(meta.hashes.is_empty());
        assert!(meta.tags.is_empty());
    }
}
