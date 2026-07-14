use crate::types::{TelemetryCategory, TelemetryEvent, TelemetryEventType};

#[derive(Debug, Clone)]
pub struct EventNormalizer {
    provider_name: String,
}

impl EventNormalizer {
    pub fn new(provider_name: &str) -> Self {
        Self {
            provider_name: provider_name.to_string(),
        }
    }

    pub fn normalize(
        &self,
        raw_event_type: &str,
        pid: Option<u32>,
        uid: Option<u32>,
        object_id: Option<&str>,
        metadata: serde_json::Value,
    ) -> Option<TelemetryEvent> {
        let event_type = TelemetryEventType::parse_from(raw_event_type)?;
        let mut event = TelemetryEvent::new(&self.provider_name, event_type);

        if let Some(p) = pid {
            event = event.with_pid(p);
        }
        if let Some(u) = uid {
            event = event.with_uid(u);
        }
        if let Some(oid) = object_id {
            event = event.with_object_id(oid);
        }
        if !metadata.is_null() {
            event = event.with_metadata(metadata);
        }

        Some(event)
    }

    pub fn normalize_raw(
        &self,
        category: TelemetryCategory,
        event_type: &str,
        pid: Option<u32>,
        uid: Option<u32>,
        object_id: Option<&str>,
        metadata: serde_json::Value,
    ) -> TelemetryEvent {
        let parsed_type = TelemetryEventType::parse_from(event_type).unwrap_or(match category {
            TelemetryCategory::Process => TelemetryEventType::ProcessCreate,
            TelemetryCategory::Filesystem => TelemetryEventType::FileOpen,
            TelemetryCategory::Network => TelemetryEventType::NetConnect,
            TelemetryCategory::Kernel => TelemetryEventType::KernelModuleLoad,
            TelemetryCategory::Persistence => TelemetryEventType::PersistenceServiceCreate,
        });

        let mut event = TelemetryEvent::new(&self.provider_name, parsed_type);

        if let Some(p) = pid {
            event = event.with_pid(p);
        }
        if let Some(u) = uid {
            event = event.with_uid(u);
        }
        if let Some(oid) = object_id {
            event = event.with_object_id(oid);
        }
        if !metadata.is_null() {
            event = event.with_metadata(metadata);
        }

        event
    }

    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizer_create() {
        let n = EventNormalizer::new("test_provider");
        assert_eq!(n.provider_name(), "test_provider");
    }

    #[test]
    fn normalize_valid_event_type() {
        let n = EventNormalizer::new("test");
        let event = n
            .normalize(
                "process_create",
                Some(100),
                Some(0),
                Some("proc_100"),
                serde_json::json!({}),
            )
            .unwrap();

        assert_eq!(event.provider, "test");
        assert_eq!(event.event_type, TelemetryEventType::ProcessCreate);
        assert_eq!(event.category, TelemetryCategory::Process);
        assert_eq!(event.pid, Some(100));
        assert_eq!(event.uid, Some(0));
        assert_eq!(event.object_id, Some("proc_100".to_string()));
    }

    #[test]
    fn normalize_invalid_event_type_returns_none() {
        let n = EventNormalizer::new("test");
        let result = n.normalize(
            "nonexistent_type",
            None,
            None,
            None,
            serde_json::Value::Null,
        );
        assert!(result.is_none());
    }

    #[test]
    fn normalize_with_null_fields() {
        let n = EventNormalizer::new("test");
        let event = n
            .normalize("file_write", None, None, None, serde_json::Value::Null)
            .unwrap();

        assert_eq!(event.pid, None);
        assert_eq!(event.uid, None);
        assert_eq!(event.object_id, None);
    }

    #[test]
    fn normalize_raw_with_valid_type() {
        let n = EventNormalizer::new("test");
        let event = n.normalize_raw(
            TelemetryCategory::Process,
            "process_exec",
            Some(200),
            Some(1000),
            Some("/bin/sh"),
            serde_json::json!({"path": "/bin/sh"}),
        );

        assert_eq!(event.event_type, TelemetryEventType::ProcessExec);
        assert_eq!(event.pid, Some(200));
        assert_eq!(event.metadata["path"], "/bin/sh");
    }

    #[test]
    fn normalize_raw_fallback_on_invalid_type() {
        let n = EventNormalizer::new("test");
        let event = n.normalize_raw(
            TelemetryCategory::Network,
            "unknown_event",
            None,
            None,
            None,
            serde_json::Value::Null,
        );

        assert_eq!(event.event_type, TelemetryEventType::NetConnect);
    }

    #[test]
    fn normalize_raw_filesystem_fallback() {
        let n = EventNormalizer::new("test");
        let event = n.normalize_raw(
            TelemetryCategory::Filesystem,
            "unknown",
            None,
            None,
            None,
            serde_json::Value::Null,
        );
        assert_eq!(event.event_type, TelemetryEventType::FileOpen);
    }

    #[test]
    fn normalize_raw_kernel_fallback() {
        let n = EventNormalizer::new("test");
        let event = n.normalize_raw(
            TelemetryCategory::Kernel,
            "unknown",
            None,
            None,
            None,
            serde_json::Value::Null,
        );
        assert_eq!(event.event_type, TelemetryEventType::KernelModuleLoad);
    }

    #[test]
    fn normalize_raw_persistence_fallback() {
        let n = EventNormalizer::new("test");
        let event = n.normalize_raw(
            TelemetryCategory::Persistence,
            "unknown",
            None,
            None,
            None,
            serde_json::Value::Null,
        );
        assert_eq!(
            event.event_type,
            TelemetryEventType::PersistenceServiceCreate
        );
    }

    #[test]
    fn normalize_with_metadata() {
        let n = EventNormalizer::new("test");
        let event = n
            .normalize(
                "net_connect",
                Some(500),
                None,
                None,
                serde_json::json!({"dest_ip": "1.2.3.4", "dest_port": 443}),
            )
            .unwrap();

        assert_eq!(event.metadata["dest_ip"], "1.2.3.4");
        assert_eq!(event.metadata["dest_port"], 443);
    }
}
