use sentinelx_common::hash::HashValue;
use sentinelx_common::types::{ConnectionState, NetworkConnection, Protocol};
use sentinelx_core::object::{ObjectMetadata, ObjectType, SentinelObject};

#[derive(Debug, Clone)]
pub struct NetworkObject {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub protocol: Protocol,
    pub state: ConnectionState,
    pub pid: Option<u32>,
    pub inode: u64,
    pub uid: u32,
    pub process_name: Option<String>,
    pub process_hash: Option<HashValue>,
    pub is_hidden: bool,
    pub risk_score: f64,
}

impl From<NetworkConnection> for NetworkObject {
    fn from(conn: NetworkConnection) -> Self {
        Self {
            local_ip: conn.local_addr.ip.to_string(),
            local_port: conn.local_addr.port,
            remote_ip: conn.remote_addr.as_ref().map(|a| a.ip.to_string()),
            remote_port: conn.remote_addr.as_ref().map(|a| a.port),
            protocol: conn.protocol,
            state: conn.state,
            pid: conn.pid.map(|p| p.as_u32()),
            inode: conn.inode,
            uid: conn.uid,
            process_name: conn.process_name,
            process_hash: conn.process_hash,
            is_hidden: false,
            risk_score: 0.5,
        }
    }
}

impl NetworkObject {
    pub fn to_sentinel_object(&self, source: &str) -> SentinelObject {
        let identifier = format!("{}:{}", self.inode, self.local_port);
        let mut metadata = ObjectMetadata::new()
            .with_property("local_ip", serde_json::json!(self.local_ip))
            .with_property("local_port", serde_json::json!(self.local_port))
            .with_property(
                "protocol",
                serde_json::json!(format!("{:?}", self.protocol)),
            )
            .with_property("state", serde_json::json!(format!("{:?}", self.state)))
            .with_property("inode", serde_json::json!(self.inode))
            .with_property("uid", serde_json::json!(self.uid))
            .with_property("is_hidden", serde_json::json!(self.is_hidden))
            .with_property("risk_score", serde_json::json!(self.risk_score));

        if let Some(ref rip) = self.remote_ip {
            metadata = metadata.with_property("remote_ip", serde_json::json!(rip));
        }
        if let Some(rport) = self.remote_port {
            metadata = metadata.with_property("remote_port", serde_json::json!(rport));
        }
        if let Some(pid) = self.pid {
            metadata = metadata.with_property("pid", serde_json::json!(pid));
        }
        if let Some(ref name) = self.process_name {
            metadata = metadata.with_property("process_name", serde_json::json!(name));
        }
        if let Some(ref h) = self.process_hash {
            metadata
                .hashes
                .insert("process_sha256".to_string(), h.as_hex().to_string());
        }

        SentinelObject::new(ObjectType::NetworkConnection, source, &identifier)
            .with_metadata(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_common::pid::Pid;
    use sentinelx_common::types::SocketAddr;

    fn make_connection(inode: u64, port: u16) -> NetworkConnection {
        NetworkConnection {
            local_addr: SocketAddr {
                ip: "127.0.0.1".to_string(),
                port,
            },
            remote_addr: Some(SocketAddr {
                ip: "10.0.0.1".to_string(),
                port: 443,
            }),
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            pid: Some(Pid::new(1234)),
            inode,
            uid: 0,
            process_name: Some("test".to_string()),
            process_hash: None,
        }
    }

    #[test]
    fn test_network_object_from_connection() {
        let conn = make_connection(12345, 8080);
        let obj = NetworkObject::from(conn);
        assert_eq!(obj.local_ip, "127.0.0.1");
        assert_eq!(obj.local_port, 8080);
        assert_eq!(obj.remote_ip, Some("10.0.0.1".to_string()));
        assert_eq!(obj.remote_port, Some(443));
        assert_eq!(obj.pid, Some(1234));
        assert_eq!(obj.inode, 12345);
    }

    #[test]
    fn test_to_sentinel_object() {
        let conn = make_connection(9999, 443);
        let obj = NetworkObject::from(conn);
        let sentinel = obj.to_sentinel_object("network_discovery");

        assert_eq!(sentinel.object_type, ObjectType::NetworkConnection);
        assert_eq!(sentinel.source, "network_discovery");
        assert!(sentinel.id.starts_with("network_connection:"));
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("local_ip")
                .and_then(|v| v.as_str()),
            Some("127.0.0.1")
        );
        assert_eq!(
            sentinel
                .metadata
                .properties
                .get("local_port")
                .and_then(|v| v.as_u64()),
            Some(443)
        );
    }

    #[test]
    fn test_to_sentinel_object_no_pid() {
        let conn = NetworkConnection {
            local_addr: SocketAddr {
                ip: "0.0.0.0".to_string(),
                port: 80,
            },
            remote_addr: None,
            protocol: Protocol::Udp,
            state: ConnectionState::Listen,
            pid: None,
            inode: 5555,
            uid: 1000,
            process_name: None,
            process_hash: None,
        };
        let obj = NetworkObject::from(conn);
        let sentinel = obj.to_sentinel_object("test");
        assert!(!sentinel.metadata.properties.contains_key("pid"));
        assert!(!sentinel.metadata.properties.contains_key("remote_ip"));
    }
}
