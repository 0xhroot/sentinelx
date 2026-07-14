use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use flate2::read::{GzDecoder, GzEncoder};
use flate2::Compression;
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

const PROTOCOL_VERSION: u32 = 1;
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
const DEFAULT_RETRY_COUNT: u32 = 5;
const DEFAULT_RETRY_DELAY_MS: u64 = 1000;
const DEFAULT_RECONNECT_DELAY_MS: u64 = 5000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub tls: Option<TlsConfig>,
    pub compress: bool,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    pub reconnect_delay_ms: u64,
    pub heartbeat_interval_secs: u64,
    pub buffer_size: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            tls: None,
            compress: true,
            max_retries: DEFAULT_RETRY_COUNT,
            retry_delay_ms: DEFAULT_RETRY_DELAY_MS,
            reconnect_delay_ms: DEFAULT_RECONNECT_DELAY_MS,
            heartbeat_interval_secs: 30,
            buffer_size: 8192,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub version: u32,
    pub compressed: bool,
    pub requires_ack: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageType {
    Heartbeat,
    HeartbeatAck,
    Telemetry,
    Incident,
    Threat,
    Policy,
    PolicyAck,
    RemoteAction,
    RemoteActionResult,
    Registration,
    RegistrationAck,
    VersionNegotiation,
    VersionNegotiationAck,
    Ping,
    Pong,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub message: Message,
    pub source_agent_id: Option<String>,
    pub dest_agent_id: Option<String>,
    pub correlation_id: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Message too large: {size} > {max}")]
    MessageTooLarge { size: usize, max: usize },
    #[error("Compression error: {0}")]
    Compression(String),
    #[error("Retry exhausted after {0} attempts")]
    RetryExhausted(u32),
    #[error("Channel closed")]
    ChannelClosed,
    #[error("IO error: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, TransportError>;

#[derive(Debug, Clone)]
pub struct TransportStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_dropped: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub reconnections: u64,
    pub compression_ratio: f64,
}

struct StatsInner {
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    messages_dropped: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    reconnections: AtomicU64,
    total_uncompressed: AtomicU64,
    total_compressed: AtomicU64,
}

pub struct TransportManager {
    #[allow(dead_code)]
    config: TransportConfig,
    stats: Arc<StatsInner>,
    running: Arc<AtomicBool>,
    connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,
}

#[allow(dead_code)]
struct ConnectionInfo {
    agent_id: String,
    connected_at: chrono::DateTime<chrono::Utc>,
    last_message_at: chrono::DateTime<chrono::Utc>,
    messages_exchanged: u64,
}

impl TransportManager {
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            stats: Arc::new(StatsInner {
                messages_sent: AtomicU64::new(0),
                messages_received: AtomicU64::new(0),
                messages_dropped: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                reconnections: AtomicU64::new(0),
                total_uncompressed: AtomicU64::new(0),
                total_compressed: AtomicU64::new(0),
            }),
            running: Arc::new(AtomicBool::new(false)),
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn stats(&self) -> TransportStats {
        let uncompressed = self.stats.total_uncompressed.load(Ordering::Relaxed);
        let compressed = self.stats.total_compressed.load(Ordering::Relaxed);
        TransportStats {
            messages_sent: self.stats.messages_sent.load(Ordering::Relaxed),
            messages_received: self.stats.messages_received.load(Ordering::Relaxed),
            messages_dropped: self.stats.messages_dropped.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            reconnections: self.stats.reconnections.load(Ordering::Relaxed),
            compression_ratio: if uncompressed > 0 {
                compressed as f64 / uncompressed as f64
            } else {
                1.0
            },
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }
}

pub fn create_message(msg_type: MessageType, payload: Vec<u8>) -> Message {
    Message {
        id: uuid::Uuid::new_v4().to_string(),
        msg_type,
        payload,
        timestamp: chrono::Utc::now(),
        version: PROTOCOL_VERSION,
        compressed: false,
        requires_ack: matches!(
            msg_type,
            MessageType::RemoteAction | MessageType::Registration | MessageType::Policy
        ),
    }
}

pub fn compress_message(msg: &mut Message) -> Result<()> {
    if msg.compressed {
        return Ok(());
    }
    let original_size = msg.payload.len();
    let mut encoder = GzEncoder::new(&msg.payload[..], Compression::fast());
    let mut compressed = Vec::new();
    std::io::Read::read_to_end(&mut encoder, &mut compressed)
        .map_err(|e| TransportError::Compression(e.to_string()))?;
    if compressed.len() < original_size {
        msg.payload = compressed;
        msg.compressed = true;
    }
    Ok(())
}

pub fn decompress_message(msg: &mut Message) -> Result<()> {
    if !msg.compressed {
        return Ok(());
    }
    let mut decoder = GzDecoder::new(&msg.payload[..]);
    let mut decompressed = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut decompressed)
        .map_err(|e| TransportError::Compression(e.to_string()))?;
    msg.payload = decompressed;
    msg.compressed = false;
    Ok(())
}

pub fn serialize_message(msg: &Message) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(msg).map_err(|e| TransportError::Protocol(e.to_string()))?;
    if json.len() > MAX_MESSAGE_SIZE {
        return Err(TransportError::MessageTooLarge {
            size: json.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }
    let len = (json.len() as u32).to_le_bytes();
    let mut wire = Vec::with_capacity(4 + json.len());
    wire.extend_from_slice(&len);
    wire.extend_from_slice(&json);
    Ok(wire)
}

pub fn deserialize_message(data: &[u8]) -> Result<Message> {
    if data.len() < 4 {
        return Err(TransportError::Protocol(
            "Message too short for length prefix".to_string(),
        ));
    }
    let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return Err(TransportError::Protocol(format!(
            "Incomplete message: expected {} bytes, got {}",
            4 + len,
            data.len()
        )));
    }
    serde_json::from_slice(&data[4..4 + len]).map_err(|e| TransportError::Protocol(e.to_string()))
}

pub fn verify_version(msg: &Message) -> Result<()> {
    if msg.version != PROTOCOL_VERSION {
        return Err(TransportError::Protocol(format!(
            "Version mismatch: expected {}, got {}",
            PROTOCOL_VERSION, msg.version
        )));
    }
    Ok(())
}

pub fn create_version_negotiation() -> Message {
    let payload = serde_json::to_vec(&VersionNegotiation {
        supported_versions: vec![PROTOCOL_VERSION],
        preferred_version: PROTOCOL_VERSION,
    })
    .unwrap_or_default();
    create_message(MessageType::VersionNegotiation, payload)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionNegotiation {
    pub supported_versions: Vec<u32>,
    pub preferred_version: u32,
}

pub async fn start_server(
    bind_addr: &str,
    config: TransportConfig,
    message_tx: mpsc::Sender<MessageEnvelope>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| TransportError::Connection(e.to_string()))?;

    info!("Transport server listening on {}", bind_addr);

    let tls_acceptor = if let Some(ref tls_config) = config.tls {
        Some(
            load_server_tls(tls_config)
                .await
                .map_err(|e| TransportError::Tls(e.to_string()))?,
        )
    } else {
        None
    };

    loop {
        let (stream, addr) = listener
            .accept()
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        info!("New connection from {}", addr);

        let config = config.clone();
        let tx = message_tx.clone();
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Some(acceptor) = acceptor {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        handle_connection(tls_stream, config, tx).await;
                    }
                    Err(e) => {
                        error!("TLS handshake failed from {}: {}", addr, e);
                    }
                }
            } else {
                handle_connection(stream, config, tx).await;
            }
        });
    }
}

async fn handle_connection<S>(stream: S, config: TransportConfig, tx: mpsc::Sender<MessageEnvelope>)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut reader, _writer) = tokio::io::split(stream);
    let mut buf = BytesMut::with_capacity(config.buffer_size);

    loop {
        match reader.read_buf(&mut buf).await {
            Ok(0) => break,
            Ok(_) => {
                while buf.len() >= 4 {
                    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                    if buf.len() < 4 + len {
                        break;
                    }
                    let data = buf.split_to(4 + len);
                    match deserialize_message(&data) {
                        Ok(mut msg) => {
                            if config.compress && msg.compressed {
                                let _ = decompress_message(&mut msg);
                            }
                            let envelope = MessageEnvelope {
                                message: msg,
                                source_agent_id: None,
                                dest_agent_id: None,
                                correlation_id: None,
                            };
                            if tx.send(envelope).await.is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to deserialize message: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Read error: {}", e);
                break;
            }
        }
    }
}

async fn load_server_tls(
    config: &TlsConfig,
) -> std::result::Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let cert_file = fs::File::open(&config.cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<std::result::Result<Vec<_>, _>>()?;

    let key_file = fs::File::open(&config.key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or("No private key found")?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

pub async fn connect_with_retry(addr: &str, config: &TransportConfig) -> Result<TcpStream> {
    let mut attempts = 0;
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                attempts += 1;
                if attempts >= config.max_retries {
                    return Err(TransportError::RetryExhausted(attempts));
                }
                warn!(
                    "Connection attempt {} to {} failed: {}, retrying in {}ms",
                    attempts, addr, e, config.retry_delay_ms
                );
                tokio::time::sleep(Duration::from_millis(config.retry_delay_ms)).await;
            }
        }
    }
}

pub fn spawn_reconnector(
    addr: String,
    config: TransportConfig,
    reconnect_tx: mpsc::Sender<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(config.reconnect_delay_ms)).await;
            info!("Attempting reconnection to {}", addr);
            match connect_with_retry(&addr, &config).await {
                Ok(_) => {
                    info!("Reconnected to {}", addr);
                    if reconnect_tx.send(()).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Reconnection failed: {}", e);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_serialization_roundtrip() {
        let msg = create_message(MessageType::Heartbeat, b"test".to_vec());
        let wire = serialize_message(&msg).unwrap();
        let decoded = deserialize_message(&wire).unwrap();
        assert_eq!(decoded.id, msg.id);
        assert_eq!(decoded.msg_type, MessageType::Heartbeat);
        assert_eq!(decoded.payload, b"test");
        assert_eq!(decoded.version, PROTOCOL_VERSION);
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let mut msg = create_message(
            MessageType::Telemetry,
            b"hello world hello world hello world".to_vec(),
        );
        let original_len = msg.payload.len();
        compress_message(&mut msg).unwrap();
        assert!(msg.compressed);
        assert!(msg.payload.len() <= original_len);

        decompress_message(&mut msg).unwrap();
        assert!(!msg.compressed);
        assert_eq!(msg.payload.len(), original_len);
    }

    #[test]
    fn compress_idempotent() {
        let mut msg = create_message(MessageType::Heartbeat, b"data".to_vec());
        compress_message(&mut msg).unwrap();
        let first = msg.payload.clone();
        compress_message(&mut msg).unwrap();
        assert_eq!(msg.payload, first);
    }

    #[test]
    fn decompress_idempotent() {
        let mut msg = create_message(MessageType::Heartbeat, b"data".to_vec());
        decompress_message(&mut msg).unwrap();
        assert!(!msg.compressed);
        assert_eq!(msg.payload, b"data");
    }

    #[test]
    fn version_check_passes() {
        let msg = create_message(MessageType::Ping, vec![]);
        assert!(verify_version(&msg).is_ok());
    }

    #[test]
    fn version_check_fails() {
        let mut msg = create_message(MessageType::Ping, vec![]);
        msg.version = 999;
        assert!(verify_version(&msg).is_err());
    }

    #[test]
    fn message_too_large() {
        let msg = create_message(MessageType::Telemetry, vec![0u8; MAX_MESSAGE_SIZE + 1]);
        let result = serialize_message(&msg);
        assert!(matches!(
            result,
            Err(TransportError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn transport_stats_default() {
        let manager = TransportManager::new(TransportConfig::default());
        let stats = manager.stats();
        assert_eq!(stats.messages_sent, 0);
        assert_eq!(stats.messages_received, 0);
        assert_eq!(stats.reconnections, 0);
    }

    #[test]
    fn version_negotiation_message() {
        let msg = create_version_negotiation();
        assert_eq!(msg.msg_type, MessageType::VersionNegotiation);
        let neg: VersionNegotiation = serde_json::from_slice(&msg.payload).unwrap();
        assert!(neg.supported_versions.contains(&PROTOCOL_VERSION));
    }

    #[test]
    fn message_envelope_fields() {
        let msg = create_message(MessageType::Telemetry, vec![]);
        let envelope = MessageEnvelope {
            message: msg.clone(),
            source_agent_id: Some("agent-1".to_string()),
            dest_agent_id: Some("coordinator".to_string()),
            correlation_id: Some("corr-1".to_string()),
        };
        assert_eq!(envelope.source_agent_id.as_deref(), Some("agent-1"));
        assert_eq!(envelope.dest_agent_id.as_deref(), Some("coordinator"));
    }

    #[test]
    fn message_requires_ack() {
        let msg = create_message(MessageType::RemoteAction, vec![]);
        assert!(msg.requires_ack);
        let msg = create_message(MessageType::Heartbeat, vec![]);
        assert!(!msg.requires_ack);
    }

    #[test]
    fn transport_manager_not_running() {
        let manager = TransportManager::new(TransportConfig::default());
        assert!(!manager.is_running());
    }

    #[tokio::test]
    async fn connection_count_starts_at_zero() {
        let manager = TransportManager::new(TransportConfig::default());
        assert_eq!(manager.connection_count().await, 0);
    }

    #[test]
    fn create_message_fields() {
        let msg = create_message(MessageType::Policy, b"policy-data".to_vec());
        assert_eq!(msg.msg_type, MessageType::Policy);
        assert_eq!(msg.payload, b"policy-data");
        assert!(!msg.compressed);
        assert!(!msg.id.is_empty());
    }

    #[test]
    fn serialize_deserialize_large_message() {
        let payload = vec![0xAB; 10000];
        let msg = create_message(MessageType::Telemetry, payload.clone());
        let wire = serialize_message(&msg).unwrap();
        let decoded = deserialize_message(&wire).unwrap();
        assert_eq!(decoded.payload, payload);
    }
}
