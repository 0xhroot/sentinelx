use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use sentinelx_transport::{
    create_message, MessageEnvelope, MessageType, TransportConfig, TransportError, TransportManager,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_id: Option<String>,
    pub coordinator_addr: String,
    pub transport: TransportConfig,
    pub hostname: String,
    pub agent_version: String,
    pub kernel_version: String,
    pub distribution: String,
    pub architecture: String,
    pub heartbeat_interval_secs: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "localhost".to_string());

        Self {
            agent_id: None,
            coordinator_addr: "127.0.0.1:9443".to_string(),
            transport: TransportConfig::default(),
            hostname,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            kernel_version: detect_kernel_version(),
            distribution: detect_distribution(),
            architecture: detect_architecture(),
            heartbeat_interval_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub agent_id: String,
    pub hostname: String,
    pub status: AgentState,
    pub started_at: DateTime<Utc>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub events_sent: u64,
    pub incidents_sent: u64,
    pub policies_received: u64,
    pub actions_executed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentState {
    Initializing,
    Registering,
    Connected,
    Disconnected,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub agent_id: String,
    pub hostname: String,
    pub timestamp: DateTime<Utc>,
    pub health: SystemHealth,
    pub telemetry_status: TelemetryStatus,
    pub detection_stats: DetectionStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub cpu_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub load_avg_1: f64,
    pub load_avg_5: f64,
    pub load_avg_15: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryStatus {
    pub active_providers: u32,
    pub total_events: u64,
    pub dropped_events: u64,
    pub provider_statuses: Vec<ProviderStatusEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStatusEntry {
    pub name: String,
    pub status: String,
    pub events_received: u64,
    pub events_dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionStats {
    pub total_threats: u64,
    pub total_incidents: u64,
    pub total_scans: u64,
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub policy_id: String,
    pub name: String,
    pub policy_type: PolicyType,
    pub config: serde_json::Value,
    pub version: u32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyType {
    Telemetry,
    Assessment,
    Response,
    Correlation,
    ThreatThreshold,
    Workflow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteActionRequest {
    pub action_id: String,
    pub action_type: RemoteActionType,
    pub params: serde_json::Value,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemoteActionType {
    KillProcess,
    CollectMemory,
    CollectBinary,
    GenerateReport,
    BlockIp,
    DisableService,
    RunScan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteActionResult {
    pub action_id: String,
    pub success: bool,
    pub result: serde_json::Value,
    pub error: Option<String>,
    pub duration_ms: u64,
}

pub struct AgentEngine {
    config: AgentConfig,
    agent_id: String,
    status: Arc<RwLock<AgentState>>,
    #[allow(dead_code)]
    transport: Arc<TransportManager>,
    running: Arc<AtomicBool>,
    events_sent: Arc<AtomicU64>,
    incidents_sent: Arc<AtomicU64>,
    policies_received: Arc<AtomicU64>,
    actions_executed: Arc<AtomicU64>,
    policies: Arc<RwLock<HashMap<String, PolicyPayload>>>,
    action_tx: mpsc::Sender<RemoteActionRequest>,
    #[allow(dead_code)]
    action_rx: Arc<RwLock<mpsc::Receiver<RemoteActionRequest>>>,
    message_tx: mpsc::Sender<MessageEnvelope>,
}

impl AgentEngine {
    pub fn new(config: AgentConfig, message_tx: mpsc::Sender<MessageEnvelope>) -> Self {
        let agent_id = config
            .agent_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let (action_tx, action_rx) = mpsc::channel(100);

        Self {
            config,
            agent_id,
            status: Arc::new(RwLock::new(AgentState::Initializing)),
            transport: Arc::new(TransportManager::new(TransportConfig::default())),
            running: Arc::new(AtomicBool::new(false)),
            events_sent: Arc::new(AtomicU64::new(0)),
            incidents_sent: Arc::new(AtomicU64::new(0)),
            policies_received: Arc::new(AtomicU64::new(0)),
            actions_executed: Arc::new(AtomicU64::new(0)),
            policies: Arc::new(RwLock::new(HashMap::new())),
            action_tx,
            action_rx: Arc::new(RwLock::new(action_rx)),
            message_tx,
        }
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    pub async fn status(&self) -> AgentState {
        self.status.read().await.clone()
    }

    pub async fn agent_status(&self) -> AgentStatus {
        AgentStatus {
            agent_id: self.agent_id.clone(),
            hostname: self.config.hostname.clone(),
            status: self.status.read().await.clone(),
            started_at: chrono::Utc::now(),
            last_heartbeat: None,
            events_sent: self.events_sent.load(Ordering::Relaxed),
            incidents_sent: self.incidents_sent.load(Ordering::Relaxed),
            policies_received: self.policies_received.load(Ordering::Relaxed),
            actions_executed: self.actions_executed.load(Ordering::Relaxed),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub async fn start(&self) {
        self.running.store(true, Ordering::Relaxed);
        *self.status.write().await = AgentState::Registering;
        info!("Agent {} starting", self.agent_id);

        let registration = create_message(
            MessageType::Registration,
            serde_json::to_vec(&RegistrationPayload {
                agent_id: self.agent_id.clone(),
                hostname: self.config.hostname.clone(),
                version: self.config.agent_version.clone(),
                kernel: self.config.kernel_version.clone(),
                distribution: self.config.distribution.clone(),
                architecture: self.config.architecture.clone(),
            })
            .unwrap_or_default(),
        );

        if self
            .message_tx
            .send(MessageEnvelope {
                message: registration,
                source_agent_id: Some(self.agent_id.clone()),
                dest_agent_id: None,
                correlation_id: None,
            })
            .await
            .is_err()
        {
            warn!("Failed to send registration");
        }

        *self.status.write().await = AgentState::Connected;
    }

    pub async fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        *self.status.write().await = AgentState::Disconnected;
        info!("Agent {} stopped", self.agent_id);
    }

    pub fn action_sender(&self) -> mpsc::Sender<RemoteActionRequest> {
        self.action_tx.clone()
    }

    pub async fn create_heartbeat(&self) -> HeartbeatPayload {
        let health = collect_system_health().await;
        HeartbeatPayload {
            agent_id: self.agent_id.clone(),
            hostname: self.config.hostname.clone(),
            timestamp: Utc::now(),
            health,
            telemetry_status: TelemetryStatus {
                active_providers: 0,
                total_events: 0,
                dropped_events: 0,
                provider_statuses: vec![],
            },
            detection_stats: DetectionStats {
                total_threats: 0,
                total_incidents: 0,
                total_scans: 0,
                last_scan_at: None,
            },
        }
    }

    pub async fn send_heartbeat(&self) -> Result<(), TransportError> {
        let heartbeat = self.create_heartbeat().await;
        let payload =
            serde_json::to_vec(&heartbeat).map_err(|e| TransportError::Protocol(e.to_string()))?;
        let msg = create_message(MessageType::Heartbeat, payload);

        self.events_sent.fetch_add(1, Ordering::Relaxed);

        self.message_tx
            .send(MessageEnvelope {
                message: msg,
                source_agent_id: Some(self.agent_id.clone()),
                dest_agent_id: None,
                correlation_id: None,
            })
            .await
            .map_err(|_| TransportError::ChannelClosed)
    }

    pub async fn handle_message(&self, envelope: MessageEnvelope) {
        let msg = envelope.message;
        match msg.msg_type {
            MessageType::HeartbeatAck => {
                info!("Heartbeat acknowledged");
            }
            MessageType::Policy => {
                if let Ok(policy) = serde_json::from_slice::<PolicyPayload>(&msg.payload) {
                    info!("Received policy: {} v{}", policy.name, policy.version);
                    self.policies
                        .write()
                        .await
                        .insert(policy.policy_id.clone(), policy);
                    self.policies_received.fetch_add(1, Ordering::Relaxed);

                    let ack = create_message(MessageType::PolicyAck, vec![]);
                    let _ = self
                        .message_tx
                        .send(MessageEnvelope {
                            message: ack,
                            source_agent_id: Some(self.agent_id.clone()),
                            dest_agent_id: envelope.source_agent_id.clone(),
                            correlation_id: Some(msg.id),
                        })
                        .await;
                }
            }
            MessageType::RemoteAction => {
                if let Ok(action) = serde_json::from_slice::<RemoteActionRequest>(&msg.payload) {
                    info!("Received remote action: {:?}", action.action_type);
                    let _ = self.action_tx.send(action).await;
                }
            }
            MessageType::Ping => {
                let pong = create_message(MessageType::Pong, vec![]);
                let _ = self
                    .message_tx
                    .send(MessageEnvelope {
                        message: pong,
                        source_agent_id: Some(self.agent_id.clone()),
                        dest_agent_id: envelope.source_agent_id.clone(),
                        correlation_id: Some(msg.id),
                    })
                    .await;
            }
            _ => {
                warn!("Unhandled message type: {:?}", msg.msg_type);
            }
        }
    }

    pub async fn policies(&self) -> Vec<PolicyPayload> {
        self.policies.read().await.values().cloned().collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RegistrationPayload {
    agent_id: String,
    hostname: String,
    version: String,
    kernel: String,
    distribution: String,
    architecture: String,
}

async fn collect_system_health() -> SystemHealth {
    let (cpu, mem_used, mem_total, disk_used, disk_total) = {
        let mem_info = std::fs::read_to_string("/proc/meminfo").ok();
        let mem_total = mem_info
            .as_ref()
            .and_then(|s| parse_mem_field(s, "MemTotal:"))
            .unwrap_or(0);
        let mem_avail = mem_info
            .as_ref()
            .and_then(|s| parse_mem_field(s, "MemAvailable:"))
            .unwrap_or(mem_total);
        let mem_used = mem_total.saturating_sub(mem_avail);

        let disk = std::fs::metadata("/").ok();
        let disk_total = disk.map(|m| m.len()).unwrap_or(0);
        let disk_used = 0;

        (
            0.0_f64,
            mem_used * 1024,
            mem_total * 1024,
            disk_used,
            disk_total,
        )
    };

    let load = std::fs::read_to_string("/proc/loadavg").ok();
    let loads = parse_load_avg(load.as_deref().unwrap_or("0 0 0"));

    SystemHealth {
        cpu_percent: cpu,
        memory_used_bytes: mem_used,
        memory_total_bytes: mem_total,
        disk_used_bytes: disk_used,
        disk_total_bytes: disk_total,
        load_avg_1: loads[0],
        load_avg_5: loads[1],
        load_avg_15: loads[2],
    }
}

fn parse_mem_field(content: &str, field: &str) -> Option<u64> {
    content.lines().find_map(|line| {
        let val = line.strip_prefix(field)?.split_whitespace().next()?;
        val.parse::<u64>().ok()
    })
}

fn parse_load_avg(s: &str) -> [f64; 3] {
    let parts: Vec<&str> = s.split_whitespace().collect();
    [
        parts.first().and_then(|s| s.parse().ok()).unwrap_or(0.0),
        parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0),
        parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0),
    ]
}

fn detect_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .map(|s| s.split_whitespace().next().unwrap_or("unknown").to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn detect_distribution() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                l.trim_start_matches("PRETTY_NAME=")
                    .trim_matches('"')
                    .to_string()
            })
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn detect_architecture() -> String {
    std::env::consts::ARCH.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_config_default() {
        let config = AgentConfig::default();
        assert!(!config.hostname.is_empty());
        assert_eq!(config.heartbeat_interval_secs, 30);
    }

    #[test]
    fn agent_state_variants() {
        assert_eq!(AgentState::Initializing, AgentState::Initializing);
        assert_ne!(AgentState::Connected, AgentState::Disconnected);
    }

    #[test]
    fn heartbeat_payload_serialization() {
        let hb = HeartbeatPayload {
            agent_id: "test-agent".to_string(),
            hostname: "test-host".to_string(),
            timestamp: Utc::now(),
            health: SystemHealth {
                cpu_percent: 45.5,
                memory_used_bytes: 1024 * 1024 * 512,
                memory_total_bytes: 1024 * 1024 * 1024 * 4,
                disk_used_bytes: 0,
                disk_total_bytes: 0,
                load_avg_1: 0.5,
                load_avg_5: 0.3,
                load_avg_15: 0.2,
            },
            telemetry_status: TelemetryStatus {
                active_providers: 4,
                total_events: 1000,
                dropped_events: 5,
                provider_statuses: vec![],
            },
            detection_stats: DetectionStats {
                total_threats: 10,
                total_incidents: 3,
                total_scans: 50,
                last_scan_at: None,
            },
        };

        let json = serde_json::to_string(&hb).unwrap();
        let decoded: HeartbeatPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.agent_id, "test-agent");
        assert_eq!(decoded.telemetry_status.active_providers, 4);
    }

    #[test]
    fn policy_serialization() {
        let policy = PolicyPayload {
            policy_id: "p-1".to_string(),
            name: "telemetry-config".to_string(),
            policy_type: PolicyType::Telemetry,
            config: serde_json::json!({"max_rate": 1000}),
            version: 1,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: PolicyPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "telemetry-config");
        assert_eq!(decoded.policy_type, PolicyType::Telemetry);
    }

    #[test]
    fn remote_action_types() {
        assert_ne!(RemoteActionType::KillProcess, RemoteActionType::BlockIp);
    }

    #[test]
    fn system_health_fields() {
        let h = SystemHealth {
            cpu_percent: 10.0,
            memory_used_bytes: 100,
            memory_total_bytes: 200,
            disk_used_bytes: 300,
            disk_total_bytes: 400,
            load_avg_1: 0.1,
            load_avg_5: 0.2,
            load_avg_15: 0.3,
        };
        assert!(h.cpu_percent > 0.0);
        assert!(h.memory_used_bytes < h.memory_total_bytes);
    }

    #[test]
    fn parse_mem_field_works() {
        let content = "MemTotal:       16384000 kB\nMemFree:         8192000 kB\nMemAvailable:   12288000 kB\n";
        assert_eq!(parse_mem_field(content, "MemTotal:"), Some(16384000));
        assert_eq!(parse_mem_field(content, "MemAvailable:"), Some(12288000));
        assert_eq!(parse_mem_field(content, "MemFree:"), Some(8192000));
    }

    #[test]
    fn parse_load_avg_works() {
        let loads = parse_load_avg("1.23 4.56 7.89");
        assert!((loads[0] - 1.23).abs() < 0.01);
        assert!((loads[1] - 4.56).abs() < 0.01);
        assert!((loads[2] - 7.89).abs() < 0.01);
    }

    #[test]
    fn parse_load_avg_empty() {
        let loads = parse_load_avg("");
        assert_eq!(loads, [0.0, 0.0, 0.0]);
    }

    #[test]
    fn detect_kernel_version_returns_string() {
        let kv = detect_kernel_version();
        assert!(!kv.is_empty());
    }

    #[test]
    fn detect_architecture_returns_string() {
        let arch = detect_architecture();
        assert!(!arch.is_empty());
    }

    #[tokio::test]
    async fn agent_engine_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let config = AgentConfig::default();
        let engine = AgentEngine::new(config, tx);
        assert!(!engine.agent_id().is_empty());
        assert!(!engine.is_running());
    }

    #[tokio::test]
    async fn agent_engine_start_stop() {
        let (tx, _rx) = mpsc::channel(10);
        let config = AgentConfig::default();
        let engine = AgentEngine::new(config, tx);
        engine.start().await;
        assert!(engine.is_running());
        assert_eq!(engine.status().await, AgentState::Connected);

        engine.stop().await;
        assert!(!engine.is_running());
        assert_eq!(engine.status().await, AgentState::Disconnected);
    }

    #[tokio::test]
    async fn agent_status_report() {
        let (tx, _rx) = mpsc::channel(10);
        let config = AgentConfig::default();
        let engine = AgentEngine::new(config, tx);
        let status = engine.agent_status().await;
        assert_eq!(status.events_sent, 0);
        assert_eq!(status.actions_executed, 0);
    }

    #[tokio::test]
    async fn agent_policies_starts_empty() {
        let (tx, _rx) = mpsc::channel(10);
        let engine = AgentEngine::new(AgentConfig::default(), tx);
        assert!(engine.policies().await.is_empty());
    }
}
