use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::info;

use sentinelx_transport::{create_message, MessageEnvelope, MessageType, TransportConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorConfig {
    pub bind_addr: String,
    pub transport: TransportConfig,
    pub heartbeat_timeout_secs: u64,
    pub max_agents: usize,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:9443".to_string(),
            transport: TransportConfig::default(),
            heartbeat_timeout_secs: 90,
            max_agents: 10000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub agent_id: String,
    pub hostname: String,
    pub version: String,
    pub kernel: String,
    pub distribution: String,
    pub architecture: String,
    pub registered_at: DateTime<Utc>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub status: AgentHealthStatus,
    pub events_received: u64,
    pub incidents_received: u64,
    pub policies_sent: u64,
    pub actions_sent: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentHealthStatus {
    Healthy,
    Degraded,
    Unreachable,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRecord {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub cpu_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub load_avg_1: f64,
    pub active_telemetry_providers: u32,
    pub total_events: u64,
    pub total_threats: u64,
    pub total_incidents: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorStats {
    pub total_agents: usize,
    pub healthy_agents: usize,
    pub degraded_agents: usize,
    pub offline_agents: usize,
    pub total_heartbeats: u64,
    pub total_incidents_aggregated: u64,
    pub total_threats_aggregated: u64,
    pub policies_distributed: u64,
}

pub struct CoordinatorEngine {
    config: CoordinatorConfig,
    agents: Arc<RwLock<HashMap<String, AgentRecord>>>,
    heartbeats: Arc<RwLock<Vec<HeartbeatRecord>>>,
    policies: Arc<RwLock<HashMap<String, PolicyRecord>>>,
    running: Arc<AtomicBool>,
    stats: Arc<CoordinatorStatsInner>,
    event_tx: broadcast::Sender<CoordinatorEvent>,
    message_tx: mpsc::Sender<MessageEnvelope>,
}

struct CoordinatorStatsInner {
    total_heartbeats: AtomicU64,
    total_incidents_aggregated: AtomicU64,
    total_threats_aggregated: AtomicU64,
    policies_distributed: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub policy_id: String,
    pub name: String,
    pub policy_type: String,
    pub config: serde_json::Value,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub distributed_to: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum CoordinatorEvent {
    AgentRegistered(String),
    AgentDisconnected(String),
    HeartbeatReceived(String),
    IncidentAggregated(String),
    PolicyDistributed(String),
}

impl CoordinatorEngine {
    pub fn new(config: CoordinatorConfig, message_tx: mpsc::Sender<MessageEnvelope>) -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            config,
            agents: Arc::new(RwLock::new(HashMap::new())),
            heartbeats: Arc::new(RwLock::new(Vec::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(CoordinatorStatsInner {
                total_heartbeats: AtomicU64::new(0),
                total_incidents_aggregated: AtomicU64::new(0),
                total_threats_aggregated: AtomicU64::new(0),
                policies_distributed: AtomicU64::new(0),
            }),
            event_tx,
            message_tx,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub async fn start(&self) {
        self.running.store(true, Ordering::Relaxed);
        info!("Coordinator started on {}", self.config.bind_addr);
    }

    pub async fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        info!("Coordinator stopped");
    }

    pub async fn register_agent(
        &self,
        agent_id: String,
        hostname: String,
        version: String,
        kernel: String,
        distribution: String,
        architecture: String,
    ) -> Result<(), String> {
        let agents = self.agents.read().await;
        if agents.len() >= self.config.max_agents {
            return Err("Maximum agent limit reached".to_string());
        }
        drop(agents);

        let record = AgentRecord {
            agent_id: agent_id.clone(),
            hostname,
            version,
            kernel,
            distribution,
            architecture,
            registered_at: Utc::now(),
            last_heartbeat: None,
            status: AgentHealthStatus::Healthy,
            events_received: 0,
            incidents_received: 0,
            policies_sent: 0,
            actions_sent: 0,
        };

        self.agents.write().await.insert(agent_id.clone(), record);
        info!("Agent {} registered", agent_id);

        let _ = self
            .event_tx
            .send(CoordinatorEvent::AgentRegistered(agent_id));

        Ok(())
    }

    pub async fn unregister_agent(&self, agent_id: &str) {
        self.agents.write().await.remove(agent_id);
        info!("Agent {} unregistered", agent_id);
        let _ = self
            .event_tx
            .send(CoordinatorEvent::AgentDisconnected(agent_id.to_string()));
    }

    pub async fn receive_heartbeat(&self, heartbeat: HeartbeatRecord) {
        let agent_id = heartbeat.agent_id.clone();

        if let Some(agent) = self.agents.write().await.get_mut(&agent_id) {
            agent.last_heartbeat = Some(heartbeat.timestamp);
            agent.status = AgentHealthStatus::Healthy;
            agent.events_received += 1;
        }

        self.heartbeats.write().await.push(heartbeat);
        self.stats.total_heartbeats.fetch_add(1, Ordering::Relaxed);

        let _ = self
            .event_tx
            .send(CoordinatorEvent::HeartbeatReceived(agent_id));
    }

    pub async fn check_stale_agents(&self) {
        let timeout = chrono::Duration::seconds(self.config.heartbeat_timeout_secs as i64);
        let now = Utc::now();
        let mut agents = self.agents.write().await;

        for agent in agents.values_mut() {
            if let Some(last) = agent.last_heartbeat {
                if now.signed_duration_since(last) > timeout * 3 {
                    agent.status = AgentHealthStatus::Offline;
                } else if now.signed_duration_since(last) > timeout {
                    agent.status = AgentHealthStatus::Degraded;
                }
            }
        }
    }

    pub async fn distribute_policy(
        &self,
        name: String,
        policy_type: String,
        config: serde_json::Value,
    ) -> Result<String, String> {
        let policy_id = uuid::Uuid::new_v4().to_string();
        let name_clone = name.clone();
        let policy = PolicyRecord {
            policy_id: policy_id.clone(),
            name,
            policy_type,
            config,
            version: 1,
            created_at: Utc::now(),
            distributed_to: vec![],
        };

        self.policies
            .write()
            .await
            .insert(policy_id.clone(), policy);

        let agent_ids: Vec<String> = self.agents.read().await.keys().cloned().collect();

        for agent_id in &agent_ids {
            let msg = create_message(
                MessageType::Policy,
                serde_json::to_vec(&serde_json::json!({
                    "policy_id": policy_id,
                    "name": name_clone,
                }))
                .unwrap_or_default(),
            );
            let _ = self
                .message_tx
                .send(MessageEnvelope {
                    message: msg,
                    source_agent_id: None,
                    dest_agent_id: Some(agent_id.clone()),
                    correlation_id: None,
                })
                .await;
        }

        self.stats
            .policies_distributed
            .fetch_add(agent_ids.len() as u64, Ordering::Relaxed);
        info!(
            "Policy {} distributed to {} agents",
            policy_id,
            agent_ids.len()
        );
        let _ = self
            .event_tx
            .send(CoordinatorEvent::PolicyDistributed(policy_id.clone()));

        Ok(policy_id)
    }

    pub async fn aggregate_incident(&self, incident: serde_json::Value) {
        self.stats
            .total_incidents_aggregated
            .fetch_add(1, Ordering::Relaxed);
        let _ = self
            .event_tx
            .send(CoordinatorEvent::IncidentAggregated(incident.to_string()));
    }

    pub async fn agents(&self) -> Vec<AgentRecord> {
        self.agents.read().await.values().cloned().collect()
    }

    pub async fn agent(&self, agent_id: &str) -> Option<AgentRecord> {
        self.agents.read().await.get(agent_id).cloned()
    }

    pub async fn agent_count(&self) -> usize {
        self.agents.read().await.len()
    }

    pub async fn heartbeats(&self, agent_id: &str, limit: usize) -> Vec<HeartbeatRecord> {
        self.heartbeats
            .read()
            .await
            .iter()
            .filter(|h| h.agent_id == agent_id)
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    pub async fn policies(&self) -> Vec<PolicyRecord> {
        self.policies.read().await.values().cloned().collect()
    }

    pub async fn stats(&self) -> CoordinatorStats {
        let agents = self.agents.read().await;
        let healthy = agents
            .values()
            .filter(|a| a.status == AgentHealthStatus::Healthy)
            .count();
        let degraded = agents
            .values()
            .filter(|a| a.status == AgentHealthStatus::Degraded)
            .count();
        let offline = agents
            .values()
            .filter(|a| a.status == AgentHealthStatus::Offline)
            .count();

        CoordinatorStats {
            total_agents: agents.len(),
            healthy_agents: healthy,
            degraded_agents: degraded,
            offline_agents: offline,
            total_heartbeats: self.stats.total_heartbeats.load(Ordering::Relaxed),
            total_incidents_aggregated: self
                .stats
                .total_incidents_aggregated
                .load(Ordering::Relaxed),
            total_threats_aggregated: self.stats.total_threats_aggregated.load(Ordering::Relaxed),
            policies_distributed: self.stats.policies_distributed.load(Ordering::Relaxed),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CoordinatorEvent> {
        self.event_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> CoordinatorConfig {
        CoordinatorConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            transport: TransportConfig::default(),
            heartbeat_timeout_secs: 60,
            max_agents: 100,
        }
    }

    #[tokio::test]
    async fn coordinator_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let engine = CoordinatorEngine::new(create_test_config(), tx);
        assert!(!engine.is_running());
        assert_eq!(engine.agent_count().await, 0);
    }

    #[tokio::test]
    async fn coordinator_start_stop() {
        let (tx, _rx) = mpsc::channel(10);
        let engine = CoordinatorEngine::new(create_test_config(), tx);
        engine.start().await;
        assert!(engine.is_running());
        engine.stop().await;
        assert!(!engine.is_running());
    }

    #[tokio::test]
    async fn register_agent_success() {
        let (tx, _rx) = mpsc::channel(10);
        let engine = CoordinatorEngine::new(create_test_config(), tx);
        engine.start().await;

        let result = engine
            .register_agent(
                "agent-1".to_string(),
                "host-1".to_string(),
                "1.0.0".to_string(),
                "6.1.0".to_string(),
                "Ubuntu 22.04".to_string(),
                "x86_64".to_string(),
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(engine.agent_count().await, 1);

        let agent = engine.agent("agent-1").await.unwrap();
        assert_eq!(agent.hostname, "host-1");
        assert_eq!(agent.status, AgentHealthStatus::Healthy);
    }

    #[tokio::test]
    async fn register_agent_max_limit() {
        let (tx, _rx) = mpsc::channel(10);
        let mut config = create_test_config();
        config.max_agents = 1;
        let engine = CoordinatorEngine::new(config, tx);
        engine.start().await;

        engine
            .register_agent(
                "a1".to_string(),
                "h1".to_string(),
                "1.0".to_string(),
                "k".to_string(),
                "d".to_string(),
                "x86_64".to_string(),
            )
            .await
            .unwrap();

        let result = engine
            .register_agent(
                "a2".to_string(),
                "h2".to_string(),
                "1.0".to_string(),
                "k".to_string(),
                "d".to_string(),
                "x86_64".to_string(),
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn unregister_agent() {
        let (tx, _rx) = mpsc::channel(10);
        let engine = CoordinatorEngine::new(create_test_config(), tx);
        engine.start().await;

        engine
            .register_agent(
                "agent-1".to_string(),
                "h".to_string(),
                "1.0".to_string(),
                "k".to_string(),
                "d".to_string(),
                "x86_64".to_string(),
            )
            .await
            .unwrap();
        assert_eq!(engine.agent_count().await, 1);

        engine.unregister_agent("agent-1").await;
        assert_eq!(engine.agent_count().await, 0);
    }

    #[tokio::test]
    async fn receive_heartbeat_updates_agent() {
        let (tx, _rx) = mpsc::channel(10);
        let engine = CoordinatorEngine::new(create_test_config(), tx);
        engine.start().await;

        engine
            .register_agent(
                "agent-1".to_string(),
                "h".to_string(),
                "1.0".to_string(),
                "k".to_string(),
                "d".to_string(),
                "x86_64".to_string(),
            )
            .await
            .unwrap();

        let hb = HeartbeatRecord {
            agent_id: "agent-1".to_string(),
            timestamp: Utc::now(),
            cpu_percent: 45.0,
            memory_used_bytes: 1024,
            memory_total_bytes: 4096,
            disk_used_bytes: 0,
            disk_total_bytes: 0,
            load_avg_1: 0.5,
            active_telemetry_providers: 4,
            total_events: 100,
            total_threats: 5,
            total_incidents: 2,
        };

        engine.receive_heartbeat(hb).await;

        let stats = engine.stats().await;
        assert_eq!(stats.total_heartbeats, 1);

        let agent = engine.agent("agent-1").await.unwrap();
        assert!(agent.last_heartbeat.is_some());
    }

    #[tokio::test]
    async fn check_stale_agents() {
        let (tx, _rx) = mpsc::channel(10);
        let mut config = create_test_config();
        config.heartbeat_timeout_secs = 1;
        let engine = CoordinatorEngine::new(config, tx);
        engine.start().await;

        engine
            .register_agent(
                "agent-1".to_string(),
                "h".to_string(),
                "1.0".to_string(),
                "k".to_string(),
                "d".to_string(),
                "x86_64".to_string(),
            )
            .await
            .unwrap();

        let mut agent = engine.agent("agent-1").await.unwrap();
        agent.last_heartbeat = Some(Utc::now() - chrono::Duration::seconds(120));
        engine
            .agents
            .write()
            .await
            .insert("agent-1".to_string(), agent);

        engine.check_stale_agents().await;

        let agent = engine.agent("agent-1").await.unwrap();
        assert_eq!(agent.status, AgentHealthStatus::Offline);
    }

    #[tokio::test]
    async fn distribute_policy() {
        let (tx, _rx) = mpsc::channel(10);
        let engine = CoordinatorEngine::new(create_test_config(), tx);
        engine.start().await;

        engine
            .register_agent(
                "agent-1".to_string(),
                "h".to_string(),
                "1.0".to_string(),
                "k".to_string(),
                "d".to_string(),
                "x86_64".to_string(),
            )
            .await
            .unwrap();

        let policy_id = engine
            .distribute_policy(
                "test-policy".to_string(),
                "telemetry".to_string(),
                serde_json::json!({"max_rate": 100}),
            )
            .await
            .unwrap();

        assert!(!policy_id.is_empty());
        let policies = engine.policies().await;
        assert_eq!(policies.len(), 1);
    }

    #[tokio::test]
    async fn coordinator_stats() {
        let (tx, _rx) = mpsc::channel(10);
        let engine = CoordinatorEngine::new(create_test_config(), tx);
        engine.start().await;

        engine
            .register_agent(
                "a1".to_string(),
                "h".to_string(),
                "1.0".to_string(),
                "k".to_string(),
                "d".to_string(),
                "x86_64".to_string(),
            )
            .await
            .unwrap();
        engine
            .register_agent(
                "a2".to_string(),
                "h".to_string(),
                "1.0".to_string(),
                "k".to_string(),
                "d".to_string(),
                "x86_64".to_string(),
            )
            .await
            .unwrap();

        let stats = engine.stats().await;
        assert_eq!(stats.total_agents, 2);
        assert_eq!(stats.healthy_agents, 2);
    }

    #[tokio::test]
    async fn agent_list() {
        let (tx, _rx) = mpsc::channel(10);
        let engine = CoordinatorEngine::new(create_test_config(), tx);
        engine.start().await;

        for i in 0..5 {
            engine
                .register_agent(
                    format!("a{}", i),
                    "h".to_string(),
                    "1.0".to_string(),
                    "k".to_string(),
                    "d".to_string(),
                    "x86_64".to_string(),
                )
                .await
                .unwrap();
        }

        let agents = engine.agents().await;
        assert_eq!(agents.len(), 5);
    }

    #[tokio::test]
    async fn heartbeats_filtered_by_agent() {
        let (tx, _rx) = mpsc::channel(10);
        let engine = CoordinatorEngine::new(create_test_config(), tx);
        engine.start().await;

        engine
            .register_agent(
                "a1".to_string(),
                "h".to_string(),
                "1.0".to_string(),
                "k".to_string(),
                "d".to_string(),
                "x86_64".to_string(),
            )
            .await
            .unwrap();

        let hb = HeartbeatRecord {
            agent_id: "a1".to_string(),
            timestamp: Utc::now(),
            cpu_percent: 0.0,
            memory_used_bytes: 0,
            memory_total_bytes: 0,
            disk_used_bytes: 0,
            disk_total_bytes: 0,
            load_avg_1: 0.0,
            active_telemetry_providers: 0,
            total_events: 0,
            total_threats: 0,
            total_incidents: 0,
        };

        engine.receive_heartbeat(hb).await;

        let hbs = engine.heartbeats("a1", 10).await;
        assert_eq!(hbs.len(), 1);
        assert_eq!(hbs[0].agent_id, "a1");

        let hbs_other = engine.heartbeats("nonexistent", 10).await;
        assert!(hbs_other.is_empty());
    }
}
