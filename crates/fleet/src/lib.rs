use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tracing::info;

pub use sentinelx_agent::{
    AgentConfig, AgentEngine, AgentState, AgentStatus, DetectionStats, HeartbeatPayload,
    PolicyPayload, PolicyType, RemoteActionRequest, RemoteActionResult, RemoteActionType,
    SystemHealth, TelemetryStatus,
};
pub use sentinelx_coordinator::{
    AgentHealthStatus, AgentRecord, CoordinatorConfig, CoordinatorEngine, CoordinatorEvent,
    CoordinatorStats, HeartbeatRecord, PolicyRecord,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetConfig {
    pub coordinator: CoordinatorConfig,
    pub agent: Option<AgentConfig>,
    pub db_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetOverview {
    pub total_agents: usize,
    pub healthy_agents: usize,
    pub degraded_agents: usize,
    pub offline_agents: usize,
    pub total_heartbeats: u64,
    pub total_incidents: u64,
    pub total_threats: u64,
    pub total_policies: usize,
    pub total_actions: u64,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteActionRecord {
    pub action_id: String,
    pub agent_id: String,
    pub action_type: String,
    pub params: serde_json::Value,
    pub status: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetAgentInfo {
    pub agent_id: String,
    pub hostname: String,
    pub status: String,
    pub version: String,
    pub kernel: String,
    pub distribution: String,
    pub architecture: String,
    pub registered_at: DateTime<Utc>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub uptime_secs: u64,
    pub health: Option<SystemHealth>,
    pub telemetry: Option<TelemetryStatus>,
    pub detection: Option<DetectionStats>,
}

pub struct FleetManager {
    coordinator: Arc<CoordinatorEngine>,
    agents: Arc<RwLock<HashMap<String, FleetAgentState>>>,
    actions: Arc<RwLock<Vec<RemoteActionRecord>>>,
    running: Arc<AtomicBool>,
    started_at: Arc<DateTime<Utc>>,
    total_actions: Arc<AtomicU64>,
    event_tx: broadcast::Sender<FleetEvent>,
}

#[allow(dead_code)]
struct FleetAgentState {
    info: FleetAgentInfo,
    last_health: Option<SystemHealth>,
    last_telemetry: Option<TelemetryStatus>,
}

#[derive(Debug, Clone)]
pub enum FleetEvent {
    AgentRegistered(String),
    AgentHeartbeat(String),
    ActionRequested(String),
    ActionCompleted(String),
}

impl FleetManager {
    pub fn new(coordinator: Arc<CoordinatorEngine>) -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            coordinator,
            agents: Arc::new(RwLock::new(HashMap::new())),
            actions: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            started_at: Arc::new(Utc::now()),
            total_actions: Arc::new(AtomicU64::new(0)),
            event_tx,
        }
    }

    pub async fn start(&self) {
        self.running.store(true, Ordering::Relaxed);
        self.coordinator.start().await;
        info!("Fleet manager started");
    }

    pub async fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.coordinator.stop().await;
        info!("Fleet manager stopped");
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
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
        self.coordinator
            .register_agent(
                agent_id.clone(),
                hostname.clone(),
                version.clone(),
                kernel.clone(),
                distribution.clone(),
                architecture.clone(),
            )
            .await?;

        let info = FleetAgentInfo {
            agent_id: agent_id.clone(),
            hostname,
            status: "healthy".to_string(),
            version,
            kernel,
            distribution,
            architecture,
            registered_at: Utc::now(),
            last_heartbeat: None,
            uptime_secs: 0,
            health: None,
            telemetry: None,
            detection: None,
        };

        self.agents.write().await.insert(
            agent_id.clone(),
            FleetAgentState {
                info,
                last_health: None,
                last_telemetry: None,
            },
        );

        let _ = self.event_tx.send(FleetEvent::AgentRegistered(agent_id));
        Ok(())
    }

    pub async fn unregister_agent(&self, agent_id: &str) {
        self.coordinator.unregister_agent(agent_id).await;
        self.agents.write().await.remove(agent_id);
    }

    pub async fn process_heartbeat(&self, heartbeat: HeartbeatPayload) {
        let agent_id = heartbeat.agent_id.clone();

        let hb_record = HeartbeatRecord {
            agent_id: agent_id.clone(),
            timestamp: heartbeat.timestamp,
            cpu_percent: heartbeat.health.cpu_percent,
            memory_used_bytes: heartbeat.health.memory_used_bytes,
            memory_total_bytes: heartbeat.health.memory_total_bytes,
            disk_used_bytes: heartbeat.health.disk_used_bytes,
            disk_total_bytes: heartbeat.health.disk_total_bytes,
            load_avg_1: heartbeat.health.load_avg_1,
            active_telemetry_providers: heartbeat.telemetry_status.active_providers,
            total_events: heartbeat.telemetry_status.total_events,
            total_threats: heartbeat.detection_stats.total_threats,
            total_incidents: heartbeat.detection_stats.total_incidents,
        };

        self.coordinator.receive_heartbeat(hb_record).await;

        if let Some(state) = self.agents.write().await.get_mut(&agent_id) {
            state.info.last_heartbeat = Some(heartbeat.timestamp);
            state.info.health = Some(heartbeat.health);
            state.info.telemetry = Some(heartbeat.telemetry_status);
            state.info.detection = Some(heartbeat.detection_stats);
        }

        let _ = self.event_tx.send(FleetEvent::AgentHeartbeat(agent_id));
    }

    pub async fn request_action(
        &self,
        agent_id: String,
        action_type: RemoteActionType,
        params: serde_json::Value,
    ) -> Result<String, String> {
        let action_id = uuid::Uuid::new_v4().to_string();

        let record = RemoteActionRecord {
            action_id: action_id.clone(),
            agent_id: agent_id.clone(),
            action_type: format!("{:?}", action_type),
            params,
            status: "pending".to_string(),
            result: None,
            error: None,
            created_at: Utc::now(),
            completed_at: None,
            duration_ms: None,
        };

        self.actions.write().await.push(record);
        self.total_actions.fetch_add(1, Ordering::Relaxed);

        let _ = self
            .event_tx
            .send(FleetEvent::ActionRequested(action_id.clone()));

        Ok(action_id)
    }

    pub async fn complete_action(
        &self,
        action_id: &str,
        success: bool,
        result: serde_json::Value,
        error: Option<String>,
        duration_ms: u64,
    ) {
        for action in self.actions.write().await.iter_mut() {
            if action.action_id == action_id {
                action.status = if success {
                    "completed".to_string()
                } else {
                    "failed".to_string()
                };
                action.result = Some(result);
                action.error = error;
                action.completed_at = Some(Utc::now());
                action.duration_ms = Some(duration_ms);
                break;
            }
        }

        let _ = self
            .event_tx
            .send(FleetEvent::ActionCompleted(action_id.to_string()));
    }

    pub async fn overview(&self) -> FleetOverview {
        let stats = self.coordinator.stats().await;
        let policies = self.coordinator.policies().await;
        let actions = self.actions.read().await;
        let uptime = Utc::now()
            .signed_duration_since(*self.started_at)
            .num_seconds()
            .max(0) as u64;

        FleetOverview {
            total_agents: stats.total_agents,
            healthy_agents: stats.healthy_agents,
            degraded_agents: stats.degraded_agents,
            offline_agents: stats.offline_agents,
            total_heartbeats: stats.total_heartbeats,
            total_incidents: stats.total_incidents_aggregated,
            total_threats: stats.total_threats_aggregated,
            total_policies: policies.len(),
            total_actions: actions.len() as u64,
            uptime_secs: uptime,
        }
    }

    pub async fn agent_list(&self) -> Vec<FleetAgentInfo> {
        self.agents
            .read()
            .await
            .values()
            .map(|s| s.info.clone())
            .collect()
    }

    pub async fn agent_info(&self, agent_id: &str) -> Option<FleetAgentInfo> {
        self.agents
            .read()
            .await
            .get(agent_id)
            .map(|s| s.info.clone())
    }

    pub async fn action_list(&self, limit: usize) -> Vec<RemoteActionRecord> {
        self.actions
            .read()
            .await
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    pub async fn policy_list(&self) -> Vec<PolicyRecord> {
        self.coordinator.policies().await
    }

    pub async fn distribute_policy(
        &self,
        name: String,
        policy_type: String,
        config: serde_json::Value,
    ) -> Result<String, String> {
        self.coordinator
            .distribute_policy(name, policy_type, config)
            .await
    }

    pub fn subscribe(&self) -> broadcast::Receiver<FleetEvent> {
        self.event_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    async fn create_test_fleet() -> FleetManager {
        let (tx, _rx) = mpsc::channel(10);
        let coordinator = Arc::new(CoordinatorEngine::new(CoordinatorConfig::default(), tx));
        FleetManager::new(coordinator)
    }

    #[tokio::test]
    async fn fleet_creation() {
        let fleet = create_test_fleet().await;
        assert!(!fleet.is_running());
    }

    #[tokio::test]
    async fn fleet_start_stop() {
        let fleet = create_test_fleet().await;
        fleet.start().await;
        assert!(fleet.is_running());
        fleet.stop().await;
        assert!(!fleet.is_running());
    }

    #[tokio::test]
    async fn register_and_list_agents() {
        let fleet = create_test_fleet().await;
        fleet.start().await;

        fleet
            .register_agent(
                "a1".to_string(),
                "host-1".to_string(),
                "1.0.0".to_string(),
                "6.1.0".to_string(),
                "Ubuntu 22.04".to_string(),
                "x86_64".to_string(),
            )
            .await
            .unwrap();

        let agents = fleet.agent_list().await;
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].hostname, "host-1");
    }

    #[tokio::test]
    async fn overview_after_registration() {
        let fleet = create_test_fleet().await;
        fleet.start().await;

        for i in 0..3 {
            fleet
                .register_agent(
                    format!("a{}", i),
                    format!("h{}", i),
                    "1.0".to_string(),
                    "k".to_string(),
                    "d".to_string(),
                    "x86_64".to_string(),
                )
                .await
                .unwrap();
        }

        let overview = fleet.overview().await;
        assert_eq!(overview.total_agents, 3);
        assert_eq!(overview.healthy_agents, 3);
    }

    #[tokio::test]
    async fn process_heartbeat_updates_agent() {
        let fleet = create_test_fleet().await;
        fleet.start().await;

        fleet
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

        let hb = HeartbeatPayload {
            agent_id: "a1".to_string(),
            hostname: "h".to_string(),
            timestamp: Utc::now(),
            health: SystemHealth {
                cpu_percent: 50.0,
                memory_used_bytes: 2048,
                memory_total_bytes: 8192,
                disk_used_bytes: 0,
                disk_total_bytes: 0,
                load_avg_1: 1.0,
                load_avg_5: 0.8,
                load_avg_15: 0.5,
            },
            telemetry_status: TelemetryStatus {
                active_providers: 4,
                total_events: 500,
                dropped_events: 0,
                provider_statuses: vec![],
            },
            detection_stats: DetectionStats {
                total_threats: 10,
                total_incidents: 2,
                total_scans: 25,
                last_scan_at: None,
            },
        };

        fleet.process_heartbeat(hb).await;

        let agent = fleet.agent_info("a1").await.unwrap();
        assert!(agent.health.is_some());
        assert_eq!(agent.health.unwrap().cpu_percent, 50.0);
    }

    #[tokio::test]
    async fn request_and_complete_action() {
        let fleet = create_test_fleet().await;
        fleet.start().await;

        let action_id = fleet
            .request_action(
                "a1".to_string(),
                RemoteActionType::KillProcess,
                serde_json::json!({"pid": 1234}),
            )
            .await
            .unwrap();

        assert!(!action_id.is_empty());

        fleet
            .complete_action(
                &action_id,
                true,
                serde_json::json!({"status": "killed"}),
                None,
                150,
            )
            .await;

        let actions = fleet.action_list(10).await;
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].status, "completed");
    }

    #[tokio::test]
    async fn distribute_policy() {
        let fleet = create_test_fleet().await;
        fleet.start().await;

        fleet
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

        let policy_id = fleet
            .distribute_policy(
                "rate-limit".to_string(),
                "telemetry".to_string(),
                serde_json::json!({"max_rate": 500}),
            )
            .await
            .unwrap();

        assert!(!policy_id.is_empty());
        let policies = fleet.policy_list().await;
        assert_eq!(policies.len(), 1);
    }

    #[tokio::test]
    async fn fleet_overview_uptime() {
        let fleet = create_test_fleet().await;
        fleet.start().await;
        let overview = fleet.overview().await;
        assert!(overview.uptime_secs < 5);
    }

    #[tokio::test]
    async fn action_list_limited() {
        let fleet = create_test_fleet().await;
        fleet.start().await;

        for i in 0..10 {
            fleet
                .request_action(
                    "a1".to_string(),
                    RemoteActionType::RunScan,
                    serde_json::json!({"scan_id": i}),
                )
                .await
                .unwrap();
        }

        let actions = fleet.action_list(5).await;
        assert_eq!(actions.len(), 5);
    }

    #[tokio::test]
    async fn unregister_agent_removes_from_fleet() {
        let fleet = create_test_fleet().await;
        fleet.start().await;

        fleet
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

        assert_eq!(fleet.agent_list().await.len(), 1);
        fleet.unregister_agent("a1").await;
        assert_eq!(fleet.agent_list().await.len(), 0);
    }
}
