use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BehaviorState {
    Created,
    Running,
    Suspended,
    SyscallHooked,
    IntegrityViolation,
    PrivilegeEscalated,
    PersistenceInstalled,
    NetworkActive,
    MemoryModified,
    ModuleLoaded,
    Terminated,
}

impl BehaviorState {
    pub fn as_str(&self) -> &'static str {
        match self {
            BehaviorState::Created => "created",
            BehaviorState::Running => "running",
            BehaviorState::Suspended => "suspended",
            BehaviorState::SyscallHooked => "syscall_hooked",
            BehaviorState::IntegrityViolation => "integrity_violation",
            BehaviorState::PrivilegeEscalated => "privilege_escalated",
            BehaviorState::PersistenceInstalled => "persistence_installed",
            BehaviorState::NetworkActive => "network_active",
            BehaviorState::MemoryModified => "memory_modified",
            BehaviorState::ModuleLoaded => "module_loaded",
            BehaviorState::Terminated => "terminated",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from: BehaviorState,
    pub to: BehaviorState,
    pub timestamp: DateTime<Utc>,
    pub trigger: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBehavior {
    pub pid: u32,
    pub name: String,
    pub current_state: BehaviorState,
    pub transitions: VecDeque<StateTransition>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub risk_score: f64,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalousPattern {
    pub pid: u32,
    pub process_name: String,
    pub pattern_type: String,
    pub description: String,
    pub severity: String,
    pub transition_path: Vec<BehaviorState>,
}

const MAX_TRANSITIONS_PER_PROCESS: usize = 500;

pub struct BehaviorGraph {
    processes: HashMap<u32, ProcessBehavior>,
    transition_rules: Vec<TransitionRule>,
    transition_risk_map: HashMap<(BehaviorState, BehaviorState), f64>,
}

#[derive(Debug, Clone)]
pub struct TransitionRule {
    pub from: BehaviorState,
    pub to: BehaviorState,
    pub risk_delta: f64,
    pub description: String,
}

impl BehaviorGraph {
    pub fn new() -> Self {
        let mut graph = Self {
            processes: HashMap::new(),
            transition_rules: Vec::new(),
            transition_risk_map: HashMap::new(),
        };
        graph.add_default_rules();
        graph
    }

    fn add_default_rules(&mut self) {
        let rules = vec![
            TransitionRule {
                from: BehaviorState::Running,
                to: BehaviorState::SyscallHooked,
                risk_delta: 0.3,
                description: "Syscall hooked from running state".to_string(),
            },
            TransitionRule {
                from: BehaviorState::SyscallHooked,
                to: BehaviorState::IntegrityViolation,
                risk_delta: 0.4,
                description: "Integrity violation after syscall hook".to_string(),
            },
            TransitionRule {
                from: BehaviorState::Running,
                to: BehaviorState::PrivilegeEscalated,
                risk_delta: 0.5,
                description: "Privilege escalation detected".to_string(),
            },
            TransitionRule {
                from: BehaviorState::PrivilegeEscalated,
                to: BehaviorState::PersistenceInstalled,
                risk_delta: 0.4,
                description: "Persistence after privilege escalation".to_string(),
            },
            TransitionRule {
                from: BehaviorState::Running,
                to: BehaviorState::MemoryModified,
                risk_delta: 0.3,
                description: "Memory modification detected".to_string(),
            },
            TransitionRule {
                from: BehaviorState::MemoryModified,
                to: BehaviorState::IntegrityViolation,
                risk_delta: 0.3,
                description: "Integrity violation after memory modification".to_string(),
            },
            TransitionRule {
                from: BehaviorState::Running,
                to: BehaviorState::NetworkActive,
                risk_delta: 0.1,
                description: "Network activity started".to_string(),
            },
            TransitionRule {
                from: BehaviorState::IntegrityViolation,
                to: BehaviorState::NetworkActive,
                risk_delta: 0.3,
                description: "Network activity after integrity violation".to_string(),
            },
        ];

        for rule in &rules {
            self.transition_risk_map
                .insert((rule.from.clone(), rule.to.clone()), rule.risk_delta);
        }
        self.transition_rules = rules;
    }

    pub fn observe_process(&mut self, pid: u32, name: &str) {
        use std::collections::hash_map::Entry;
        if let Entry::Vacant(e) = self.processes.entry(pid) {
            let now = Utc::now();
            let mut transitions = VecDeque::new();
            transitions.push_back(StateTransition {
                from: BehaviorState::Created,
                to: BehaviorState::Running,
                timestamp: now,
                trigger: "process_started".to_string(),
                metadata: serde_json::json!({}),
            });
            e.insert(ProcessBehavior {
                pid,
                name: name.to_string(),
                current_state: BehaviorState::Running,
                transitions,
                first_seen: now,
                last_seen: now,
                risk_score: 0.0,
                tags: Vec::new(),
            });
        }
    }

    pub fn transition(
        &mut self,
        pid: u32,
        to_state: BehaviorState,
        trigger: &str,
        metadata: serde_json::Value,
    ) -> bool {
        if let Some(process) = self.processes.get_mut(&pid) {
            let from = process.current_state.clone();
            let now = Utc::now();

            let risk_delta = self
                .transition_risk_map
                .get(&(from.clone(), to_state.clone()))
                .copied()
                .unwrap_or(0.1);

            process.risk_score = (process.risk_score + risk_delta).min(1.0);
            process.current_state = to_state.clone();
            process.last_seen = now;

            process.transitions.push_back(StateTransition {
                from,
                to: to_state,
                timestamp: now,
                trigger: trigger.to_string(),
                metadata,
            });

            if process.transitions.len() > MAX_TRANSITIONS_PER_PROCESS {
                process.transitions.pop_front();
            }

            true
        } else {
            false
        }
    }

    pub fn get_process(&self, pid: u32) -> Option<&ProcessBehavior> {
        self.processes.get(&pid)
    }

    pub fn all_processes(&self) -> Vec<&ProcessBehavior> {
        self.processes.values().collect()
    }

    pub fn detect_anomalies(&self) -> Vec<AnomalousPattern> {
        let mut anomalies = Vec::new();

        for process in self.processes.values() {
            if process.risk_score >= 0.7 {
                let path: Vec<BehaviorState> =
                    process.transitions.iter().map(|t| t.to.clone()).collect();

                anomalies.push(AnomalousPattern {
                    pid: process.pid,
                    process_name: process.name.clone(),
                    pattern_type: "high_risk_score".to_string(),
                    description: format!(
                        "Process {} has risk score {:.2}",
                        process.name, process.risk_score
                    ),
                    severity: if process.risk_score >= 0.9 {
                        "critical".to_string()
                    } else {
                        "high".to_string()
                    },
                    transition_path: path,
                });
            }

            if let Some(anomaly) = self.check_escalation_chain(process) {
                anomalies.push(anomaly);
            }

            if let Some(anomaly) = self.check_rapid_state_changes(process) {
                anomalies.push(anomaly);
            }
        }

        anomalies
    }

    fn check_escalation_chain(&self, process: &ProcessBehavior) -> Option<AnomalousPattern> {
        let mut has_hook = false;
        let mut has_integrity = false;
        let mut has_persistence = false;

        for t in &process.transitions {
            match t.to {
                BehaviorState::SyscallHooked => has_hook = true,
                BehaviorState::IntegrityViolation => has_integrity = true,
                BehaviorState::PersistenceInstalled => has_persistence = true,
                _ => {}
            }
            if has_hook && has_integrity && has_persistence {
                break;
            }
        }

        if has_hook && has_integrity && has_persistence {
            Some(AnomalousPattern {
                pid: process.pid,
                process_name: process.name.clone(),
                pattern_type: "full_escalation_chain".to_string(),
                description: format!(
                    "Process {} completed full attack chain: hook → integrity → persistence",
                    process.name
                ),
                severity: "critical".to_string(),
                transition_path: vec![
                    BehaviorState::SyscallHooked,
                    BehaviorState::IntegrityViolation,
                    BehaviorState::PersistenceInstalled,
                ],
            })
        } else {
            None
        }
    }

    fn check_rapid_state_changes(&self, process: &ProcessBehavior) -> Option<AnomalousPattern> {
        if process.transitions.len() < 3 {
            return None;
        }

        let len = process.transitions.len();
        let t0 = &process.transitions[len - 3];
        let t1 = &process.transitions[len - 2];
        let t2 = &process.transitions[len - 1];

        let span = t2.timestamp - t0.timestamp;
        if span <= chrono::Duration::seconds(5) {
            let states: Vec<BehaviorState> = vec![t0.to.clone(), t1.to.clone(), t2.to.clone()];
            return Some(AnomalousPattern {
                pid: process.pid,
                process_name: process.name.clone(),
                pattern_type: "rapid_state_change".to_string(),
                description: format!(
                    "Process {} changed state {} times in 5 seconds",
                    process.name, 3
                ),
                severity: "medium".to_string(),
                transition_path: states,
            });
        }

        None
    }

    pub fn remove_process(&mut self, pid: u32) -> Option<ProcessBehavior> {
        self.processes.remove(&pid)
    }

    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    pub fn high_risk_processes(&self) -> Vec<&ProcessBehavior> {
        self.processes
            .values()
            .filter(|p| p.risk_score >= 0.5)
            .collect()
    }
}

impl Default for BehaviorGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_graph() {
        let graph = BehaviorGraph::new();
        assert_eq!(graph.process_count(), 0);
        assert!(!graph.transition_rules.is_empty());
    }

    #[test]
    fn test_observe_process() {
        let mut graph = BehaviorGraph::new();
        graph.observe_process(100, "bash");
        assert_eq!(graph.process_count(), 1);

        let proc = graph.get_process(100).unwrap();
        assert_eq!(proc.name, "bash");
        assert_eq!(proc.current_state, BehaviorState::Running);
        assert_eq!(proc.transitions.len(), 1);
    }

    #[test]
    fn test_transition() {
        let mut graph = BehaviorGraph::new();
        graph.observe_process(100, "malware");

        let result = graph.transition(
            100,
            BehaviorState::SyscallHooked,
            "sys_call_hook",
            serde_json::json!({"syscall": "open"}),
        );
        assert!(result);

        let proc = graph.get_process(100).unwrap();
        assert_eq!(proc.current_state, BehaviorState::SyscallHooked);
        assert!(proc.risk_score > 0.0);
        assert_eq!(proc.transitions.len(), 2);
    }

    #[test]
    fn test_transition_nonexistent() {
        let mut graph = BehaviorGraph::new();
        let result = graph.transition(999, BehaviorState::Running, "test", serde_json::json!({}));
        assert!(!result);
    }

    #[test]
    fn test_risk_accumulation() {
        let mut graph = BehaviorGraph::new();
        graph.observe_process(100, "evil");

        graph.transition(
            100,
            BehaviorState::SyscallHooked,
            "hook",
            serde_json::json!({}),
        );
        let score_after_hook = graph.get_process(100).unwrap().risk_score;

        graph.transition(
            100,
            BehaviorState::IntegrityViolation,
            "violation",
            serde_json::json!({}),
        );
        let score_after_violation = graph.get_process(100).unwrap().risk_score;

        assert!(score_after_violation > score_after_hook);
    }

    #[test]
    fn test_anomaly_high_risk() {
        let mut graph = BehaviorGraph::new();
        graph.observe_process(100, "rootkit");

        for _ in 0..10 {
            graph.transition(
                100,
                BehaviorState::IntegrityViolation,
                "violation",
                serde_json::json!({}),
            );
        }

        let anomalies = graph.detect_anomalies();
        assert!(!anomalies.is_empty());
        assert_eq!(anomalies[0].pattern_type, "high_risk_score");
    }

    #[test]
    fn test_anomaly_escalation_chain() {
        let mut graph = BehaviorGraph::new();
        graph.observe_process(100, "apt_agent");

        graph.transition(
            100,
            BehaviorState::SyscallHooked,
            "hook",
            serde_json::json!({}),
        );
        graph.transition(
            100,
            BehaviorState::IntegrityViolation,
            "violation",
            serde_json::json!({}),
        );
        graph.transition(
            100,
            BehaviorState::PersistenceInstalled,
            "persist",
            serde_json::json!({}),
        );

        let anomalies = graph.detect_anomalies();
        let chain: Vec<&AnomalousPattern> = anomalies
            .iter()
            .filter(|a| a.pattern_type == "full_escalation_chain")
            .collect();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].severity, "critical");
    }

    #[test]
    fn test_high_risk_processes() {
        let mut graph = BehaviorGraph::new();

        graph.observe_process(1, "good");
        graph.observe_process(2, "bad");

        for _ in 0..5 {
            graph.transition(
                2,
                BehaviorState::IntegrityViolation,
                "v",
                serde_json::json!({}),
            );
        }

        let high_risk = graph.high_risk_processes();
        assert_eq!(high_risk.len(), 1);
        assert_eq!(high_risk[0].pid, 2);
    }

    #[test]
    fn test_remove_process() {
        let mut graph = BehaviorGraph::new();
        graph.observe_process(100, "temp");
        assert_eq!(graph.process_count(), 1);

        let removed = graph.remove_process(100);
        assert!(removed.is_some());
        assert_eq!(graph.process_count(), 0);
    }

    #[test]
    fn test_all_processes() {
        let mut graph = BehaviorGraph::new();
        graph.observe_process(1, "a");
        graph.observe_process(2, "b");
        assert_eq!(graph.all_processes().len(), 2);
    }
}
