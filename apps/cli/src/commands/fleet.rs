use std::sync::Arc;

use sentinelx_fleet::{CoordinatorConfig, CoordinatorEngine, FleetManager};
use tokio::sync::mpsc;

use super::{BOLD, CYAN, GREEN, MAGENTA, RED, RESET, YELLOW};

async fn create_fleet_manager() -> FleetManager {
    let (tx, _rx) = mpsc::channel(100);
    let coordinator = Arc::new(CoordinatorEngine::new(CoordinatorConfig::default(), tx));
    FleetManager::new(coordinator)
}

pub async fn run() {
    let fleet = create_fleet_manager().await;
    fleet.start().await;

    let overview = fleet.overview().await;

    println!("{}{}Fleet Management Overview{}", BOLD, CYAN, RESET);
    println!();

    println!(
        "{}Agents:{} {}{}",
        BOLD, RESET, GREEN, overview.total_agents
    );
    println!();

    let healthy_color = if overview.healthy_agents > 0 {
        GREEN
    } else {
        RED
    };
    let degraded_color = if overview.degraded_agents > 0 {
        YELLOW
    } else {
        GREEN
    };
    let offline_color = if overview.offline_agents > 0 {
        RED
    } else {
        GREEN
    };

    println!("{}Health Status:{}", BOLD, MAGENTA);
    println!(
        "  {}Healthy:{}  {}",
        healthy_color, RESET, overview.healthy_agents
    );
    println!(
        "  {}Degraded:{} {}",
        degraded_color, RESET, overview.degraded_agents
    );
    println!(
        "  {}Offline:{}  {}",
        offline_color, RESET, overview.offline_agents
    );
    println!();

    let uptime_h = overview.uptime_secs / 3600;
    let uptime_m = (overview.uptime_secs % 3600) / 60;
    let uptime_s = overview.uptime_secs % 60;

    println!(
        "{}Uptime:{} {}h {}m {}s",
        BOLD, RESET, uptime_h, uptime_m, uptime_s
    );
    println!();

    println!("{}Heartbeats:{} {}", BOLD, RESET, overview.total_heartbeats);
    println!("{}Policies:{} {}", BOLD, RESET, overview.total_policies);
    println!(
        "{}Remote Actions:{} {}",
        BOLD, RESET, overview.total_actions
    );
    println!("{}Incidents:{} {}", BOLD, RESET, overview.total_incidents);
    println!("{}Threats:{} {}", BOLD, RESET, overview.total_threats);
    println!();

    println!("{}Pipeline:{} Fleet Coordinator -> Agent Tracking -> Health Monitoring -> Remote Actions -> Policy Distribution", BOLD, MAGENTA);
    println!();

    fleet.stop().await;
}

pub async fn run_agents() {
    let fleet = create_fleet_manager().await;
    fleet.start().await;

    let agents = fleet.agent_list().await;

    println!("{}{}Fleet Agents{}", BOLD, CYAN, RESET);
    println!("  {}Total:{} {} agents", BOLD, RESET, agents.len());
    println!();

    if agents.is_empty() {
        println!("  {}No agents registered{}", YELLOW, RESET);
        println!();
        fleet.stop().await;
        return;
    }

    for agent in &agents {
        let (status_str, status_color) = match agent.status.as_str() {
            "healthy" => ("healthy", GREEN),
            "degraded" => ("degraded", YELLOW),
            "offline" => ("offline", RED),
            _ => ("unknown", MAGENTA),
        };

        println!(
            "{}{} {}[{}]{} {}{}{}",
            BOLD, agent.agent_id, status_color, status_str, RESET, CYAN, agent.hostname, RESET
        );
        println!(
            "    {}Version:{} {}   {}Kernel:{} {}   {}Arch:{} {}",
            CYAN, RESET, agent.version, CYAN, RESET, agent.kernel, CYAN, RESET, agent.architecture
        );

        if let Some(ref hb) = agent.last_heartbeat {
            println!(
                "    {}Last Heartbeat:{} {}",
                CYAN,
                RESET,
                hb.format("%Y-%m-%d %H:%M:%S UTC")
            );
        } else {
            println!("    {}Last Heartbeat:{} never", CYAN, RESET);
        }
        println!();
    }

    fleet.stop().await;
}

pub async fn run_agent_detail(agent_id: &str) {
    let fleet = create_fleet_manager().await;
    fleet.start().await;

    let info = match fleet.agent_info(agent_id).await {
        Some(info) => info,
        None => {
            println!("{}{}Agent not found: {}{}", BOLD, RED, agent_id, RESET);
            fleet.stop().await;
            return;
        }
    };

    let (status_str, status_color) = match info.status.as_str() {
        "healthy" => ("healthy", GREEN),
        "degraded" => ("degraded", YELLOW),
        "offline" => ("offline", RED),
        _ => ("unknown", MAGENTA),
    };

    println!("{}{}Fleet Agent Detail{}", BOLD, CYAN, RESET);
    println!();

    println!("{}Agent:{} {}", BOLD, RESET, info.agent_id);
    println!(
        "  {}Status:{} {}{}{}",
        CYAN, RESET, status_color, status_str, RESET
    );
    println!("  {}Hostname:{} {}", CYAN, RESET, info.hostname);
    println!("  {}Version:{} {}", CYAN, RESET, info.version);
    println!("  {}Kernel:{} {}", CYAN, RESET, info.kernel);
    println!("  {}Distribution:{} {}", CYAN, RESET, info.distribution);
    println!("  {}Architecture:{} {}", CYAN, RESET, info.architecture);
    println!(
        "  {}Registered:{} {}",
        CYAN,
        RESET,
        info.registered_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    if let Some(ref hb) = info.last_heartbeat {
        println!(
            "  {}Last Heartbeat:{} {}",
            CYAN,
            RESET,
            hb.format("%Y-%m-%d %H:%M:%S UTC")
        );
    } else {
        println!("  {}Last Heartbeat:{} never", CYAN, RESET);
    }

    let uptime_h = info.uptime_secs / 3600;
    let uptime_m = (info.uptime_secs % 3600) / 60;
    let uptime_s = info.uptime_secs % 60;
    println!(
        "  {}Uptime:{} {}h {}m {}s",
        CYAN, RESET, uptime_h, uptime_m, uptime_s
    );
    println!();

    if let Some(ref health) = info.health {
        println!("{}System Health:{} ", BOLD, MAGENTA);
        println!("  {}CPU:{} {:.1}%", CYAN, RESET, health.cpu_percent);
        let mem_used_mb = health.memory_used_bytes / (1024 * 1024);
        let mem_total_mb = health.memory_total_bytes / (1024 * 1024);
        println!(
            "  {}Memory:{} {} MB / {} MB",
            CYAN, RESET, mem_used_mb, mem_total_mb
        );
        println!(
            "  {}Load Avg:{} {:.2} / {:.2} / {:.2}",
            CYAN, RESET, health.load_avg_1, health.load_avg_5, health.load_avg_15
        );
        println!();
    }

    if let Some(ref telemetry) = info.telemetry {
        println!("{}Telemetry:{} ", BOLD, MAGENTA);
        println!(
            "  {}Active Providers:{} {}",
            CYAN, RESET, telemetry.active_providers
        );
        println!(
            "  {}Total Events:{} {}",
            CYAN, RESET, telemetry.total_events
        );
        println!("  {}Dropped:{} {}", CYAN, RESET, telemetry.dropped_events);
        println!();
    }

    if let Some(ref detection) = info.detection {
        println!("{}Detection:{} ", BOLD, MAGENTA);
        println!(
            "  {}Total Threats:{} {}",
            CYAN, RESET, detection.total_threats
        );
        println!(
            "  {}Total Incidents:{} {}",
            CYAN, RESET, detection.total_incidents
        );
        println!("  {}Total Scans:{} {}", CYAN, RESET, detection.total_scans);
        println!();
    }

    fleet.stop().await;
}

pub async fn run_policies() {
    let fleet = create_fleet_manager().await;
    fleet.start().await;

    let policies = fleet.policy_list().await;

    println!("{}{}Distributed Fleet Policies{}", BOLD, CYAN, RESET);
    println!("  {}Total:{} {} policies", BOLD, RESET, policies.len());
    println!();

    if policies.is_empty() {
        println!("  {}No policies distributed{}", YELLOW, RESET);
        println!();
        fleet.stop().await;
        return;
    }

    for policy in &policies {
        println!(
            "{}{} [{}]{} {}{}{} (v{})",
            BOLD,
            policy.policy_id,
            &policy.policy_id[..8],
            RESET,
            GREEN,
            policy.name,
            RESET,
            policy.version
        );
        println!(
            "    {}Type:{} {}   {}Created:{} {}",
            CYAN,
            RESET,
            policy.policy_type,
            CYAN,
            RESET,
            policy.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );

        if policy.distributed_to.is_empty() {
            println!("    {}Distributed:{} not yet sent", CYAN, RESET);
        } else {
            println!(
                "    {}Distributed:{} {} agents",
                CYAN,
                RESET,
                policy.distributed_to.len()
            );
        }
        println!();
    }

    fleet.stop().await;
}

pub async fn run_actions() {
    let fleet = create_fleet_manager().await;
    fleet.start().await;

    let actions = fleet.action_list(20).await;

    println!("{}{}Recent Remote Actions{}", BOLD, CYAN, RESET);
    println!(
        "  {}Total:{} {} actions (showing last 20)",
        BOLD,
        RESET,
        actions.len()
    );
    println!();

    if actions.is_empty() {
        println!("  {}No actions recorded{}", YELLOW, RESET);
        println!();
        fleet.stop().await;
        return;
    }

    for action in &actions {
        let (status_str, status_color) = match action.status.as_str() {
            "completed" => ("completed", GREEN),
            "failed" => ("failed", RED),
            "pending" => ("pending", YELLOW),
            "running" => ("running", CYAN),
            _ => ("unknown", MAGENTA),
        };

        println!(
            "{}{} {}[{}]{} {}{}{} on {}{}{}",
            BOLD,
            action.action_id,
            status_color,
            status_str,
            RESET,
            YELLOW,
            action.action_type,
            RESET,
            CYAN,
            action.agent_id,
            RESET
        );
        println!(
            "    {}Created:{} {}",
            CYAN,
            RESET,
            action.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );

        if let Some(ref completed) = action.completed_at {
            println!(
                "    {}Completed:{} {}",
                CYAN,
                RESET,
                completed.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }

        if let Some(duration) = action.duration_ms {
            println!("    {}Duration:{} {}ms", CYAN, RESET, duration);
        }

        if let Some(ref error) = action.error {
            println!("    {}Error:{} {}{}{}", RED, RESET, RED, error, RESET);
        }

        println!();
    }

    fleet.stop().await;
}
