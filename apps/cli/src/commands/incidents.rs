use crate::commands::{BOLD, CYAN, GREEN, RED, RESET, YELLOW};

pub async fn run() {
    println!("{}{}SentinelX Incidents{}", BOLD, CYAN, RESET);
    println!();

    let engine = sentinelx_incident::IncidentEngine::new();
    let count = engine.count().await;

    if count == 0 {
        println!(
            "{}No incidents recorded.{} Run a full scan to generate incidents from correlated evidence.",
            GREEN, RESET
        );
        return;
    }

    let status_counts = engine.count_by_status().await;
    let severity_counts = engine.count_by_severity().await;

    println!("{}Total incidents:{} {}", BOLD, RESET, count);
    println!();

    println!("{}By Status:{}", BOLD, RESET);
    for (status, cnt) in &status_counts {
        println!("  {} {}:{}  {}", CYAN, status, RESET, cnt);
    }
    println!();

    println!("{}By Severity:{}", BOLD, RESET);
    for (severity, cnt) in &severity_counts {
        let color = match severity.as_str() {
            "critical" => RED,
            "high" => YELLOW,
            _ => CYAN,
        };
        println!("  {}{}:{}  {}", color, severity, RESET, cnt);
    }
    println!();

    println!("{}Active Incidents:{}", BOLD, RESET);
    let active = engine.active_incidents().await;
    for (i, incident) in active.iter().enumerate() {
        let color = match incident.severity {
            sentinelx_incident::IncidentSeverity::Critical => RED,
            sentinelx_incident::IncidentSeverity::High => YELLOW,
            _ => CYAN,
        };
        println!(
            "{}[{}]{} {}{}{} {} {}({}){}",
            BOLD,
            i + 1,
            RESET,
            color,
            incident.severity.as_str(),
            RESET,
            BOLD,
            incident.title,
            incident.status.as_str(),
            RESET
        );
        println!("   {}", incident.description);
        println!(
            "   {}ID:{} {}   {}Created:{} {}",
            CYAN,
            RESET,
            &incident.id.to_string()[..8],
            CYAN,
            RESET,
            incident.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        if !incident.evidence_ids.is_empty() {
            println!(
                "   {}Evidence:{} {} items",
                CYAN,
                RESET,
                incident.evidence_ids.len()
            );
        }
        if !incident.attack_chain.is_empty() {
            println!(
                "   {}Attack Chain:{} {} steps",
                CYAN,
                RESET,
                incident.attack_chain.len()
            );
        }
        if !incident.mitre_mappings.is_empty() {
            for mapping in &incident.mitre_mappings {
                println!(
                    "   {}MITRE:{} {} ({})",
                    CYAN, RESET, mapping.technique_name, mapping.technique_id
                );
            }
        }
        println!();
    }

    println!("{}{}Incident engine ready.{}", GREEN, BOLD, RESET);
}
