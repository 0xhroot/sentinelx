use crate::commands::{BOLD, CYAN, GREEN, RED, RESET, YELLOW};

pub async fn run() {
    println!("{}{}SentinelX Threat Decisions{}", BOLD, CYAN, RESET);
    println!();

    let engine = sentinelx_threat::ThreatEngine::new();
    let decisions = engine.list_decisions().await;
    let count = engine.count().await;

    if count == 0 {
        println!(
            "{}No threat decisions recorded.{} Run a full pipeline to evaluate threats from incidents.",
            GREEN, RESET
        );
        return;
    }

    let severity_counts = engine.count_by_severity().await;

    println!("{}Total decisions:{} {}", BOLD, RESET, count);
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

    println!("{}Threat Decisions:{}", BOLD, RESET);
    for (i, decision) in decisions.iter().enumerate() {
        let color = match decision.severity {
            sentinelx_threat::ThreatSeverity::Critical => RED,
            sentinelx_threat::ThreatSeverity::High => YELLOW,
            _ => CYAN,
        };
        println!(
            "{}[{}]{} {}{}{} {} {}({}){}",
            BOLD,
            i + 1,
            RESET,
            color,
            decision.severity.as_str(),
            RESET,
            BOLD,
            &decision.description[..decision.description.len().min(80)],
            decision.priority.as_str(),
            RESET
        );
        println!(
            "   {}Risk Score:{:.1}/100   {}Confidence:{:.1}%",
            CYAN,
            decision.risk_score.final_score,
            CYAN,
            decision.confidence * 100.0
        );
        if !decision.recommendation.is_empty() {
            println!(
                "   {}Recommendation:{} {}",
                CYAN,
                RESET,
                &decision.recommendation[..decision.recommendation.len().min(100)]
            );
        }
        if !decision.mitre_mappings.is_empty() {
            for mapping in &decision.mitre_mappings {
                println!(
                    "   {}MITRE:{} {} ({})",
                    MAGENTA, RESET, mapping.technique_name, mapping.technique_id
                );
            }
        }
        println!();
    }

    println!("{}{}Threat engine ready.{}", GREEN, BOLD, RESET);
}

use crate::commands::MAGENTA;
