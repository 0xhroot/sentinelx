use sentinelx_behavior::engine::BehaviorEngine;
use sentinelx_behavior::types::{BehaviorCategory, BehaviorRuleConfig};

use super::{BOLD, CYAN, GREEN, MAGENTA, RED, RESET, YELLOW};

pub async fn run() {
    println!("{}{}Behavioral Analysis Engine{}", BOLD, CYAN, RESET);
    println!();

    let engine = BehaviorEngine::new();

    let config = BehaviorRuleConfig::load_default();
    println!("{}Status:{}", BOLD, GREEN);
    println!("  Engine initialized with default rules");
    println!(
        "  {}Active rules:{} {}",
        BOLD,
        RESET,
        config.enabled_rules().len()
    );
    println!("  {}Total rules:{} {}", BOLD, RESET, config.rules.len());
    println!();

    println!("{}Default Behavioral Rules:{}", BOLD, MAGENTA);
    for rule in config.enabled_rules() {
        let severity_color = match rule.severity.as_str() {
            "critical" => RED,
            "high" => YELLOW,
            "medium" => MAGENTA,
            _ => GREEN,
        };
        println!(
            "  {}[{}]{} {}{}{} - {}",
            BOLD, rule.severity, RESET, severity_color, rule.name, RESET, rule.description
        );
        if !rule.mitre_techniques.is_empty() {
            println!(
                "    {}MITRE:{} {}",
                MAGENTA,
                RESET,
                rule.mitre_techniques.join(", ")
            );
        }
    }
    println!();

    let counts = engine.count_by_severity().await;
    println!("{}Profile Statistics:{}", BOLD, MAGENTA);
    if counts.is_empty() {
        println!("  No behavioral profiles recorded yet");
    } else {
        for (severity, count) in &counts {
            println!("  {}{}:{} {}", YELLOW, severity, RESET, count);
        }
    }
    println!();

    println!("{}Behavioral Categories:{}", BOLD, MAGENTA);
    let categories = [
        (
            BehaviorCategory::ProcessAncestry,
            "Process ancestry analysis",
        ),
        (
            BehaviorCategory::ProcessLifetime,
            "Process lifetime tracking",
        ),
        (
            BehaviorCategory::ExecFrequency,
            "Execution frequency monitoring",
        ),
        (
            BehaviorCategory::NetworkActivity,
            "Network activity correlation",
        ),
        (
            BehaviorCategory::FileModifications,
            "File modification tracking",
        ),
        (
            BehaviorCategory::PersistenceCreation,
            "Persistence mechanism detection",
        ),
        (
            BehaviorCategory::PrivilegeEscalation,
            "Privilege escalation monitoring",
        ),
        (
            BehaviorCategory::ModuleLoading,
            "Kernel module loading analysis",
        ),
        (BehaviorCategory::MemoryUsage, "Memory usage anomalies"),
        (
            BehaviorCategory::CapabilityChanges,
            "Linux capability changes",
        ),
        (
            BehaviorCategory::SuspiciousActions,
            "Suspicious action correlation",
        ),
    ];
    for (cat, desc) in &categories {
        println!("  {}{}{} - {}", CYAN, cat.as_str(), RESET, desc);
    }
    println!();

    println!("{}Pipeline Integration:{}", BOLD, MAGENTA);
    println!("  Telemetry Events -> BehaviorEngine.record_event() -> Profile Build -> Rule Evaluation -> Scoring -> Alert/Investigate");
    println!();
}

pub async fn run_profiles() {
    println!("{}{}Behavioral Profiles{}", BOLD, CYAN, RESET);
    println!();

    let engine = BehaviorEngine::new();
    let profiles = engine.list_profiles().await;

    if profiles.is_empty() {
        println!("  {}No behavioral profiles recorded yet{}", YELLOW, RESET);
        println!();
        println!("  Profiles are built from telemetry events as they are recorded.");
        println!("  Run a scan first to generate behavioral data.");
        return;
    }

    let counts = engine.count_by_severity().await;
    println!("{}Total Profiles:{} {}", BOLD, RESET, profiles.len());
    for (severity, count) in &counts {
        println!("  {}{}:{} {}", YELLOW, severity, RESET, count);
    }
    println!();

    for (i, profile) in profiles.iter().enumerate() {
        let score = engine.evaluate_object(&profile.object_id).await;
        let severity_color = match score.as_ref().map(|s| s.severity.as_str()) {
            Some("critical") => RED,
            Some("high") => YELLOW,
            Some("medium") => MAGENTA,
            _ => GREEN,
        };

        println!(
            "{}[{}]{} {}{}{} {}",
            BOLD,
            i + 1,
            RESET,
            severity_color,
            profile.object_id,
            RESET,
            BOLD,
        );
        println!(
            "  {}Executions:{} {}   {}Connections:{} {}   {}Privilege:{} {}",
            CYAN,
            RESET,
            profile.execution_count,
            CYAN,
            RESET,
            profile.connection_count,
            CYAN,
            RESET,
            profile.privilege_changes,
        );
        if let Some(s) = &score {
            println!(
                "  {}Severity:{} {}   {}Score:{} {:.1}",
                CYAN, RESET, s.severity, CYAN, RESET, s.final_score
            );
        }
        println!(
            "  {}First seen:{} {}   {}Last seen:{} {}",
            CYAN,
            RESET,
            profile.first_seen.format("%Y-%m-%d %H:%M"),
            CYAN,
            RESET,
            profile.last_seen.format("%Y-%m-%d %H:%M"),
        );
        println!();
    }
}

pub async fn run_stats() {
    println!("{}{}Behavior Statistics{}", BOLD, CYAN, RESET);
    println!();

    let engine = BehaviorEngine::new();
    let counts = engine.count_by_severity().await;
    let profiles = engine.list_profiles().await;
    let config = BehaviorRuleConfig::load_default();

    println!("{}Profile Summary:{}", BOLD, MAGENTA);
    println!("  {}Total:{} {}", BOLD, RESET, profiles.len());
    for (severity, count) in &counts {
        println!("  {}{}:{} {}", YELLOW, severity, RESET, count);
    }
    println!();

    println!("{}Rule Configuration:{}", BOLD, MAGENTA);
    println!("  {}Total rules:{} {}", BOLD, RESET, config.rules.len());
    println!(
        "  {}Enabled:{} {}",
        BOLD,
        RESET,
        config.enabled_rules().len()
    );
    println!();

    println!("{}Severity Weights (Scoring):{}", BOLD, MAGENTA);
    println!("  frequency_score:     15%");
    println!("  recurrence_score:    20%");
    println!("  escalation_score:    25%");
    println!("  novelty_score:       10%");
    println!("  persistence_score:   15%");
    println!("  correlation_score:    5%");
    println!("  assessment_score:    10%");
    println!();
}
