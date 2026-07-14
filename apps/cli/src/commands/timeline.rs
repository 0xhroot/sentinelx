use crate::commands::{print_separator, severity_color, BOLD, CYAN, GREEN, RESET, YELLOW};
use sentinelx_common::traits::Detector;
use sentinelx_common::types::ThreatEvent;
use sentinelx_timeline::TimelineEngine;

async fn collect_threats() -> Vec<ThreatEvent> {
    let mut all_threats: Vec<ThreatEvent> = Vec::new();

    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(sentinelx_kernel::KernelIntegrityDetector::new()),
        Box::new(sentinelx_kernel::HookDetector::new()),
        Box::new(sentinelx_memory::MemoryIntegrityChecker::new()),
        Box::new(sentinelx_integrity::IntegrityChecker::new()),
        Box::new(sentinelx_persistence::PersistenceScanner::new()),
    ];

    for detector in &detectors {
        if let Ok(threats) = detector.detect().await {
            all_threats.extend(threats);
        }
    }

    all_threats
}

pub async fn run() {
    println!("{}{}Threat Timeline{}", BOLD, CYAN, RESET);
    println!();

    println!("{}Collecting threats...{}", CYAN, RESET);
    let threats = collect_threats().await;

    let mut engine = TimelineEngine::new();
    for threat in threats {
        engine.add_event(threat);
    }
    engine.sort_by_time();

    let entries = engine.get_timeline();

    if entries.is_empty() {
        println!(
            "{}No events in timeline. System appears clean.{}",
            GREEN, RESET
        );
        return;
    }

    println!("{}Timeline ({} events):{}", BOLD, entries.len(), RESET);
    println!();

    for (i, entry) in entries.iter().enumerate() {
        let color = severity_color(&entry.event.severity);
        println!(
            "{}  [{:>3}]{} {} {}{}{} {}",
            CYAN,
            i + 1,
            RESET,
            entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
            color,
            entry.event.severity,
            RESET,
            BOLD,
        );
        println!("        {}{}", entry.event.title, RESET);
        println!(
            "        {}Category:{} {}   {}Source:{} {}",
            CYAN,
            RESET,
            entry.event.category.as_str(),
            CYAN,
            RESET,
            entry.event.source_detector,
        );
        if !entry.related_pids.is_empty() {
            let pids: Vec<String> = entry.related_pids.iter().map(|p| p.to_string()).collect();
            println!("        {}PIDs:{} {}", CYAN, RESET, pids.join(", "));
        }
        println!();
    }

    print_separator();

    let narrative = engine.generate_attack_narrative();
    println!("{}{}Attack Narrative{}", BOLD, CYAN, RESET);
    println!();
    for line in narrative.lines() {
        println!("  {}", line);
    }

    let groups = engine.correlate();
    if !groups.is_empty() {
        println!();
        println!(
            "{}{}Correlated Event Clusters:{} {}",
            BOLD,
            CYAN,
            RESET,
            groups.len()
        );
        for (i, group) in groups.iter().enumerate() {
            println!(
                "  {}Cluster {}:{} {} events",
                YELLOW,
                i + 1,
                RESET,
                group.len()
            );
        }
    }
}
