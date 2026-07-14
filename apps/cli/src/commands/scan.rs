use crate::commands::{print_separator, print_threat, BLUE, BOLD, CYAN, GREEN, RED, RESET, YELLOW};
use sentinelx_common::traits::Detector;
use sentinelx_common::types::ThreatEvent;

async fn run_all_detectors() -> Vec<ThreatEvent> {
    let mut all_threats: Vec<ThreatEvent> = Vec::new();

    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(sentinelx_kernel::KernelIntegrityDetector::new()),
        Box::new(sentinelx_kernel::HookDetector::new()),
        Box::new(sentinelx_memory::MemoryIntegrityChecker::new()),
        Box::new(sentinelx_integrity::IntegrityChecker::new()),
        Box::new(sentinelx_persistence::PersistenceScanner::new()),
    ];

    for detector in &detectors {
        let name = detector.name().to_string();
        match detector.detect().await {
            Ok(threats) => {
                all_threats.extend(threats);
            }
            Err(e) => {
                eprintln!(
                    "{}{}[!]{} Detector '{}' failed: {}",
                    YELLOW, BOLD, RESET, name, e
                );
            }
        }
    }

    all_threats.sort_by_key(|b| std::cmp::Reverse(b.severity));
    all_threats
}

pub async fn run() {
    println!("{}{}SentinelX Detection Scan{}", BOLD, CYAN, RESET);
    println!();
    println!("Running all detectors...");
    println!();

    let start = std::time::Instant::now();
    let threats = run_all_detectors().await;
    let elapsed = start.elapsed();

    print_separator();

    if threats.is_empty() {
        println!(
            "{}{}[OK]{} No threats detected. System appears clean.",
            GREEN, BOLD, RESET
        );
    } else {
        let critical = threats
            .iter()
            .filter(|t| t.severity == sentinelx_common::Severity::Critical)
            .count();
        let high = threats
            .iter()
            .filter(|t| t.severity == sentinelx_common::Severity::High)
            .count();
        let medium = threats
            .iter()
            .filter(|t| t.severity == sentinelx_common::Severity::Medium)
            .count();
        let low = threats
            .iter()
            .filter(|t| t.severity == sentinelx_common::Severity::Low)
            .count();

        let mut parts: Vec<String> = Vec::new();
        if critical > 0 {
            parts.push(format!("{}{}{} critical", RED, critical, RESET));
        }
        if high > 0 {
            parts.push(format!("{}{}{} high", YELLOW, high, RESET));
        }
        if medium > 0 {
            parts.push(format!("{}{}{} medium", CYAN, medium, RESET));
        }
        if low > 0 {
            parts.push(format!("{}{} low", BLUE, low));
        }
        let summary = if parts.is_empty() {
            format!("{} threats", threats.len())
        } else {
            parts.join(", ")
        };

        println!(
            "{}{}[!] {} threats detected: {}{}",
            RED,
            BOLD,
            threats.len(),
            summary,
            RESET,
        );
        println!();

        for (i, threat) in threats.iter().enumerate() {
            print_threat(threat, i);
        }
    }

    print_separator();
    println!(
        "{}Scan completed in {:.2}s{}",
        CYAN,
        elapsed.as_secs_f64(),
        RESET
    );
}

pub async fn run_monitor(interval_secs: u64) {
    println!("{}{}SentinelX Continuous Monitoring{}", BOLD, CYAN, RESET);
    println!(
        "Scanning every {} seconds. Press Ctrl+C to stop.",
        interval_secs
    );
    println!();

    let mut scan_count: u64 = 0;
    let mut _total_threats: u64 = 0;

    loop {
        scan_count += 1;
        println!(
            "{}--- Scan #{} [{}] ---{}",
            CYAN,
            scan_count,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            RESET
        );

        let threats = run_all_detectors().await;

        if threats.is_empty() {
            println!("{}  No threats detected.{}", GREEN, RESET);
        } else {
            println!("  {}{}{} threats found!{}", RED, BOLD, threats.len(), RESET);
            for (i, threat) in threats.iter().enumerate() {
                print_threat(threat, i);
            }
            _total_threats += threats.len() as u64;
        }
        println!();

        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
    }
}
