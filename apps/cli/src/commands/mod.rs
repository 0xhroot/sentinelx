pub mod assess;
pub mod audit;
pub mod behavior;
pub mod config_cmd;
pub mod export;
pub mod fleet;
pub mod forensics;
pub mod graph;
pub mod incidents;
pub mod integrity;
pub mod intelligence;
pub mod kernel;
pub mod modules;
pub mod network;
pub mod processes;
pub mod response;
pub mod scan;
pub mod status;
pub mod telemetry;
pub mod threats;
pub mod timeline;
pub mod workflows;

const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";
const RESET: &str = "\x1b[0m";

pub fn severity_color(severity: &sentinelx_common::Severity) -> &'static str {
    match severity {
        sentinelx_common::Severity::Critical => RED,
        sentinelx_common::Severity::High => YELLOW,
        sentinelx_common::Severity::Medium => MAGENTA,
        sentinelx_common::Severity::Low => BLUE,
        sentinelx_common::Severity::Info => GREEN,
    }
}

pub fn print_threat(threat: &sentinelx_common::types::ThreatEvent, index: usize) {
    let color = severity_color(&threat.severity);
    println!(
        "{}[{}]{} {}{}{} {} {}({}){}",
        BOLD,
        index + 1,
        RESET,
        color,
        threat.severity,
        RESET,
        BOLD,
        threat.title,
        threat.category.as_str(),
        RESET,
    );
    println!("   {}", threat.description);
    println!(
        "   {}Source:{} {}   {}Time:{} {}   {}ID:{} {}",
        CYAN,
        RESET,
        threat.source_detector,
        CYAN,
        RESET,
        threat.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        CYAN,
        RESET,
        &threat.id.to_string()[..8],
    );
    if !threat.tags.is_empty() {
        println!("   {}Tags:{} {}", CYAN, RESET, threat.tags.join(", "));
    }
    if !threat.mitre_attack.is_empty() {
        for mapping in &threat.mitre_attack {
            println!(
                "   {}MITRE:{} {} ({})",
                MAGENTA, RESET, mapping.technique_name, mapping.technique_id
            );
        }
    }
    println!();
}

pub fn print_separator() {
    println!("{}{}{}", CYAN, "─".repeat(80), RESET);
}
