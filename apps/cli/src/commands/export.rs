use crate::commands::{print_separator, BOLD, CYAN, GREEN, RED, RESET, YELLOW};
use sentinelx_common::traits::Detector;
use sentinelx_common::types::ThreatEvent;
use sentinelx_reporting::report::{ReportFormat, ReportGenerator};

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

pub async fn run(format: &str, output: &str) {
    println!("{}{}Exporting SentinelX Report{}", BOLD, CYAN, RESET);
    println!();

    println!("{}Running detection scan...{}", CYAN, RESET);
    let threats = collect_threats().await;

    println!("{}Generating report...{}", CYAN, RESET);

    let report_gen = ReportGenerator::new();
    let out_dir = std::path::Path::new(output);

    let report_format = match format.to_lowercase().as_str() {
        "markdown" | "md" => ReportFormat::Markdown,
        _ => ReportFormat::Json,
    };

    match std::fs::create_dir_all(out_dir) {
        Ok(()) => {}
        Err(e) => {
            eprintln!(
                "{}{}[!]{} Failed to create output directory: {}",
                YELLOW, BOLD, RESET, e
            );
            return;
        }
    }

    let file_ext = match report_format {
        ReportFormat::Json => "json",
        ReportFormat::Markdown => "md",
    };
    let file_path = out_dir.join(format!("sentinelx-report.{}", file_ext));

    match report_gen.save_report(&threats, &file_path, report_format) {
        Ok(()) => {
            println!();
            println!(
                "{}{}[OK]{} Report saved: {}",
                GREEN,
                BOLD,
                RESET,
                file_path.display()
            );
            println!("   {}Threats included:{} {}", BOLD, RESET, threats.len());

            let critical = threats
                .iter()
                .filter(|t| t.severity == sentinelx_common::Severity::Critical)
                .count();
            let high = threats
                .iter()
                .filter(|t| t.severity == sentinelx_common::Severity::High)
                .count();
            println!(
                "   {}Critical:{} {}   {}High:{} {}",
                RED, RESET, critical, YELLOW, RESET, high,
            );
        }
        Err(e) => {
            eprintln!(
                "{}{}[!]{} Failed to save report: {}",
                YELLOW, BOLD, RESET, e
            );
        }
    }

    print_separator();

    let json_path = out_dir.join("threats.json");
    match std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&threats).unwrap_or_default(),
    ) {
        Ok(()) => {
            println!("{}Raw threats JSON:{} {}", CYAN, RESET, json_path.display());
        }
        Err(e) => {
            eprintln!(
                "{}{}[!]{} Failed to write threats JSON: {}",
                YELLOW, BOLD, RESET, e
            );
        }
    }
}
