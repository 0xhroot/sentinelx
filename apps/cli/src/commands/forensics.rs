use crate::commands::{print_separator, BOLD, CYAN, GREEN, RED, RESET, YELLOW};
use sentinelx_forensics::{ForensicReport, ForensicsCollector};

pub async fn run() {
    println!("{}{}Collecting Forensic Snapshot{}", BOLD, CYAN, RESET);
    println!();

    let collector = ForensicsCollector::new();

    println!("{}Collecting processes...{}", CYAN, RESET);
    let snapshot = collector.collect_all();

    println!("{}Generating report...{}", CYAN, RESET);
    let report = ForensicReport::new(snapshot);

    print_separator();
    let summary = report.to_summary();
    println!("{}", summary);
    print_separator();

    println!();
    println!("{}{}IOCs (Indicators of Compromise):{}", BOLD, CYAN, RESET);
    let iocs = report.compute_iocs();
    if iocs.is_empty() {
        println!("  {}No IOCs identified.{}", GREEN, RESET);
    } else {
        for ioc in &iocs {
            println!("  {}-{} {}", RED, RESET, ioc);
        }
    }
    println!();
    println!("{}Total IOCs:{} {}", BOLD, RESET, iocs.len());

    let out_dir = std::path::Path::new("/tmp/sentinelx-forensics");
    match report.save_to_dir(out_dir) {
        Ok(()) => {
            println!();
            println!(
                "{}{}Snapshot saved to:{} {}",
                GREEN,
                BOLD,
                RESET,
                out_dir.display()
            );
        }
        Err(e) => {
            eprintln!(
                "{}{}[!]{} Failed to save snapshot: {}",
                YELLOW, BOLD, RESET, e
            );
        }
    }
}
