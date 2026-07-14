use crate::commands::{print_separator, BOLD, CYAN, GREEN, RESET, YELLOW};
use sentinelx_config::Settings;

pub fn run() {
    println!("{}{}SentinelX Configuration{}", BOLD, CYAN, RESET);
    println!();

    let settings = match Settings::load(None) {
        Ok(s) => s,
        Err(e) => {
            println!("{}Using default configuration ({}){}", YELLOW, e, RESET);
            Settings::default()
        }
    };

    print_separator();
    println!("{}{}General{}", BOLD, CYAN, RESET);
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Hostname:", RESET, settings.general.hostname
    );
    println!(
        "  {}{:<28}{} {}s",
        BOLD, "Scan interval:", RESET, settings.general.scan_interval_seconds
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Baseline on start:", RESET, settings.general.baseline_on_start
    );
    println!(
        "  {}{:<28}{} {} MB",
        BOLD, "Max memory:", RESET, settings.general.max_memory_mb
    );
    println!(
        "  {}{:<28}{} {}%",
        BOLD, "Max CPU:", RESET, settings.general.max_cpu_percent
    );

    print_separator();
    println!("{}{}Detection{}", BOLD, CYAN, RESET);
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Severity threshold:", RESET, settings.detection.severity_threshold
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "MITRE ATT&CK mapping:", RESET, settings.detection.mitre_attack_mapping
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Evidence collection:", RESET, settings.detection.evidence_collection
    );
    println!("  {}{:<28}{} ", BOLD, "Enabled detectors:", RESET);
    for det in &settings.detection.enabled_detectors {
        println!("    {}-{} {}", GREEN, RESET, det);
    }

    print_separator();
    println!("{}{}Monitoring{}", BOLD, CYAN, RESET);
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Process monitoring:", RESET, settings.monitoring.process_monitoring
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Network monitoring:", RESET, settings.monitoring.network_monitoring
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Module monitoring:", RESET, settings.monitoring.module_monitoring
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Memory monitoring:", RESET, settings.monitoring.memory_monitoring
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Syscall monitoring:", RESET, settings.monitoring.syscall_monitoring
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "File integrity:", RESET, settings.monitoring.file_integrity_monitoring
    );

    print_separator();
    println!("{}{}Storage{}", BOLD, CYAN, RESET);
    println!(
        "  {}{:<28}{} {}",
        BOLD,
        "Database:",
        RESET,
        settings.storage.database_path.display()
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD,
        "Evidence:",
        RESET,
        settings.storage.evidence_path.display()
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD,
        "Logs:",
        RESET,
        settings.storage.log_path.display()
    );
    println!(
        "  {}{:<28}{} {} days",
        BOLD, "Retention:", RESET, settings.storage.retention_days
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Max events:", RESET, settings.storage.max_events
    );

    print_separator();
    println!("{}{}API{}", BOLD, CYAN, RESET);
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Enabled:", RESET, settings.api.enabled
    );
    println!(
        "  {}{:<28}{} {}:{}",
        BOLD, "Bind address:", RESET, settings.api.host, settings.api.port
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "TLS:", RESET, settings.api.tls_enabled
    );

    print_separator();
    println!("{}{}Logging{}", BOLD, CYAN, RESET);
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Level:", RESET, settings.logging.level
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Format:", RESET, settings.logging.format
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "File output:", RESET, settings.logging.file_output
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "JSON format:", RESET, settings.logging.json_format
    );

    print_separator();
    println!("{}{}eBPF{}", BOLD, CYAN, RESET);
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Enabled:", RESET, settings.ebpf.enabled
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Map size:", RESET, settings.ebpf.map_size
    );
    println!(
        "  {}{:<28}{} {}",
        BOLD, "Perf buffer pages:", RESET, settings.ebpf.perf_buffer_pages
    );
    println!(
        "  {}{:<28}{} {}/s",
        BOLD, "Max events/s:", RESET, settings.ebpf.max_events_per_second
    );
    print_separator();
}
