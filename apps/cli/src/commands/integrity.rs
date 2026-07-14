use crate::commands::{print_separator, BOLD, CYAN, GREEN, RED, RESET, YELLOW};
use sentinelx_common::traits::Detector;

pub async fn run() {
    println!("{}{}Kernel & File Integrity Status{}", BOLD, CYAN, RESET);
    println!();

    println!("{}{}Kernel Hardening:{}{}", BOLD, CYAN, RESET, BOLD);
    print_separator();

    let checks = vec![
        check_sysctl("kptr_restrict", "/proc/sys/kernel/kptr_restrict", "1 or 2"),
        check_sysctl("dmesg_restrict", "/proc/sys/kernel/dmesg_restrict", "1"),
        check_sysctl("modules_disabled", "/proc/sys/kernel/modules_disabled", "1"),
    ];

    for (name, passed, value) in &checks {
        let (icon, color) = if *passed {
            ("PASS", GREEN)
        } else {
            ("WARN", YELLOW)
        };
        println!(
            "  {}{}[{}]{} {} = {}",
            color, BOLD, icon, RESET, name, value
        );
    }

    println!();
    println!("{}{}Kernel Integrity:{}{}", BOLD, CYAN, RESET, BOLD);
    print_separator();

    let kernel_detector = sentinelx_kernel::KernelIntegrityDetector::new();
    match kernel_detector.detect().await {
        Ok(threats) => {
            if threats.is_empty() {
                println!(
                    "  {}{}[PASS]{} No kernel integrity violations detected.",
                    GREEN, BOLD, RESET
                );
            } else {
                for threat in &threats {
                    let color = match threat.severity {
                        sentinelx_common::Severity::Critical => RED,
                        sentinelx_common::Severity::High => YELLOW,
                        _ => CYAN,
                    };
                    println!(
                        "  {}{}[!]{} {}{}{} - {}",
                        color, BOLD, RESET, color, threat.title, RESET, threat.description
                    );
                }
            }
        }
        Err(e) => {
            println!(
                "  {}{}[ERROR]{} Kernel integrity check failed: {}",
                RED, BOLD, RESET, e
            );
        }
    }

    println!();
    println!("{}{}File Integrity:{}{}", BOLD, CYAN, RESET, BOLD);
    print_separator();

    let file_detector = sentinelx_integrity::IntegrityChecker::new();
    match file_detector.detect().await {
        Ok(threats) => {
            if threats.is_empty() {
                println!(
                    "  {}{}[PASS]{} All monitored files have valid integrity.",
                    GREEN, BOLD, RESET
                );
            } else {
                for threat in &threats {
                    println!(
                        "  {}{}[!]{} {} - {}",
                        RED, BOLD, RESET, threat.title, threat.description
                    );
                }
            }
        }
        Err(e) => {
            println!(
                "  {}{}[ERROR]{} File integrity check failed: {}",
                RED, BOLD, RESET, e
            );
        }
    }

    println!();
    println!("{}{}Memory Integrity:{}{}", BOLD, CYAN, RESET, BOLD);
    print_separator();

    let mem_detector = sentinelx_memory::MemoryIntegrityChecker::new();
    match mem_detector.detect().await {
        Ok(threats) => {
            if threats.is_empty() {
                println!(
                    "  {}{}[PASS]{} Memory integrity checks passed.",
                    GREEN, BOLD, RESET
                );
            } else {
                for threat in &threats {
                    println!(
                        "  {}{}[!]{} {} - {}",
                        RED, BOLD, RESET, threat.title, threat.description
                    );
                }
            }
        }
        Err(e) => {
            println!(
                "  {}{}[ERROR]{} Memory integrity check failed: {}",
                RED, BOLD, RESET, e
            );
        }
    }

    println!();
    print_separator();
}

fn check_sysctl(name: &'static str, path: &str, _expected: &str) -> (&'static str, bool, String) {
    let value = std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unreadable".to_string());
    let passed = match name {
        "kptr_restrict" => value == "1" || value == "2",
        "dmesg_restrict" => value == "1",
        "modules_disabled" => value == "1",
        _ => false,
    };
    (name, passed, value)
}
