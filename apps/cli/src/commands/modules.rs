use crate::commands::{print_separator, BOLD, CYAN, GREEN, RED, RESET, YELLOW};
use sentinelx_module::{ModuleScanner, ModuleTrustChecker};

pub fn run() {
    println!("{}{}Loaded Kernel Modules{}", BOLD, CYAN, RESET);
    println!();

    let scanner = ModuleScanner::new();
    let modules = scanner.scan_proc_modules();
    let checker = ModuleTrustChecker::new();

    if modules.is_empty() {
        println!("{}No kernel modules found.{}", YELLOW, RESET);
        return;
    }

    println!(
        "{}{:<3} {:<28} {:<10} {:<8} {:<18} {:<8}{}",
        BOLD, "#", "NAME", "SIZE", "REFS", "STATE", "TRUST", RESET
    );
    print_separator();

    for (i, module) in modules.iter().enumerate() {
        let result = checker.check(module);

        let state_str = match module.state {
            sentinelx_common::types::ModuleState::Live => "Live",
            sentinelx_common::types::ModuleState::Coming => "Coming",
            sentinelx_common::types::ModuleState::Going => "Going",
            sentinelx_common::types::ModuleState::Unknown => "Unknown",
        };

        let (trust_str, trust_color) = if result.trusted {
            ("Trusted", GREEN)
        } else if result.score >= 0.4 {
            ("Unknown", YELLOW)
        } else {
            ("Suspicious", RED)
        };

        let size_str = format_size(module.size);

        println!(
            "  {:<3} {:<28} {:<10} {:<8} {:<18} {}{}{}",
            i + 1,
            truncate(&module.name, 27),
            size_str,
            module.ref_count,
            state_str,
            trust_color,
            trust_str,
            RESET
        );
    }

    println!();
    print_separator();
    let trusted = modules.iter().filter(|m| checker.check(m).trusted).count();
    let suspicious = modules
        .iter()
        .filter(|m| {
            let r = checker.check(m);
            !r.trusted && r.score < 0.4
        })
        .count();
    println!(
        "{}Total:{} {}   {}Trusted:{} {}   {}Suspicious:{} {}",
        BOLD,
        RESET,
        modules.len(),
        GREEN,
        RESET,
        trusted,
        RED,
        RESET,
        suspicious,
    );
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}
