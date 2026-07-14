use crate::commands::{print_separator, BOLD, CYAN, GREEN, RESET, YELLOW};

pub async fn run() {
    println!("{}{}SentinelX System Status{}", BOLD, CYAN, RESET);
    println!();

    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let kernel_version = std::fs::read_to_string("/proc/version")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| {
            let secs: f64 = s.split_whitespace().next()?.parse().ok()?;
            let days = (secs / 86400.0) as u64;
            let hours = ((secs % 86400.0) / 3600.0) as u64;
            let mins = ((secs % 3600.0) / 60.0) as u64;
            Some(format!("{}d {}h {}m", days, hours, mins))
        })
        .unwrap_or_else(|| "unknown".to_string());

    let process_count = std::fs::read_dir("/proc")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.parse::<u32>().is_ok())
                })
                .count()
        })
        .unwrap_or(0);

    let module_count = std::fs::read_to_string("/proc/modules")
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0);

    let tcp_count = std::fs::read_to_string("/proc/net/tcp")
        .map(|s| s.lines().count().saturating_sub(1))
        .unwrap_or(0);
    let tcp6_count = std::fs::read_to_string("/proc/net/tcp6")
        .map(|s| s.lines().count().saturating_sub(1))
        .unwrap_or(0);
    let udp_count = std::fs::read_to_string("/proc/net/udp")
        .map(|s| s.lines().count().saturating_sub(1))
        .unwrap_or(0);
    let udp6_count = std::fs::read_to_string("/proc/net/udp6")
        .map(|s| s.lines().count().saturating_sub(1))
        .unwrap_or(0);
    let conn_count = tcp_count + tcp6_count + udp_count + udp6_count;

    let kptr_restrict = std::fs::read_to_string("/proc/sys/kernel/kptr_restrict")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unreadable".to_string());
    let dmesg_restrict = std::fs::read_to_string("/proc/sys/kernel/dmesg_restrict")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unreadable".to_string());

    print_separator();
    println!("{}{:<24}{} {}", BOLD, "Hostname:", RESET, hostname);
    println!("{}{:<24}{} {}", BOLD, "Kernel:", RESET, kernel_version);
    println!("{}{:<24}{} {}", BOLD, "Uptime:", RESET, uptime);
    print_separator();
    println!("{}{:<24}{} {}", BOLD, "Processes:", RESET, process_count);
    println!(
        "{}{:<24}{} {}",
        BOLD, "Kernel modules:", RESET, module_count
    );
    println!(
        "{}{:<24}{} {}",
        BOLD, "Network connections:", RESET, conn_count
    );
    print_separator();
    println!("{}{}Detectors{}", BOLD, CYAN, RESET);
    println!("  {}{:<22}{} {}", BOLD, "Active detectors:", RESET, 8usize);
    println!();
    print_separator();
    println!("{}{}Hardening{}", BOLD, CYAN, RESET);
    let kptr_color = if kptr_restrict == "1" || kptr_restrict == "2" {
        GREEN
    } else {
        YELLOW
    };
    println!(
        "  {}kptr_restrict:{} {}{}{}",
        BOLD, RESET, kptr_color, kptr_restrict, RESET
    );
    let dmesg_color = if dmesg_restrict == "1" { GREEN } else { YELLOW };
    println!(
        "  {}dmesg_restrict:{} {}{}{}",
        BOLD, RESET, dmesg_color, dmesg_restrict, RESET
    );
    print_separator();
}
