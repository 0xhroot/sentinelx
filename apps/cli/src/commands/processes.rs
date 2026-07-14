use crate::commands::{print_separator, BOLD, CYAN, RED, RESET, YELLOW};
use sentinelx_process::ProcessScanner;

pub fn run() {
    println!("{}{}Running Processes{}", BOLD, CYAN, RESET);
    println!();

    let scanner = ProcessScanner::new();
    let processes = scanner.scan_all();

    if processes.is_empty() {
        println!("{}No processes found.{}", YELLOW, RESET);
        return;
    }

    println!(
        "{}{:<8} {:<8} {:<20} {:<16} {:<10} {:<10} {:<8}{}",
        BOLD, "PID", "PPID", "NAME", "USER", "STATE", "MEMORY", "FLAGS", RESET
    );
    print_separator();

    for proc in &processes {
        let state_str = match proc.status {
            sentinelx_common::types::ProcessStatus::Running => "Running",
            sentinelx_common::types::ProcessStatus::Sleeping => "Sleeping",
            sentinelx_common::types::ProcessStatus::Stopped => "Stopped",
            sentinelx_common::types::ProcessStatus::Zombie => "Zombie",
            sentinelx_common::types::ProcessStatus::Dead => "Dead",
            sentinelx_common::types::ProcessStatus::Unknown => "Unknown",
        };

        let mem_str = if proc.memory_usage_kb >= 1024 * 1024 {
            format!("{:.1}G", proc.memory_usage_kb as f64 / (1024.0 * 1024.0))
        } else if proc.memory_usage_kb >= 1024 {
            format!("{:.1}M", proc.memory_usage_kb as f64 / 1024.0)
        } else {
            format!("{}K", proc.memory_usage_kb)
        };

        let mut flags = Vec::new();
        if proc.uid == 0 {
            flags.push("root");
        }
        if !proc.capabilities.is_empty() {
            flags.push("caps");
        }
        if proc.status == sentinelx_common::types::ProcessStatus::Zombie {
            flags.push("zombie");
        }

        let flags_str = flags.join(",");
        let name_color = if proc.uid == 0 && proc.pid.as_u32() != 1 {
            YELLOW
        } else {
            ""
        };

        println!(
            "  {:<8} {:<8} {}{}{} {:<20} {:<10} {:<10} {:<8}",
            proc.pid,
            proc.ppid,
            name_color,
            truncate_utf8(&proc.name, 19),
            RESET,
            truncate_utf8(&proc.user, 19),
            state_str,
            mem_str,
            flags_str,
        );
    }

    println!();
    print_separator();
    let total = processes.len();
    let root_procs = processes.iter().filter(|p| p.uid == 0).count();
    let zombie_procs = processes
        .iter()
        .filter(|p| p.status == sentinelx_common::types::ProcessStatus::Zombie)
        .count();
    let with_caps = processes
        .iter()
        .filter(|p| !p.capabilities.is_empty())
        .count();
    println!(
        "{}Total:{} {}   {}Root:{} {}   {}Zombies:{} {}   {}With Caps:{} {}",
        BOLD,
        RESET,
        total,
        YELLOW,
        RESET,
        root_procs,
        RED,
        RESET,
        zombie_procs,
        CYAN,
        RESET,
        with_caps,
    );
}

fn truncate_utf8(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count > max_chars {
        let truncated: String = s.chars().take(max_chars - 1).collect();
        format!("{}…", truncated)
    } else {
        s.to_string()
    }
}
