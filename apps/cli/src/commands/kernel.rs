use sentinelx_telemetry::ProviderManager;

use super::{BOLD, CYAN, GREEN, MAGENTA, RED, RESET, YELLOW};

pub async fn run_ebpf() {
    println!("{}{}eBPF Kernel Sensor{}", BOLD, CYAN, RESET);
    println!();

    let manager = ProviderManager::detect();
    let caps = manager.capabilities();

    println!("{}Kernel Capabilities:{}", BOLD, GREEN);
    for cap in caps {
        let (icon, color) = if cap.available {
            ("\u{2713}", GREEN)
        } else {
            ("\u{2717}", RED)
        };

        let name = format!("{:?}", cap.capability);
        println!(
            "  {} {} {}{}{}",
            icon,
            color,
            name,
            RESET,
            if cap.available { " (available)" } else { "" }
        );
        if let Some(ref reason) = cap.reason {
            println!("    {}Reason:{} {}", CYAN, RESET, reason);
        }
    }
    println!();

    println!("{}eBPF Status:{}", BOLD, GREEN);
    if manager.is_available(&sentinelx_telemetry::Capability::Ebpf) {
        println!(
            "  {}Status:{} {}eBPF is available{}",
            GREEN, RESET, GREEN, RESET
        );
        println!("  The eBPF sensor uses Aya to load programs into the kernel for");
        println!("  high-performance tracing of process, file, network, and kernel events.");
        println!();

        println!("{}Supported Program Types:{}", BOLD, MAGENTA);
        println!(
            "  {}Tracepoints{} - Stable kernel tracepoints (process lifecycle, syscalls)",
            CYAN, RESET
        );
        println!(
            "  {}Kprobes{}    - Dynamic kernel probes (function entry/exit)",
            CYAN, RESET
        );
        println!(
            "  {}XDP{}        - Express Data Path (network packet processing)",
            CYAN, RESET
        );
        println!(
            "  {}Perf Events{} - Performance monitoring counters",
            CYAN, RESET
        );
        println!();

        println!("{}Event Types:{}", BOLD, MAGENTA);
        println!(
            "  {}Process{} - exec, exit, fork, clone, setuid, setgid, ptrace, cap_change",
            CYAN, RESET
        );
        println!(
            "  {}File{}    - open, write, delete, rename, perm_change, execute",
            CYAN, RESET
        );
        println!("  {}Network{} - connect, bind", CYAN, RESET);
        println!(
            "  {}Kernel{}  - module_load, module_unload, bpf_load, param_change",
            CYAN, RESET
        );
    } else {
        println!(
            "  {}Status:{} {}eBPF is NOT available{}",
            YELLOW, RESET, YELLOW, RESET
        );
        println!("  The eBPF sensor requires:");
        println!("    - Linux kernel 5.8+ with BTF support");
        println!("    - CAP_BPF or CAP_SYS_ADMIN capability");
        println!("    - /sys/kernel/btf/vmlinux present");
        println!();
        println!(
            "  {}Fallback:{} Other providers (fanotify, audit, netlink) will be used instead.",
            CYAN, RESET
        );
    }
    println!();

    println!("{}Preferred Provider Order:{}", BOLD, MAGENTA);
    let preferred = manager.preferred_order();
    for (i, cap) in preferred.iter().enumerate() {
        println!("  {}. {:?}", i + 1, cap);
    }
    println!();
}

pub async fn run_providers_health() {
    println!("{}{}Telemetry Providers Health{}", BOLD, CYAN, RESET);
    println!();

    let manager = ProviderManager::detect();

    println!("{}Capability Detection:{}", BOLD, GREEN);
    for cap in manager.capabilities() {
        let (icon, color) = if cap.available {
            ("\u{2713}", GREEN)
        } else {
            ("\u{2717}", RED)
        };
        let name = format!("{:?}", cap.capability);
        println!("  {} {}{} - {}", icon, color, name, RESET);
        if let Some(ref reason) = cap.reason {
            println!("    {}{}", CYAN, reason);
        }
    }
    println!();

    println!("{}Active Providers:{}", BOLD, GREEN);
    for name in manager.active_providers() {
        println!("  {}{}{}", GREEN, name, RESET);
    }
    println!();

    println!("{}Kernel Latency:{}", BOLD, GREEN);
    let latency = manager.latency_report();
    if latency.is_empty() {
        println!("  {}No latency data yet{}", CYAN, RESET);
    } else {
        for r in &latency {
            println!(
                "  {}avg:{:.1}us  max:{:.1}us  samples:{}{}",
                CYAN, r.avg_latency_us, r.max_latency_us, r.samples, RESET
            );
        }
    }
    println!();

    println!("{}Telemetry Rates:{}", BOLD, GREEN);
    let rates = manager.rate_report();
    if rates.is_empty() {
        println!("  {}No rate data yet{}", CYAN, RESET);
    } else {
        for r in &rates {
            println!(
                "  {}{}: {} received, {} dropped ({:.1}% drop rate){}",
                CYAN, r.provider, r.total_events, r.total_dropped, r.drop_rate_percent, RESET
            );
        }
    }
    println!();

    println!("{}Provider Summary:{}", BOLD, GREEN);
    println!(
        "  {}Total:{} {}  {}Active:{} {}",
        CYAN,
        RESET,
        manager.capabilities().len(),
        CYAN,
        RESET,
        manager.active_providers().len(),
    );
    println!();
}
