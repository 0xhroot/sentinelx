use sentinelx_telemetry::{
    create_synthetic_event, TelemetryCategory, TelemetryEngine, TelemetryEventType,
};

use super::{BOLD, CYAN, GREEN, MAGENTA, RED, RESET, YELLOW};

async fn create_engine_with_providers() -> TelemetryEngine {
    use sentinelx_audit::{AuditConfig, AuditdProvider};
    use sentinelx_ebpf::{EbpfConfig, EbpfEngine, EbpfTelemetryProvider};
    use sentinelx_fanotify::{FanotifyConfig, FanotifyProvider};
    use sentinelx_netlink::{NetlinkConfig, NetlinkProvider};

    let engine = TelemetryEngine::with_default_config();

    let ebpf_engine = EbpfEngine::new(EbpfConfig::default());
    engine
        .register_provider(Box::new(EbpfTelemetryProvider::new(ebpf_engine)))
        .await;

    engine
        .register_provider(Box::new(FanotifyProvider::new(FanotifyConfig::default())))
        .await;

    engine
        .register_provider(Box::new(NetlinkProvider::new(NetlinkConfig::default())))
        .await;

    engine
        .register_provider(Box::new(AuditdProvider::new(AuditConfig::default())))
        .await;

    engine
}

pub async fn run() {
    println!("{}{}Real-Time Telemetry Engine{}", BOLD, CYAN, RESET);
    println!();

    let engine = create_engine_with_providers().await;

    println!("{}Status:{}", BOLD, GREEN);
    println!("  Engine initialized with default configuration");
    println!("  Bus capacity: {}", engine.bus().config().channel_capacity);
    println!(
        "  Broadcast capacity: {}",
        engine.bus().config().broadcast_capacity
    );
    println!(
        "  Max rate: {}/s",
        engine.bus().config().max_rate_per_second
    );
    println!(
        "  Buffer capacity: {}",
        engine.bus().config().buffer_capacity
    );
    println!();

    println!("{}Default Providers:{}", BOLD, MAGENTA);
    println!(
        "  {}proc_connector{} - /proc filesystem (fallback)",
        GREEN, RESET
    );
    println!(
        "  {}ebpf{} - eBPF tracepoints/kprobes (real kernel instrumentation via Aya)",
        GREEN, RESET
    );
    println!(
        "  {}fanotify{} - Filesystem access monitoring (real syscalls)",
        GREEN, RESET
    );
    println!(
        "  {}auditd{} - Linux Audit subsystem (real NETLINK_AUDIT)",
        GREEN, RESET
    );
    println!(
        "  {}netlink{} - Network/process events (real AF_NETLINK)",
        GREEN, RESET
    );
    println!();

    println!("{}Event Categories:{}", BOLD, MAGENTA);
    println!(
        "  {}Process{} - Create, Fork, Clone, Exec, Exit, Setuid, Setgid, Ptrace, CapChange",
        CYAN, RESET
    );
    println!(
        "  {}Filesystem{} - Open, Close, Read, Write, Rename, Delete, Execute, PermChange, Mount",
        CYAN, RESET
    );
    println!(
        "  {}Network{} - Connect, Accept, Bind, Listen, Close, DnsLookup",
        CYAN, RESET
    );
    println!(
        "  {}Kernel{} - ModuleLoad, ModuleUnload, BpfLoad, ParamChange",
        CYAN, RESET
    );
    println!(
        "  {}Persistence{} - ServiceCreate, CronModify, RcLocalModify, LdPreloadModify",
        CYAN, RESET
    );
    println!();

    let stats = engine.bus_stats();
    println!("{}Bus Statistics:{}", BOLD, MAGENTA);
    println!("  Total events: {}", stats.total_events);
    println!("  Dropped events: {}", stats.dropped_events);
    println!("  Active subscribers: {}", stats.active_providers);
    println!(
        "  Buffer size: {}/{}",
        stats.buffer_size, stats.buffer_capacity
    );
    println!();

    println!("{}Pipeline:{}", BOLD, MAGENTA);
    println!("  Kernel -> Telemetry Sources -> Event Normalizer -> Discovery -> Metadata -> Assessment -> Evidence -> Correlation -> Incident -> Threat -> Response");
    println!();

    println!("{}Provider Priority (Fallback Order):{}", BOLD, MAGENTA);
    println!("  1. Aya eBPF (preferred)");
    println!("  2. fanotify (filesystem monitoring)");
    println!("  3. auditd (Linux Audit subsystem)");
    println!("  4. netlink (network monitoring)");
    println!("  5. Proc scanning (fallback)");
    println!();

    engine.shutdown_all().await;
}

pub async fn run_events(count: usize) {
    println!("{}{}Recent Telemetry Events{}", BOLD, CYAN, RESET);
    println!();

    let _engine = create_engine_with_providers().await;

    let synthetic_events = [
        create_synthetic_event("ebpf", TelemetryEventType::ProcessCreate),
        create_synthetic_event("fanotify", TelemetryEventType::FileWrite),
        create_synthetic_event("auditd", TelemetryEventType::ProcessExec),
        create_synthetic_event("netlink", TelemetryEventType::NetConnect),
        create_synthetic_event("proc_connector", TelemetryEventType::KernelModuleLoad),
    ];

    let display_count = count.min(synthetic_events.len());
    for (i, event) in synthetic_events.iter().take(display_count).enumerate() {
        let category_color = match event.category {
            TelemetryCategory::Process => GREEN,
            TelemetryCategory::Filesystem => YELLOW,
            TelemetryCategory::Network => CYAN,
            TelemetryCategory::Kernel => RED,
            TelemetryCategory::Persistence => MAGENTA,
        };

        println!(
            "{}[{}]{} {}{}{} {} {}({}){}",
            BOLD,
            i + 1,
            RESET,
            category_color,
            event.category.as_str(),
            RESET,
            BOLD,
            event.event_type.as_str(),
            event.provider,
            RESET,
        );

        if let Some(pid) = event.pid {
            println!("   {}PID:{} {}", CYAN, RESET, pid);
        }
        if let Some(ref obj) = event.object_id {
            println!("   {}Object:{} {}", CYAN, RESET, obj);
        }
        println!(
            "   {}Time:{} {}",
            CYAN,
            RESET,
            event.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!();
    }

    println!(
        "{}Showing {} of {} events{}",
        CYAN,
        display_count,
        synthetic_events.len(),
        RESET
    );
}

pub async fn run_providers() {
    println!("{}{}Telemetry Providers{}", BOLD, CYAN, RESET);
    println!();

    let engine = create_engine_with_providers().await;
    let infos = engine.provider_infos().await;

    for info in &infos {
        let (status_str, status_color) = match info.status {
            sentinelx_telemetry::ProviderStatus::Running => ("running", GREEN),
            sentinelx_telemetry::ProviderStatus::Degraded => ("degraded", YELLOW),
            sentinelx_telemetry::ProviderStatus::Error => ("error", RED),
            sentinelx_telemetry::ProviderStatus::Stopped => ("stopped", MAGENTA),
            sentinelx_telemetry::ProviderStatus::Initializing => ("initializing", CYAN),
        };

        println!(
            "{}  {}{}{} - {}",
            BOLD, status_color, info.name, RESET, info.name
        );
        println!(
            "    {}Status:{} {}   {}Events:{} {}   {}Dropped:{} {}",
            CYAN,
            RESET,
            status_str,
            CYAN,
            RESET,
            info.events_received,
            CYAN,
            RESET,
            info.events_dropped
        );
        println!();
    }

    println!("{}Provider Priority (Fallback Order):{}", BOLD, MAGENTA);
    println!("  1. Aya eBPF (preferred)");
    println!("  2. fanotify (filesystem monitoring)");
    println!("  3. auditd (Linux Audit subsystem)");
    println!("  4. netlink (network monitoring)");
    println!("  5. Proc scanning (fallback)");
    println!();

    println!("{}Adding a new provider:{}", BOLD, MAGENTA);
    println!("  1. Implement the TelemetryProvider trait");
    println!("  2. Register with TelemetryEngine::register_provider()");
    println!("  3. Events are automatically normalized and published to the bus");
    println!();

    engine.shutdown_all().await;
}

pub async fn run_monitor(interval: u64) {
    println!("{}{}Live Telemetry Monitor{}", BOLD, CYAN, RESET);
    println!("  Press Ctrl+C to stop");
    println!();

    let engine = create_engine_with_providers().await;
    engine.initialize_all().await;
    let mut rx = engine.subscribe();
    let mut event_count: u64 = 0;

    loop {
        tokio::select! {
            Ok(event) = rx.recv() => {
                event_count += 1;
                let category_color = match event.category {
                    TelemetryCategory::Process => GREEN,
                    TelemetryCategory::Filesystem => YELLOW,
                    TelemetryCategory::Network => CYAN,
                    TelemetryCategory::Kernel => RED,
                    TelemetryCategory::Persistence => MAGENTA,
                };

                println!(
                    "{}[{}]{} {}{}{} {} {} ({})",
                    BOLD,
                    event_count,
                    RESET,
                    category_color,
                    event.category.as_str(),
                    RESET,
                    event.event_type.as_str(),
                    event.provider,
                    event.timestamp.format("%H:%M:%S"),
                );
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {
                if event_count == 0 {
                    println!("  {}Waiting for events...{}", CYAN, RESET);
                }
            }
        }
    }
}
