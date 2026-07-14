mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sentinelx",
    about = "SentinelX - Linux Runtime Integrity & Rootkit Detection Platform",
    version,
    long_about = "Enterprise-grade Linux runtime integrity monitoring and rootkit detection.\n\nSentinelX performs deep system inspection to detect kernel rootkits, hidden processes,\ntampered modules, suspicious hooks, and other advanced threats."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true, help = "Path to configuration file")]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Run a full detection scan across all detectors")]
    Scan,

    #[command(about = "Run continuous monitoring with periodic scans")]
    Monitor {
        #[arg(short, long, default_value = "60", help = "Scan interval in seconds")]
        interval: u64,
    },

    #[command(about = "Show system status, metrics, and detector information")]
    Status,

    #[command(about = "Display the threat event timeline")]
    Timeline,

    #[command(about = "Show kernel and file integrity status")]
    Integrity,

    #[command(about = "List loaded kernel modules with trust assessment")]
    Modules,

    #[command(about = "List running processes with suspicious indicators")]
    Processes,

    #[command(about = "List active network connections")]
    Network,

    #[command(about = "Collect a comprehensive forensic snapshot")]
    Forensics,

    #[command(about = "Export threats or reports to a file")]
    Export {
        #[arg(
            short,
            long,
            default_value = "json",
            help = "Output format: json or markdown"
        )]
        format: String,
        #[arg(
            short,
            long,
            default_value = "sentinelx-report",
            help = "Output directory path"
        )]
        output: String,
    },

    #[command(about = "Show current configuration")]
    Config,

    #[command(about = "Run the central assessment engine")]
    Assess {
        #[arg(
            short,
            long,
            help = "Filter by object type (e.g., process, file, kernel_module)"
        )]
        object_type: Option<String>,
    },

    #[command(about = "Show correlated security incidents")]
    Incidents,

    #[command(about = "Show threat decisions with risk scores")]
    Threats,

    #[command(about = "Show the correlation graph and rules")]
    Graph,

    #[command(about = "Show response engine status and history")]
    Response,

    #[command(about = "Show available workflows and policies")]
    Workflows,

    #[command(about = "Show response audit log")]
    Audit,

    #[command(about = "Show real-time telemetry engine status and events")]
    Telemetry,

    #[command(about = "Show recent telemetry events")]
    Events {
        #[arg(short, long, default_value = "20", help = "Number of events to show")]
        count: usize,
    },

    #[command(about = "Show registered telemetry providers")]
    Providers,

    #[command(about = "Live monitoring of telemetry events (telemetry stream)")]
    MonitorLive {
        #[arg(short, long, default_value = "1", help = "Refresh interval in seconds")]
        interval: u64,
    },

    #[command(about = "Show behavioral analysis engine status and rules")]
    Behavior,

    #[command(about = "Show behavioral profiles")]
    BehaviorProfiles,

    #[command(about = "Show behavioral statistics and scoring weights")]
    BehaviorStats,

    #[command(about = "Show threat intelligence engine status")]
    Intel,

    #[command(about = "Show MITRE ATT&CK technique coverage")]
    Mitre,

    #[command(about = "Show loaded Indicators of Compromise")]
    Iocs,

    #[command(about = "Check if an IoC is known malicious")]
    IocCheck {
        #[arg(help = "IoC type (hash, ip_address, domain, filename, url, email)")]
        ioc_type: String,
        #[arg(help = "IoC value to check")]
        value: String,
    },

    #[command(about = "Show tracked CVE vulnerabilities")]
    Cves,

    #[command(about = "Show loaded YARA rules")]
    Yara,

    #[command(about = "Show loaded Sigma detection rules")]
    Sigma,

    #[command(about = "Show eBPF kernel sensor status and capabilities")]
    Ebpf,

    #[command(about = "Show telemetry provider health with detailed diagnostics")]
    ProvidersHealth,

    #[command(about = "Show fleet overview and agent management")]
    Fleet,

    #[command(about = "List all fleet agents")]
    FleetAgents,

    #[command(about = "Show detailed info for a specific agent")]
    FleetAgent {
        #[arg(help = "Agent ID")]
        agent_id: String,
    },

    #[command(about = "Show distributed fleet policies")]
    FleetPolicies,

    #[command(about = "Show recent remote actions")]
    FleetActions,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan => commands::scan::run().await,
        Commands::Monitor { interval } => commands::scan::run_monitor(interval).await,
        Commands::Status => commands::status::run().await,
        Commands::Timeline => commands::timeline::run().await,
        Commands::Integrity => commands::integrity::run().await,
        Commands::Modules => commands::modules::run(),
        Commands::Processes => commands::processes::run(),
        Commands::Network => commands::network::run(),
        Commands::Forensics => commands::forensics::run().await,
        Commands::Export { format, output } => commands::export::run(&format, &output).await,
        Commands::Config => commands::config_cmd::run(),
        Commands::Assess { object_type } => commands::assess::run(object_type).await,
        Commands::Incidents => commands::incidents::run().await,
        Commands::Threats => commands::threats::run().await,
        Commands::Graph => commands::graph::run().await,
        Commands::Response => commands::response::run().await,
        Commands::Workflows => commands::workflows::run().await,
        Commands::Audit => commands::audit::run().await,
        Commands::Telemetry => commands::telemetry::run().await,
        Commands::Events { count } => commands::telemetry::run_events(count).await,
        Commands::Providers => commands::telemetry::run_providers().await,
        Commands::MonitorLive { interval } => commands::telemetry::run_monitor(interval).await,
        Commands::Behavior => commands::behavior::run().await,
        Commands::BehaviorProfiles => commands::behavior::run_profiles().await,
        Commands::BehaviorStats => commands::behavior::run_stats().await,
        Commands::Intel => commands::intelligence::run().await,
        Commands::Mitre => commands::intelligence::run_mitre().await,
        Commands::Iocs => commands::intelligence::run_iocs().await,
        Commands::IocCheck { ioc_type, value } => {
            commands::intelligence::run_ioc_check(&ioc_type, &value).await
        }
        Commands::Cves => commands::intelligence::run_cves().await,
        Commands::Yara => commands::intelligence::run_yara().await,
        Commands::Sigma => commands::intelligence::run_sigma().await,
        Commands::Ebpf => commands::kernel::run_ebpf().await,
        Commands::ProvidersHealth => commands::kernel::run_providers_health().await,
        Commands::Fleet => commands::fleet::run().await,
        Commands::FleetAgents => commands::fleet::run_agents().await,
        Commands::FleetAgent { agent_id } => commands::fleet::run_agent_detail(&agent_id).await,
        Commands::FleetPolicies => commands::fleet::run_policies().await,
        Commands::FleetActions => commands::fleet::run_actions().await,
    }
}
