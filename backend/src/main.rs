mod error;
mod routes;

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use sentinelx_config::Settings;
use sentinelx_database::Store;
use sentinelx_detector::DetectionEngine;
use sentinelx_fleet::{CoordinatorConfig, CoordinatorEngine, FleetManager};
use sentinelx_integrity::{IntegrityDiscoveryProvider, IntegrityMetadataCollector};
use sentinelx_kernel::{HookDetector, KernelDiscoveryProvider, KernelMetadataCollector};
use sentinelx_memory::{MemoryDiscoveryProvider, MemoryMetadataCollector};
use sentinelx_module::{ModuleDiscoveryProvider, ModuleMetadataCollector};
use sentinelx_network::{NetworkDiscoveryProvider, NetworkMetadataCollector};
use sentinelx_persistence::{PersistenceDiscoveryProvider, PersistenceMetadataCollector};
use sentinelx_process::{ProcessDiscoveryProvider, ProcessMetadataCollector};
use sentinelx_telemetry::{init_tracing, MetricsCollector, ProviderManager, TelemetryEngine};
use sentinelx_timeline::TimelineEngine;

use routes::{router, AppState};

struct CliArgs {
    host: String,
    port: u16,
    config: Option<PathBuf>,
}

fn parse_args() -> CliArgs {
    let mut host = None;
    let mut port = None;
    let mut config = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                i += 1;
                host = args.get(i).cloned();
            }
            "--port" => {
                i += 1;
                port = args.get(i).and_then(|v| v.parse::<u16>().ok());
            }
            "--config" => {
                i += 1;
                config = args.get(i).map(PathBuf::from);
            }
            _ => {}
        }
        i += 1;
    }

    CliArgs {
        host: host.unwrap_or_else(|| "0.0.0.0".to_string()),
        port: port.unwrap_or(8443),
        config,
    }
}

#[tokio::main]
async fn main() {
    let cli = parse_args();

    init_tracing("info", None, false);
    info!("SentinelX backend starting");

    let settings = Settings::load(cli.config.as_deref()).unwrap_or_else(|e| {
        tracing::warn!("Failed to load config, using defaults: {}", e);
        Settings::default()
    });

    let db_path = settings
        .storage
        .database_path
        .to_str()
        .unwrap_or("sentinelx.db");
    let store = Arc::new(match Store::new(db_path).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "Failed to open database at {}, using in-memory: {}",
                db_path,
                e
            );
            Store::new("sqlite::memory:")
                .await
                .expect("Failed to create in-memory database")
        }
    });

    let metrics = MetricsCollector::new();
    let engine = Arc::new(DetectionEngine::new(
        settings.clone(),
        Arc::clone(&store),
        metrics.clone(),
    ));

    engine
        .registry()
        .register(Box::new(HookDetector::new()))
        .await;

    engine.start().await;

    let threats = engine.run_scan().await;
    if !threats.is_empty() {
        use sentinelx_database::repository::ThreatRepository;
        let repo = ThreatRepository::new(&store);
        for threat in &threats {
            if let Err(e) = repo.insert(threat).await {
                tracing::error!("Failed to persist startup threat {}: {}", threat.id, e);
            }
        }
        info!("Persisted {} threats from initial scan", threats.len());
    }
    engine.run_evidence_collection().await;

    // --- New evidence-driven pipeline ---
    {
        use sentinelx_core::pipeline::PipelineCoordinator;

        let mut pipeline = PipelineCoordinator::new();

        // Native process providers (migrated from adapter)
        pipeline
            .discovery()
            .register(Arc::new(Box::new(ProcessDiscoveryProvider::new())));
        pipeline
            .metadata()
            .register(Arc::new(ProcessMetadataCollector));

        // Native module providers (migrated from adapter)
        pipeline
            .discovery()
            .register(Arc::new(Box::new(ModuleDiscoveryProvider::new())));
        pipeline
            .metadata()
            .register(Arc::new(ModuleMetadataCollector::new()));

        // Native network providers (migrated from adapter)
        pipeline
            .discovery()
            .register(Arc::new(Box::new(NetworkDiscoveryProvider::new())));
        pipeline
            .metadata()
            .register(Arc::new(NetworkMetadataCollector::new()));

        // Native persistence providers (migrated from adapter)
        pipeline
            .discovery()
            .register(Arc::new(Box::new(PersistenceDiscoveryProvider::new())));
        pipeline
            .metadata()
            .register(Arc::new(PersistenceMetadataCollector::new()));

        // Native kernel providers (migrated from adapter)
        pipeline
            .discovery()
            .register(Arc::new(Box::new(KernelDiscoveryProvider::new())));
        pipeline
            .metadata()
            .register(Arc::new(KernelMetadataCollector::new()));

        // Native memory providers (migrated from adapter)
        pipeline
            .discovery()
            .register(Arc::new(Box::new(MemoryDiscoveryProvider::new())));
        pipeline
            .metadata()
            .register(Arc::new(MemoryMetadataCollector::new()));

        // Native integrity providers (migrated from adapter)
        pipeline
            .discovery()
            .register(Arc::new(Box::new(IntegrityDiscoveryProvider::new())));
        pipeline
            .metadata()
            .register(Arc::new(IntegrityMetadataCollector::new()));

        // Central assessment engine — all 7 assessors from sentinelx-assessment crate
        for assessor in sentinelx_assessment::create_all_assessors() {
            pipeline.assessment().register(assessor);
        }

        match pipeline.run().await {
            Ok(result) => {
                info!(
                    objects_discovered = result.objects_discovered,
                    objects_enriched = result.objects_enriched,
                    objects_assessed = result.objects_assessed,
                    evidence_count = result.evidence_count,
                    duration_ms = result.duration_ms,
                    "Evidence-driven pipeline completed"
                );
            }
            Err(e) => {
                tracing::error!("Evidence-driven pipeline failed: {}", e);
            }
        }
    }

    let timeline = Arc::new(RwLock::new(TimelineEngine::new()));
    let incident_engine = Arc::new(sentinelx_incident::IncidentEngine::new());
    let threat_engine = Arc::new(sentinelx_threat::ThreatEngine::new());
    let response_engine = Arc::new(RwLock::new(
        sentinelx_response::ResponseEngine::with_default_config(),
    ));

    let behavior_engine = Arc::new(sentinelx_behavior::engine::BehaviorEngine::new());
    let intelligence_engine = Arc::new(sentinelx_intelligence::engine::IntelligenceEngine::new());

    let (fleet_tx, _fleet_rx) = tokio::sync::mpsc::channel(100);
    let coordinator = Arc::new(CoordinatorEngine::new(
        CoordinatorConfig::default(),
        fleet_tx,
    ));
    let fleet_manager = Arc::new(FleetManager::new(coordinator));
    fleet_manager.start().await;

    // --- Telemetry engine ---
    let telemetry_engine = Arc::new(TelemetryEngine::with_default_config());

    {
        use sentinelx_audit::{AuditConfig, AuditdProvider};
        use sentinelx_ebpf::{EbpfConfig, EbpfEngine, EbpfTelemetryProvider};
        use sentinelx_fanotify::{FanotifyConfig, FanotifyProvider};
        use sentinelx_netlink::{NetlinkConfig, NetlinkProvider};

        let ebpf_engine = EbpfEngine::new(EbpfConfig::default());
        telemetry_engine
            .register_provider(Box::new(EbpfTelemetryProvider::new(ebpf_engine)))
            .await;

        telemetry_engine
            .register_provider(Box::new(FanotifyProvider::new(FanotifyConfig::default())))
            .await;

        telemetry_engine
            .register_provider(Box::new(NetlinkProvider::new(NetlinkConfig::default())))
            .await;

        telemetry_engine
            .register_provider(Box::new(AuditdProvider::new(AuditConfig::default())))
            .await;
    }

    telemetry_engine.initialize_default_providers().await;

    let provider_manager = Arc::new(ProviderManager::detect());

    let state = Arc::new(AppState {
        store,
        engine: Arc::clone(&engine),
        metrics,
        timeline,
        incident_engine,
        threat_engine,
        response_engine,
        telemetry_engine,
        behavior_engine,
        intelligence_engine,
        provider_manager,
        fleet_manager,
    });

    let app = router(Arc::clone(&state));

    let addr = format!("{}:{}", cli.host, cli.port);
    info!("Listening on {}", addr);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    let server = axum::serve(listener, app);

    let shutdown_signal = async {
        let _ = tokio::signal::ctrl_c().await;
        info!("Received SIGINT, shutting down");
    };

    if let Err(e) = server.with_graceful_shutdown(shutdown_signal).await {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }

    engine.stop().await;
    state.telemetry_engine.shutdown_all().await;
    info!("SentinelX backend stopped");
}
