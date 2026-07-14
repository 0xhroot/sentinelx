use std::path::Path;
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_tracing(log_level: &str, log_dir: Option<&Path>, json_format: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    if let Some(dir) = log_dir {
        let _ = std::fs::create_dir_all(dir);
        let file_appender = tracing_appender::rolling::daily(dir, "sentinelx.log");
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        std::mem::forget(_guard);

        if json_format {
            let layer = fmt::layer()
                .with_writer(non_blocking)
                .json()
                .with_target(true)
                .with_thread_ids(true);
            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .init();
        } else {
            let layer = fmt::layer()
                .with_writer(non_blocking)
                .with_target(true)
                .with_thread_ids(true);
            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .init();
        }
    } else if json_format {
        let layer = fmt::layer().json().with_target(true).with_thread_ids(true);
        tracing_subscriber::registry()
            .with(filter)
            .with(layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(true))
            .init();
    }

    info!("Tracing initialized at level: {}", log_level);
}
