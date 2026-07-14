use crate::commands::{BOLD, CYAN, GREEN, RED, RESET};

pub async fn run() {
    println!("{}{}SentinelX Response History{}", BOLD, CYAN, RESET);
    println!();

    let engine = sentinelx_response::ResponseEngine::with_default_config();
    let history = engine.history();
    let config = engine.config();
    let safety = engine.safety();

    println!("{}Configuration:{}", BOLD, RESET);
    println!(
        "  {}Enabled:{} {}",
        CYAN,
        RESET,
        if config.enabled { "yes" } else { "no" }
    );
    println!(
        "  {}Dry Run:{} {}",
        CYAN,
        RESET,
        if config.dry_run { "yes" } else { "no" }
    );
    println!(
        "  {}Safety - Kill Init:{} {}",
        CYAN,
        RESET,
        if safety.never_kill_init {
            "protected"
        } else {
            "not protected"
        }
    );
    println!(
        "  {}Safety - Core Modules:{} {}",
        CYAN,
        RESET,
        if safety.never_unload_core_modules {
            "protected"
        } else {
            "not protected"
        }
    );
    println!();

    if history.is_empty() {
        println!(
            "{}No response history.{} Run the pipeline to generate threats that trigger responses.",
            GREEN, RESET
        );
        return;
    }

    println!(
        "{}Response History:{} {} records",
        BOLD,
        RESET,
        history.len()
    );
    println!();

    for (i, record) in history.iter().rev().take(20).enumerate() {
        let color = if record.success { GREEN } else { RED };
        let dry = if record.dry_run { " [DRY RUN]" } else { "" };
        println!(
            "{}[{}]{} {}{}{} {}{}{}",
            BOLD,
            i + 1,
            RESET,
            color,
            record.action.as_str(),
            RESET,
            BOLD,
            record.action.parameter_summary(),
            RESET
        );
        println!(
            "   {}Threat:{} {}   {}Result:{} {}{}",
            CYAN,
            RESET,
            &record.threat_id.to_string()[..8],
            CYAN,
            RESET,
            if record.success { "success" } else { "failed" },
            dry
        );
    }

    println!();
    println!("{}{}Response engine ready.{}", GREEN, BOLD, RESET);
}
