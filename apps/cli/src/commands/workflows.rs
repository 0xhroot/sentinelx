use crate::commands::{BOLD, CYAN, GREEN, RESET};

pub async fn run() {
    println!("{}{}SentinelX Workflows & Policies{}", BOLD, CYAN, RESET);
    println!();

    let engine = sentinelx_response::ResponseEngine::with_default_config();

    println!("{}Safety Configuration:{}", BOLD, RESET);
    let safety = engine.safety();
    println!(
        "  {}Dry Run:{} {}",
        CYAN,
        RESET,
        if safety.dry_run {
            "ENABLED"
        } else {
            "disabled"
        }
    );
    println!(
        "  {}Never Kill Init:{} {}",
        CYAN,
        RESET,
        if safety.never_kill_init {
            "yes (PID 1 protected)"
        } else {
            "no"
        }
    );
    println!(
        "  {}Never Unload Core Modules:{} {}",
        CYAN,
        RESET,
        if safety.never_unload_core_modules {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "  {}Protected PIDs:{} {:?}",
        CYAN, RESET, safety.protected_pids
    );
    println!(
        "  {}Protected Modules:{} {:?}",
        CYAN, RESET, safety.protected_modules
    );
    println!();

    println!("{}Workflows:{}", BOLD, RESET);
    let workflows = engine.workflow_engine().workflows();
    for wf in workflows {
        println!("  {} * {}{} - {}", GREEN, BOLD, wf.name, RESET);
        println!("    {}", wf.description);
        println!(
            "    {}Trigger:{} severity >= {}   {}Steps:{} {}",
            CYAN,
            RESET,
            wf.trigger_severity,
            CYAN,
            RESET,
            wf.steps.len()
        );
        for (j, step) in wf.steps.iter().enumerate() {
            let dry = if step.action.is_dangerous() {
                " [DANGEROUS]"
            } else {
                ""
            };
            println!("      {}. {}{}", j + 1, step.description, dry,);
            println!(
                "         Action: {}{}   Params: {}",
                step.action.as_str(),
                dry,
                step.action.parameter_summary()
            );
            if let Some(ref rollback) = step.rollback_action {
                println!("         {}Rollback:{} {}", CYAN, RESET, rollback.as_str());
            }
        }
        println!();
    }

    println!("{}Policies:{}", BOLD, RESET);
    let policies = engine.policy_engine().policies();
    for policy in policies {
        println!("  {} * {}{} - {}", GREEN, BOLD, policy.name, RESET);
        println!("    {}", policy.description);
        println!(
            "    {}Severity:{} >= {}   {}Confidence:{} >= {:.0}%",
            CYAN,
            RESET,
            policy.severity_threshold,
            CYAN,
            RESET,
            policy.confidence_threshold * 100.0
        );
        println!(
            "    {}Actions:{} {}",
            CYAN,
            RESET,
            policy.allowed_actions.join(", ")
        );
        println!(
            "    {}Timeout:{} {}s   {}Approval:{} {}",
            CYAN,
            RESET,
            policy.timeout_seconds,
            CYAN,
            RESET,
            if policy.approval_required {
                "required"
            } else {
                "not required"
            }
        );
        println!();
    }

    println!("{}{}Workflows engine ready.{}", GREEN, BOLD, RESET);
}
