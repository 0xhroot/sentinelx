use crate::commands::{BOLD, CYAN, GREEN, RED, RESET, YELLOW};

pub async fn run() {
    println!("{}{}SentinelX Response Audit Log{}", BOLD, CYAN, RESET);
    println!();

    let engine = sentinelx_response::ResponseEngine::with_default_config();
    let audit = engine.audit_log();

    if audit.count() == 0 {
        println!(
            "{}No audit records.{} Run the pipeline with threats to generate response audit entries.",
            GREEN, RESET
        );
        println!();
        println!(
            "{}Tip:{} Use `sentinelx scan` to run a full scan, then check audit logs.",
            CYAN, RESET
        );
        return;
    }

    let summary = audit.summary();
    println!("{}Audit Summary:{}", BOLD, RESET);
    println!("  {}Total:{} {}", CYAN, RESET, summary.total);
    println!("  {}Succeeded:{} {}", GREEN, RESET, summary.succeeded);
    println!("  {}Failed:{} {}", RED, RESET, summary.failed);
    println!("  {}Skipped:{} {}", YELLOW, RESET, summary.skipped);
    println!("  {}Rollbacks:{} {}", YELLOW, RESET, summary.rollbacks);
    println!("  {}Dry Run:{} {}", CYAN, RESET, summary.dry_run);
    println!();

    println!("{}Recent Audit Records:{}", BOLD, RESET);
    let records = audit.records();
    for (i, record) in records.iter().rev().take(20).enumerate() {
        let color = match &record.result {
            sentinelx_response::WorkflowStepResult::Success => GREEN,
            sentinelx_response::WorkflowStepResult::Failed(_) => RED,
            sentinelx_response::WorkflowStepResult::Skipped(_) => YELLOW,
            sentinelx_response::WorkflowStepResult::RolledBack => YELLOW,
        };
        let result_str = match &record.result {
            sentinelx_response::WorkflowStepResult::Success => "success",
            sentinelx_response::WorkflowStepResult::Failed(_) => "failed",
            sentinelx_response::WorkflowStepResult::Skipped(_) => "skipped",
            sentinelx_response::WorkflowStepResult::RolledBack => "rolled_back",
        };
        let dry = if record.dry_run { " [DRY]" } else { "" };
        println!(
            "{}[{}]{} {}{}{} {}{}{} ({}ms){}",
            BOLD,
            i + 1,
            RESET,
            color,
            result_str,
            RESET,
            BOLD,
            record.action.as_str(),
            RESET,
            record.duration_ms,
            dry
        );
        println!(
            "   {}Workflow:{} {}   {}Threat:{} {}   {}Action:{} {}",
            CYAN,
            RESET,
            record.workflow_name,
            CYAN,
            RESET,
            &record.threat_id.to_string()[..8],
            CYAN,
            RESET,
            record.action.parameter_summary()
        );
        if record.rollback_status != sentinelx_response::RollbackStatus::None {
            println!(
                "   {}Rollback:{} {:?}",
                YELLOW, RESET, record.rollback_status
            );
        }
        if !record.errors.is_empty() {
            println!("   {}Errors:{} {:?}", RED, RESET, record.errors);
        }
        println!();
    }

    println!("{}{}Audit engine ready.{}", GREEN, BOLD, RESET);
}
