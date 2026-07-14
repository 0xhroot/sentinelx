use std::sync::Arc;

use crate::commands::{BOLD, CYAN, GREEN, RED, RESET};

pub async fn run(object_type: Option<String>) {
    println!("{}{}SentinelX Assessment Engine{}", BOLD, CYAN, RESET);
    println!();

    let config = sentinelx_assessment::ScoringConfig::load_default();
    let store = sentinelx_assessment::AssessmentStore::new();

    let assessors: Vec<Arc<dyn sentinelx_assessment::Assessor>> = vec![
        Arc::new(sentinelx_assessment::ProcessAssessor),
        Arc::new(sentinelx_assessment::ModuleAssessor),
        Arc::new(sentinelx_assessment::NetworkAssessor),
        Arc::new(sentinelx_assessment::ServiceAssessor),
        Arc::new(sentinelx_assessment::FileAssessor),
        Arc::new(sentinelx_assessment::MemoryAssessor),
        Arc::new(sentinelx_assessment::KernelAssessor),
    ];

    let filtered: Vec<_> = if let Some(ref filter) = object_type {
        assessors
            .iter()
            .filter(|a| {
                a.supported_object_types()
                    .iter()
                    .any(|t| t.as_str() == filter.as_str())
            })
            .cloned()
            .collect()
    } else {
        assessors
    };

    if filtered.is_empty() {
        println!(
            "{}No assessors found for object type: {}{}",
            RED,
            object_type.unwrap_or_default(),
            RESET
        );
        return;
    }

    println!("{}Loaded assessors:{} {}", BOLD, RESET, filtered.len());
    println!();

    for assessor in &filtered {
        println!(
            "{}  * {}{}{} - {}",
            GREEN,
            BOLD,
            assessor.name(),
            RESET,
            assessor.description()
        );
        let types: Vec<String> = assessor
            .supported_object_types()
            .iter()
            .map(|t| t.as_str().to_string())
            .collect();
        println!("    {}Types:{} {}", CYAN, RESET, types.join(", "));
    }

    println!();
    println!("{}Scoring Config:{}", BOLD, RESET);
    println!(
        "  {}Trust base:{}     {}   {}Risk base:{}      {}",
        CYAN, RESET, config.trust.base, CYAN, RESET, config.risk.base
    );
    println!(
        "  {}Integrity base:{} {}   {}Reputation base:{} {}",
        CYAN, RESET, config.integrity.base, CYAN, RESET, config.reputation.base
    );
    println!(
        "  {}Confidence base:{} {}",
        CYAN, RESET, config.confidence.base
    );

    println!();
    println!(
        "{}Assessment store:{} {} objects assessed",
        CYAN,
        RESET,
        store.object_count().await
    );
    println!();
    println!("{}{}Assessment engine ready.{}", GREEN, BOLD, RESET);
}
