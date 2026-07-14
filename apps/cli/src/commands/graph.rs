use crate::commands::{BOLD, CYAN, GREEN, RESET};

pub async fn run() {
    println!("{}{}SentinelX Correlation Graph{}", BOLD, CYAN, RESET);
    println!();

    let graph = sentinelx_correlation::InMemoryGraph::new();

    println!("{}Graph Status:{}", BOLD, RESET);
    println!(
        "  {}Nodes:{} {} (empty - run pipeline to populate)",
        CYAN,
        RESET,
        graph.node_count()
    );
    println!(
        "  {}Edges:{} {} (empty - run pipeline to populate)",
        CYAN,
        RESET,
        graph.edge_count()
    );
    println!();

    println!("{}Relationship Types:{}", BOLD, RESET);
    println!("  {}spawned{}    - Process spawned Process", CYAN, RESET);
    println!("  {}opened{}     - Process opened File/Socket", CYAN, RESET);
    println!(
        "  {}connected{}  - Process connected to Network",
        CYAN, RESET
    );
    println!(
        "  {}loaded{}     - Process loaded Kernel Module",
        CYAN, RESET
    );
    println!("  {}modified{}   - Process modified File", CYAN, RESET);
    println!("  {}created{}    - Process created Service", CYAN, RESET);
    println!(
        "  {}executes{}   - Service executes Executable",
        CYAN, RESET
    );
    println!("  {}owns{}       - User owns Process", CYAN, RESET);
    println!();

    println!("{}Correlation Rules:{}", BOLD, RESET);
    let config = sentinelx_correlation::CorrelationRuleConfig::load_default();
    for rule in config.enabled_rules() {
        println!("  {} * {}{} - {}", GREEN, BOLD, rule.name, RESET);
        println!("    {}", rule.description);
        println!(
            "    {}Requires:{} {:?}   {}Min Evidence:{} {}",
            CYAN, RESET, rule.requires, CYAN, RESET, rule.min_evidence
        );
    }

    println!();
    println!(
        "{}{}Graph engine ready. Run the full pipeline to populate with data.{}",
        GREEN, BOLD, RESET
    );
}
