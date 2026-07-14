use sentinelx_intelligence::engine::IntelligenceEngine;
use sentinelx_intelligence::types::{IoC, IoCType};

use super::{BOLD, CYAN, GREEN, MAGENTA, RED, RESET, YELLOW};

pub async fn run() {
    println!("{}{}Threat Intelligence Engine{}", BOLD, CYAN, RESET);
    println!();

    let engine = IntelligenceEngine::new();
    let stats = engine.stats().await;

    println!("{}Status:{}", BOLD, GREEN);
    println!("  Engine initialized with offline intelligence");
    println!();

    println!("{}Intelligence Summary:{}", BOLD, MAGENTA);
    println!("  {}IoCs:{} {}", BOLD, RESET, stats.total_iocs);
    println!(
        "  {}MITRE Techniques:{} {}",
        BOLD, RESET, stats.total_mitre_techniques
    );
    println!("  {}YARA Rules:{} {}", BOLD, RESET, stats.total_yara_rules);
    println!(
        "  {}Sigma Rules:{} {}",
        BOLD, RESET, stats.total_sigma_rules
    );
    println!("  {}CVEs:{} {}", BOLD, RESET, stats.total_cves);
    println!();

    if !stats.iocs_by_type.is_empty() {
        println!("{}IoCs by Type:{}", BOLD, MAGENTA);
        for (ioc_type, count) in &stats.iocs_by_type {
            println!("  {}{}:{} {}", CYAN, ioc_type, RESET, count);
        }
        println!();
    }

    println!("{}MITRE ATT&CK Coverage:{}", BOLD, MAGENTA);
    let techniques = engine.list_mitre_techniques().await;
    let mut tactics: std::collections::HashMap<String, Vec<&str>> =
        std::collections::HashMap::new();
    for t in &techniques {
        tactics.entry(t.tactic.clone()).or_default().push(&t.id);
    }
    for (tactic, ids) in &tactics {
        println!("  {}{}:{} {}", CYAN, tactic, RESET, ids.join(", "));
    }
    println!();

    println!("{}IoC Types:{}", BOLD, MAGENTA);
    let ioc_types = [
        ("hash", "File hashes (MD5, SHA1, SHA256)"),
        ("ip_address", "Malicious IP addresses"),
        ("domain", "Malicious domains"),
        ("filename", "Known malicious filenames"),
        ("process_name", "Suspicious process names"),
        ("module_name", "Malicious kernel modules"),
        ("url", "Malicious URLs"),
        ("email", "Phishing/spam emails"),
    ];
    for (ioc_type, desc) in &ioc_types {
        println!("  {}{}{} - {}", CYAN, ioc_type, RESET, desc);
    }
    println!();
}

pub async fn run_mitre() {
    println!("{}{}MITRE ATT&CK Matrix{}", BOLD, CYAN, RESET);
    println!();

    let engine = IntelligenceEngine::new();
    let techniques = engine.list_mitre_techniques().await;

    let mut tactics: std::collections::HashMap<
        String,
        Vec<&sentinelx_intelligence::types::MitreTechnique>,
    > = std::collections::HashMap::new();
    for t in &techniques {
        tactics.entry(t.tactic.clone()).or_default().push(t);
    }

    let mut sorted_tactics: Vec<_> = tactics.iter().collect();
    sorted_tactics.sort_by_key(|(tactic, _)| tactic.to_lowercase());

    for (tactic, techs) in &sorted_tactics {
        println!("{}[{}]{}", BOLD, tactic, RESET);
        for t in *techs {
            println!(
                "  {}{}{} {} - {}{}",
                GREEN, t.id, RESET, BOLD, t.name, RESET
            );
            if !t.description.is_empty() {
                println!("    {}", t.description);
            }
        }
        println!();
    }
}

pub async fn run_iocs() {
    println!("{}{}Indicators of Compromise (IoCs){}", BOLD, CYAN, RESET);
    println!();

    let engine = IntelligenceEngine::new();
    let iocs = engine.list_iocs_limit(50).await;

    if iocs.is_empty() {
        println!("  {}No IoCs loaded{}", YELLOW, RESET);
        println!();
        println!("  IoCs can be added via the API or loaded from threat intelligence feeds.");
        println!("  Supported types: hash, ip_address, domain, filename, process_name, module_name, url, email");
        return;
    }

    println!("{}Loaded IoCs:{} {}", BOLD, RESET, iocs.len());
    println!();

    for (i, ioc) in iocs.iter().enumerate() {
        let severity_color = match ioc.severity.as_str() {
            "critical" => RED,
            "high" => YELLOW,
            "medium" => MAGENTA,
            _ => GREEN,
        };

        println!(
            "{}[{}]{} {}{}{}{}",
            BOLD,
            i + 1,
            RESET,
            severity_color,
            ioc.severity,
            RESET,
            BOLD,
        );
        println!(
            "  {}{}: {}{}",
            BOLD,
            ioc.ioc_type.as_str(),
            ioc.value,
            RESET
        );
        if !ioc.description.is_empty() {
            println!("    {}", ioc.description);
        }
        println!(
            "    {}Source:{} {}   {}Confidence:{} {:.0}%",
            CYAN,
            RESET,
            ioc.source,
            CYAN,
            RESET,
            ioc.confidence * 100.0,
        );
        println!();
    }
}

pub async fn run_ioc_check(ioc_type_str: &str, value: &str) {
    println!(
        "{}{}Checking IoC:{} {}:{}{}",
        BOLD, CYAN, RESET, ioc_type_str, value, RESET
    );
    println!();

    let engine = IntelligenceEngine::new();

    if let Some(_ioc_type) = IoCType::parse_from(ioc_type_str) {
        // Seed with some known IOCs for demo
        engine
            .add_ioc(
                IoC::new(IoCType::Hash, "abc123def456", "demo_feed")
                    .with_severity("critical")
                    .with_confidence(0.95)
                    .with_description("Known malware hash"),
            )
            .await;

        let found = engine.get_ioc_by_str(ioc_type_str, value).await;
        match found {
            Some(ioc) => {
                let severity_color = match ioc.severity.as_str() {
                    "critical" => RED,
                    "high" => YELLOW,
                    _ => MAGENTA,
                };
                println!("{}FOUND!{}", RED, BOLD);
                println!(
                    "  {}Severity:{} {}{}{}",
                    BOLD, RESET, severity_color, ioc.severity, RESET
                );
                println!("  {}Source:{} {}", BOLD, RESET, ioc.source);
                println!(
                    "  {}Confidence:{} {:.0}%",
                    BOLD,
                    RESET,
                    ioc.confidence * 100.0
                );
                if !ioc.description.is_empty() {
                    println!("  {}Description:{} {}", BOLD, RESET, ioc.description);
                }
            }
            None => {
                println!("{}NOT FOUND{}", GREEN, RESET);
                println!("  IoC is not currently flagged as malicious.");
            }
        }
    } else {
        println!("{}Invalid IoC type:{} {}", RED, RESET, ioc_type_str);
        println!("  Valid types: hash, ip_address, domain, filename, process_name, module_name, url, email");
    }
    println!();
}

pub async fn run_cves() {
    println!("{}{}Known Vulnerabilities (CVEs){}", BOLD, CYAN, RESET);
    println!();

    let engine = IntelligenceEngine::new();
    let cves = engine.list_cves_limit(50).await;

    if cves.is_empty() {
        println!("  {}No CVEs loaded{}", YELLOW, RESET);
        println!();
        println!("  CVEs can be added via the API for vulnerability tracking.");
        return;
    }

    println!("{}Loaded CVEs:{} {}", BOLD, RESET, cves.len());
    println!();

    for (i, cve) in cves.iter().enumerate() {
        let severity_color = match cve.severity.as_str() {
            "critical" => RED,
            "high" => YELLOW,
            "medium" => MAGENTA,
            _ => GREEN,
        };

        println!(
            "{}[{}]{} {}{}{} {}{}{}",
            BOLD,
            i + 1,
            RESET,
            severity_color,
            cve.severity,
            RESET,
            BOLD,
            cve.id,
            RESET,
        );
        println!("  {}CVSS:{} {:.1}", BOLD, RESET, cve.cvss_score);
        if !cve.description.is_empty() {
            println!("    {}", cve.description);
        }
        if !cve.affected_products.is_empty() {
            println!(
                "    {}Products:{} {}",
                CYAN,
                RESET,
                cve.affected_products.join(", ")
            );
        }
        println!();
    }
}

pub async fn run_yara() {
    println!("{}{}YARA Rules{}", BOLD, CYAN, RESET);
    println!();

    let engine = IntelligenceEngine::new();
    let rules = engine.list_yara_rules().await;

    if rules.is_empty() {
        println!("  {}No YARA rules loaded{}", YELLOW, RESET);
        println!();
        println!("  YARA rules can be added via the API for malware pattern matching.");
        return;
    }

    println!("{}Loaded Rules:{} {}", BOLD, RESET, rules.len());
    println!();

    for (i, rule) in rules.iter().enumerate() {
        let severity_color = match rule.severity.as_str() {
            "critical" => RED,
            "high" => YELLOW,
            "medium" => MAGENTA,
            _ => GREEN,
        };

        println!(
            "{}[{}]{} {}{}{} {}{}{}",
            BOLD,
            i + 1,
            RESET,
            severity_color,
            rule.severity,
            RESET,
            BOLD,
            rule.name,
            RESET,
        );
        if !rule.description.is_empty() {
            println!("    {}", rule.description);
        }
        println!(
            "    {}Author:{} {}   {}Enabled:{} {}",
            CYAN, RESET, rule.author, CYAN, RESET, rule.enabled,
        );
        if !rule.tags.is_empty() {
            println!("    {}Tags:{} {}", CYAN, RESET, rule.tags.join(", "));
        }
        println!();
    }
}

pub async fn run_sigma() {
    println!("{}{}Sigma Detection Rules{}", BOLD, CYAN, RESET);
    println!();

    let engine = IntelligenceEngine::new();
    let rules = engine.list_sigma_rules().await;

    if rules.is_empty() {
        println!("  {}No Sigma rules loaded{}", YELLOW, RESET);
        println!();
        println!("  Sigma rules can be added via the API for SIEM-compatible detection.");
        return;
    }

    println!("{}Loaded Rules:{} {}", BOLD, RESET, rules.len());
    println!();

    for (i, rule) in rules.iter().enumerate() {
        let severity_color = match rule.severity.as_str() {
            "critical" => RED,
            "high" => YELLOW,
            "medium" => MAGENTA,
            _ => GREEN,
        };

        println!(
            "{}[{}]{} {}{}{} {}{}{}",
            BOLD,
            i + 1,
            RESET,
            severity_color,
            rule.severity,
            RESET,
            BOLD,
            rule.name,
            RESET,
        );
        if !rule.description.is_empty() {
            println!("    {}", rule.description);
        }
        println!(
            "    {}Condition:{} {}",
            CYAN, RESET, rule.detection.condition
        );
        if !rule.tags.is_empty() {
            println!("    {}Tags:{} {}", CYAN, RESET, rule.tags.join(", "));
        }
        println!();
    }
}
