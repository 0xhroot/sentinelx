#![no_main]

use libfuzzer_sys::fuzz_target;

use sentinelx_response::policies::PolicyEngine;
use sentinelx_response::types::ResponsePolicyConfig;

fuzz_target!(|data: &[u8]| {
    // Fuzz policy engine with random TOML config
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(config) = toml::from_str::<ResponsePolicyConfig>(s) {
            let engine = PolicyEngine::new(config);

            // Fuzz policy matching with random inputs
            let _ = engine.find_matching_policies("critical", 1.0, "malware");
            let _ = engine.find_matching_policies("high", 0.5, "rootkit");
            let _ = engine.find_matching_policies("low", 0.1, "suspicious");
            let _ = engine.find_matching_policies(s, 0.5, s);
            let _ = engine.best_matching_policy(s, 0.5, s);
        }
    }

    // Fuzz severity comparison
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sentinelx_response::types::severity_meets_threshold(s, "high");
        let _ = sentinelx_response::types::severity_meets_threshold(s, s);
    }
});
