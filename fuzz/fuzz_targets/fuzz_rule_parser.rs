#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz TOML rule parsing
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse as ResponsePolicyConfig
        let _ = toml::from_str::<sentinelx_response::types::ResponsePolicyConfig>(s);

        // Try to parse as generic TOML value
        if let Ok(value) = toml::from_str::<toml::Value>(s) {
            let _ = value.as_table();
            let _ = value.get("rules");
            let _ = value.get("policies");
        }
    }
});
