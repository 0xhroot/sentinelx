#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz API request JSON parsing
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(s) {
            // Simulate parsing various API request types
            let _ = json_value.get("type");
            let _ = json_value.get("data");
            let _ = json_value.get("id");
            let _ = json_value.get("timestamp");

            // Try to extract common API fields
            if let Some(obj) = json_value.as_object() {
                for (key, value) in obj {
                    let _ = key.as_str();
                    let _ = value.is_string();
                    let _ = value.is_number();
                    let _ = value.is_object();
                    let _ = value.is_array();
                }
            }
        }
    }
});
