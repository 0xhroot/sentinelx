#![no_main]

use libfuzzer_sys::fuzz_target;

use sentinelx_telemetry::types::TelemetryEvent;

fuzz_target!(|data: &[u8]| {
    // Fuzz TelemetryEvent JSON deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(s) {
            // Try to deserialize as TelemetryEvent
            let _ = serde_json::from_value::<TelemetryEvent>(json_value);
        }
    }

    // Fuzz from raw bytes via JSON
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(event) = serde_json::from_str::<TelemetryEvent>(s) {
            // Roundtrip: serialize back
            let _ = serde_json::to_string(&event);
            let _ = serde_json::to_value(&event);
        }
    }
});
