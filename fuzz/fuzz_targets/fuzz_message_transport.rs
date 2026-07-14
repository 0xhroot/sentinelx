#![no_main]

use libfuzzer_sys::fuzz_target;

use sentinelx_transport::deserialize_message;

fuzz_target!(|data: &[u8]| {
    // Fuzz message deserialization from raw bytes
    let _ = deserialize_message(data);

    // Fuzz JSON-based message parsing
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = serde_json::from_value::<sentinelx_transport::MessageEnvelope>(json_value);
        }
    }

    // Fuzz Message struct deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = serde_json::from_value::<sentinelx_transport::Message>(json_value);
        }
    }
});
