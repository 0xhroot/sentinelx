#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz SQL query construction with random inputs
    if let Ok(s) = std::str::from_utf8(data) {
        // Test that random strings don't cause panics in query construction
        let _ = sqlx::query(s);

        // Test parameter binding with random values
        let _ = sqlx::query("SELECT * FROM test WHERE id = ?")
            .bind(s);

        // Test random LIKE patterns
        let _ = sqlx::query("SELECT * FROM test WHERE name LIKE ?")
            .bind(format!("%{}%", s));

        // Test random ORDER BY
        let _ = sqlx::query(&format!("SELECT * FROM test ORDER BY {}", s));
    }
});
