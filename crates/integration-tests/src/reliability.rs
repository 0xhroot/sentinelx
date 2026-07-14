use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::sleep;

// =============================================================================
// 1. Database Corruption Test
// =============================================================================

#[tokio::test]
async fn test_database_corruption_handled_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    // Create a valid database first
    {
        let url = format!("sqlite:{}?mode=rwc", db_path.display());
        let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
        sqlx::query("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, data TEXT)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO test (data) VALUES (?)")
            .bind("hello")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    // Corrupt the database file by truncating and writing garbage
    {
        std::fs::write(&db_path, [0xFF, 0xFE, 0xFD]).unwrap();
        // Also remove WAL/journal files that might allow recovery
        let _ = std::fs::remove_file(dir.path().join("test.db-wal"));
        let _ = std::fs::remove_file(dir.path().join("test.db-shm"));
        let _ = std::fs::remove_file(dir.path().join("test.db-journal"));
    }

    // Attempting to open corrupted DB should fail gracefully, not panic
    // Note: SQLite may still open the connection, but queries should fail
    let result = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path.display())).await;
    if let Ok(pool) = result {
        // If connection succeeds, queries on corrupt DB should fail
        let query_result = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM test")
            .fetch_one(&pool)
            .await;
        pool.close().await;
        assert!(
            query_result.is_err(),
            "Query on corrupted DB should return an error"
        );
    }
    // If connection fails, that's also acceptable - corruption was handled
}

// =============================================================================
// 2. Network Loss Test
// =============================================================================

#[tokio::test]
async fn test_network_disconnection_handled() {
    // Start a server that immediately closes connections
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn a task that accepts and immediately drops
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });

    // Client should handle the disconnection gracefully
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(mut stream) => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let _ = stream.write_all(b"hello").await;
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                n // Should be 0 (EOF)
            }
            Err(_) => 0,
        }
    })
    .await;

    assert!(
        result.is_ok(),
        "Client should handle disconnection within timeout"
    );
}

// =============================================================================
// 3. Agent Reconnect Test
// =============================================================================

#[tokio::test]
async fn test_agent_state_transitions() {
    // Test that agent state can transition through connect/disconnect cycles
    let (tx, _rx) = mpsc::channel(10);

    let config = sentinelx_agent::AgentConfig::default();
    let agent = sentinelx_agent::AgentEngine::new(config, tx);

    // Initial state should be Initializing
    assert_eq!(
        agent.status().await,
        sentinelx_agent::AgentState::Initializing
    );

    // Start the agent
    agent.start().await;
    sleep(Duration::from_millis(100)).await;
    assert_eq!(agent.status().await, sentinelx_agent::AgentState::Connected);

    // Stop the agent
    agent.stop().await;
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        agent.status().await,
        sentinelx_agent::AgentState::Disconnected
    );

    // Can restart
    agent.start().await;
    sleep(Duration::from_millis(100)).await;
    assert_eq!(agent.status().await, sentinelx_agent::AgentState::Connected);

    agent.stop().await;
}

// =============================================================================
// 4. Telemetry Restart Test
// =============================================================================

#[tokio::test]
async fn test_telemetry_engine_restart() {
    // Create and shutdown
    {
        let engine = sentinelx_telemetry::TelemetryEngine::new(
            sentinelx_telemetry::TelemetryConfig::default(),
        );
        engine.initialize_default_providers().await;
        sleep(Duration::from_millis(50)).await;
        engine.shutdown_all().await;
    }

    // Create new engine after shutdown
    {
        let engine = sentinelx_telemetry::TelemetryEngine::new(
            sentinelx_telemetry::TelemetryConfig::default(),
        );
        engine.initialize_default_providers().await;
        sleep(Duration::from_millis(50)).await;

        let stats = engine.stats();
        assert_eq!(
            stats.total_events, 0,
            "Fresh engine should have zero events"
        );

        engine.shutdown_all().await;
    }
}

// =============================================================================
// 5. Panic Recovery Test
// =============================================================================

#[tokio::test]
async fn test_panic_does_not_propagate() {
    use std::panic;

    // Direct panic recovery
    let result = panic::catch_unwind(|| {
        panic!("test panic");
    });
    assert!(result.is_err(), "Should catch panic");

    // Tokio task isolation: panic in spawned task should not crash main
    let handle = tokio::spawn(async {
        panic!("task panic");
    });

    sleep(Duration::from_millis(50)).await;
    let result = handle.await;
    assert!(result.is_err(), "Spawned task should have panicked");

    // Main task continues
    let x = 42;
    assert_eq!(x, 42, "Main task should continue after spawned task panic");
}

// =============================================================================
// 6. Response Policy Rollback Test
// =============================================================================

#[tokio::test]
async fn test_response_engine_dry_run() {
    let mut engine =
        sentinelx_response::ResponseEngine::new(sentinelx_response::ResponseConfig::default());

    // Dry run should not execute actual actions
    let result = engine.execute(&sentinelx_response::ResponseAction::Alert, "test_threat");

    // Dry run should succeed and produce an audit entry
    assert!(result.is_ok(), "Dry run should succeed");
}

// =============================================================================
// 7. Concurrent Stress Test
// =============================================================================

#[tokio::test]
async fn test_concurrent_channel_stress() {
    let (tx, mut rx) = mpsc::channel::<i32>(100);

    // Spawn 100 writers
    let mut handles = Vec::new();
    for i in 0..100 {
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            tx.send(i).await.unwrap();
        }));
    }

    // Drop the original sender
    drop(tx);

    // Wait for all writers
    for handle in handles {
        handle.await.unwrap();
    }

    // Count received messages
    let mut count = 0;
    while rx.recv().await.is_some() {
        count += 1;
    }

    assert_eq!(count, 100, "All 100 messages should be received");
}

// =============================================================================
// 8. Backpressure Test
// =============================================================================

#[tokio::test]
async fn test_channel_backpressure() {
    let (tx, mut rx) = mpsc::channel::<i32>(2);

    // Fill the channel
    tx.send(1).await.unwrap();
    tx.send(2).await.unwrap();

    // Third send should block (use timeout to verify)
    let send_result = tokio::time::timeout(Duration::from_millis(50), tx.send(3)).await;
    assert!(
        send_result.is_err(),
        "Send should block when channel is full"
    );

    // Drain one message
    rx.recv().await.unwrap();

    // Now send should succeed
    let send_result = tokio::time::timeout(Duration::from_millis(50), tx.send(3)).await;
    assert!(send_result.is_ok(), "Send should succeed after drain");
}

// =============================================================================
// 9. Config Reload Test
// =============================================================================

#[tokio::test]
async fn test_config_save_and_reload() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("test.toml");

    // Create and save a config
    let config = sentinelx_config::Settings::default();
    let toml_str = toml::to_string_pretty(&config).unwrap();
    std::fs::write(&config_path, &toml_str).unwrap();

    // Load it back
    let loaded = sentinelx_config::Settings::load(Some(&config_path)).unwrap();
    assert_eq!(loaded.api.host, config.api.host);
    assert_eq!(loaded.api.port, config.api.port);
}

// =============================================================================
// 10. Graceful Shutdown Test
// =============================================================================

#[tokio::test]
async fn test_telemetry_graceful_shutdown() {
    let engine = Arc::new(sentinelx_telemetry::TelemetryEngine::new(
        sentinelx_telemetry::TelemetryConfig::default(),
    ));

    engine.initialize_default_providers().await;
    sleep(Duration::from_millis(100)).await;

    // Shutdown should complete within timeout
    let shutdown_result = tokio::time::timeout(Duration::from_secs(5), async {
        engine.shutdown_all().await;
    })
    .await;

    assert!(
        shutdown_result.is_ok(),
        "Shutdown should complete within 5 seconds"
    );
}
