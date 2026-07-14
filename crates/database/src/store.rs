use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;
use tracing::info;

use crate::error::Result;

pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn new(database_path: &str) -> Result<Self> {
        let options = SqliteConnectOptions::from_str(database_path)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5))
            .auto_vacuum(sqlx::sqlite::SqliteAutoVacuum::Full);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect_with(options)
            .await?;

        let store = Self { pool };
        store.run_migrations().await?;
        info!("Database initialized at {}", database_path);
        Ok(store)
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    async fn run_migrations(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                kind TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT,
                title TEXT,
                description TEXT,
                data TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);

            CREATE TABLE IF NOT EXISTS processes (
                pid INTEGER PRIMARY KEY,
                ppid INTEGER NOT NULL,
                name TEXT NOT NULL,
                binary_path TEXT NOT NULL,
                uid INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                start_time TEXT NOT NULL,
                status TEXT NOT NULL,
                hash TEXT,
                namespace_pid INTEGER,
                namespace_net INTEGER,
                namespace_mnt INTEGER,
                first_seen TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS kernel_modules (
                name TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                load_address INTEGER NOT NULL,
                state TEXT NOT NULL,
                ref_count INTEGER NOT NULL DEFAULT 0,
                version TEXT,
                license TEXT,
                hash TEXT,
                signature_valid INTEGER,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                local_ip TEXT NOT NULL,
                local_port INTEGER NOT NULL,
                remote_ip TEXT,
                remote_port INTEGER,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                pid INTEGER,
                inode INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                process_name TEXT,
                process_hash TEXT,
                first_seen TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS integrity_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                hash TEXT NOT NULL,
                size INTEGER NOT NULL,
                permissions INTEGER NOT NULL,
                owner INTEGER NOT NULL,
                "group" INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(path)
            );

            CREATE TABLE IF NOT EXISTS threat_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '[]',
                mitre_attack TEXT NOT NULL DEFAULT '[]',
                source_detector TEXT NOT NULL,
                process_pid INTEGER,
                process_name TEXT,
                hash TEXT,
                tags TEXT NOT NULL DEFAULT '[]',
                acknowledged INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threat_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_threats_severity ON threat_events(severity);
            CREATE INDEX IF NOT EXISTS idx_threats_category ON threat_events(category);

            CREATE TABLE IF NOT EXISTS forensic_snapshots (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                hostname TEXT NOT NULL,
                kernel_version TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                threats_found INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'running'
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                description TEXT NOT NULL,
                data TEXT NOT NULL DEFAULT '{}',
                tags TEXT NOT NULL DEFAULT '[]',
                confidence REAL NOT NULL DEFAULT 1.0,
                related_evidence TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_evidence_timestamp ON evidence(timestamp);
            CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(evidence_type);
            CREATE INDEX IF NOT EXISTS idx_evidence_severity ON evidence(severity);
            CREATE INDEX IF NOT EXISTS idx_evidence_source ON evidence(source);

            CREATE TABLE IF NOT EXISTS assessment_results (
                id TEXT PRIMARY KEY,
                object_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                trust INTEGER NOT NULL,
                integrity INTEGER NOT NULL,
                risk INTEGER NOT NULL,
                reputation INTEGER NOT NULL,
                confidence REAL NOT NULL,
                reasons TEXT NOT NULL DEFAULT '[]',
                warnings TEXT NOT NULL DEFAULT '[]',
                metadata_references TEXT NOT NULL DEFAULT '[]',
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_assessment_object_id ON assessment_results(object_id);
            CREATE INDEX IF NOT EXISTS idx_assessment_timestamp ON assessment_results(timestamp);
            CREATE INDEX IF NOT EXISTS idx_assessment_risk ON assessment_results(risk);

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                evidence_ids TEXT NOT NULL DEFAULT '[]',
                object_ids TEXT NOT NULL DEFAULT '[]',
                assessment_ids TEXT NOT NULL DEFAULT '[]',
                related_processes TEXT NOT NULL DEFAULT '[]',
                related_files TEXT NOT NULL DEFAULT '[]',
                related_modules TEXT NOT NULL DEFAULT '[]',
                attack_chain TEXT NOT NULL DEFAULT '[]',
                mitre_mappings TEXT NOT NULL DEFAULT '[]',
                recommended_response TEXT,
                tags TEXT NOT NULL DEFAULT '[]',
                metadata TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
            CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);

            CREATE TABLE IF NOT EXISTS threat_decisions (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score_trust REAL NOT NULL DEFAULT 0,
                risk_score_integrity REAL NOT NULL DEFAULT 0,
                risk_score_risk REAL NOT NULL DEFAULT 0,
                risk_score_reputation REAL NOT NULL DEFAULT 0,
                risk_score_evidence_count REAL NOT NULL DEFAULT 0,
                risk_score_incident_complexity REAL NOT NULL DEFAULT 0,
                risk_score_rule_confidence REAL NOT NULL DEFAULT 0,
                risk_score_final REAL NOT NULL DEFAULT 0,
                confidence REAL NOT NULL,
                priority TEXT NOT NULL DEFAULT 'normal',
                mitre_mappings TEXT NOT NULL DEFAULT '[]',
                description TEXT NOT NULL,
                recommendation TEXT NOT NULL DEFAULT '',
                response_plan TEXT,
                created_at TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                metadata TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_threats_decision_severity ON threat_decisions(severity);
            CREATE INDEX IF NOT EXISTS idx_threats_decision_priority ON threat_decisions(priority);
            CREATE INDEX IF NOT EXISTS idx_threats_decision_incident ON threat_decisions(incident_id);

            CREATE TABLE IF NOT EXISTS correlation_graph (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                properties TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_graph_source ON correlation_graph(source_id);
            CREATE INDEX IF NOT EXISTS idx_graph_target ON correlation_graph(target_id);
            CREATE INDEX IF NOT EXISTS idx_graph_edge_type ON correlation_graph(edge_type);

            CREATE TABLE IF NOT EXISTS response_audit (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                threat_id TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                action_type TEXT NOT NULL,
                action_params TEXT NOT NULL DEFAULT '',
                result TEXT NOT NULL,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                errors TEXT NOT NULL DEFAULT '[]',
                rollback_status TEXT NOT NULL DEFAULT 'none',
                dry_run INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON response_audit(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_threat_id ON response_audit(threat_id);
            CREATE INDEX IF NOT EXISTS idx_audit_workflow ON response_audit(workflow_name);
            CREATE INDEX IF NOT EXISTS idx_audit_result ON response_audit(result);

            CREATE TABLE IF NOT EXISTS telemetry_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                provider TEXT NOT NULL,
                category TEXT NOT NULL,
                event_type TEXT NOT NULL,
                pid INTEGER,
                uid INTEGER,
                namespace TEXT,
                container TEXT,
                object_id TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_telemetry_pid ON telemetry_events(pid);
            CREATE INDEX IF NOT EXISTS idx_telemetry_provider ON telemetry_events(provider);
            CREATE INDEX IF NOT EXISTS idx_telemetry_category ON telemetry_events(category);
            CREATE INDEX IF NOT EXISTS idx_telemetry_event_type ON telemetry_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_telemetry_object_id ON telemetry_events(object_id);

            CREATE TABLE IF NOT EXISTS behavior_profiles (
                id TEXT PRIMARY KEY,
                object_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                execution_count INTEGER NOT NULL DEFAULT 0,
                connection_count INTEGER NOT NULL DEFAULT 0,
                privilege_changes INTEGER NOT NULL DEFAULT 0,
                persistence_events INTEGER NOT NULL DEFAULT 0,
                integrity_violations INTEGER NOT NULL DEFAULT 0,
                risk_trend TEXT NOT NULL DEFAULT '[]',
                confidence_trend TEXT NOT NULL DEFAULT '[]',
                historical_score REAL NOT NULL DEFAULT 0.0,
                categories TEXT NOT NULL DEFAULT '[]',
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_behavior_object_id ON behavior_profiles(object_id);
            CREATE INDEX IF NOT EXISTS idx_behavior_last_seen ON behavior_profiles(last_seen);
            CREATE INDEX IF NOT EXISTS idx_behavior_historical_score ON behavior_profiles(historical_score);

            CREATE TABLE IF NOT EXISTS iocs (
                id TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'medium',
                confidence REAL NOT NULL DEFAULT 0.5,
                source TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                tags TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                expiry TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type);
            CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value);
            CREATE INDEX IF NOT EXISTS idx_ioc_severity ON iocs(severity);

            CREATE TABLE IF NOT EXISTS yara_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                author TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'medium',
                tags TEXT NOT NULL DEFAULT '[]',
                rule_content TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_yara_name ON yara_rules(name);

            CREATE TABLE IF NOT EXISTS sigma_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                author TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'medium',
                tags TEXT NOT NULL DEFAULT '[]',
                logsource_category TEXT,
                logsource_product TEXT,
                logsource_service TEXT,
                detection_condition TEXT NOT NULL DEFAULT '',
                detection_fields TEXT NOT NULL DEFAULT '{}',
                falsepositives TEXT NOT NULL DEFAULT '[]',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_sigma_name ON sigma_rules(name);

            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'medium',
                cvss_score REAL NOT NULL DEFAULT 0.0,
                affected_products TEXT NOT NULL DEFAULT '[]',
                published_at TEXT NOT NULL,
                references_list TEXT NOT NULL DEFAULT '[]'
            );

            CREATE INDEX IF NOT EXISTS idx_cve_severity ON cves(severity);
            CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cves(cvss_score);

            CREATE TABLE IF NOT EXISTS fleet_agents (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                version TEXT NOT NULL DEFAULT '',
                kernel TEXT NOT NULL DEFAULT '',
                distribution TEXT NOT NULL DEFAULT '',
                architecture TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'healthy',
                registered_at TEXT NOT NULL,
                last_heartbeat TEXT,
                events_received INTEGER NOT NULL DEFAULT 0,
                incidents_received INTEGER NOT NULL DEFAULT 0,
                policies_sent INTEGER NOT NULL DEFAULT 0,
                actions_sent INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_fleet_agents_status ON fleet_agents(status);
            CREATE INDEX IF NOT EXISTS idx_fleet_agents_hostname ON fleet_agents(hostname);

            CREATE TABLE IF NOT EXISTS fleet_health (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                cpu_percent REAL NOT NULL DEFAULT 0.0,
                memory_used_bytes INTEGER NOT NULL DEFAULT 0,
                memory_total_bytes INTEGER NOT NULL DEFAULT 0,
                disk_used_bytes INTEGER NOT NULL DEFAULT 0,
                disk_total_bytes INTEGER NOT NULL DEFAULT 0,
                load_avg_1 REAL NOT NULL DEFAULT 0.0,
                load_avg_5 REAL NOT NULL DEFAULT 0.0,
                load_avg_15 REAL NOT NULL DEFAULT 0.0,
                active_telemetry_providers INTEGER NOT NULL DEFAULT 0,
                total_events INTEGER NOT NULL DEFAULT 0,
                total_threats INTEGER NOT NULL DEFAULT 0,
                total_incidents INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_fleet_health_agent_id ON fleet_health(agent_id);
            CREATE INDEX IF NOT EXISTS idx_fleet_health_timestamp ON fleet_health(timestamp);

            CREATE TABLE IF NOT EXISTS fleet_policies (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                policy_type TEXT NOT NULL,
                config TEXT NOT NULL DEFAULT '{}',
                version INTEGER NOT NULL DEFAULT 1,
                enabled INTEGER NOT NULL DEFAULT 1,
                distributed_to TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_fleet_policies_type ON fleet_policies(policy_type);

            CREATE TABLE IF NOT EXISTS remote_actions (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                params TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                result TEXT,
                error TEXT,
                duration_ms INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                completed_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_remote_actions_agent_id ON remote_actions(agent_id);
            CREATE INDEX IF NOT EXISTS idx_remote_actions_status ON remote_actions(status);

            CREATE TABLE IF NOT EXISTS heartbeat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'healthy',
                cpu_percent REAL NOT NULL DEFAULT 0.0,
                memory_used_bytes INTEGER NOT NULL DEFAULT 0,
                memory_total_bytes INTEGER NOT NULL DEFAULT 0,
                total_events INTEGER NOT NULL DEFAULT 0,
                total_threats INTEGER NOT NULL DEFAULT 0,
                total_incidents INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_heartbeat_history_agent_id ON heartbeat_history(agent_id);
            CREATE INDEX IF NOT EXISTS idx_heartbeat_history_timestamp ON heartbeat_history(timestamp);
            "#,
        )
        .execute(&self.pool)
        .await?;

        info!("Database migrations completed");
        Ok(())
    }
}
