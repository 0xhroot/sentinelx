use crate::error::{ConfigError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DEFAULT_CONFIG_FILE: &str = "sentinelx.toml";
const DEFAULT_DB_PATH: &str = "/var/lib/sentinelx/sentinelx.db";
const DEFAULT_LOG_LEVEL: &str = "info";
const MAX_MEMORY_MB: u64 = 150;
const MAX_CPU_PERCENT: f64 = 3.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub general: GeneralSettings,
    pub detection: DetectionSettings,
    pub monitoring: MonitoringSettings,
    pub storage: StorageSettings,
    pub api: ApiSettings,
    pub logging: LoggingSettings,
    pub ebpf: EbpfSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralSettings {
    pub hostname: String,
    pub scan_interval_seconds: u64,
    pub baseline_on_start: bool,
    pub max_memory_mb: u64,
    pub max_cpu_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSettings {
    pub enabled_detectors: Vec<String>,
    pub severity_threshold: String,
    pub mitre_attack_mapping: bool,
    pub evidence_collection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringSettings {
    pub process_monitoring: bool,
    pub network_monitoring: bool,
    pub module_monitoring: bool,
    pub memory_monitoring: bool,
    pub syscall_monitoring: bool,
    pub file_integrity_monitoring: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSettings {
    pub database_path: PathBuf,
    pub evidence_path: PathBuf,
    pub log_path: PathBuf,
    pub retention_days: u32,
    pub max_events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSettings {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub cors_origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSettings {
    pub level: String,
    pub format: String,
    pub file_output: bool,
    pub json_format: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfSettings {
    pub enabled: bool,
    pub map_size: u32,
    pub perf_buffer_pages: u32,
    pub max_events_per_second: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            general: GeneralSettings {
                hostname: hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".to_string()),
                scan_interval_seconds: 60,
                baseline_on_start: true,
                max_memory_mb: MAX_MEMORY_MB,
                max_cpu_percent: MAX_CPU_PERCENT,
            },
            detection: DetectionSettings {
                enabled_detectors: vec![
                    "kernel_integrity".to_string(),
                    "hidden_process".to_string(),
                    "hidden_module".to_string(),
                    "hidden_connection".to_string(),
                    "hook_detection".to_string(),
                    "memory_integrity".to_string(),
                    "persistence".to_string(),
                    "privilege_escalation".to_string(),
                ],
                severity_threshold: "low".to_string(),
                mitre_attack_mapping: true,
                evidence_collection: true,
            },
            monitoring: MonitoringSettings {
                process_monitoring: true,
                network_monitoring: true,
                module_monitoring: true,
                memory_monitoring: true,
                syscall_monitoring: true,
                file_integrity_monitoring: true,
            },
            storage: StorageSettings {
                database_path: PathBuf::from(DEFAULT_DB_PATH),
                evidence_path: PathBuf::from("/var/lib/sentinelx/evidence"),
                log_path: PathBuf::from("/var/log/sentinelx"),
                retention_days: 90,
                max_events: 1_000_000,
            },
            api: ApiSettings {
                enabled: true,
                host: "127.0.0.1".to_string(),
                port: 8443,
                tls_enabled: false,
                cors_origins: vec!["http://localhost:3000".to_string()],
            },
            logging: LoggingSettings {
                level: DEFAULT_LOG_LEVEL.to_string(),
                format: "pretty".to_string(),
                file_output: true,
                json_format: false,
            },
            ebpf: EbpfSettings {
                enabled: true,
                map_size: 10240,
                perf_buffer_pages: 64,
                max_events_per_second: 10000,
            },
        }
    }
}

impl Settings {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let config_path = match path {
            Some(p) => p.to_path_buf(),
            None => Self::default_config_path()?,
        };

        if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)?;
            let settings: Settings = toml::from_str(&contents)?;
            settings.validate()?;
            Ok(settings)
        } else {
            let settings = Settings::default();
            settings.validate()?;
            Ok(settings)
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::ValidationError(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, contents)?;
        Ok(())
    }

    fn default_config_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("", "", "sentinelx").ok_or_else(|| {
            ConfigError::ValidationError("Cannot determine config directory".to_string())
        })?;
        Ok(dirs.config_dir().join(DEFAULT_CONFIG_FILE))
    }

    fn validate(&self) -> Result<()> {
        if self.general.scan_interval_seconds == 0 {
            return Err(ConfigError::ValidationError(
                "scan_interval_seconds must be > 0".to_string(),
            ));
        }
        if self.general.max_memory_mb == 0 || self.general.max_memory_mb > 1024 {
            return Err(ConfigError::ValidationError(
                "max_memory_mb must be between 1 and 1024".to_string(),
            ));
        }
        if self.general.max_cpu_percent <= 0.0 || self.general.max_cpu_percent > 100.0 {
            return Err(ConfigError::ValidationError(
                "max_cpu_percent must be between 0 and 100".to_string(),
            ));
        }
        if self.api.port == 0 {
            return Err(ConfigError::ValidationError(
                "api.port cannot be 0".to_string(),
            ));
        }
        if self.storage.retention_days == 0 {
            return Err(ConfigError::ValidationError(
                "retention_days must be > 0".to_string(),
            ));
        }
        Ok(())
    }

    pub fn is_detector_enabled(&self, name: &str) -> bool {
        self.detection.enabled_detectors.iter().any(|d| d == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_are_valid() {
        let settings = Settings::default();
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn default_settings_have_correct_limits() {
        let settings = Settings::default();
        assert_eq!(settings.general.max_memory_mb, MAX_MEMORY_MB);
        assert_eq!(settings.general.max_cpu_percent, MAX_CPU_PERCENT);
    }

    #[test]
    fn detector_toggle_works() {
        let mut settings = Settings::default();
        settings.detection.enabled_detectors = vec!["kernel_integrity".to_string()];
        assert!(settings.is_detector_enabled("kernel_integrity"));
        assert!(!settings.is_detector_enabled("hidden_process"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let settings = Settings::default();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        settings.save(&path).unwrap();
        let loaded = Settings::load(Some(&path)).unwrap();
        assert_eq!(
            settings.general.scan_interval_seconds,
            loaded.general.scan_interval_seconds
        );
    }
}
