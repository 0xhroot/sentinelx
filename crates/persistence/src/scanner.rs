use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use async_trait::async_trait;
use sentinelx_common::hash::HashValue;
use sentinelx_common::traits::Detector;
use sentinelx_common::types::{PersistenceEntry, PersistenceType, ThreatCategory, ThreatEvent};
use sentinelx_common::{Result, Severity};
use sentinelx_evidence::{
    Evidence as EvidenceItem, EvidenceCollector, EvidenceError, EvidenceType,
};
use tracing::{debug, info};

use crate::file_analysis;
use crate::locations;
use crate::package::{self, PackageInfo};
use crate::trust::{Classification, TrustConfig, TrustEngine};

pub struct PersistenceScanner {
    package_manager: Option<Box<dyn package::PackageManager>>,
    trust_engine: TrustEngine,
    package_cache: RwLock<HashMap<String, Option<PackageInfo>>>,
}

impl PersistenceScanner {
    pub fn new() -> Self {
        let package_manager = package::detect_package_manager();
        let trust_engine = TrustEngine::default_engine();
        Self {
            package_manager,
            trust_engine,
            package_cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_config(config: TrustConfig) -> Self {
        let package_manager = package::detect_package_manager();
        let trust_engine = TrustEngine::new(config);
        Self {
            package_manager,
            trust_engine,
            package_cache: RwLock::new(HashMap::new()),
        }
    }

    fn query_package(&self, path: &str) -> Option<PackageInfo> {
        {
            let cache = self.package_cache.read().unwrap();
            if let Some(cached) = cache.get(path) {
                return cached.clone();
            }
        }

        let result = if let Some(ref pm) = self.package_manager {
            pm.query_owner(path)
        } else {
            None
        };

        self.package_cache
            .write()
            .unwrap()
            .insert(path.to_string(), result.clone());
        result
    }

    fn expand_entry(&self, entry: &mut PersistenceEntry) {
        let meta = file_analysis::FileMetadata::analyze(&entry.path);
        entry.owner_uid = Some(meta.uid);
        entry.group_uid = Some(meta.gid);
        entry.permissions = Some(meta.permissions);
        entry.size = Some(meta.size);
        entry.is_symlink = meta.is_symlink;
    }

    fn analyze_entry(
        &self,
        entry: &PersistenceEntry,
    ) -> (
        file_analysis::FileMetadata,
        Option<PackageInfo>,
        Vec<file_analysis::ExecAnalysis>,
        bool,
    ) {
        let file_meta = file_analysis::FileMetadata::analyze(&entry.path);

        let package_info = self.query_package(&entry.path);

        let exec_analyses = if entry.entry_type == PersistenceType::SystemdService {
            file_analysis::analyze_exec_start_for_path(&entry.path)
        } else {
            Vec::new()
        };

        let is_standard_dir = package::is_system_directory(&entry.path);

        (file_meta, package_info, exec_analyses, is_standard_dir)
    }

    fn read_file_content(path: &Path) -> Option<String> {
        fs::read_to_string(path).ok()
    }

    fn compute_hash(content: &str) -> Option<HashValue> {
        Some(HashValue::new(content.as_bytes()))
    }

    pub fn scan_systemd_services(&self) -> Vec<PersistenceEntry> {
        let mut entries = Vec::new();

        for dir in locations::SYSTEMD_SYSTEM_DIRS {
            let path = Path::new(dir);
            if !path.exists() {
                continue;
            }

            debug!("Scanning systemd directory: {}", dir);

            let walker = walkdir::WalkDir::new(path)
                .max_depth(1)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok());

            for entry in walker {
                if !entry.file_type().is_file() {
                    continue;
                }

                let file_path = entry.path();
                let file_name = file_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();

                if !file_name.ends_with(".service") && !file_name.ends_with(".timer") {
                    continue;
                }

                let entry_type = if file_name.ends_with(".service") {
                    PersistenceType::SystemdService
                } else {
                    PersistenceType::SystemdTimer
                };

                let content = Self::read_file_content(file_path);
                let hash = content.as_deref().and_then(Self::compute_hash);

                let enabled = content
                    .as_ref()
                    .map(|c| !c.contains("[Install]") || c.contains("WantedBy="))
                    .unwrap_or(false);

                let mut entry = PersistenceEntry {
                    entry_type,
                    name: file_name,
                    path: file_path.to_string_lossy().into_owned(),
                    content,
                    enabled,
                    hash,
                    user: None,
                    owner_uid: None,
                    group_uid: None,
                    permissions: None,
                    size: None,
                    is_symlink: false,
                };
                self.expand_entry(&mut entry);
                entries.push(entry);
            }
        }

        info!("Found {} systemd service/timer entries", entries.len());
        entries
    }

    pub fn scan_cron_jobs(&self) -> Vec<PersistenceEntry> {
        let mut entries = Vec::new();

        let mut cron_files = Vec::new();
        cron_files.push(PathBuf::from("/etc/crontab"));

        for dir in locations::CRON_DIRS {
            let path = Path::new(dir);
            if !path.exists() {
                continue;
            }

            if let Ok(read_dir) = fs::read_dir(path) {
                for entry in read_dir.flatten() {
                    let entry_path = entry.path();
                    if entry_path.is_file() {
                        cron_files.push(entry_path);
                    }
                }
            }
        }

        for file_path in &cron_files {
            if !file_path.exists() {
                continue;
            }

            debug!("Scanning cron file: {}", file_path.display());

            let content = match Self::read_file_content(file_path) {
                Some(c) => c,
                None => continue,
            };

            let file_name = file_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            let hash = Self::compute_hash(&content);

            let has_schedule = content.lines().any(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty()
                    && !trimmed.starts_with('#')
                    && trimmed.split_whitespace().count() >= 5
            });

            let mut entry = PersistenceEntry {
                entry_type: PersistenceType::CronJob,
                name: file_name,
                path: file_path.to_string_lossy().into_owned(),
                content: Some(content),
                enabled: has_schedule,
                hash,
                user: None,
                owner_uid: None,
                group_uid: None,
                permissions: None,
                size: None,
                is_symlink: false,
            };
            self.expand_entry(&mut entry);
            entries.push(entry);
        }

        info!("Found {} cron job entries", entries.len());
        entries
    }

    pub fn scan_rc_local(&self) -> Vec<PersistenceEntry> {
        let mut entries = Vec::new();

        for rc_path in locations::RC_LOCAL_PATHS {
            let path = Path::new(rc_path);
            if !path.exists() {
                continue;
            }

            debug!("Checking rc.local: {}", rc_path);

            let content = Self::read_file_content(path);
            let hash = content.as_deref().and_then(Self::compute_hash);

            let enabled = content
                .as_ref()
                .map(|c| {
                    let trimmed = c.trim();
                    !trimmed.is_empty()
                        && !trimmed.starts_with("#!/bin/false")
                        && !trimmed.contains("exit 0")
                })
                .unwrap_or(false);

            let mut entry = PersistenceEntry {
                entry_type: PersistenceType::RcLocal,
                name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                path: rc_path.to_string(),
                content,
                enabled,
                hash,
                user: None,
                owner_uid: None,
                group_uid: None,
                permissions: None,
                size: None,
                is_symlink: false,
            };
            self.expand_entry(&mut entry);
            entries.push(entry);
        }

        info!("Found {} rc.local entries", entries.len());
        entries
    }

    pub fn scan_ld_preload(&self) -> Vec<PersistenceEntry> {
        let mut entries = Vec::new();

        let path = Path::new(locations::PRELOAD_PATH);
        if !path.exists() {
            info!("No ld.so.preload found");
            return entries;
        }

        debug!("Checking ld.so.preload");

        let content = match Self::read_file_content(path) {
            Some(c) => c,
            None => return entries,
        };

        let hash = Self::compute_hash(&content);

        let lib_count = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .count();

        let enabled = lib_count > 0;

        let mut entry = PersistenceEntry {
            entry_type: PersistenceType::LdPreload,
            name: "ld.so.preload".to_string(),
            path: locations::PRELOAD_PATH.to_string(),
            content: Some(content),
            enabled,
            hash,
            user: None,
            owner_uid: None,
            group_uid: None,
            permissions: None,
            size: None,
            is_symlink: false,
        };
        self.expand_entry(&mut entry);
        entries.push(entry);

        info!("Found ld.so.preload with {} library entries", lib_count);
        entries
    }

    pub fn scan_bash_profiles(&self) -> Vec<PersistenceEntry> {
        let mut entries = Vec::new();

        let home = std::env::var("HOME").unwrap_or_default();

        for profile_path in locations::PROFILE_FILES {
            let resolved = if let Some(stripped) = profile_path.strip_prefix("~/") {
                PathBuf::from(home.trim_end_matches('/')).join(stripped)
            } else {
                PathBuf::from(profile_path)
            };

            if !resolved.exists() {
                continue;
            }

            debug!("Checking profile: {}", resolved.display());

            let content = match Self::read_file_content(&resolved) {
                Some(c) => c,
                None => continue,
            };

            let hash = Self::compute_hash(&content);

            let mut entry = PersistenceEntry {
                entry_type: PersistenceType::BashProfile,
                name: resolved
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                path: resolved.to_string_lossy().into_owned(),
                content: Some(content),
                enabled: true,
                hash,
                user: None,
                owner_uid: None,
                group_uid: None,
                permissions: None,
                size: None,
                is_symlink: false,
            };
            self.expand_entry(&mut entry);
            entries.push(entry);
        }

        info!("Found {} bash profile entries", entries.len());
        entries
    }

    pub fn scan_init_scripts(&self) -> Vec<PersistenceEntry> {
        let mut entries = Vec::new();

        let init_dir = Path::new("/etc/init.d");
        if !init_dir.exists() {
            info!("No /etc/init.d directory found");
            return entries;
        }

        debug!("Scanning /etc/init.d/");

        if let Ok(read_dir) = fs::read_dir(init_dir) {
            for entry in read_dir.flatten() {
                let entry_path = entry.path();
                if !entry_path.is_file() {
                    continue;
                }

                let file_name = entry_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();

                let content = Self::read_file_content(&entry_path);
                let hash = content.as_deref().and_then(Self::compute_hash);

                let enabled = content
                    .as_ref()
                    .map(|c| {
                        c.contains("#!/bin/sh")
                            || c.contains("#!/bin/bash")
                            || c.contains("### BEGIN INIT INFO")
                    })
                    .unwrap_or(false);

                let mut entry = PersistenceEntry {
                    entry_type: PersistenceType::InitScript,
                    name: file_name,
                    path: entry_path.to_string_lossy().into_owned(),
                    content,
                    enabled,
                    hash,
                    user: None,
                    owner_uid: None,
                    group_uid: None,
                    permissions: None,
                    size: None,
                    is_symlink: false,
                };
                self.expand_entry(&mut entry);
                entries.push(entry);
            }
        }

        info!("Found {} init script entries", entries.len());
        entries
    }

    pub fn scan_all(&self) -> Vec<PersistenceEntry> {
        let mut all_entries = Vec::new();

        all_entries.extend(self.scan_systemd_services());
        all_entries.extend(self.scan_cron_jobs());
        all_entries.extend(self.scan_rc_local());
        all_entries.extend(self.scan_ld_preload());
        all_entries.extend(self.scan_bash_profiles());
        all_entries.extend(self.scan_init_scripts());

        info!("Total persistence entries found: {}", all_entries.len());
        all_entries
    }

    fn build_evidence_for_entry(
        &self,
        entry: &PersistenceEntry,
        file_meta: &file_analysis::FileMetadata,
        package_info: &Option<PackageInfo>,
        exec_analyses: &[file_analysis::ExecAnalysis],
        is_standard_dir: bool,
    ) -> EvidenceItem {
        let exec_risks: Vec<file_analysis::ExecRisk> =
            exec_analyses.iter().map(|a| a.risk.clone()).collect();

        let trust = self.trust_engine.score(
            file_meta,
            package_info.is_some(),
            package_info.as_ref().map(|p| p.name.as_str()),
            &exec_risks,
            is_standard_dir,
        );

        let severity = match trust.classification {
            Classification::TrustedOS | Classification::TrustedPackage => {
                sentinelx_evidence::Severity::Info
            }
            Classification::Unknown => sentinelx_evidence::Severity::Low,
            Classification::Suspicious => sentinelx_evidence::Severity::Medium,
            Classification::Malicious => sentinelx_evidence::Severity::High,
        };

        let description = format!(
            "[{}] {} at {}",
            trust.classification.as_str(),
            entry.name,
            entry.path
        );

        let mut item = EvidenceItem::new(
            EvidenceType::PersistenceIntegrity,
            severity,
            "persistence".to_string(),
            description,
        )
        .with_data(
            "classification".to_string(),
            serde_json::Value::String(trust.classification.as_str().to_string()),
        )
        .with_data(
            "trust_score".to_string(),
            serde_json::Value::Number(trust.score.into()),
        )
        .with_data(
            "path".to_string(),
            serde_json::Value::String(entry.path.clone()),
        )
        .with_data(
            "entry_type".to_string(),
            serde_json::Value::String(format!("{:?}", entry.entry_type)),
        )
        .with_data(
            "enabled".to_string(),
            serde_json::Value::Bool(entry.enabled),
        )
        .with_confidence(trust.confidence)
        .with_tag("persistence".to_string())
        .with_tag(format!("{:?}", entry.entry_type).to_lowercase())
        .with_tag(trust.classification.as_str().to_string());

        if let Some(ref pkg) = package_info {
            item = item
                .with_data(
                    "package_name".to_string(),
                    serde_json::Value::String(pkg.name.clone()),
                )
                .with_data(
                    "package_version".to_string(),
                    serde_json::Value::String(pkg.version.clone()),
                );
        }

        if let Some(uid) = file_meta.exists.then_some(file_meta.uid) {
            item = item.with_data(
                "owner_uid".to_string(),
                serde_json::Value::Number(uid.into()),
            );
        }

        if !exec_analyses.is_empty() {
            let exec_raws: Vec<serde_json::Value> = exec_analyses
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "command": a.command,
                        "risk": format!("{:?}", a.risk),
                        "raw": a.raw,
                    })
                })
                .collect();
            item = item.with_data(
                "exec_starts".to_string(),
                serde_json::Value::Array(exec_raws),
            );
        }

        if !trust.reasons.is_empty() {
            let reasons: Vec<serde_json::Value> = trust
                .reasons
                .iter()
                .map(|r| serde_json::Value::String(r.clone()))
                .collect();
            item = item.with_data(
                "trust_reasons".to_string(),
                serde_json::Value::Array(reasons),
            );
        }

        if let Some(ref content) = entry.content {
            item = item.with_data(
                "content_preview".to_string(),
                serde_json::Value::String(content.chars().take(512).collect()),
            );
        }

        item
    }
}

impl Default for PersistenceScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EvidenceCollector for PersistenceScanner {
    async fn collect_evidence(&self) -> std::result::Result<Vec<EvidenceItem>, EvidenceError> {
        let entries = self.scan_all();
        let mut evidence_items = Vec::with_capacity(entries.len());

        for entry in &entries {
            let (file_meta, package_info, exec_analyses, is_standard_dir) =
                self.analyze_entry(entry);

            let item = self.build_evidence_for_entry(
                entry,
                &file_meta,
                &package_info,
                &exec_analyses,
                is_standard_dir,
            );
            evidence_items.push(item);
        }

        Ok(evidence_items)
    }

    fn get_evidence_type(&self) -> EvidenceType {
        EvidenceType::PersistenceIntegrity
    }

    fn get_source(&self) -> String {
        "persistence".to_string()
    }
}

#[async_trait]
impl Detector for PersistenceScanner {
    fn name(&self) -> &str {
        "persistence"
    }

    fn description(&self) -> &str {
        "Scans for persistence mechanisms. This detector produces classified evidence only; threat generation is the responsibility of the correlation engine."
    }

    fn category(&self) -> ThreatCategory {
        ThreatCategory::PersistenceMechanism
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    async fn detect(&self) -> Result<Vec<ThreatEvent>> {
        info!("Persistence detector: producing no threats directly (evidence-only mode)");
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_scanner_new() {
        let scanner = PersistenceScanner::new();
        assert_eq!(scanner.name(), "persistence");
        assert_eq!(scanner.category(), ThreatCategory::PersistenceMechanism);
        assert_eq!(scanner.severity(), Severity::Medium);
    }

    #[test]
    fn test_scan_ld_preload_nonexistent() {
        let scanner = PersistenceScanner::new();
        let entries = scanner.scan_ld_preload();
        if !Path::new(locations::PRELOAD_PATH).exists() {
            assert!(entries.is_empty());
        }
    }

    #[test]
    fn test_scan_rc_local_nonexistent() {
        let scanner = PersistenceScanner::new();
        let entries = scanner.scan_rc_local();
        let any_exist = locations::RC_LOCAL_PATHS
            .iter()
            .any(|p| Path::new(p).exists());
        if !any_exist {
            assert!(entries.is_empty());
        }
    }

    #[test]
    fn test_scan_systemd_services() {
        let scanner = PersistenceScanner::new();
        let entries = scanner.scan_systemd_services();
        assert!(entries.iter().all(|e| {
            matches!(
                e.entry_type,
                PersistenceType::SystemdService | PersistenceType::SystemdTimer
            )
        }));
    }

    #[test]
    fn test_scan_systemd_services_have_metadata() {
        let scanner = PersistenceScanner::new();
        let entries = scanner.scan_systemd_services();
        for entry in &entries {
            assert!(
                entry.owner_uid.is_some(),
                "entry {} missing owner_uid",
                entry.path
            );
            assert!(
                entry.permissions.is_some(),
                "entry {} missing permissions",
                entry.path
            );
        }
    }

    #[test]
    fn test_scan_init_scripts() {
        let scanner = PersistenceScanner::new();
        let entries = scanner.scan_init_scripts();
        assert!(entries
            .iter()
            .all(|e| e.entry_type == PersistenceType::InitScript));
    }

    #[test]
    fn test_locations_constants() {
        assert!(!locations::SYSTEMD_SYSTEM_DIRS.is_empty());
        assert!(!locations::CRON_DIRS.is_empty());
        assert!(!locations::PROFILE_FILES.is_empty());
        assert!(!locations::RC_LOCAL_PATHS.is_empty());
        assert_eq!(locations::PRELOAD_PATH, "/etc/ld.so.preload");
    }

    #[tokio::test]
    async fn test_detect_returns_empty() {
        let scanner = PersistenceScanner::new();
        let threats = scanner.detect().await.unwrap();
        assert!(threats.is_empty());
    }

    #[tokio::test]
    async fn test_collect_evidence_returns_entries() {
        let scanner = PersistenceScanner::new();
        let evidence = scanner.collect_evidence().await.unwrap();
        assert!(
            !evidence.is_empty(),
            "should produce evidence for discovered entries"
        );
        for item in &evidence {
            assert!(item.data.contains_key("classification"));
            assert!(item.data.contains_key("trust_score"));
            assert!(item.data.contains_key("path"));
        }
    }

    #[test]
    fn test_package_cache_hit() {
        let scanner = PersistenceScanner::new();
        let result1 = scanner.query_package("/usr/lib/systemd/system/systemd-journald.service");
        let result2 = scanner.query_package("/usr/lib/systemd/system/systemd-journald.service");
        assert_eq!(
            result1.is_some(),
            result2.is_some(),
            "cache should return consistent results"
        );
    }

    #[test]
    fn test_entry_type_classification_in_evidence() {
        let scanner = PersistenceScanner::new();
        let entries = scanner.scan_ld_preload();
        if !entries.is_empty() {
            let (file_meta, pkg, execs, is_std) = scanner.analyze_entry(&entries[0]);
            let item =
                scanner.build_evidence_for_entry(&entries[0], &file_meta, &pkg, &execs, is_std);
            let classification = item.data.get("classification").and_then(|v| v.as_str());
            assert!(
                classification.is_some(),
                "evidence should have classification field"
            );
        }
    }
}
