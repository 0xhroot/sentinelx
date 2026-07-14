use std::fs;
use std::os::unix::fs::MetadataExt;

use chrono::{DateTime, Utc};
use tracing::{debug, info, warn};

use sentinelx_common::hash::HashValue;
use sentinelx_common::severity::Severity;

#[derive(Debug, Clone)]
pub struct BaselineRecord {
    pub path: String,
    pub hash: HashValue,
    pub size: u64,
    pub permissions: u32,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct IntegrityViolation {
    pub path: String,
    pub expected_hash: HashValue,
    pub actual_hash: HashValue,
    pub severity: Severity,
}

pub struct IntegrityBaseline {
    records: Vec<BaselineRecord>,
}

impl IntegrityBaseline {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn record(&mut self, path: &str) -> sentinelx_common::Result<()> {
        let metadata = fs::metadata(path)?;
        let data = fs::read(path)?;
        let hash = HashValue::new(&data);

        let record = BaselineRecord {
            path: path.to_string(),
            hash: hash.clone(),
            size: metadata.len(),
            permissions: metadata.mode(),
            checked_at: Utc::now(),
        };

        debug!(
            path = path,
            hash = hash.as_hex(),
            size = metadata.len(),
            "Baseline record created"
        );

        self.records.push(record);
        Ok(())
    }

    pub fn verify(&self) -> sentinelx_common::Result<Vec<IntegrityViolation>> {
        let mut violations = Vec::new();

        for record in &self.records {
            let current_data = match fs::read(&record.path) {
                Ok(d) => d,
                Err(e) => {
                    warn!(
                        path = record.path,
                        error = e.to_string(),
                        "Cannot read file during verification"
                    );
                    violations.push(IntegrityViolation {
                        path: record.path.clone(),
                        expected_hash: record.hash.clone(),
                        actual_hash: HashValue::new(b""),
                        severity: Severity::Critical,
                    });
                    continue;
                }
            };

            let current_hash = HashValue::new(&current_data);

            if !current_hash.matches(&record.hash) {
                let metadata = fs::metadata(&record.path).ok();
                let severity = if metadata.map(|m| m.mode()) != Some(record.permissions) {
                    Severity::Critical
                } else {
                    Severity::High
                };

                warn!(
                    path = record.path,
                    expected = record.hash.as_hex(),
                    actual = current_hash.as_hex(),
                    "Integrity violation found"
                );

                violations.push(IntegrityViolation {
                    path: record.path.clone(),
                    expected_hash: record.hash.clone(),
                    actual_hash: current_hash,
                    severity,
                });
            } else if let Ok(metadata) = fs::metadata(&record.path) {
                if metadata.mode() != record.permissions {
                    warn!(
                        path = record.path,
                        expected_perms = record.permissions,
                        actual_perms = metadata.mode(),
                        "Permission change detected"
                    );

                    violations.push(IntegrityViolation {
                        path: record.path.clone(),
                        expected_hash: record.hash.clone(),
                        actual_hash: current_hash,
                        severity: Severity::Critical,
                    });
                }
            }
        }

        info!(
            total = self.records.len(),
            violations = violations.len(),
            "Verification complete"
        );

        Ok(violations)
    }
}

impl Default for IntegrityBaseline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn new_baseline_is_empty() {
        let baseline = IntegrityBaseline::new();
        assert!(baseline.records.is_empty());
    }

    #[test]
    fn record_and_verify_no_violations() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), b"hello world").unwrap();

        let mut baseline = IntegrityBaseline::new();
        baseline.record(tmp.path().to_str().unwrap()).unwrap();

        let violations = baseline.verify().unwrap();
        assert!(violations.is_empty());
    }

    #[test]
    fn detect_modification() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), b"original content").unwrap();

        let mut baseline = IntegrityBaseline::new();
        baseline.record(tmp.path().to_str().unwrap()).unwrap();

        fs::write(tmp.path(), b"tampered content").unwrap();

        let violations = baseline.verify().unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].path, tmp.path().to_str().unwrap());
    }

    #[test]
    fn detect_permission_change() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), b"same content").unwrap();

        let mut baseline = IntegrityBaseline::new();
        baseline.record(tmp.path().to_str().unwrap()).unwrap();

        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o777)).unwrap();

        let violations = baseline.verify().unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, Severity::Critical);
    }
}
