use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;

use chrono::Utc;
use sentinelx_common::types::{MitreAttackMapping, ThreatCategory, ThreatEvent};
use sentinelx_common::Severity;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ReportError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Markdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonReport {
    pub generated_at: String,
    pub total_threats: usize,
    pub summary: ReportSummary,
    pub threats: Vec<ThreatEvent>,
    pub mitre_coverage: Vec<MitreAttackMapping>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub category_breakdown: HashMap<String, usize>,
    pub severity_breakdown: HashMap<String, usize>,
}

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_summary_report(&self, threats: &[ThreatEvent]) -> String {
        let mut report = String::new();

        writeln!(report, "# SentinelX Threat Report").unwrap();
        writeln!(
            report,
            "**Generated:** {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        )
        .unwrap();
        writeln!(report).unwrap();

        writeln!(report, "## Executive Summary").unwrap();
        writeln!(report, "Total threats detected: **{}**", threats.len()).unwrap();
        if threats.is_empty() {
            writeln!(
                report,
                "No threats were detected during the analysis period."
            )
            .unwrap();
        } else {
            let critical = threats
                .iter()
                .filter(|t| t.severity == Severity::Critical)
                .count();
            let high = threats
                .iter()
                .filter(|t| t.severity == Severity::High)
                .count();
            let medium = threats
                .iter()
                .filter(|t| t.severity == Severity::Medium)
                .count();
            let low = threats
                .iter()
                .filter(|t| t.severity == Severity::Low)
                .count();
            let info = threats
                .iter()
                .filter(|t| t.severity == Severity::Info)
                .count();
            writeln!(
                report,
                "- Critical: {critical} | High: {high} | Medium: {medium} | Low: {low} | Info: {info}"
            )
            .unwrap();
        }
        writeln!(report).unwrap();

        writeln!(report, "## Threat Breakdown by Category").unwrap();
        let category_counts = self.count_by_category(threats);
        if category_counts.is_empty() {
            writeln!(report, "No threats to categorize.").unwrap();
        } else {
            for (category, count) in &category_counts {
                writeln!(report, "- **{category}**: {count}").unwrap();
            }
        }
        writeln!(report).unwrap();

        writeln!(report, "## Threat Breakdown by Severity").unwrap();
        let severity_counts = self.count_by_severity(threats);
        if severity_counts.is_empty() {
            writeln!(report, "No threats to classify.").unwrap();
        } else {
            for (severity, count) in &severity_counts {
                writeln!(report, "- **{severity}**: {count}").unwrap();
            }
        }
        writeln!(report).unwrap();

        writeln!(report, "## MITRE ATT&CK Coverage").unwrap();
        let mitre = self.compute_mitre_coverage(threats);
        if mitre.is_empty() {
            writeln!(report, "No MITRE ATT&CK mappings identified.").unwrap();
        } else {
            for mapping in &mitre {
                writeln!(
                    report,
                    "- **{}** ({}) — {}",
                    mapping.technique_name, mapping.technique_id, mapping.tactic
                )
                .unwrap();
            }
        }
        writeln!(report).unwrap();

        writeln!(report, "## Recommendations").unwrap();
        let recommendations = self.generate_recommendations(threats);
        if recommendations.is_empty() {
            writeln!(report, "No specific recommendations at this time.").unwrap();
        } else {
            for (i, rec) in recommendations.iter().enumerate() {
                writeln!(report, "{}. {rec}", i + 1).unwrap();
            }
        }

        report
    }

    pub fn generate_json_report(&self, threats: &[ThreatEvent]) -> String {
        let report = JsonReport {
            generated_at: Utc::now().to_rfc3339(),
            total_threats: threats.len(),
            summary: ReportSummary {
                category_breakdown: self.count_by_category(threats),
                severity_breakdown: self.count_by_severity(threats),
            },
            threats: threats.to_vec(),
            mitre_coverage: self.compute_mitre_coverage(threats),
            recommendations: self.generate_recommendations(threats),
        };
        serde_json::to_string_pretty(&report).unwrap_or_default()
    }

    pub fn save_report(
        &self,
        threats: &[ThreatEvent],
        path: &Path,
        format: ReportFormat,
    ) -> Result<()> {
        let content = match format {
            ReportFormat::Json => self.generate_json_report(threats),
            ReportFormat::Markdown => self.generate_summary_report(threats),
        };
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn compute_mitre_coverage(&self, threats: &[ThreatEvent]) -> Vec<MitreAttackMapping> {
        let mut seen = HashMap::new();
        let mut mappings = Vec::new();
        for threat in threats {
            for mapping in &threat.mitre_attack {
                let key = (&mapping.tactic, &mapping.technique_id);
                if seen.insert(key, true).is_none() {
                    mappings.push(mapping.clone());
                }
            }
        }
        mappings.sort_by(|a, b| a.technique_id.cmp(&b.technique_id));
        mappings
    }

    pub fn generate_recommendations(&self, threats: &[ThreatEvent]) -> Vec<String> {
        let mut recommendations = Vec::new();
        let category_counts = self.count_by_category(threats);

        if category_counts
            .get(ThreatCategory::Rootkit.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "Rootkit activity detected. Perform a full system audit and consider a clean reinstall of affected systems.".to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::ReverseShell.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "Reverse shell connections detected. Block outbound connections on suspicious ports and investigate the source process.".to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::PrivilegeEscalation.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "Privilege escalation attempts detected. Review sudoers configuration and kernel capabilities.".to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::PersistenceMechanism.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "Persistence mechanisms found. Audit systemd services, cron jobs, and startup scripts.".to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::HookDetected.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "System hooks detected. Verify syscall table integrity and check for inline hooks in critical binaries.".to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::MemoryTampering.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "Memory tampering detected. Enable ASLR and verify process memory integrity."
                    .to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::HiddenProcess.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "Hidden processes detected. Compare process lists across multiple sources (procfs, eBPF) to identify discrepancies.".to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::HiddenModule.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "Hidden kernel modules detected. Verify loaded modules against /proc/modules and check for tained kernel flags.".to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::ContainerEscape.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "Container escape attempt detected. Review container security profiles (AppArmor, seccomp) and update runtime configurations.".to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::FilelessMalware.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "Fileless malware activity detected. Enable memory-only execution monitoring and review shared memory segments.".to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::IntegrityViolation.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "File integrity violations detected. Restore affected files from known-good backups and re-verify file hashes.".to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::SuspiciousSyscall.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "Suspicious syscalls observed. Review syscall filtering policies (seccomp) and restrict unnecessary syscall access.".to_string(),
            );
        }
        if category_counts
            .get(ThreatCategory::DkomAttack.as_str())
            .copied()
            .unwrap_or(0)
            > 0
        {
            recommendations.push(
                "DKOM attack detected. Cross-reference process lists with kernel data structures to find hidden processes.".to_string(),
            );
        }
        if threats.iter().any(|t| t.severity >= Severity::Critical) {
            recommendations.push(
                "Critical severity threats detected. Initiate incident response procedures immediately.".to_string(),
            );
        }
        if recommendations.is_empty() {
            recommendations.push(
                "No specific threats detected. Continue monitoring and maintain current security posture.".to_string(),
            );
        }
        recommendations
    }

    fn count_by_category(&self, threats: &[ThreatEvent]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for threat in threats {
            *counts
                .entry(threat.category.as_str().to_string())
                .or_insert(0) += 1;
        }
        counts
    }

    fn count_by_severity(&self, threats: &[ThreatEvent]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for threat in threats {
            *counts.entry(threat.severity.to_string()).or_insert(0) += 1;
        }
        counts
    }

    pub fn generate_assessment_section(
        &self,
        assessments: &[sentinelx_assessment::ObjectAssessment],
    ) -> String {
        let mut section = String::new();

        writeln!(section, "## Assessment Summary").unwrap();
        writeln!(section, "Total objects assessed: **{}**", assessments.len()).unwrap();

        if assessments.is_empty() {
            writeln!(section, "No assessments to report.").unwrap();
            return section;
        }
        writeln!(section).unwrap();

        let high_risk = assessments.iter().filter(|a| a.risk >= 61).count();
        let medium_risk = assessments
            .iter()
            .filter(|a| a.risk >= 41 && a.risk < 61)
            .count();
        let low_risk = assessments
            .iter()
            .filter(|a| a.risk >= 21 && a.risk < 41)
            .count();
        let no_risk = assessments.iter().filter(|a| a.risk < 21).count();

        writeln!(section, "### Risk Distribution").unwrap();
        writeln!(section, "- **Critical/High**: {high_risk}").unwrap();
        writeln!(section, "- **Medium**: {medium_risk}").unwrap();
        writeln!(section, "- **Low**: {low_risk}").unwrap();
        writeln!(section, "- **None**: {no_risk}").unwrap();
        writeln!(section).unwrap();

        let avg_trust: f64 =
            assessments.iter().map(|a| a.trust as f64).sum::<f64>() / assessments.len() as f64;
        let avg_integrity: f64 =
            assessments.iter().map(|a| a.integrity as f64).sum::<f64>() / assessments.len() as f64;
        let avg_confidence: f64 =
            assessments.iter().map(|a| a.confidence).sum::<f64>() / assessments.len() as f64;

        writeln!(section, "### Score Averages").unwrap();
        writeln!(section, "- **Trust**: {:.1}/100", avg_trust).unwrap();
        writeln!(section, "- **Integrity**: {:.1}/100", avg_integrity).unwrap();
        writeln!(section, "- **Confidence**: {:.1}%", avg_confidence * 100.0).unwrap();
        writeln!(section).unwrap();

        let mut warnings_count = 0;
        let mut reasons_count = 0;
        for a in assessments {
            warnings_count += a.warnings.len();
            reasons_count += a.reasons.len();
        }
        writeln!(section, "### Details").unwrap();
        writeln!(section, "- Total warnings: {warnings_count}").unwrap();
        writeln!(section, "- Total reasons: {reasons_count}").unwrap();

        section
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinelx_common::types::{Evidence, ThreatCategory};
    use sentinelx_common::Severity;
    use std::collections::HashMap;

    fn make_threat(
        category: ThreatCategory,
        severity: Severity,
        tactic: &str,
        technique_id: &str,
    ) -> ThreatEvent {
        let title = format!("Test threat: {}", category.as_str());
        ThreatEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category,
            title,
            description: "Test description".to_string(),
            evidence: vec![Evidence {
                description: "test evidence".to_string(),
                data: HashMap::new(),
                confidence: 0.9,
            }],
            mitre_attack: vec![MitreAttackMapping {
                tactic: tactic.to_string(),
                technique_id: technique_id.to_string(),
                technique_name: "Test Technique".to_string(),
            }],
            source_detector: "test".to_string(),
            process: None,
            network: None,
            hash: None,
            tags: vec![],
        }
    }

    #[test]
    fn test_empty_report() {
        let gen = ReportGenerator::new();
        let report = gen.generate_summary_report(&[]);
        assert!(report.contains("No threats were detected"));
    }

    #[test]
    fn test_json_report_structure() {
        let gen = ReportGenerator::new();
        let threats = vec![
            make_threat(
                ThreatCategory::Rootkit,
                Severity::Critical,
                "defense-evasion",
                "T1014",
            ),
            make_threat(
                ThreatCategory::ReverseShell,
                Severity::High,
                "command-and-control",
                "T1071",
            ),
        ];
        let json = gen.generate_json_report(&threats);
        let parsed: JsonReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_threats, 2);
        assert!(parsed.summary.severity_breakdown.contains_key("critical"));
        assert!(parsed.summary.severity_breakdown.contains_key("high"));
        assert!(parsed.summary.category_breakdown.contains_key("rootkit"));
        assert!(parsed
            .summary
            .category_breakdown
            .contains_key("reverse_shell"));
    }

    #[test]
    fn test_mitre_coverage_deduplication() {
        let gen = ReportGenerator::new();
        let mapping = MitreAttackMapping {
            tactic: "defense-evasion".to_string(),
            technique_id: "T1014".to_string(),
            technique_name: "Rootkit Detection Evasion".to_string(),
        };
        let threats: Vec<ThreatEvent> = (0..3)
            .map(|_| ThreatEvent {
                id: uuid::Uuid::new_v4(),
                timestamp: Utc::now(),
                severity: Severity::High,
                category: ThreatCategory::Rootkit,
                title: "test".to_string(),
                description: "test".to_string(),
                evidence: vec![],
                mitre_attack: vec![mapping.clone()],
                source_detector: "test".to_string(),
                process: None,
                network: None,
                hash: None,
                tags: vec![],
            })
            .collect();
        let coverage = gen.compute_mitre_coverage(&threats);
        assert_eq!(coverage.len(), 1);
    }

    #[test]
    fn test_recommendations_for_rootkit() {
        let gen = ReportGenerator::new();
        let threats = vec![make_threat(
            ThreatCategory::Rootkit,
            Severity::Critical,
            "defense-evasion",
            "T1014",
        )];
        let recs = gen.generate_recommendations(&threats);
        assert!(recs.iter().any(|r| r.contains("Rootkit activity detected")));
        assert!(recs
            .iter()
            .any(|r| r.contains("Critical severity threats detected")));
    }

    #[test]
    fn test_recommendations_empty() {
        let gen = ReportGenerator::new();
        let recs = gen.generate_recommendations(&[]);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].contains("No specific threats detected"));
    }

    #[test]
    fn test_save_json_report() {
        let gen = ReportGenerator::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let threats = vec![make_threat(
            ThreatCategory::HookDetected,
            Severity::Medium,
            "defense-evasion",
            "T1056",
        )];
        gen.save_report(&threats, &path, ReportFormat::Json)
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: JsonReport = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.total_threats, 1);
    }

    #[test]
    fn test_save_markdown_report() {
        let gen = ReportGenerator::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.md");
        let threats = vec![make_threat(
            ThreatCategory::MemoryTampering,
            Severity::High,
            "defense-evasion",
            "T1027",
        )];
        gen.save_report(&threats, &path, ReportFormat::Markdown)
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# SentinelX Threat Report"));
        assert!(content.contains("## Executive Summary"));
    }

    #[test]
    fn test_category_counts() {
        let gen = ReportGenerator::new();
        let threats = vec![
            make_threat(ThreatCategory::Rootkit, Severity::Critical, "t", "T1"),
            make_threat(ThreatCategory::Rootkit, Severity::High, "t", "T2"),
            make_threat(ThreatCategory::HiddenProcess, Severity::Medium, "t", "T3"),
        ];
        let counts = gen.count_by_category(&threats);
        assert_eq!(counts.get("rootkit"), Some(&2));
        assert_eq!(counts.get("hidden_process"), Some(&1));
    }
}
