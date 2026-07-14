use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IoCType {
    Hash,
    IpAddress,
    Domain,
    Filename,
    ProcessName,
    ModuleName,
    Url,
    Email,
}

impl IoCType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::IpAddress => "ip_address",
            Self::Domain => "domain",
            Self::Filename => "filename",
            Self::ProcessName => "process_name",
            Self::ModuleName => "module_name",
            Self::Url => "url",
            Self::Email => "email",
        }
    }

    pub fn parse_from(s: &str) -> Option<Self> {
        match s {
            "hash" => Some(Self::Hash),
            "ip_address" => Some(Self::IpAddress),
            "domain" => Some(Self::Domain),
            "filename" => Some(Self::Filename),
            "process_name" => Some(Self::ProcessName),
            "module_name" => Some(Self::ModuleName),
            "url" => Some(Self::Url),
            "email" => Some(Self::Email),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoC {
    pub id: Uuid,
    pub ioc_type: IoCType,
    pub value: String,
    pub severity: String,
    pub confidence: f64,
    pub source: String,
    pub description: String,
    pub tags: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub expiry: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
}

impl IoC {
    pub fn new(ioc_type: IoCType, value: &str, source: &str) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            ioc_type,
            value: value.to_string(),
            severity: "medium".to_string(),
            confidence: 0.5,
            source: source.to_string(),
            description: String::new(),
            tags: Vec::new(),
            first_seen: now,
            last_seen: now,
            expiry: None,
            metadata: serde_json::Value::Null,
        }
    }

    pub fn with_severity(mut self, severity: &str) -> Self {
        self.severity = severity.to_string();
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_expiry(mut self, expiry: DateTime<Utc>) -> Self {
        self.expiry = Some(expiry);
        self
    }

    pub fn parse_type(s: &str) -> Option<IoCType> {
        IoCType::parse_from(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
    pub data_sources: Vec<String>,
    pub platforms: Vec<String>,
    pub detection: String,
}

impl MitreTechnique {
    pub fn new(id: &str, name: &str, tactic: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            tactic: tactic.to_string(),
            description: String::new(),
            data_sources: Vec::new(),
            platforms: vec!["Linux".to_string()],
            detection: String::new(),
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMatrix {
    pub techniques: Vec<MitreTechnique>,
    pub tactic_mapping: std::collections::HashMap<String, Vec<String>>,
}

impl MitreMatrix {
    pub fn new() -> Self {
        Self {
            techniques: Vec::new(),
            tactic_mapping: std::collections::HashMap::new(),
        }
    }

    pub fn load_defaults() -> Self {
        let mut matrix = Self::new();
        let defaults = vec![
            MitreTechnique::new("T1014", "Rootkit", "defense-evasion")
                .with_description("Adversaries may use rootkits to hide the presence of programs, files, network connections, services, and other system components."),
            MitreTechnique::new("T1055", "Process Injection", "defense-evasion")
                .with_description("Adversaries may inject code into processes in order to evade process-based defenses."),
            MitreTechnique::new("T1059", "Command and Scripting Interpreter", "execution")
                .with_description("Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."),
            MitreTechnique::new("T1068", "Exploitation for Privilege Escalation", "privilege-escalation")
                .with_description("Adversaries may exploit software vulnerabilities to escalate privileges."),
            MitreTechnique::new("T1547", "Boot or Logon Autostart Execution", "persistence")
                .with_description("Adversaries may configure system settings to automatically execute a program during boot or logon."),
            MitreTechnique::new("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation")
                .with_description("Adversaries may circumvent mechanisms designed to control elevated privileges."),
            MitreTechnique::new("T1014", "Rootkit", "defense-evasion"),
            MitreTechnique::new("T1041", "Exfiltration Over C2 Channel", "exfiltration")
                .with_description("Adversaries may steal data by exfiltrating it over an existing command and control channel."),
            MitreTechnique::new("T1048", "Exfiltration Over Alternative Protocol", "exfiltration")
                .with_description("Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel."),
            MitreTechnique::new("T1057", "Process Discovery", "discovery")
                .with_description("Adversaries may attempt to get information about running processes on a system."),
            MitreTechnique::new("T1082", "System Information Discovery", "discovery")
                .with_description("An adversary may attempt to get detailed information about the operating system and hardware."),
            MitreTechnique::new("T1083", "File and Directory Discovery", "discovery")
                .with_description("Adversaries may enumerate files and directories or may search in specific locations of a host or network share."),
            MitreTechnique::new("T1105", "Ingress Tool Transfer", "command-and-control")
                .with_description("Adversaries may transfer tools or other files from an external system into a compromised environment."),
            MitreTechnique::new("T1070", "Indicator Removal", "defense-evasion")
                .with_description("Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence."),
            MitreTechnique::new("T1003", "OS Credential Dumping", "credential-access")
                .with_description("Adversaries may attempt to dump credentials to obtain account login and credential material."),
            MitreTechnique::new("T1574", "Hijack Execution Flow", "persistence")
                .with_description("Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs."),
        ];

        for technique in defaults {
            matrix
                .tactic_mapping
                .entry(technique.tactic.clone())
                .or_default()
                .push(technique.id.clone());
            matrix.techniques.push(technique);
        }
        matrix
    }

    pub fn find_technique(&self, id: &str) -> Option<&MitreTechnique> {
        self.techniques.iter().find(|t| t.id == id)
    }

    pub fn techniques_for_tactic(&self, tactic: &str) -> Vec<&MitreTechnique> {
        self.techniques
            .iter()
            .filter(|t| t.tactic == tactic)
            .collect()
    }
}

impl Default for MitreMatrix {
    fn default() -> Self {
        Self::load_defaults()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub author: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub rule_content: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

impl YaraRule {
    pub fn new(name: &str, rule_content: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: String::new(),
            author: String::new(),
            severity: "medium".to_string(),
            tags: Vec::new(),
            rule_content: rule_content.to_string(),
            enabled: true,
            created_at: Utc::now(),
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_severity(mut self, severity: &str) -> Self {
        self.severity = severity.to_string();
        self
    }

    pub fn with_author(mut self, author: &str) -> Self {
        self.author = author.to_string();
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub author: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub logsource: SigmaLogSource,
    pub detection: SigmaDetection,
    pub falsepositives: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaLogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaDetection {
    pub condition: String,
    pub fields: std::collections::HashMap<String, serde_json::Value>,
}

impl SigmaRule {
    pub fn new(name: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: String::new(),
            author: String::new(),
            severity: "medium".to_string(),
            tags: Vec::new(),
            logsource: SigmaLogSource {
                category: None,
                product: None,
                service: None,
            },
            detection: SigmaDetection {
                condition: String::new(),
                fields: std::collections::HashMap::new(),
            },
            falsepositives: Vec::new(),
            enabled: true,
            created_at: Utc::now(),
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_author(mut self, author: &str) -> Self {
        self.author = author.to_string();
        self
    }

    pub fn with_severity(mut self, severity: &str) -> Self {
        self.severity = severity.to_string();
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_logsource_category(mut self, category: &str) -> Self {
        self.logsource.category = Some(category.to_string());
        self
    }

    pub fn with_logsource_product(mut self, product: &str) -> Self {
        self.logsource.product = Some(product.to_string());
        self
    }

    pub fn with_logsource_service(mut self, service: &str) -> Self {
        self.logsource.service = Some(service.to_string());
        self
    }

    pub fn with_falsepositives(mut self, fps: Vec<String>) -> Self {
        self.falsepositives = fps;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: f64,
    pub affected_products: Vec<String>,
    pub published_at: DateTime<Utc>,
    pub references: Vec<String>,
}

impl CveEntry {
    pub fn new(id: &str, cvss_score: f64) -> Self {
        Self {
            id: id.to_string(),
            description: String::new(),
            severity: if cvss_score >= 9.0 {
                "critical"
            } else if cvss_score >= 7.0 {
                "high"
            } else if cvss_score >= 4.0 {
                "medium"
            } else {
                "low"
            }
            .to_string(),
            cvss_score,
            affected_products: Vec::new(),
            published_at: Utc::now(),
            references: Vec::new(),
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_severity(mut self, severity: &str) -> Self {
        self.severity = severity.to_string();
        self
    }

    pub fn with_affected_products(mut self, products: Vec<String>) -> Self {
        self.affected_products = products;
        self
    }

    pub fn with_references(mut self, references: Vec<String>) -> Self {
        self.references = references;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    pub object_id: String,
    pub hash: Option<String>,
    pub score: f64,
    pub sources: Vec<String>,
    pub last_checked: DateTime<Utc>,
    pub known_malicious: bool,
    pub detection_count: u32,
}

impl ReputationScore {
    pub fn new(object_id: &str) -> Self {
        Self {
            object_id: object_id.to_string(),
            hash: None,
            score: 0.0,
            sources: Vec::new(),
            last_checked: Utc::now(),
            known_malicious: false,
            detection_count: 0,
        }
    }

    pub fn with_hash(mut self, hash: &str) -> Self {
        self.hash = Some(hash.to_string());
        self
    }

    pub fn with_score(mut self, score: f64) -> Self {
        self.score = score.clamp(0.0, 1.0);
        self
    }

    pub fn with_malicious(mut self, malicious: bool) -> Self {
        self.known_malicious = malicious;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceStats {
    pub total_iocs: usize,
    pub iocs_by_type: std::collections::HashMap<String, usize>,
    pub total_mitre_techniques: usize,
    pub total_yara_rules: usize,
    pub total_sigma_rules: usize,
    pub total_cves: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_type_as_str() {
        assert_eq!(IoCType::Hash.as_str(), "hash");
        assert_eq!(IoCType::IpAddress.as_str(), "ip_address");
        assert_eq!(IoCType::Domain.as_str(), "domain");
    }

    #[test]
    fn ioc_type_parse() {
        assert_eq!(IoCType::parse_from("hash"), Some(IoCType::Hash));
        assert_eq!(IoCType::parse_from("ip_address"), Some(IoCType::IpAddress));
        assert_eq!(IoCType::parse_from("invalid"), None);
    }

    #[test]
    fn ioc_creation() {
        let ioc = IoC::new(IoCType::Hash, "abc123", "test")
            .with_severity("high")
            .with_confidence(0.9)
            .with_description("Test IOC");
        assert_eq!(ioc.value, "abc123");
        assert_eq!(ioc.severity, "high");
        assert_eq!(ioc.confidence, 0.9);
    }

    #[test]
    fn mitre_technique_creation() {
        let t =
            MitreTechnique::new("T1059", "Command Execution", "execution").with_description("Test");
        assert_eq!(t.id, "T1059");
        assert_eq!(t.tactic, "execution");
    }

    #[test]
    fn mitre_matrix_defaults() {
        let matrix = MitreMatrix::load_defaults();
        assert!(!matrix.techniques.is_empty());
        assert!(matrix.find_technique("T1059").is_some());
        assert!(!matrix.techniques_for_tactic("execution").is_empty());
    }

    #[test]
    fn yara_rule_creation() {
        let rule = YaraRule::new("test_rule", "rule test { condition: true }")
            .with_description("Test")
            .with_severity("high");
        assert_eq!(rule.name, "test_rule");
        assert!(rule.enabled);
    }

    #[test]
    fn sigma_rule_creation() {
        let rule = SigmaRule::new("test_sigma").with_description("Test detection");
        assert_eq!(rule.name, "test_sigma");
        assert!(rule.enabled);
    }

    #[test]
    fn cve_entry_creation() {
        let cve = CveEntry::new("CVE-2024-1234", 9.5).with_description("Critical vuln");
        assert_eq!(cve.id, "CVE-2024-1234");
        assert_eq!(cve.severity, "critical");
    }

    #[test]
    fn reputation_score_creation() {
        let rep = ReputationScore::new("file:/tmp/test")
            .with_hash("abc123")
            .with_score(0.8)
            .with_malicious(true);
        assert_eq!(rep.object_id, "file:/tmp/test");
        assert!(rep.known_malicious);
    }

    #[test]
    fn all_ioc_types_parse_roundtrip() {
        let types = vec![
            IoCType::Hash,
            IoCType::IpAddress,
            IoCType::Domain,
            IoCType::Filename,
            IoCType::ProcessName,
            IoCType::ModuleName,
            IoCType::Url,
            IoCType::Email,
        ];
        for t in &types {
            let s = t.as_str();
            let parsed = IoCType::parse_from(s);
            assert_eq!(parsed.as_ref(), Some(t));
        }
    }
}
