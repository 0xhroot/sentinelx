use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::types::{
    CveEntry, IntelligenceStats, IoC, IoCType, MitreMatrix, MitreTechnique, ReputationScore,
    SigmaRule, YaraRule,
};

pub struct IntelligenceEngine {
    iocs: Arc<RwLock<HashMap<String, IoC>>>,
    mitre: Arc<RwLock<MitreMatrix>>,
    yara_rules: Arc<RwLock<Vec<YaraRule>>>,
    sigma_rules: Arc<RwLock<Vec<SigmaRule>>>,
    cves: Arc<RwLock<HashMap<String, CveEntry>>>,
    reputation: Arc<RwLock<HashMap<String, ReputationScore>>>,
}

impl IntelligenceEngine {
    pub fn new() -> Self {
        Self {
            iocs: Arc::new(RwLock::new(HashMap::new())),
            mitre: Arc::new(RwLock::new(MitreMatrix::load_defaults())),
            yara_rules: Arc::new(RwLock::new(Vec::new())),
            sigma_rules: Arc::new(RwLock::new(Vec::new())),
            cves: Arc::new(RwLock::new(HashMap::new())),
            reputation: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_ioc(&self, ioc: IoC) {
        let mut iocs = self.iocs.write().await;
        let key = format!("{}:{}", ioc.ioc_type.as_str(), ioc.value);
        iocs.insert(key, ioc);
    }

    pub async fn get_ioc(&self, ioc_type: &IoCType, value: &str) -> Option<IoC> {
        let iocs = self.iocs.read().await;
        let key = format!("{}:{}", ioc_type.as_str(), value);
        iocs.get(&key).cloned()
    }

    pub async fn list_iocs(&self) -> Vec<IoC> {
        let iocs = self.iocs.read().await;
        iocs.values().cloned().collect()
    }

    pub async fn list_iocs_by_type(&self, ioc_type: &IoCType) -> Vec<IoC> {
        let iocs = self.iocs.read().await;
        iocs.values()
            .filter(|i| i.ioc_type == *ioc_type)
            .cloned()
            .collect()
    }

    pub async fn check_hash(&self, hash: &str) -> Option<IoC> {
        let iocs = self.iocs.read().await;
        iocs.values()
            .find(|i| i.ioc_type == IoCType::Hash && i.value == hash)
            .cloned()
    }

    pub async fn check_ip(&self, ip: &str) -> Option<IoC> {
        let iocs = self.iocs.read().await;
        iocs.values()
            .find(|i| i.ioc_type == IoCType::IpAddress && i.value == ip)
            .cloned()
    }

    pub async fn check_domain(&self, domain: &str) -> Option<IoC> {
        let iocs = self.iocs.read().await;
        iocs.values()
            .find(|i| i.ioc_type == IoCType::Domain && i.value == domain)
            .cloned()
    }

    pub async fn remove_ioc(&self, ioc_type: &IoCType, value: &str) -> bool {
        let mut iocs = self.iocs.write().await;
        let key = format!("{}:{}", ioc_type.as_str(), value);
        iocs.remove(&key).is_some()
    }

    pub async fn ioc_count(&self) -> usize {
        let iocs = self.iocs.read().await;
        iocs.len()
    }

    pub async fn iocs_by_type_count(&self) -> HashMap<String, usize> {
        let iocs = self.iocs.read().await;
        let mut counts = HashMap::new();
        for ioc in iocs.values() {
            *counts.entry(ioc.ioc_type.as_str().to_string()).or_insert(0) += 1;
        }
        counts
    }

    pub async fn find_mitre_technique(&self, id: &str) -> Option<MitreTechnique> {
        let mitre = self.mitre.read().await;
        mitre.find_technique(id).cloned()
    }

    pub async fn list_mitre_techniques(&self) -> Vec<MitreTechnique> {
        let mitre = self.mitre.read().await;
        mitre.techniques.clone()
    }

    pub async fn mitre_techniques_for_tactic(&self, tactic: &str) -> Vec<MitreTechnique> {
        let mitre = self.mitre.read().await;
        mitre
            .techniques_for_tactic(tactic)
            .into_iter()
            .cloned()
            .collect()
    }

    pub async fn add_yara_rule(&self, rule: YaraRule) {
        let mut rules = self.yara_rules.write().await;
        rules.push(rule);
    }

    pub async fn list_yara_rules(&self) -> Vec<YaraRule> {
        let rules = self.yara_rules.read().await;
        rules.clone()
    }

    pub async fn find_yara_rule(&self, name: &str) -> Option<YaraRule> {
        let rules = self.yara_rules.read().await;
        rules.iter().find(|r| r.name == name).cloned()
    }

    pub async fn add_sigma_rule(&self, rule: SigmaRule) {
        let mut rules = self.sigma_rules.write().await;
        rules.push(rule);
    }

    pub async fn list_sigma_rules(&self) -> Vec<SigmaRule> {
        let rules = self.sigma_rules.read().await;
        rules.clone()
    }

    pub async fn find_sigma_rule(&self, name: &str) -> Option<SigmaRule> {
        let rules = self.sigma_rules.read().await;
        rules.iter().find(|r| r.name == name).cloned()
    }

    pub async fn add_cve(&self, cve: CveEntry) {
        let mut cves = self.cves.write().await;
        cves.insert(cve.id.clone(), cve);
    }

    pub async fn find_cve(&self, id: &str) -> Option<CveEntry> {
        let cves = self.cves.read().await;
        cves.get(id).cloned()
    }

    pub async fn list_cves(&self) -> Vec<CveEntry> {
        let cves = self.cves.read().await;
        cves.values().cloned().collect()
    }

    pub async fn update_reputation(&self, rep: ReputationScore) {
        let mut reputation = self.reputation.write().await;
        reputation.insert(rep.object_id.clone(), rep);
    }

    pub async fn get_reputation(&self, object_id: &str) -> Option<ReputationScore> {
        let reputation = self.reputation.read().await;
        reputation.get(object_id).cloned()
    }

    pub async fn stats(&self) -> IntelligenceStats {
        IntelligenceStats {
            total_iocs: self.ioc_count().await,
            iocs_by_type: self.iocs_by_type_count().await,
            total_mitre_techniques: {
                let mitre = self.mitre.read().await;
                mitre.techniques.len()
            },
            total_yara_rules: {
                let rules = self.yara_rules.read().await;
                rules.len()
            },
            total_sigma_rules: {
                let rules = self.sigma_rules.read().await;
                rules.len()
            },
            total_cves: {
                let cves = self.cves.read().await;
                cves.len()
            },
        }
    }

    pub async fn clear(&self) {
        self.iocs.write().await.clear();
        self.yara_rules.write().await.clear();
        self.sigma_rules.write().await.clear();
        self.cves.write().await.clear();
        self.reputation.write().await.clear();
    }

    pub async fn get_ioc_by_str(&self, ioc_type: &str, value: &str) -> Option<IoC> {
        if let Some(ioc_type) = IoCType::parse_from(ioc_type) {
            self.get_ioc(&ioc_type, value).await
        } else {
            None
        }
    }

    pub async fn remove_ioc_by_str(&self, ioc_type: &str, value: &str) -> bool {
        if let Some(ioc_type) = IoCType::parse_from(ioc_type) {
            self.remove_ioc(&ioc_type, value).await
        } else {
            false
        }
    }

    pub async fn list_iocs_limit(&self, limit: usize) -> Vec<IoC> {
        let iocs = self.iocs.read().await;
        iocs.values().take(limit).cloned().collect()
    }

    pub async fn list_cves_limit(&self, limit: usize) -> Vec<CveEntry> {
        let cves = self.cves.read().await;
        cves.values().take(limit).cloned().collect()
    }

    pub async fn get_mitre_technique(&self, id: &str) -> Option<MitreTechnique> {
        self.find_mitre_technique(id).await
    }

    pub async fn get_yara_rule(&self, name: &str) -> Option<YaraRule> {
        self.find_yara_rule(name).await
    }

    pub async fn get_sigma_rule(&self, name: &str) -> Option<SigmaRule> {
        self.find_sigma_rule(name).await
    }

    pub async fn get_cve(&self, id: &str) -> Option<CveEntry> {
        self.find_cve(id).await
    }

    pub async fn get_global_reputation(&self) -> ReputationScore {
        let reputation = self.reputation.read().await;
        if reputation.is_empty() {
            ReputationScore::new("global").with_score(0.5)
        } else {
            let avg_score: f64 =
                reputation.values().map(|r| r.score).sum::<f64>() / reputation.len() as f64;
            let known_malicious = reputation.values().any(|r| r.known_malicious);
            ReputationScore::new("global")
                .with_score(avg_score)
                .with_malicious(known_malicious)
        }
    }
}

impl Default for IntelligenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn engine_creation() {
        let engine = IntelligenceEngine::new();
        let stats = engine.stats().await;
        assert_eq!(stats.total_iocs, 0);
        assert!(stats.total_mitre_techniques > 0);
    }

    #[tokio::test]
    async fn engine_add_and_get_ioc() {
        let engine = IntelligenceEngine::new();
        let ioc = IoC::new(IoCType::Hash, "abc123def", "test")
            .with_severity("high")
            .with_confidence(0.9);
        engine.add_ioc(ioc.clone()).await;

        let found = engine.check_hash("abc123def").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().severity, "high");
    }

    #[tokio::test]
    async fn engine_ioc_by_type() {
        let engine = IntelligenceEngine::new();
        engine.add_ioc(IoC::new(IoCType::Hash, "h1", "test")).await;
        engine
            .add_ioc(IoC::new(IoCType::IpAddress, "1.2.3.4", "test"))
            .await;

        let hashes = engine.list_iocs_by_type(&IoCType::Hash).await;
        assert_eq!(hashes.len(), 1);
    }

    #[tokio::test]
    async fn engine_check_ip() {
        let engine = IntelligenceEngine::new();
        engine
            .add_ioc(IoC::new(IoCType::IpAddress, "10.0.0.1", "test").with_severity("critical"))
            .await;

        let found = engine.check_ip("10.0.0.1").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().severity, "critical");
    }

    #[tokio::test]
    async fn engine_mitre_techniques() {
        let engine = IntelligenceEngine::new();
        let techniques = engine.list_mitre_techniques().await;
        assert!(!techniques.is_empty());

        let t = engine.find_mitre_technique("T1059").await;
        assert!(t.is_some());

        let execution = engine.mitre_techniques_for_tactic("execution").await;
        assert!(!execution.is_empty());
    }

    #[tokio::test]
    async fn engine_yara_rules() {
        let engine = IntelligenceEngine::new();
        let rule = YaraRule::new("test_rule", "rule test { condition: true }");
        engine.add_yara_rule(rule).await;

        let rules = engine.list_yara_rules().await;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "test_rule");
    }

    #[tokio::test]
    async fn engine_sigma_rules() {
        let engine = IntelligenceEngine::new();
        let rule = SigmaRule::new("test_sigma");
        engine.add_sigma_rule(rule).await;

        let rules = engine.list_sigma_rules().await;
        assert_eq!(rules.len(), 1);
    }

    #[tokio::test]
    async fn engine_cve() {
        let engine = IntelligenceEngine::new();
        let cve = CveEntry::new("CVE-2024-1234", 9.5);
        engine.add_cve(cve).await;

        let found = engine.find_cve("CVE-2024-1234").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().cvss_score, 9.5);
    }

    #[tokio::test]
    async fn engine_reputation() {
        let engine = IntelligenceEngine::new();
        let rep = ReputationScore::new("file:/tmp/test")
            .with_score(0.8)
            .with_malicious(true);
        engine.update_reputation(rep).await;

        let found = engine.get_reputation("file:/tmp/test").await;
        assert!(found.is_some());
        assert!(found.unwrap().known_malicious);
    }

    #[tokio::test]
    async fn engine_remove_ioc() {
        let engine = IntelligenceEngine::new();
        engine
            .add_ioc(IoC::new(IoCType::Hash, "to_remove", "test"))
            .await;
        assert_eq!(engine.ioc_count().await, 1);

        let removed = engine.remove_ioc(&IoCType::Hash, "to_remove").await;
        assert!(removed);
        assert_eq!(engine.ioc_count().await, 0);
    }

    #[tokio::test]
    async fn engine_clear() {
        let engine = IntelligenceEngine::new();
        engine.add_ioc(IoC::new(IoCType::Hash, "h1", "test")).await;
        engine.add_cve(CveEntry::new("CVE-2024-0001", 5.0)).await;
        engine.clear().await;
        let stats = engine.stats().await;
        assert_eq!(stats.total_iocs, 0);
        assert_eq!(stats.total_cves, 0);
    }

    #[tokio::test]
    async fn engine_stats() {
        let engine = IntelligenceEngine::new();
        engine.add_ioc(IoC::new(IoCType::Hash, "h1", "test")).await;
        engine
            .add_ioc(IoC::new(IoCType::IpAddress, "1.2.3.4", "test"))
            .await;
        engine.add_yara_rule(YaraRule::new("r1", "rule {}")).await;

        let stats = engine.stats().await;
        assert_eq!(stats.total_iocs, 2);
        assert_eq!(stats.total_yara_rules, 1);
    }
}
