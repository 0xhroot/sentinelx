use sentinelx_common::hash::HashValue;
use sentinelx_common::types::KernelModuleInfo;

pub struct ModuleTrustChecker {
    known_modules: Vec<KnownModule>,
}

#[derive(Debug, Clone)]
pub struct KnownModule {
    pub name: String,
    pub hash: Option<HashValue>,
    pub publisher: Option<String>,
    pub trusted: bool,
}

#[derive(Debug, Clone)]
pub struct ModuleTrustResult {
    pub module: KernelModuleInfo,
    pub trusted: bool,
    pub reason: String,
    pub score: f64,
}

impl ModuleTrustChecker {
    pub fn new() -> Self {
        Self {
            known_modules: Vec::new(),
        }
    }

    pub fn with_known_modules(known: Vec<KnownModule>) -> Self {
        Self {
            known_modules: known,
        }
    }

    pub fn check(&self, module: &KernelModuleInfo) -> ModuleTrustResult {
        if let Some(known) = self.known_modules.iter().find(|k| k.name == module.name) {
            if let (Some(expected_hash), Some(actual_hash)) = (&known.hash, &module.hash) {
                if expected_hash.matches(actual_hash) {
                    return ModuleTrustResult {
                        module: module.clone(),
                        trusted: known.trusted,
                        reason: "Hash matches known module".to_string(),
                        score: if known.trusted { 1.0 } else { 0.3 },
                    };
                } else {
                    return ModuleTrustResult {
                        module: module.clone(),
                        trusted: false,
                        reason: "Hash mismatch with known module".to_string(),
                        score: 0.1,
                    };
                }
            }

            return ModuleTrustResult {
                module: module.clone(),
                trusted: known.trusted,
                reason: "Module name matches known module".to_string(),
                score: if known.trusted { 0.9 } else { 0.4 },
            };
        }

        let mut reasons = Vec::new();
        let mut score: f64 = 0.5;

        if module.hash.is_none() {
            reasons.push("No hash available".to_string());
            score -= 0.1;
        }

        if module.signature_valid == Some(false) {
            reasons.push("Invalid signature".to_string());
            score -= 0.3;
        }

        match module.license.as_deref() {
            Some("GPL") | Some("GPL v2") => {
                score += 0.1;
            }
            Some(license) => {
                reasons.push(format!("Non-GPL license: {}", license));
                score -= 0.05;
            }
            None => {
                reasons.push("No license information".to_string());
                score -= 0.1;
            }
        }

        if module.version.is_none() {
            reasons.push("No version information".to_string());
            score -= 0.05;
        }

        let trusted = score >= 0.6;

        ModuleTrustResult {
            module: module.clone(),
            trusted,
            reason: if reasons.is_empty() {
                "Module not in known list but appears legitimate".to_string()
            } else {
                reasons.join("; ")
            },
            score: score.clamp(0.0, 1.0),
        }
    }
}

impl Default for ModuleTrustChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_common::types::{ModuleSource, ModuleState};

    fn test_module(name: &str) -> KernelModuleInfo {
        KernelModuleInfo {
            name: name.to_string(),
            size: 1024,
            ref_count: 1,
            load_address: 0xffffffffc0000000,
            state: ModuleState::Live,
            version: Some("1.0.0".to_string()),
            license: Some("GPL".to_string()),
            hash: None,
            signature_valid: Some(true),
            source: ModuleSource::ProcModules,
        }
    }

    #[test]
    fn unknown_module_gets_lower_score() {
        let checker = ModuleTrustChecker::new();
        let module = test_module("mystery_module");
        let result = checker.check(&module);
        assert!(!result.trusted || result.score < 1.0);
    }

    #[test]
    fn known_trusted_module() {
        let checker = ModuleTrustChecker::with_known_modules(vec![KnownModule {
            name: "e1000e".to_string(),
            hash: None,
            publisher: Some("Intel".to_string()),
            trusted: true,
        }]);
        let module = test_module("e1000e");
        let result = checker.check(&module);
        assert!(result.trusted);
    }
}
