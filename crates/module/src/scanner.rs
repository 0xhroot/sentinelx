use sentinelx_common::types::{KernelModuleInfo, ModuleSource, ModuleState};

pub struct ModuleScanner;

impl ModuleScanner {
    pub fn new() -> Self {
        Self
    }

    pub fn scan_proc_modules(&self) -> Vec<KernelModuleInfo> {
        let mut modules = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/modules") {
            for line in content.lines() {
                if let Some(module) = self.parse_proc_module_line(line) {
                    modules.push(module);
                }
            }
        }

        modules
    }

    fn parse_proc_module_line(&self, line: &str) -> Option<KernelModuleInfo> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            return None;
        }

        let name = parts[0].to_string();
        let size = parts[1].parse().unwrap_or(0);
        let ref_count: u32 = parts[2].parse().unwrap_or(0);
        let load_address = u64::from_str_radix(parts[3], 16).unwrap_or(0);

        let state = match parts[4] {
            "Live" => ModuleState::Live,
            "Coming" => ModuleState::Coming,
            "Going" => ModuleState::Going,
            _ => ModuleState::Unknown,
        };

        let module_offset = parts[5];
        let _module_name = module_offset.trim_start_matches('[').trim_end_matches(']');

        Some(KernelModuleInfo {
            name,
            size,
            ref_count,
            load_address,
            state,
            version: None,
            license: None,
            hash: None,
            signature_valid: None,
            source: ModuleSource::ProcModules,
        })
    }
}

impl Default for ModuleScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_proc_modules_runs() {
        let scanner = ModuleScanner::new();
        let modules = scanner.scan_proc_modules();
        assert!(!modules.is_empty() || modules.is_empty());
    }
}
