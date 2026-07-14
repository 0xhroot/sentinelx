use std::collections::HashMap;
use tracing::debug;

use sentinelx_common::hash::HashValue;
use sentinelx_common::types::KernelSymbol;

pub struct KernelSymbolTable {
    symbols: HashMap<String, KernelSymbol>,
}

impl KernelSymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
        }
    }

    pub fn load_from_kallsyms() -> Result<Self, std::io::Error> {
        let mut table = Self::new();
        let content = std::fs::read_to_string("/proc/kallsyms")?;

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let address = u64::from_str_radix(parts[0], 16).unwrap_or(0);
                let sym_type = parts[1];
                let name = parts[2].to_string();
                let module = if parts.len() > 3 {
                    parts[3]
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_string()
                } else {
                    String::new()
                };

                let symbol = KernelSymbol {
                    name: name.clone(),
                    address,
                    size: 0,
                    module: if module.is_empty() {
                        None
                    } else {
                        Some(module)
                    },
                    is_function: sym_type == "T" || sym_type == "t",
                };

                table.symbols.insert(name, symbol);
            }
        }

        debug!(
            count = table.symbols.len(),
            "Loaded kernel symbols from kallsyms"
        );
        Ok(table)
    }

    pub fn get_symbol(&self, name: &str) -> Option<&KernelSymbol> {
        self.symbols.get(name)
    }

    pub fn get_all(&self) -> &HashMap<String, KernelSymbol> {
        &self.symbols
    }

    pub fn count(&self) -> usize {
        self.symbols.len()
    }

    pub fn compute_hash(&self) -> HashValue {
        let mut data = Vec::new();
        let mut sorted: Vec<_> = self.symbols.iter().collect();
        sorted.sort_by_key(|(name, _)| name.to_string());

        for (name, sym) in &sorted {
            data.extend_from_slice(name.as_bytes());
            data.extend_from_slice(&sym.address.to_le_bytes());
        }

        HashValue::new(&data)
    }

    pub fn diff(&self, other: &KernelSymbolTable) -> SymbolDiff {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut modified = Vec::new();

        for (name, sym) in &other.symbols {
            if let Some(old_sym) = self.symbols.get(name) {
                if old_sym.address != sym.address {
                    modified.push(name.clone());
                }
            } else {
                added.push(name.clone());
            }
        }

        for name in self.symbols.keys() {
            if !other.symbols.contains_key(name) {
                removed.push(name.clone());
            }
        }

        SymbolDiff {
            added,
            removed,
            modified,
        }
    }
}

impl Default for KernelSymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct SymbolDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
}

impl SymbolDiff {
    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.modified.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table() {
        let table = KernelSymbolTable::new();
        assert_eq!(table.count(), 0);
        assert!(table.get_symbol("nonexistent").is_none());
    }

    #[test]
    fn symbol_diff() {
        let mut t1 = KernelSymbolTable::new();
        t1.symbols.insert(
            "sys_read".to_string(),
            KernelSymbol {
                name: "sys_read".to_string(),
                address: 0xffffffff81000000,
                size: 100,
                module: None,
                is_function: true,
            },
        );

        let mut t2 = KernelSymbolTable::new();
        t2.symbols.insert(
            "sys_write".to_string(),
            KernelSymbol {
                name: "sys_write".to_string(),
                address: 0xffffffff81000100,
                size: 100,
                module: None,
                is_function: true,
            },
        );

        let diff = t1.diff(&t2);
        assert!(diff.has_changes());
        assert!(diff.added.contains(&"sys_write".to_string()));
        assert!(diff.removed.contains(&"sys_read".to_string()));
    }
}
