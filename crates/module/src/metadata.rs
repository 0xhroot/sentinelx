use sentinelx_core::error::CoreError;
use sentinelx_core::metadata::MetadataCollector;
use sentinelx_core::object::SentinelObject;

pub struct ModuleMetadataCollector {
    builtin_modules: Vec<String>,
}

impl ModuleMetadataCollector {
    pub fn new() -> Self {
        Self {
            builtin_modules: builtin_modules_list(),
        }
    }

    fn scan_sysfs_modules(&self) -> Vec<String> {
        let mut modules = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/sys/module") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name != "." && name != ".." {
                    modules.push(name);
                }
            }
        }
        modules
    }

    fn scan_kallsyms_modules(&self) -> Vec<String> {
        let mut modules = Vec::new();
        if let Ok(content) = std::fs::read_to_string("/proc/kallsyms") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let module_part = parts[3].trim_start_matches('[').trim_end_matches(']');
                    if !module_part.is_empty() && !modules.contains(&module_part.to_string()) {
                        modules.push(module_part.to_string());
                    }
                }
            }
        }
        modules
    }
}

impl Default for ModuleMetadataCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl MetadataCollector for ModuleMetadataCollector {
    fn name(&self) -> &str {
        "module_metadata"
    }

    fn description(&self) -> &str {
        "Enriches module objects with DKOM detection via sysfs/kallsyms cross-referencing"
    }

    async fn enrich(&self, objects: &mut [SentinelObject]) -> Result<(), CoreError> {
        let sysfs_modules = self.scan_sysfs_modules();
        let kallsyms_modules = self.scan_kallsyms_modules();

        let sysfs_set: std::collections::HashSet<&String> = sysfs_modules.iter().collect();
        let kallsyms_set: std::collections::HashSet<&String> = kallsyms_modules.iter().collect();

        for obj in objects.iter_mut() {
            let module_name = match obj.metadata.properties.get("name").and_then(|v| v.as_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            let is_builtin = self.builtin_modules.contains(&module_name);
            obj.metadata
                .properties
                .insert("is_builtin".to_string(), serde_json::json!(is_builtin));

            let in_sysfs = sysfs_set.contains(&module_name);
            let in_kallsyms = kallsyms_set.contains(&module_name);

            obj.metadata
                .properties
                .insert("in_sysfs".to_string(), serde_json::json!(in_sysfs));
            obj.metadata
                .properties
                .insert("in_kallsyms".to_string(), serde_json::json!(in_kallsyms));

            if !is_builtin && in_sysfs && !in_kallsyms {
                obj.metadata
                    .properties
                    .insert("dkom_suspected".to_string(), serde_json::Value::Bool(true));
                obj.metadata.tags.push("dkom".to_string());
                obj.metadata.tags.push("hidden_module".to_string());
            }

            let mut trust_score = obj
                .metadata
                .properties
                .get("trust_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.5);

            let license = obj
                .metadata
                .properties
                .get("license")
                .and_then(|v| v.as_str());
            if license == Some("GPL") || license == Some("GPL v2") {
                trust_score += 0.1;
            }

            let sig_valid = obj
                .metadata
                .properties
                .get("signature_valid")
                .and_then(|v| v.as_bool());
            if sig_valid == Some(true) {
                trust_score += 0.1;
            }

            obj.metadata.properties.insert(
                "trust_score".to_string(),
                serde_json::json!(trust_score.clamp(0.0, 1.0)),
            );
        }

        Ok(())
    }
}

fn builtin_modules_list() -> Vec<String> {
    vec![
        "vDSO",
        "kvm",
        "kvm_amd",
        "kvm_intel",
        "irqbounce",
        "acpi_pad",
        "aes_x86_64",
        "aes_ni_intel",
        "algif_hash",
        "autofs4",
        "binfmt_misc",
        "bluetooth",
        "br_netfilter",
        "bridge",
        "btnet",
        "btrtl",
        "btusb",
        "ccm",
        "cfg80211",
        "cmac",
        "coretemp",
        "cpufreq",
        "cpufreq_powersave",
        "cpufreq_stats",
        "cpufreq_ondemand",
        "crc32c_generic",
        "cryptd",
        "crypto_simd",
        "dcdbas",
        "dca",
        "dell_laptop",
        "dell_smbios",
        "drm",
        "drm_kms_helper",
        "e1000e",
        "edac_core",
        "efi_pstore",
        "ext4",
        "fat",
        "fb_sys_fops",
        "floppy",
        "fscrypto",
        "fuse",
        "gf128mul",
        "ghash_clmulni_intel",
        "glue_helper",
        "hid",
        "hid_generic",
        "hp_wmi",
        "hpcicoe",
        "i2c_algo_bit",
        "i2c_core",
        "i2c_i801",
        "i2c_smbus",
        "i915",
        "input_leds",
        "intel_cstate",
        "intel_pch_thermal",
        "intel_powerclamp",
        "intel_rapl",
        "intel_rapl_perf",
        "intel_soc_dts_iosf",
        "intel_turbo_boost",
        "intel_uncore",
        "ip6t_REJECT",
        "ip6table_filter",
        "ip6table_mangle",
        "ip6table_nat",
        "ip_tables",
        "ipt_REJECT",
        "iptable_filter",
        "iptable_mangle",
        "iptable_nat",
        "joydev",
        "kvm",
        "leds_class",
        "leds_hp_sddisk",
        "llc",
        "loop",
        "lrw",
        "mac_hid",
        "mbcache",
        "md_mod",
        "mei",
        "mei_me",
        "mfd_core",
        "module",
        "mmc_block",
        "mmc_core",
        "mousedev",
        "msr",
        "nbd",
        "nfit",
        "nf_conntrack",
        "nf_defrag_ipv4",
        "nf_defrag_ipv6",
        "nf_nat",
        "nf_reject_ipv4",
        "nf_reject_ipv6",
        "nls_cp437",
        "nls_iso8859_1",
        "nvme",
        "nvme_core",
        "overlay",
        "parport",
        "parport_pc",
        "pcspkr",
        "ppdev",
        "psmouse",
        "qrtr",
        "qxl",
        "rapl",
        "rcupdate",
        "rcupdate_nocb",
        "reed_solomon",
        "rfcomm",
        "rgb_led",
        "rng_core",
        "roles",
        "rt2800pci",
        "rt2x00pci",
        "sd_mod",
        "serio_raw",
        "sg",
        "snd",
        "snd_hda_codec",
        "snd_hda_intel",
        "snd_pcm",
        "soundcore",
        "sparse_keymap",
        "sr_mod",
        "stp",
        "sunrpc",
        "syscopyarea",
        "sysfillrect",
        "sysimgblt",
        "tcp_diag",
        "thermal",
        "thermal_sys",
        "tmcore",
        "tpm",
        "tpm_tis",
        "ttm",
        "tun",
        "uas",
        "usbhid",
        "usb_storage",
        "usbcore",
        "usb_common",
        "uvcvideo",
        "vfat",
        "video",
        "virtio",
        "virtio_blk",
        "virtio_console",
        "virtio_net",
        "virtio_pci",
        "virtio_ring",
        "vmw_balloon",
        "vmw_vmci",
        "vmwgfx",
        "wmi",
        "wmi_bmof",
        "x86_pkg_temp_thermal",
        "xor",
        "x_tables",
        "xt_conntrack",
        "xt_owner",
        "xt_statistic",
        "zram",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelx_core::object::{ObjectMetadata, ObjectType};

    fn make_module_object(name: &str) -> SentinelObject {
        let metadata = ObjectMetadata::new()
            .with_property("name", serde_json::json!(name))
            .with_property("size", serde_json::json!(1024))
            .with_property("trust_score", serde_json::json!(0.5))
            .with_property("license", serde_json::json!("GPL"))
            .with_property("signature_valid", serde_json::json!(true));

        SentinelObject::new(ObjectType::KernelModule, "test", name).with_metadata(metadata)
    }

    #[tokio::test]
    async fn test_enrich_populates_sysfs_and_kallsyms_flags() {
        let collector = ModuleMetadataCollector::new();
        let mut objects = vec![make_module_object("test_module")];
        collector.enrich(&mut objects).await.unwrap();

        assert!(objects[0].metadata.properties.contains_key("in_sysfs"));
        assert!(objects[0].metadata.properties.contains_key("in_kallsyms"));
    }

    #[tokio::test]
    async fn test_enrich_handles_empty_objects() {
        let collector = ModuleMetadataCollector::new();
        let mut empty: Vec<SentinelObject> = vec![];
        assert!(collector.enrich(&mut empty).await.is_ok());
    }

    #[test]
    fn test_builtin_list_contains_common_modules() {
        let builtins = builtin_modules_list();
        assert!(builtins.contains(&"kvm".to_string()));
        assert!(builtins.contains(&"ext4".to_string()));
        assert!(builtins.contains(&"e1000e".to_string()));
        assert!(!builtins.contains(&"nvidia".to_string()));
    }

    #[test]
    fn test_provider_name() {
        let collector = ModuleMetadataCollector::new();
        assert_eq!(collector.name(), "module_metadata");
    }
}
