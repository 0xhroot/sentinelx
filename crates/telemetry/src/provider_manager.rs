use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::types::ProviderStatus;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Capability {
    Ebpf,
    Fanotify,
    Netlink,
    Audit,
    ProcConnector,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub capability: Capability,
    pub available: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHealthReport {
    pub name: String,
    pub status: ProviderStatus,
    pub events_received: u64,
    pub events_dropped: u64,
    pub started_at: Option<String>,
    pub uptime_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelLatencyReport {
    pub provider: String,
    pub avg_latency_us: f64,
    pub max_latency_us: f64,
    pub samples: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryRateReport {
    pub provider: String,
    pub events_per_second: f64,
    pub total_events: u64,
    pub total_dropped: u64,
    pub drop_rate_percent: f64,
}

pub struct ProviderManager {
    capabilities: Vec<CapabilityReport>,
    active_providers: Arc<Vec<String>>,
    provider_health: Arc<tokio::sync::RwLock<Vec<ProviderHealthReport>>>,
    latency_tracker: Arc<LatencyTracker>,
}

struct LatencyTracker {
    samples: AtomicU64,
    total_latency_us: AtomicU64,
    max_latency_us: AtomicU64,
}

impl LatencyTracker {
    fn new() -> Self {
        Self {
            samples: AtomicU64::new(0),
            total_latency_us: AtomicU64::new(0),
            max_latency_us: AtomicU64::new(0),
        }
    }

    fn record(&self, latency_us: u64) {
        self.samples.fetch_add(1, Ordering::Relaxed);
        self.total_latency_us
            .fetch_add(latency_us, Ordering::Relaxed);
        self.max_latency_us.fetch_max(latency_us, Ordering::Relaxed);
    }

    fn avg(&self) -> f64 {
        let samples = self.samples.load(Ordering::Relaxed);
        if samples == 0 {
            0.0
        } else {
            self.total_latency_us.load(Ordering::Relaxed) as f64 / samples as f64
        }
    }

    fn max(&self) -> f64 {
        self.max_latency_us.load(Ordering::Relaxed) as f64
    }

    fn count(&self) -> u64 {
        self.samples.load(Ordering::Relaxed)
    }
}

impl ProviderManager {
    pub fn detect() -> Self {
        let capabilities = detect_capabilities();

        let active: Vec<String> = capabilities
            .iter()
            .filter(|c| c.available)
            .map(|c| match c.capability {
                Capability::Ebpf => "ebpf".to_string(),
                Capability::Fanotify => "fanotify".to_string(),
                Capability::Netlink => "netlink".to_string(),
                Capability::Audit => "auditd".to_string(),
                Capability::ProcConnector => "proc_connector".to_string(),
            })
            .collect();

        info!(
            "ProviderManager detected {} active capabilities: {:?}",
            active.len(),
            active
        );

        Self {
            capabilities,
            active_providers: Arc::new(active),
            provider_health: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            latency_tracker: Arc::new(LatencyTracker::new()),
        }
    }

    pub fn capabilities(&self) -> &[CapabilityReport] {
        &self.capabilities
    }

    pub fn active_providers(&self) -> &[String] {
        &self.active_providers
    }

    pub fn is_available(&self, cap: &Capability) -> bool {
        self.capabilities
            .iter()
            .any(|c| &c.capability == cap && c.available)
    }

    pub fn preferred_order(&self) -> Vec<Capability> {
        let mut available: Vec<Capability> = self
            .capabilities
            .iter()
            .filter(|c| c.available)
            .map(|c| c.capability.clone())
            .collect();

        available.sort_by_key(capability_priority);
        available
    }

    pub fn record_latency(&self, latency_us: u64) {
        self.latency_tracker.record(latency_us);
    }

    pub fn latency_report(&self) -> Vec<KernelLatencyReport> {
        self.active_providers
            .iter()
            .map(|name| KernelLatencyReport {
                provider: name.clone(),
                avg_latency_us: self.latency_tracker.avg(),
                max_latency_us: self.latency_tracker.max(),
                samples: self.latency_tracker.count(),
            })
            .collect()
    }

    pub async fn update_provider_health(&self, health: Vec<ProviderHealthReport>) {
        *self.provider_health.write().await = health;
    }

    pub async fn provider_health(&self) -> Vec<ProviderHealthReport> {
        self.provider_health.read().await.clone()
    }

    pub fn rate_report(&self) -> Vec<TelemetryRateReport> {
        self.active_providers
            .iter()
            .map(|name| TelemetryRateReport {
                provider: name.clone(),
                events_per_second: 0.0,
                total_events: 0,
                total_dropped: 0,
                drop_rate_percent: 0.0,
            })
            .collect()
    }
}

fn capability_priority(cap: &Capability) -> u8 {
    match cap {
        Capability::Ebpf => 0,
        Capability::Fanotify => 1,
        Capability::Netlink => 2,
        Capability::Audit => 3,
        Capability::ProcConnector => 4,
    }
}

fn detect_capabilities() -> Vec<CapabilityReport> {
    let mut caps = Vec::new();

    let ebpf_cap = detect_ebpf();
    caps.push(ebpf_cap);

    let fanotify_cap = detect_fanotify();
    caps.push(fanotify_cap);

    let netlink_cap = detect_netlink();
    caps.push(netlink_cap);

    let audit_cap = detect_audit();
    caps.push(audit_cap);

    caps.push(CapabilityReport {
        capability: Capability::ProcConnector,
        available: true,
        reason: Some("Always available via /proc filesystem".to_string()),
    });

    caps
}

fn detect_ebpf() -> CapabilityReport {
    if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        let has_bpf = check_cap_sys_admin() || check_cap_bpf();
        CapabilityReport {
            capability: Capability::Ebpf,
            available: has_bpf,
            reason: if has_bpf {
                Some("BTF available, sufficient capabilities".to_string())
            } else {
                Some(
                    "BTF available but insufficient capabilities (need CAP_BPF or CAP_SYS_ADMIN)"
                        .to_string(),
                )
            },
        }
    } else {
        CapabilityReport {
            capability: Capability::Ebpf,
            available: false,
            reason: Some("BTF not available (/sys/kernel/btf/vmlinux not found)".to_string()),
        }
    }
}

fn detect_fanotify() -> CapabilityReport {
    let available = check_cap_sys_admin();
    CapabilityReport {
        capability: Capability::Fanotify,
        available,
        reason: if available {
            Some("CAP_SYS_ADMIN available".to_string())
        } else {
            Some("Requires CAP_SYS_ADMIN for fanotify_mark".to_string())
        },
    }
}

fn detect_netlink() -> CapabilityReport {
    CapabilityReport {
        capability: Capability::Netlink,
        available: true,
        reason: Some("AF_NETLINK sockets available to all processes".to_string()),
    }
}

fn detect_audit() -> CapabilityReport {
    let available = check_cap_audit_write() || check_cap_audit_control();
    CapabilityReport {
        capability: Capability::Audit,
        available,
        reason: if available {
            Some("CAP_AUDIT_WRITE or CAP_AUDIT_CONTROL available".to_string())
        } else {
            Some("Requires CAP_AUDIT_WRITE or CAP_AUDIT_CONTROL for NETLINK_AUDIT".to_string())
        },
    }
}

fn check_cap_sys_admin() -> bool {
    check_capability(21)
}

fn check_cap_bpf() -> bool {
    check_capability(39)
}

fn check_cap_audit_write() -> bool {
    check_capability(29)
}

fn check_cap_audit_control() -> bool {
    check_capability(30)
}

fn check_capability(bit: u32) -> bool {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // SAFETY: capget syscall with _LINUX_CAPABILITY_VERSION_3 (0x20080522).
    // CapHeader and CapData are repr(C) matching kernel struct layout.
    // data array is size 2 as required by V3 capability header.
    // Return value checked: non-zero means capget failed.
    unsafe {
        let mut header = CapHeader {
            version: 0x20080522,
            pid: 0,
        };
        let mut data = [
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];

        let ret = libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr());
        if ret != 0 {
            return false;
        }

        let word = (bit / 32) as usize;
        let offset = bit % 32;
        (data[word].effective & (1 << offset)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_manager() {
        let manager = ProviderManager::detect();
        assert!(!manager.capabilities().is_empty());
        assert!(!manager.active_providers().is_empty());
    }

    #[test]
    fn capability_report_has_all() {
        let manager = ProviderManager::detect();
        let caps: Vec<_> = manager
            .capabilities()
            .iter()
            .map(|c| &c.capability)
            .collect();
        assert!(caps.contains(&&Capability::Ebpf));
        assert!(caps.contains(&&Capability::Fanotify));
        assert!(caps.contains(&&Capability::Netlink));
        assert!(caps.contains(&&Capability::Audit));
        assert!(caps.contains(&&Capability::ProcConnector));
    }

    #[test]
    fn proc_connector_always_available() {
        let manager = ProviderManager::detect();
        assert!(manager.is_available(&Capability::ProcConnector));
    }

    #[test]
    fn netlink_always_available() {
        let manager = ProviderManager::detect();
        assert!(manager.is_available(&Capability::Netlink));
    }

    #[test]
    fn preferred_order_excludes_unavailable() {
        let manager = ProviderManager::detect();
        let order = manager.preferred_order();
        assert!(order.contains(&Capability::ProcConnector));
        assert!(order.contains(&Capability::Netlink));
    }

    #[test]
    fn preferred_order_priority() {
        let mut order = [
            Capability::ProcConnector,
            Capability::Ebpf,
            Capability::Audit,
        ];
        order.sort_by_key(capability_priority);
        assert_eq!(order[0], Capability::Ebpf);
        assert_eq!(order[1], Capability::Audit);
        assert_eq!(order[2], Capability::ProcConnector);
    }

    #[test]
    fn capability_priority_values() {
        assert!(
            capability_priority(&Capability::Ebpf) < capability_priority(&Capability::Fanotify)
        );
        assert!(
            capability_priority(&Capability::Fanotify) < capability_priority(&Capability::Netlink)
        );
        assert!(
            capability_priority(&Capability::Netlink) < capability_priority(&Capability::Audit)
        );
        assert!(
            capability_priority(&Capability::Audit)
                < capability_priority(&Capability::ProcConnector)
        );
    }

    #[test]
    fn latency_tracker() {
        let tracker = LatencyTracker::new();
        assert_eq!(tracker.avg(), 0.0);
        assert_eq!(tracker.max(), 0.0);
        assert_eq!(tracker.count(), 0);

        tracker.record(100);
        tracker.record(200);
        tracker.record(50);

        assert_eq!(tracker.count(), 3);
        assert!((tracker.avg() - 116.666).abs() < 1.0);
        assert_eq!(tracker.max(), 200.0);
    }

    #[test]
    fn provider_manager_latency_report() {
        let manager = ProviderManager::detect();
        manager.record_latency(100);
        manager.record_latency(200);

        let report = manager.latency_report();
        assert!(!report.is_empty());
        assert_eq!(report[0].samples, 2);
    }

    #[tokio::test]
    async fn provider_health_update() {
        let manager = ProviderManager::detect();
        let health = vec![ProviderHealthReport {
            name: "test".to_string(),
            status: ProviderStatus::Running,
            events_received: 100,
            events_dropped: 5,
            started_at: None,
            uptime_seconds: Some(3600),
        }];

        manager.update_provider_health(health).await;
        let retrieved = manager.provider_health().await;
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].name, "test");
    }

    #[test]
    fn rate_report_for_active_providers() {
        let manager = ProviderManager::detect();
        let rates = manager.rate_report();
        assert!(!rates.is_empty());
        for r in &rates {
            assert!(!r.provider.is_empty());
        }
    }

    #[test]
    fn check_capability_returns_bool() {
        let result = check_cap_sys_admin();
        let _ = result;
    }
}
