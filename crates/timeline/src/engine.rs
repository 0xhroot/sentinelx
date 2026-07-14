use chrono::{DateTime, Utc};
use sentinelx_common::pid::Pid;
use sentinelx_common::severity::Severity;
use sentinelx_common::types::{ThreatEvent, TimelineEntry};

#[derive(Debug, Clone)]
pub struct TimelineEngine {
    entries: Vec<TimelineEntry>,
}

impl TimelineEngine {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add_event(&mut self, event: ThreatEvent) {
        let mut related_pids = Vec::new();
        let mut related_inodes = Vec::new();

        if let Some(ref process) = event.process {
            related_pids.push(process.pid);
            related_pids.push(process.ppid);
        }

        if let Some(ref network) = event.network {
            if let Some(pid) = network.pid {
                related_pids.push(pid);
            }
            related_inodes.push(network.inode);
        }

        related_pids.sort();
        related_pids.dedup();
        related_inodes.sort();
        related_inodes.dedup();

        let entry = TimelineEntry {
            timestamp: event.timestamp,
            event,
            related_pids,
            related_inodes,
        };
        self.entries.push(entry);
    }

    pub fn get_timeline(&self) -> &[TimelineEntry] {
        &self.entries
    }

    pub fn get_timeline_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    pub fn get_timeline_for_pid(&self, pid: Pid) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.related_pids.contains(&pid))
            .collect()
    }

    pub fn get_timeline_by_severity(&self, severity: Severity) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| e.event.severity == severity)
            .collect()
    }

    pub fn sort_by_time(&mut self) {
        self.entries.sort_by_key(|e| e.timestamp);
    }

    pub fn correlate(&self) -> Vec<Vec<&TimelineEntry>> {
        let mut groups: Vec<Vec<&TimelineEntry>> = Vec::new();
        let mut visited = vec![false; self.entries.len()];

        for i in 0..self.entries.len() {
            if visited[i] {
                continue;
            }

            let mut group = vec![&self.entries[i]];
            visited[i] = true;

            let mut pids: Vec<Pid> = self.entries[i].related_pids.clone();

            let mut changed = true;
            while changed {
                changed = false;
                for (j, was_visited) in visited.iter_mut().enumerate().take(self.entries.len()) {
                    if *was_visited {
                        continue;
                    }
                    if self.entries[j]
                        .related_pids
                        .iter()
                        .any(|pid| pids.contains(pid))
                    {
                        group.push(&self.entries[j]);
                        *was_visited = true;
                        for pid in &self.entries[j].related_pids {
                            if !pids.contains(pid) {
                                pids.push(*pid);
                                changed = true;
                            }
                        }
                    }
                }
            }

            group.sort_by_key(|e| e.timestamp);
            groups.push(group);
        }

        groups
    }

    pub fn generate_attack_narrative(&self) -> String {
        if self.entries.is_empty() {
            return "No events recorded.".to_string();
        }

        let mut sorted = self.entries.clone();
        sorted.sort_by_key(|e| e.timestamp);

        let mut narrative = String::from("Attack Timeline Narrative\n");
        narrative.push_str("========================\n\n");

        for (i, entry) in sorted.iter().enumerate() {
            narrative.push_str(&format!(
                "[{}] {} | {} | {}\n",
                i + 1,
                entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                entry.event.severity,
                entry.event.title
            ));
            narrative.push_str(&format!("  Category: {}\n", entry.event.category.as_str()));
            narrative.push_str(&format!("  {}\n", entry.event.description));

            if !entry.related_pids.is_empty() {
                let pids: Vec<String> = entry.related_pids.iter().map(|p| p.to_string()).collect();
                narrative.push_str(&format!("  Related PIDs: {}\n", pids.join(", ")));
            }

            if !entry.event.mitre_attack.is_empty() {
                for mapping in &entry.event.mitre_attack {
                    narrative.push_str(&format!(
                        "  MITRE: {} ({})\n",
                        mapping.technique_name, mapping.technique_id
                    ));
                }
            }
            narrative.push('\n');
        }

        let critical_count = sorted
            .iter()
            .filter(|e| e.event.severity == Severity::Critical)
            .count();
        let high_count = sorted
            .iter()
            .filter(|e| e.event.severity == Severity::High)
            .count();

        narrative.push_str("Summary\n");
        narrative.push_str("-------\n");
        narrative.push_str(&format!("Total events: {}\n", sorted.len()));
        narrative.push_str(&format!(
            "Critical: {}, High: {}\n",
            critical_count, high_count
        ));

        let groups = self.correlate();
        narrative.push_str(&format!("Event clusters: {}\n", groups.len()));

        narrative
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.entries)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }
}

impl Default for TimelineEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinelx_common::pid::Pid;
    use sentinelx_common::types::*;
    use std::collections::HashMap;

    fn make_event(
        title: &str,
        severity: Severity,
        category: ThreatCategory,
        pid: Option<u32>,
    ) -> ThreatEvent {
        let process = pid.map(|p| ProcessInfo {
            pid: Pid::new(p),
            ppid: Pid::new(1),
            name: format!("proc_{}", p),
            binary_path: format!("/usr/bin/proc_{}", p),
            command_line: vec![format!("proc_{}", p)],
            user: "root".to_string(),
            uid: 0,
            gid: 0,
            start_time: Utc::now(),
            status: ProcessStatus::Running,
            hash: None,
            namespace: NamespaceInfo::default(),
            capabilities: vec![],
            threads: 1,
            memory_usage_kb: 1024,
        });

        ThreatEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category,
            title: title.to_string(),
            description: format!("Description of {}", title),
            evidence: vec![Evidence {
                description: "evidence".to_string(),
                data: HashMap::new(),
                confidence: 0.9,
            }],
            mitre_attack: vec![],
            source_detector: "test".to_string(),
            process,
            network: None,
            hash: None,
            tags: vec![],
        }
    }

    #[test]
    fn test_new_engine_is_empty() {
        let engine = TimelineEngine::new();
        assert!(engine.get_timeline().is_empty());
    }

    #[test]
    fn test_add_event() {
        let mut engine = TimelineEngine::new();
        let event = make_event(
            "test",
            Severity::Low,
            ThreatCategory::HookDetected,
            Some(100),
        );
        engine.add_event(event);
        assert_eq!(engine.get_timeline().len(), 1);
    }

    #[test]
    fn test_get_timeline_for_pid() {
        let mut engine = TimelineEngine::new();
        engine.add_event(make_event(
            "ev1",
            Severity::Low,
            ThreatCategory::HookDetected,
            Some(100),
        ));
        engine.add_event(make_event(
            "ev2",
            Severity::Low,
            ThreatCategory::HookDetected,
            Some(200),
        ));
        engine.add_event(make_event(
            "ev3",
            Severity::Low,
            ThreatCategory::HookDetected,
            Some(100),
        ));

        let result = engine.get_timeline_for_pid(Pid::new(100));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_get_timeline_by_severity() {
        let mut engine = TimelineEngine::new();
        engine.add_event(make_event(
            "ev1",
            Severity::Critical,
            ThreatCategory::Rootkit,
            None,
        ));
        engine.add_event(make_event(
            "ev2",
            Severity::Low,
            ThreatCategory::HookDetected,
            None,
        ));
        engine.add_event(make_event(
            "ev3",
            Severity::Critical,
            ThreatCategory::Rootkit,
            None,
        ));

        let result = engine.get_timeline_by_severity(Severity::Critical);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_sort_by_time() {
        let mut engine = TimelineEngine::new();

        let mut ev1 = make_event("first", Severity::Low, ThreatCategory::HookDetected, None);
        ev1.timestamp = Utc::now();
        let mut ev2 = make_event("second", Severity::Low, ThreatCategory::HookDetected, None);
        ev2.timestamp = Utc::now() + chrono::Duration::seconds(5);

        engine.add_event(ev2);
        engine.add_event(ev1);

        engine.sort_by_time();
        assert_eq!(engine.get_timeline()[0].event.title, "first");
    }

    fn make_event_with_ppid(
        title: &str,
        severity: Severity,
        category: ThreatCategory,
        pid: Option<u32>,
        ppid: u32,
    ) -> ThreatEvent {
        let process = pid.map(|p| ProcessInfo {
            pid: Pid::new(p),
            ppid: Pid::new(ppid),
            name: format!("proc_{}", p),
            binary_path: format!("/usr/bin/proc_{}", p),
            command_line: vec![format!("proc_{}", p)],
            user: "root".to_string(),
            uid: 0,
            gid: 0,
            start_time: Utc::now(),
            status: ProcessStatus::Running,
            hash: None,
            namespace: NamespaceInfo::default(),
            capabilities: vec![],
            threads: 1,
            memory_usage_kb: 1024,
        });

        ThreatEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category,
            title: title.to_string(),
            description: format!("Description of {}", title),
            evidence: vec![Evidence {
                description: "evidence".to_string(),
                data: HashMap::new(),
                confidence: 0.9,
            }],
            mitre_attack: vec![],
            source_detector: "test".to_string(),
            process,
            network: None,
            hash: None,
            tags: vec![],
        }
    }

    #[test]
    fn test_correlate_groups_related_events() {
        let mut engine = TimelineEngine::new();
        engine.add_event(make_event_with_ppid(
            "ev1",
            Severity::High,
            ThreatCategory::HookDetected,
            Some(10),
            100,
        ));
        engine.add_event(make_event_with_ppid(
            "ev2",
            Severity::High,
            ThreatCategory::HiddenProcess,
            Some(10),
            100,
        ));
        engine.add_event(make_event_with_ppid(
            "ev3",
            Severity::Medium,
            ThreatCategory::ReverseShell,
            Some(99),
            200,
        ));

        let groups = engine.correlate();
        assert_eq!(groups.len(), 2);
        let group_with_10: Vec<&Vec<&TimelineEntry>> =
            groups.iter().filter(|g| g.len() == 2).collect();
        assert_eq!(group_with_10.len(), 1);
    }

    #[test]
    fn test_generate_attack_narrative() {
        let mut engine = TimelineEngine::new();
        assert_eq!(engine.generate_attack_narrative(), "No events recorded.");

        engine.add_event(make_event(
            "Rootkit detected",
            Severity::Critical,
            ThreatCategory::Rootkit,
            Some(42),
        ));
        let narrative = engine.generate_attack_narrative();
        assert!(narrative.contains("Attack Timeline Narrative"));
        assert!(narrative.contains("Rootkit detected"));
        assert!(narrative.contains("Total events: 1"));
    }

    #[test]
    fn test_to_json() {
        let mut engine = TimelineEngine::new();
        engine.add_event(make_event(
            "test",
            Severity::Low,
            ThreatCategory::HookDetected,
            Some(1),
        ));
        let json = engine.to_json();
        assert!(json.contains("test"));
    }
}
