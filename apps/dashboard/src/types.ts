export interface StatusResponse {
  metrics: MetricsSnapshot;
  detector_count: number;
}

export interface ThreatRow {
  id: string;
  timestamp: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  source_detector: string;
  acknowledged: boolean;
}

export interface ProcessInfo {
  pid: number;
  ppid: number;
  name: string;
  binary_path: string;
  command_line: string[];
  user: string;
  uid: number;
  gid: number;
  start_time: string;
  status: string;
  namespace: Record<string, unknown>;
  capabilities: string[];
  threads: number;
  memory_usage_kb: number;
}

export interface NetworkConnection {
  local_addr: { ip: string; port: number };
  remote_addr: { ip: string; port: number } | null;
  protocol: string;
  state: string;
  pid: number | null;
  inode: number;
  uid: number;
  process_name: string | null;
}

export interface KernelModuleInfo {
  name: string;
  size: number;
  ref_count: number;
  load_address: number;
  state: string;
  version: string | null;
  license: string | null;
  signature_valid: boolean | null;
  source: string;
}

export interface MetricsSnapshot {
  timestamp: string;
  events_processed: number;
  threats_detected: number;
  scans_completed: number;
  errors: number;
  active_detectors: number;
  memory_usage_bytes: number;
  cpu_usage_percent: number;
}

export interface ForensicSnapshot {
  id: string;
  timestamp: string;
  hostname: string;
  kernel_version: string;
  processes: ProcessInfo[];
  modules: KernelModuleInfo[];
  connections: NetworkConnection[];
  hooks: { hook_type: string; address: number; symbol: string | null; module: string | null }[];
  threats: ThreatRow[];
  open_files: string[];
}

export interface DetectorInfo {
  name: string;
  description: string;
  category: string;
  severity: string;
}

export interface ScanResponse {
  threats_found: number;
  threats: ThreatRow[];
}
