import {
  ThreatRow,
  ProcessInfo,
  NetworkConnection,
  KernelModuleInfo,
  MetricsSnapshot,
  ForensicSnapshot,
  StatusResponse,
  DetectorInfo,
  ScanResponse,
} from './types';

const BASE_URL = '/api';

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${endpoint}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export function fetchThreats(): Promise<ThreatRow[]> {
  return request<ThreatRow[]>('/threats');
}

export function acknowledgeThreat(id: string): Promise<void> {
  return request<void>(`/threats/${id}/acknowledge`, { method: 'POST' });
}

export function resolveThreat(id: string): Promise<void> {
  return request<void>(`/threats/${id}/resolve`, { method: 'POST' });
}

export function fetchProcesses(): Promise<ProcessInfo[]> {
  return request<ProcessInfo[]>('/processes');
}

export function fetchModules(): Promise<KernelModuleInfo[]> {
  return request<KernelModuleInfo[]>('/modules');
}

export function fetchNetwork(): Promise<NetworkConnection[]> {
  return request<NetworkConnection[]>('/network');
}

export function fetchStatus(): Promise<StatusResponse> {
  return request<StatusResponse>('/status');
}

export function runScan(): Promise<ScanResponse> {
  return request<ScanResponse>('/scan', { method: 'POST' });
}

export function fetchForensics(): Promise<ForensicSnapshot> {
  return request<ForensicSnapshot>('/forensics');
}

export function fetchTimeline(): Promise<unknown[]> {
  return request<unknown[]>('/timeline');
}

export function fetchDetectors(): Promise<{ detectors: DetectorInfo[] }> {
  return request<{ detectors: DetectorInfo[] }>('/detectors');
}

export function fetchMetrics(): Promise<MetricsSnapshot> {
  return request<StatusResponse>('/status').then((s) => s.metrics);
}

export interface IntegrityCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface KernelIntegrityResponse {
  secure_boot: boolean;
  kptr_restricted: boolean;
  dmesg_restrict: boolean;
  lockdown: string;
  checks: IntegrityCheck[];
}

export interface MemoryIntegrityResponse {
  total_memory_kb: number;
  available_memory_kb: number;
  used_memory_kb: number;
  swap_total_kb: number;
  swap_used_kb: number;
  checks: IntegrityCheck[];
}

export function fetchKernelIntegrity(): Promise<KernelIntegrityResponse> {
  return request<KernelIntegrityResponse>('/kernel/integrity');
}

export function fetchMemoryIntegrity(): Promise<MemoryIntegrityResponse> {
  return request<MemoryIntegrityResponse>('/memory/integrity');
}
