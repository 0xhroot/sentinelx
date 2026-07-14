import { useState, useEffect } from 'react';
import { fetchMemoryIntegrity, MemoryIntegrityResponse } from '../api';

export default function Memory() {
  const [status, setStatus] = useState<MemoryIntegrityResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchMemoryIntegrity().then(setStatus).catch((e) => setError(String(e)));
  }, []);

  const formatKB = (kb: number) => {
    if (kb > 1073741824) return `${(kb / 1073741824).toFixed(1)} TB`;
    if (kb > 1048576) return `${(kb / 1048576).toFixed(1)} GB`;
    if (kb > 1024) return `${(kb / 1024).toFixed(1)} MB`;
    return `${kb} KB`;
  };

  const memPercent = status ? (status.used_memory_kb / status.total_memory_kb) * 100 : 0;
  const swapPercent = status && status.swap_total_kb > 0 ? (status.swap_used_kb / status.swap_total_kb) * 100 : 0;

  const passedCount = status ? status.checks.filter((c) => c.passed).length : 0;
  const totalChecks = status ? status.checks.length : 0;

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-300">
          Failed to load memory data: {error}
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card p-5">
          <p className="stat-label">Total Memory</p>
          <p className="stat-value text-white">{status ? formatKB(status.total_memory_kb) : '-'}</p>
        </div>
        <div className="card p-5">
          <p className="stat-label">Used Memory</p>
          <p className="stat-value text-blue-400">{status ? formatKB(status.used_memory_kb) : '-'}</p>
        </div>
        <div className="card p-5">
          <p className="stat-label">Available</p>
          <p className="stat-value text-green-400">{status ? formatKB(status.available_memory_kb) : '-'}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Memory Usage</h3>
          <div className="relative pt-1">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-slate-400">RAM</span>
              <span className="text-xs font-medium text-slate-300">{memPercent.toFixed(1)}%</span>
            </div>
            <div className="w-full bg-slate-700/30 rounded-full h-3">
              <div
                className={`h-3 rounded-full transition-all duration-500 ${
                  memPercent > 90 ? 'bg-red-500' : memPercent > 70 ? 'bg-yellow-500' : 'bg-blue-500'
                }`}
                style={{ width: `${Math.min(memPercent, 100)}%` }}
              />
            </div>
            <div className="flex justify-between mt-2 text-xs text-slate-500">
              <span>{status ? formatKB(status.used_memory_kb) : '0'}</span>
              <span>{status ? formatKB(status.total_memory_kb) : '0'}</span>
            </div>
          </div>

          <div className="mt-6 relative pt-1">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-slate-400">Swap</span>
              <span className="text-xs font-medium text-slate-300">{swapPercent.toFixed(1)}%</span>
            </div>
            <div className="w-full bg-slate-700/30 rounded-full h-3">
              <div
                className="bg-purple-500 h-3 rounded-full transition-all duration-500"
                style={{ width: `${Math.min(swapPercent, 100)}%` }}
              />
            </div>
            <div className="flex justify-between mt-2 text-xs text-slate-500">
              <span>{status ? formatKB(status.swap_used_kb) : '0'}</span>
              <span>{status ? formatKB(status.swap_total_kb) : '0'}</span>
            </div>
          </div>
        </div>

        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300">Integrity Checks</h3>
            <span className={`badge ${
              totalChecks > 0 && passedCount === totalChecks
                ? 'bg-green-500/10 text-green-400 border border-green-500/30'
                : 'bg-red-500/10 text-red-400 border border-red-500/30'
            }`}>
              {passedCount}/{totalChecks}
            </span>
          </div>

          <div className="space-y-3">
            {status?.checks.map((check, i) => (
              <div
                key={i}
                className={`flex items-start gap-3 p-3 rounded-lg border ${
                  check.passed
                    ? 'bg-green-500/5 border-green-500/20'
                    : 'bg-red-500/5 border-red-500/20'
                }`}
              >
                <div className={`mt-0.5 ${
                  check.passed ? 'text-green-400' : 'text-red-400'
                }`}>
                  {check.passed ? (
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                    </svg>
                  ) : (
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                    </svg>
                  )}
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-200">{check.name}</p>
                  <p className="text-xs text-slate-400 mt-0.5">{check.detail}</p>
                </div>
              </div>
            ))}
            {(!status || status.checks.length === 0) && (
              <div className="text-center py-8 text-slate-500 text-sm">
                No integrity check data available
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
