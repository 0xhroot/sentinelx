import { useState, useEffect } from 'react';
import { fetchKernelIntegrity, KernelIntegrityResponse } from '../api';

export default function KernelIntegrity() {
  const [status, setStatus] = useState<KernelIntegrityResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchKernelIntegrity().then(setStatus).catch((e) => setError(String(e)));
  }, []);

  const passedCount = status ? status.checks.filter((c) => c.passed).length : 0;
  const totalChecks = status ? status.checks.length : 0;
  const overallStatus = totalChecks > 0 && passedCount === totalChecks
    ? 'secure'
    : passedCount > 0
    ? 'warning'
    : 'insecure';

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-300">
          Failed to load kernel integrity data: {error}
        </div>
      )}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h3 className="text-lg font-semibold text-white">Kernel Security Posture</h3>
            <p className="text-sm text-slate-400 mt-1">
              {passedCount}/{totalChecks} checks passed
            </p>
          </div>
          <div className={`px-4 py-2 rounded-lg text-sm font-semibold ${
            overallStatus === 'secure'
              ? 'bg-green-500/10 text-green-400 border border-green-500/30'
              : overallStatus === 'warning'
              ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
              : 'bg-red-500/10 text-red-400 border border-red-500/30'
          }`}>
            {overallStatus.toUpperCase()}
          </div>
        </div>

        <div className="w-full bg-slate-700/30 rounded-full h-2 mb-6">
          <div
            className="bg-gradient-to-r from-green-500 to-emerald-400 h-2 rounded-full transition-all duration-500"
            style={{ width: `${totalChecks > 0 ? (passedCount / totalChecks) * 100 : 0}%` }}
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {status?.checks.map((check) => (
            <div
              key={check.name}
              className={`flex items-center gap-4 p-4 rounded-xl border transition-colors ${
                check.passed
                  ? 'bg-green-500/5 border-green-500/20'
                  : 'bg-red-500/5 border-red-500/20'
              }`}
            >
              <div className={`flex items-center justify-center w-10 h-10 rounded-lg ${
                check.passed
                  ? 'bg-green-500/10 text-green-400'
                  : 'bg-red-500/10 text-red-400'
              }`}>
                {check.passed ? (
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                  </svg>
                ) : (
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                )}
              </div>
              <div>
                <p className={`text-sm font-medium ${check.passed ? 'text-green-300' : 'text-red-300'}`}>
                  {check.name}
                </p>
                <p className="text-xs text-slate-500 mt-0.5">{check.detail}</p>
              </div>
            </div>
          ))}
          {(!status || status.checks.length === 0) && (
            <div className="col-span-2 text-center py-8 text-slate-500 text-sm">
              No kernel integrity data available
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
