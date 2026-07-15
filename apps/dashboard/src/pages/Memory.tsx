import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { HardDrive, CheckCircle2, XCircle } from 'lucide-react';
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

  const ProgressBar = ({ percent, color }: { percent: number; color: string }) => (
    <div className="w-full h-2 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.04)' }}>
      <motion.div
        initial={{ width: 0 }}
        animate={{ width: `${Math.min(percent, 100)}%` }}
        transition={{ duration: 0.8, ease: 'easeOut' }}
        className="h-full rounded-full"
        style={{ background: color }}
      />
    </div>
  );

  return (
    <div className="space-y-4">
      {error && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="rounded-xl px-4 py-3 text-sm"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)', color: '#F87171' }}>
          {error}
        </motion.div>
      )}

      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Total Memory', value: status ? formatKB(status.total_memory_kb) : '—', color: 'rgba(255,255,255,0.87)' },
          { label: 'Used Memory', value: status ? formatKB(status.used_memory_kb) : '—', color: '#60A5FA' },
          { label: 'Available', value: status ? formatKB(status.available_memory_kb) : '—', color: '#4ADE80' },
        ].map((item, i) => (
          <motion.div key={item.label} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}
            className="sx-card p-4">
            <p className="text-[10px] font-medium uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.3)' }}>{item.label}</p>
            <p className="text-xl font-bold mt-1" style={{ color: item.color }}>{item.value}</p>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <div className="sx-card p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'rgba(255,255,255,0.35)' }}>Memory Usage</h3>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between mb-2 text-xs">
                <span style={{ color: 'rgba(255,255,255,0.4)' }}>RAM</span>
                <span style={{ color: 'rgba(255,255,255,0.6)' }}>{memPercent.toFixed(1)}%</span>
              </div>
              <ProgressBar percent={memPercent} color={memPercent > 90 ? '#EF4444' : memPercent > 70 ? '#EAB308' : '#3B82F6'} />
            </div>
            <div>
              <div className="flex justify-between mb-2 text-xs">
                <span style={{ color: 'rgba(255,255,255,0.4)' }}>Swap</span>
                <span style={{ color: 'rgba(255,255,255,0.6)' }}>{swapPercent.toFixed(1)}%</span>
              </div>
              <ProgressBar percent={swapPercent} color="#8B5CF6" />
            </div>
          </div>
        </div>

        <div className="sx-card p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.35)' }}>Integrity Checks</h3>
            <span className={totalChecks > 0 && passedCount === totalChecks ? 'sx-badge-green' : 'sx-badge-red'}>
              {passedCount}/{totalChecks}
            </span>
          </div>
          <div className="space-y-2">
            {status?.checks.map((check, i) => (
              <motion.div key={i} initial={{ opacity: 0, x: -5 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}
                className="flex items-center gap-3 p-2.5 rounded-lg"
                style={{ background: check.passed ? 'rgba(34,197,94,0.04)' : 'rgba(239,68,68,0.04)', border: `1px solid ${check.passed ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)'}` }}>
                {check.passed ? <CheckCircle2 size={14} style={{ color: '#4ADE80' }} /> : <XCircle size={14} style={{ color: '#F87171' }} />}
                <div>
                  <p className="text-xs font-medium" style={{ color: 'rgba(255,255,255,0.7)' }}>{check.name}</p>
                  <p className="text-[10px]" style={{ color: 'rgba(255,255,255,0.25)' }}>{check.detail}</p>
                </div>
              </motion.div>
            ))}
            {(!status || status.checks.length === 0) && (
              <div className="text-center py-8 text-xs" style={{ color: 'rgba(255,255,255,0.2)' }}>No data available</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
