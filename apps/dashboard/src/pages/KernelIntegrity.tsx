import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Lock, CheckCircle2, XCircle } from 'lucide-react';
import { fetchKernelIntegrity, KernelIntegrityResponse } from '../api';

export default function KernelIntegrity() {
  const [status, setStatus] = useState<KernelIntegrityResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchKernelIntegrity().then(setStatus).catch((e) => setError(String(e)));
  }, []);

  const passedCount = status ? status.checks.filter((c) => c.passed).length : 0;
  const totalChecks = status ? status.checks.length : 0;
  const overallStatus = totalChecks > 0 && passedCount === totalChecks ? 'SECURE' : passedCount > 0 ? 'WARNING' : 'INSECURE';
  const overallColor = totalChecks > 0 && passedCount === totalChecks ? '#4ADE80' : passedCount > 0 ? '#FACC15' : '#F87171';

  return (
    <div className="space-y-4">
      {error && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="rounded-xl px-4 py-3 text-sm"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)', color: '#F87171' }}>
          {error}
        </motion.div>
      )}

      <div className="sx-card p-5">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-base font-semibold" style={{ color: 'rgba(255,255,255,0.92)' }}>Kernel Security Posture</h3>
            <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,0.3)' }}>{passedCount}/{totalChecks} checks passed</p>
          </div>
          <span className="sx-badge text-xs font-bold" style={{ background: `${overallColor}12`, color: overallColor, border: `1px solid ${overallColor}33` }}>
            {overallStatus}
          </span>
        </div>

        <div className="w-full h-2 rounded-full overflow-hidden mb-6" style={{ background: 'rgba(255,255,255,0.04)' }}>
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${totalChecks > 0 ? (passedCount / totalChecks) * 100 : 0}%` }}
            transition={{ duration: 0.8, ease: 'easeOut' }}
            className="h-full rounded-full"
            style={{ background: `linear-gradient(90deg, ${overallColor}, ${overallColor}88)` }}
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {status?.checks.map((check, i) => (
            <motion.div key={check.name}
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className="flex items-center gap-3 p-3 rounded-xl"
              style={{
                background: check.passed ? 'rgba(34,197,94,0.04)' : 'rgba(239,68,68,0.04)',
                border: `1px solid ${check.passed ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)'}`,
              }}>
              <div className="flex items-center justify-center w-8 h-8 rounded-lg shrink-0"
                style={{ background: check.passed ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)' }}>
                {check.passed ? <CheckCircle2 size={14} style={{ color: '#4ADE80' }} /> : <XCircle size={14} style={{ color: '#F87171' }} />}
              </div>
              <div>
                <p className="text-xs font-medium" style={{ color: check.passed ? '#4ADE80' : '#F87171' }}>{check.name}</p>
                <p className="text-[10px] mt-0.5" style={{ color: 'rgba(255,255,255,0.25)' }}>{check.detail}</p>
              </div>
            </motion.div>
          ))}
          {(!status || status.checks.length === 0) && (
            <div className="col-span-2 text-center py-12">
              <Lock size={32} className="mx-auto mb-3" style={{ color: 'rgba(255,255,255,0.08)' }} />
              <p className="text-sm" style={{ color: 'rgba(255,255,255,0.2)' }}>No kernel integrity data</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
