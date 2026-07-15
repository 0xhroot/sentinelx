import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { FileSearch, Download, AlertTriangle, Link2, File } from 'lucide-react';
import { fetchForensics } from '../api';
import { ForensicSnapshot } from '../types';
import ThreatBadge from '../components/ThreatBadge';
import LoadingSkeleton from '../components/LoadingSkeleton';

export default function Forensics() {
  const [snapshot, setSnapshot] = useState<ForensicSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchForensics().then(setSnapshot).catch((e) => setError(String(e)));
  }, []);

  if (!snapshot && !error) {
    return (
      <div className="space-y-3">
        <LoadingSkeleton className="h-32 w-full" count={2} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {error && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="rounded-xl px-4 py-3 text-sm"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)', color: '#F87171' }}>
          {error}
        </motion.div>
      )}

      {snapshot && (
        <>
          {/* Host info */}
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="sx-card p-4">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                  style={{ background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.15)' }}>
                  <FileSearch size={18} style={{ color: '#A78BFA' }} />
                </div>
                <div>
                  <h3 className="text-sm font-semibold" style={{ color: 'rgba(255,255,255,0.9)' }}>{snapshot.hostname}</h3>
                  <p className="text-[10px] font-mono" style={{ color: 'rgba(255,255,255,0.25)' }}>{snapshot.kernel_version}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.2)' }}>
                  {new Date(snapshot.timestamp).toLocaleString()}
                </span>
                <button className="sx-btn-ghost text-[11px] h-7">
                  <Download size={12} /> Export
                </button>
              </div>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { label: 'Processes', value: snapshot.processes.length, color: '#60A5FA' },
                { label: 'Modules', value: snapshot.modules.length, color: '#A78BFA' },
                { label: 'Connections', value: snapshot.connections.length, color: '#22D3EE' },
                { label: 'Hooks', value: snapshot.hooks.length, color: snapshot.hooks.length > 0 ? '#F87171' : '#4ADE80' },
              ].map((item, i) => (
                <div key={item.label} className="p-3 rounded-lg" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
                  <p className="text-[10px] uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.25)' }}>{item.label}</p>
                  <p className="text-lg font-bold mt-1" style={{ color: item.color }}>{item.value}</p>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Threats */}
          {snapshot.threats.length > 0 && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="sx-card p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'rgba(255,255,255,0.35)' }}>
                Threats ({snapshot.threats.length})
              </h3>
              <div className="space-y-2">
                {snapshot.threats.map((threat) => (
                  <div key={threat.id} className="flex items-start gap-3 p-3 rounded-lg"
                    style={{ background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.08)' }}>
                    <AlertTriangle size={14} className="mt-0.5 shrink-0" style={{ color: '#F87171' }} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-xs font-medium" style={{ color: 'rgba(255,255,255,0.8)' }}>{threat.title}</p>
                        <ThreatBadge severity={threat.severity} />
                      </div>
                      <p className="text-[10px] mt-0.5" style={{ color: 'rgba(255,255,255,0.3)' }}>{threat.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          )}

          {/* Hooks */}
          {snapshot.hooks.length > 0 && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="sx-card p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'rgba(255,255,255,0.35)' }}>
                Hooks Detected ({snapshot.hooks.length})
              </h3>
              <div className="space-y-1.5">
                {snapshot.hooks.map((hook, i) => (
                  <div key={i} className="flex items-center gap-3 p-2.5 rounded-lg font-mono text-[11px]"
                    style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
                    <span className="px-1.5 py-0.5 rounded" style={{ background: 'rgba(249,115,22,0.1)', color: '#FB923C' }}>
                      {hook.hook_type}
                    </span>
                    <span style={{ color: 'rgba(255,255,255,0.3)' }}>0x{hook.address.toString(16)}</span>
                    {hook.symbol && <span style={{ color: '#60A5FA' }}>{hook.symbol}</span>}
                    {hook.module && <span style={{ color: 'rgba(255,255,255,0.2)' }}>[{hook.module}]</span>}
                  </div>
                ))}
              </div>
            </motion.div>
          )}

          {/* Open Files */}
          {snapshot.open_files.length > 0 && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="sx-card p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'rgba(255,255,255,0.35)' }}>
                Open Files ({snapshot.open_files.length})
              </h3>
              <div className="max-h-48 overflow-y-auto space-y-0.5">
                {snapshot.open_files.slice(0, 50).map((file, i) => (
                  <div key={i} className="flex items-center gap-2 py-0.5 text-[11px] font-mono"
                    style={{ color: 'rgba(255,255,255,0.3)' }}>
                    <File size={10} style={{ color: 'rgba(255,255,255,0.15)' }} />
                    {file}
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </>
      )}
    </div>
  );
}
