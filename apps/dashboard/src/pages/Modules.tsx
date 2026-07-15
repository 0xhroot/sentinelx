import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Search, Box, CheckCircle2, XCircle, HelpCircle } from 'lucide-react';
import { fetchModules } from '../api';
import { KernelModuleInfo } from '../types';
import EmptyState from '../components/EmptyState';

export default function Modules() {
  const [modules, setModules] = useState<KernelModuleInfo[]>([]);
  const [search, setSearch] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchModules().then(setModules).catch((e) => setError(String(e)));
  }, []);

  const filtered = modules.filter((m) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return m.name.toLowerCase().includes(q) || (m.license || '').toLowerCase().includes(q);
  });

  const liveCount = modules.filter((m) => m.state === 'Live').length;
  const unsignedCount = modules.filter((m) => m.signature_valid === false).length;

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
          { label: 'Total', value: modules.length, color: 'rgba(255,255,255,0.87)' },
          { label: 'Live', value: liveCount, color: '#4ADE80' },
          { label: 'Unsigned', value: unsignedCount, color: '#F87171' },
        ].map((item, i) => (
          <motion.div key={item.label} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}
            className="sx-card p-4">
            <p className="text-[10px] font-medium uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.3)' }}>{item.label}</p>
            <p className="text-xl font-bold mt-1" style={{ color: item.color }}>{item.value}</p>
          </motion.div>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 h-9 px-3 rounded-lg sx-input max-w-xs">
          <Search size={14} style={{ color: 'rgba(255,255,255,0.25)' }} />
          <input type="text" placeholder="Search modules..." value={search} onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent border-none outline-none text-xs flex-1" style={{ color: 'rgba(255,255,255,0.87)' }} />
        </div>
        <span className="text-[11px] ml-auto" style={{ color: 'rgba(255,255,255,0.25)' }}>
          {filtered.length} module{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {filtered.length === 0 ? (
        <EmptyState icon={Box} title="No modules found" description="No kernel modules match your search" />
      ) : (
        <div className="sx-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="sx-table">
              <thead>
                <tr>
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>Module</th>
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>Size</th>
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>State</th>
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>Signed</th>
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>License</th>
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>Version</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((mod, i) => (
                  <motion.tr key={mod.name} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }}>
                    <td className="text-xs font-medium" style={{ color: 'rgba(255,255,255,0.8)' }}>{mod.name}</td>
                    <td className="text-[11px] font-mono" style={{ color: 'rgba(255,255,255,0.5)' }}>{(mod.size / 1024).toFixed(1)} KB</td>
                    <td><span className={mod.state === 'Live' ? 'sx-badge-green' : 'sx-badge-low'}>{mod.state}</span></td>
                    <td>
                      {mod.signature_valid === true ? (
                        <span className="sx-badge-green"><CheckCircle2 size={10} /> Signed</span>
                      ) : mod.signature_valid === false ? (
                        <span className="sx-badge-red"><XCircle size={10} /> Unsigned</span>
                      ) : (
                        <span className="sx-badge-low"><HelpCircle size={10} /> Unknown</span>
                      )}
                    </td>
                    <td className="text-[11px] font-mono" style={{ color: 'rgba(255,255,255,0.35)' }}>{mod.license || '—'}</td>
                    <td className="text-[11px] font-mono" style={{ color: 'rgba(255,255,255,0.35)' }}>{mod.version || '—'}</td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
