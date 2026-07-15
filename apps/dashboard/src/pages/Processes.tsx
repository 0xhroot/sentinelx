import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Search, Cpu, ArrowUpDown, ChevronDown, ChevronUp } from 'lucide-react';
import { fetchProcesses } from '../api';
import { ProcessInfo } from '../types';
import EmptyState from '../components/EmptyState';

type SortKey = 'pid' | 'name' | 'user' | 'memory_usage_kb';

export default function Processes() {
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>('pid');
  const [sortAsc, setSortAsc] = useState(false);
  const [search, setSearch] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    fetchProcesses().then(setProcesses).catch((e) => setError(String(e)));
  }, []);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(!sortAsc);
    else { setSortKey(key); setSortAsc(false); }
  };

  const sorted = [...processes]
    .filter((p) => {
      if (!search) return true;
      const q = search.toLowerCase();
      return p.name.toLowerCase().includes(q) || p.user.toLowerCase().includes(q) || String(p.pid).includes(q);
    })
    .sort((a, b) => {
      const aVal = a[sortKey];
      const bVal = b[sortKey];
      const cmp = typeof aVal === 'string' ? aVal.localeCompare(bVal as string) : (aVal as number) - (bVal as number);
      return sortAsc ? cmp : -cmp;
    });

  const SortHeader = ({ field, label }: { field: SortKey; label: string }) => (
    <th
      className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider cursor-pointer select-none text-left"
      style={{ color: 'rgba(255,255,255,0.3)' }}
      onClick={() => handleSort(field)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {sortKey === field && <span style={{ color: '#60A5FA' }}>{sortAsc ? '↑' : '↓'}</span>}
        {sortKey !== field && <ArrowUpDown size={10} />}
      </span>
    </th>
  );

  const maxMem = Math.max(...sorted.map((p) => p.memory_usage_kb), 1);

  return (
    <div className="space-y-4">
      {error && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="rounded-xl px-4 py-3 text-sm"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)', color: '#F87171' }}>
          {error}
        </motion.div>
      )}

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 h-9 px-3 rounded-lg sx-input max-w-xs">
          <Search size={14} style={{ color: 'rgba(255,255,255,0.25)' }} />
          <input type="text" placeholder="Search processes..." value={search} onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent border-none outline-none text-xs flex-1" style={{ color: 'rgba(255,255,255,0.87)' }} />
        </div>
        <span className="text-[11px] ml-auto" style={{ color: 'rgba(255,255,255,0.25)' }}>
          {sorted.length} process{sorted.length !== 1 ? 'es' : ''}
        </span>
      </div>

      {sorted.length === 0 ? (
        <EmptyState icon={Cpu} title="No processes found" description="No processes match your search" />
      ) : (
        <div className="sx-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="sx-table">
              <thead>
                <tr>
                  <SortHeader field="pid" label="PID" />
                  <SortHeader field="name" label="Name" />
                  <SortHeader field="user" label="User" />
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>Memory</th>
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>Status</th>
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>Started</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((proc) => {
                  const isOpen = expanded === proc.pid;
                  const memPercent = (proc.memory_usage_kb / maxMem) * 100;
                  return (
                    <motion.tr
                      key={proc.pid}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="cursor-pointer"
                      onClick={() => setExpanded(isOpen ? null : proc.pid)}
                    >
                      <td className="font-mono text-xs" style={{ color: '#60A5FA' }}>{proc.pid}</td>
                      <td>
                        <div className="text-xs font-medium" style={{ color: 'rgba(255,255,255,0.8)' }}>{proc.name}</div>
                        {proc.binary_path && (
                          <div className="text-[10px] truncate max-w-[200px] mt-0.5" style={{ color: 'rgba(255,255,255,0.25)' }}>
                            {proc.binary_path}
                          </div>
                        )}
                      </td>
                      <td className="text-xs" style={{ color: 'rgba(255,255,255,0.5)' }}>{proc.user}</td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.04)' }}>
                            <div className="h-full rounded-full" style={{
                              width: `${memPercent}%`,
                              background: memPercent > 80 ? '#EF4444' : memPercent > 50 ? '#EAB308' : '#3B82F6',
                            }} />
                          </div>
                          <span className="text-[10px] font-mono w-12 text-right" style={{ color: 'rgba(255,255,255,0.3)' }}>
                            {proc.memory_usage_kb > 1024 ? `${(proc.memory_usage_kb / 1024).toFixed(1)}M` : `${proc.memory_usage_kb}K`}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className={proc.status === 'Running' ? 'sx-badge-green' : 'sx-badge-low'}>
                          {proc.status}
                        </span>
                      </td>
                      <td className="text-[10px] whitespace-nowrap" style={{ color: 'rgba(255,255,255,0.25)' }}>
                        {new Date(proc.start_time).toLocaleTimeString()}
                      </td>
                    </motion.tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
