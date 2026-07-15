import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Search, Network as NetworkIcon, ArrowUpDown } from 'lucide-react';
import { fetchNetwork } from '../api';
import { NetworkConnection } from '../types';
import EmptyState from '../components/EmptyState';

type SortKey = 'protocol' | 'state';

export default function Network() {
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>('state');
  const [sortAsc, setSortAsc] = useState(true);
  const [search, setSearch] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchNetwork().then(setConnections).catch((e) => setError(String(e)));
  }, []);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(!sortAsc);
    else { setSortKey(key); setSortAsc(true); }
  };

  const sorted = [...connections]
    .filter((c) => {
      if (!search) return true;
      const q = search.toLowerCase();
      return c.process_name?.toLowerCase().includes(q) || c.protocol.toLowerCase().includes(q) ||
        c.state.toLowerCase().includes(q) || c.local_addr.ip.includes(q) || c.remote_addr?.ip.includes(q);
    })
    .sort((a, b) => {
      const cmp = String(a[sortKey]).localeCompare(String(b[sortKey]));
      return sortAsc ? cmp : -cmp;
    });

  const SortHeader = ({ field, label }: { field: SortKey; label: string }) => (
    <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider cursor-pointer select-none text-left"
      style={{ color: 'rgba(255,255,255,0.3)' }} onClick={() => handleSort(field)}>
      <span className="inline-flex items-center gap-1">
        {label}
        {sortKey === field && <span style={{ color: '#60A5FA' }}>{sortAsc ? '↑' : '↓'}</span>}
        {sortKey !== field && <ArrowUpDown size={10} />}
      </span>
    </th>
  );

  const stateColor = (state: string) => {
    if (state === 'Established') return 'sx-badge-green';
    if (state === 'Listen') return 'sx-badge-blue';
    return 'sx-badge-low';
  };

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
          <input type="text" placeholder="Search connections..." value={search} onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent border-none outline-none text-xs flex-1" style={{ color: 'rgba(255,255,255,0.87)' }} />
        </div>
        <span className="text-[11px] ml-auto" style={{ color: 'rgba(255,255,255,0.25)' }}>
          {sorted.length} connection{sorted.length !== 1 ? 's' : ''}
        </span>
      </div>

      {sorted.length === 0 ? (
        <EmptyState icon={NetworkIcon} title="No connections" description="No network connections found" />
      ) : (
        <div className="sx-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="sx-table">
              <thead>
                <tr>
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>Local</th>
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>Remote</th>
                  <SortHeader field="protocol" label="Proto" />
                  <SortHeader field="state" label="State" />
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>Process</th>
                  <th className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-left" style={{ color: 'rgba(255,255,255,0.3)' }}>PID</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((conn, i) => (
                  <motion.tr key={`${conn.local_addr.port}-${conn.remote_addr?.port}-${i}`}
                    initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.01 }}>
                    <td className="font-mono text-[11px]" style={{ color: 'rgba(255,255,255,0.6)' }}>
                      {conn.local_addr.ip}:{conn.local_addr.port}
                    </td>
                    <td className="font-mono text-[11px]" style={{ color: conn.remote_addr ? 'rgba(255,255,255,0.6)' : 'rgba(255,255,255,0.15)' }}>
                      {conn.remote_addr ? `${conn.remote_addr.ip}:${conn.remote_addr.port}` : '—'}
                    </td>
                    <td>
                      <span className="text-[10px] font-medium px-1.5 py-0.5 rounded"
                        style={{ background: 'rgba(139,92,246,0.1)', color: '#A78BFA' }}>
                        {conn.protocol.toUpperCase()}
                      </span>
                    </td>
                    <td><span className={stateColor(conn.state)}>{conn.state}</span></td>
                    <td className="text-xs" style={{ color: 'rgba(255,255,255,0.5)' }}>{conn.process_name || '—'}</td>
                    <td className="font-mono text-[10px]" style={{ color: 'rgba(255,255,255,0.3)' }}>{conn.pid || '—'}</td>
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
