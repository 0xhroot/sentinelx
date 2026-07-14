import { useState, useEffect } from 'react';
import { fetchNetwork } from '../api';
import { NetworkConnection } from '../types';

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
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  const sorted = [...connections]
    .filter((c) => {
      if (!search) return true;
      const q = search.toLowerCase();
      return (
        c.process_name?.toLowerCase().includes(q) ||
        c.protocol.toLowerCase().includes(q) ||
        c.state.toLowerCase().includes(q) ||
        c.local_addr.ip.toLowerCase().includes(q) ||
        c.remote_addr?.ip.toLowerCase().includes(q)
      );
    })
    .sort((a, b) => {
      const aVal = a[sortKey];
      const bVal = b[sortKey];
      const cmp = String(aVal).localeCompare(String(bVal));
      return sortAsc ? cmp : -cmp;
    });

  const SortHeader = ({ field, label }: { field: SortKey; label: string }) => (
    <th
      className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider cursor-pointer hover:text-slate-200 transition-colors select-none text-left"
      onClick={() => handleSort(field)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {sortKey === field && <span className="text-blue-400">{sortAsc ? '↑' : '↓'}</span>}
      </span>
    </th>
  );

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-300">
          Failed to load network data: {error}
        </div>
      )}
      <div className="flex items-center gap-4">
        <input
          type="text"
          placeholder="Search connections..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input-field max-w-xs"
        />
        <span className="text-sm text-slate-500">
          {sorted.length} connection{sorted.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider text-left">Local</th>
                <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider text-left">Remote</th>
                <SortHeader field="protocol" label="Protocol" />
                <SortHeader field="state" label="State" />
                <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider text-left">Process</th>
                <th className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider text-left">PID</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((conn, i) => (
                <tr key={`${conn.local_addr.port}-${conn.remote_addr?.port}-${conn.remote_addr?.ip}-${i}`} className="table-row">
                  <td className="px-4 py-3.5 font-mono text-xs text-slate-300">
                    {conn.local_addr.ip}:{conn.local_addr.port}
                  </td>
                  <td className="px-4 py-3.5 font-mono text-xs text-slate-300">
                    {conn.remote_addr ? `${conn.remote_addr.ip}:${conn.remote_addr.port}` : '-'}
                  </td>
                  <td className="px-4 py-3.5 text-slate-300 uppercase text-xs font-medium">{conn.protocol}</td>
                  <td className="px-4 py-3.5">
                    <span className={`badge ${
                      conn.state === 'Established'
                        ? 'bg-green-500/10 text-green-400 border border-green-500/30'
                        : conn.state === 'Listen'
                        ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                        : 'bg-slate-500/10 text-slate-400 border border-slate-500/30'
                    }`}>
                      {conn.state}
                    </span>
                  </td>
                  <td className="px-4 py-3.5 text-slate-300">
                    {conn.process_name || '-'}
                  </td>
                  <td className="px-4 py-3.5 font-mono text-xs text-slate-400">
                    {conn.pid || '-'}
                  </td>
                </tr>
              ))}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500">
                    No connections found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
