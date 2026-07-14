import { useState, useEffect } from 'react';
import { fetchProcesses } from '../api';
import { ProcessInfo } from '../types';

type SortKey = 'pid' | 'name' | 'user' | 'memory_usage_kb';

export default function Processes() {
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>('pid');
  const [sortAsc, setSortAsc] = useState(false);
  const [search, setSearch] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchProcesses().then(setProcesses).catch((e) => setError(String(e)));
  }, []);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(false);
    }
  };

  const sorted = [...processes]
    .filter((p) => {
      if (!search) return true;
      const q = search.toLowerCase();
      return (
        p.name.toLowerCase().includes(q) ||
        p.user.toLowerCase().includes(q) ||
        String(p.pid).includes(q)
      );
    })
    .sort((a, b) => {
      const aVal = a[sortKey];
      const bVal = b[sortKey];
      const cmp = typeof aVal === 'string' ? aVal.localeCompare(bVal as string) : (aVal as number) - (bVal as number);
      return sortAsc ? cmp : -cmp;
    });

  const SortHeader = ({ field, label }: { field: SortKey; label: string }) => (
    <th
      className="px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider cursor-pointer hover:text-slate-200 transition-colors select-none"
      onClick={() => handleSort(field)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {sortKey === field && (
          <span className="text-blue-400">{sortAsc ? '↑' : '↓'}</span>
        )}
      </span>
    </th>
  );

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-300">
          Failed to load processes: {error}
        </div>
      )}
      <div className="flex items-center gap-4">
        <input
          type="text"
          placeholder="Search processes..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input-field max-w-xs"
        />
        <span className="text-sm text-slate-500">
          {sorted.length} process{sorted.length !== 1 ? 'es' : ''}
        </span>
      </div>

      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700/50">
                <SortHeader field="pid" label="PID" />
                <SortHeader field="name" label="Name" />
                <SortHeader field="user" label="User" />
                <SortHeader field="memory_usage_kb" label="Memory" />
                <th className="px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Status</th>
                <th className="px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Started</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((proc) => (
                <tr key={proc.pid} className="table-row">
                  <td className="px-5 py-3.5 font-mono text-slate-300">{proc.pid}</td>
                  <td className="px-5 py-3.5">
                    <div className="font-medium text-slate-100">{proc.name}</div>
                    {proc.binary_path && (
                      <div className="text-xs text-slate-500 mt-0.5 max-w-sm truncate">{proc.binary_path}</div>
                    )}
                  </td>
                  <td className="px-5 py-3.5 text-slate-300">{proc.user}</td>
                  <td className="px-5 py-3.5 font-mono text-xs text-slate-300">
                    {proc.memory_usage_kb > 1024
                      ? `${(proc.memory_usage_kb / 1024).toFixed(1)} MB`
                      : `${proc.memory_usage_kb} KB`}
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={`badge ${
                      proc.status === 'Running' ? 'bg-green-500/10 text-green-400 border border-green-500/30' : 'bg-slate-500/10 text-slate-400 border border-slate-500/30'
                    }`}>
                      {proc.status}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-slate-400 whitespace-nowrap">
                    {new Date(proc.start_time).toLocaleString()}
                  </td>
                </tr>
              ))}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500">
                    No processes found
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
