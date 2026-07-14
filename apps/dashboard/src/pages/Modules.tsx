import { useState, useEffect } from 'react';
import { fetchModules } from '../api';
import { KernelModuleInfo } from '../types';

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
    <div className="space-y-6">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-300">
          Failed to load modules: {error}
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card p-4">
          <p className="stat-label">Total Modules</p>
          <p className="stat-value text-white">{modules.length}</p>
        </div>
        <div className="card p-4">
          <p className="stat-label">Live</p>
          <p className="stat-value text-green-400">{liveCount}</p>
        </div>
        <div className="card p-4">
          <p className="stat-label">Unsigned</p>
          <p className="stat-value text-red-400">{unsignedCount}</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <input
          type="text"
          placeholder="Search modules..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="input-field max-w-xs"
        />
        <span className="text-sm text-slate-500">
          {filtered.length} module{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider text-left">Module</th>
                <th className="px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider text-left">Size</th>
                <th className="px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider text-left">State</th>
                <th className="px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider text-left">Signed</th>
                <th className="px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider text-left">License</th>
                <th className="px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider text-left">Version</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((mod) => (
                <tr key={mod.name} className="table-row">
                  <td className="px-5 py-3.5">
                    <div className="font-medium text-slate-100">{mod.name}</div>
                  </td>
                  <td className="px-5 py-3.5 text-slate-300 font-mono text-xs">
                    {(mod.size / 1024).toFixed(1)} KB
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={`badge ${
                      mod.state === 'Live'
                        ? 'bg-green-500/10 text-green-400 border border-green-500/30'
                        : 'bg-slate-500/10 text-slate-400 border border-slate-500/30'
                    }`}>
                      {mod.state}
                    </span>
                  </td>
                  <td className="px-5 py-3.5">
                    {mod.signature_valid === true ? (
                      <span className="badge bg-green-500/10 text-green-400 border border-green-500/30">
                        Signed
                      </span>
                    ) : mod.signature_valid === false ? (
                      <span className="badge bg-red-500/10 text-red-400 border border-red-500/30">
                        Unsigned
                      </span>
                    ) : (
                      <span className="badge bg-slate-500/10 text-slate-400 border border-slate-500/30">
                        Unknown
                      </span>
                    )}
                  </td>
                  <td className="px-5 py-3.5 text-slate-400 font-mono text-xs">
                    {mod.license || '-'}
                  </td>
                  <td className="px-5 py-3.5 text-slate-400 font-mono text-xs">
                    {mod.version || '-'}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500">
                    No modules found
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
