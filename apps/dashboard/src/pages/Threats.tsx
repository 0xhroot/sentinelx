import { useState, useEffect } from 'react';
import { fetchThreats, acknowledgeThreat, resolveThreat } from '../api';
import { ThreatRow } from '../types';
import ThreatBadge from '../components/ThreatBadge';

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';

export default function Threats() {
  const [threats, setThreats] = useState<ThreatRow[]>([]);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [error, setError] = useState<string | null>(null);

  const loadThreats = () => {
    fetchThreats().then(setThreats).catch((e) => setError(String(e)));
  };

  useEffect(() => {
    loadThreats();
  }, []);

  const filtered = threats.filter((t) => {
    if (severityFilter !== 'all' && t.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        t.title.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.source_detector.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleAcknowledge = async (id: string) => {
    try {
      await acknowledgeThreat(id);
      setThreats((prev) =>
        prev.map((t) => (t.id === id ? { ...t, acknowledged: true } : t)),
      );
    } catch {}
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-300">
          Failed to load threats: {error}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="text"
          placeholder="Search threats..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="input-field max-w-xs"
        />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
          className="input-field max-w-[150px]"
        >
          <option value="all">All Severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <span className="text-sm text-slate-500">
          {filtered.length} threat{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="text-left px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Severity</th>
                <th className="text-left px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Title</th>
                <th className="text-left px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Source</th>
                <th className="text-left px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Status</th>
                <th className="text-left px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Time</th>
                <th className="text-right px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((threat) => (
                <tr key={threat.id} className="table-row">
                  <td className="px-5 py-3.5">
                    <ThreatBadge severity={threat.severity} />
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="font-medium text-slate-100">{threat.title}</div>
                    <div className="text-xs text-slate-500 mt-0.5 max-w-md truncate">{threat.description}</div>
                  </td>
                  <td className="px-5 py-3.5 text-slate-300">{threat.source_detector}</td>
                  <td className="px-5 py-3.5">
                    <span className={`badge ${
                      threat.acknowledged
                        ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                        : 'bg-red-500/10 text-red-400 border border-red-500/30'
                    }`}>
                      {threat.acknowledged ? 'acknowledged' : 'active'}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-slate-400 whitespace-nowrap">
                    {new Date(threat.timestamp).toLocaleString()}
                  </td>
                  <td className="px-5 py-3.5 text-right">
                    {!threat.acknowledged && (
                      <button
                        onClick={() => handleAcknowledge(threat.id)}
                        className="text-xs px-3 py-1.5 rounded-md bg-slate-700/50 text-slate-300 hover:bg-slate-600/50 transition-colors"
                      >
                        Acknowledge
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500">
                    No threats found
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
