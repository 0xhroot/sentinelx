import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, ShieldAlert, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react';
import { fetchThreats, acknowledgeThreat, resolveThreat } from '../api';
import { ThreatRow } from '../types';
import ThreatBadge from '../components/ThreatBadge';
import EmptyState from '../components/EmptyState';

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';

export default function Threats() {
  const [threats, setThreats] = useState<ThreatRow[]>([]);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const loadThreats = () => {
    fetchThreats().then(setThreats).catch((e) => setError(String(e)));
  };

  useEffect(() => { loadThreats(); }, []);

  const filtered = threats.filter((t) => {
    if (severityFilter !== 'all' && t.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return t.title.toLowerCase().includes(q) || t.description.toLowerCase().includes(q) || t.source_detector.toLowerCase().includes(q);
    }
    return true;
  });

  const handleAcknowledge = async (id: string) => {
    try {
      await acknowledgeThreat(id);
      setThreats((prev) => prev.map((t) => (t.id === id ? { ...t, acknowledged: true } : t)));
    } catch { /* ignore */ }
  };

  const handleResolve = async (id: string) => {
    try {
      await resolveThreat(id);
      setThreats((prev) => prev.filter((t) => t.id !== id));
    } catch { /* ignore */ }
  };

  const filters: SeverityFilter[] = ['all', 'critical', 'high', 'medium', 'low', 'info'];

  return (
    <div className="space-y-4">
      {error && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="rounded-xl px-4 py-3 text-sm"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)', color: '#F87171' }}>
          {error}
        </motion.div>
      )}

      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 h-9 px-3 rounded-lg sx-input max-w-xs">
          <Search size={14} style={{ color: 'rgba(255,255,255,0.25)' }} />
          <input
            type="text"
            placeholder="Search threats..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-transparent border-none outline-none text-xs flex-1"
            style={{ color: 'rgba(255,255,255,0.87)' }}
          />
        </div>
        <div className="flex items-center gap-1 p-0.5 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
          {filters.map((f) => (
            <button
              key={f}
              onClick={() => setSeverityFilter(f)}
              className="px-2.5 py-1 rounded-md text-[11px] font-medium transition-all"
              style={{
                background: severityFilter === f ? 'rgba(59,130,246,0.15)' : 'transparent',
                color: severityFilter === f ? '#60A5FA' : 'rgba(255,255,255,0.35)',
              }}
            >
              {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
        <span className="text-[11px] ml-auto" style={{ color: 'rgba(255,255,255,0.25)' }}>
          {filtered.length} threat{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Threat Cards */}
      {filtered.length === 0 ? (
        <EmptyState icon={ShieldAlert} title="No threats found" description="No threats match your current filters" />
      ) : (
        <div className="space-y-2">
          {filtered.map((threat, i) => (
            <motion.div
              key={threat.id}
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.03 }}
              className="sx-card overflow-hidden"
            >
              <div
                className="flex items-center gap-3 p-3 cursor-pointer transition-colors"
                onClick={() => setExpanded(expanded === threat.id ? null : threat.id)}
                style={{ background: expanded === threat.id ? 'rgba(255,255,255,0.02)' : 'transparent' }}
              >
                <ThreatBadge severity={threat.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium" style={{ color: 'rgba(255,255,255,0.87)' }}>
                    {threat.title}
                  </p>
                  <p className="text-[11px] mt-0.5 truncate" style={{ color: 'rgba(255,255,255,0.3)' }}>
                    {threat.description}
                  </p>
                </div>
                <span className="sx-badge-blue text-[10px] hidden sm:inline">{threat.source_detector}</span>
                <span className="text-[10px] hidden sm:inline" style={{ color: 'rgba(255,255,255,0.25)' }}>
                  {new Date(threat.timestamp).toLocaleTimeString()}
                </span>
                {expanded === threat.id ? <ChevronUp size={14} style={{ color: 'rgba(255,255,255,0.3)' }} /> : <ChevronDown size={14} style={{ color: 'rgba(255,255,255,0.3)' }} />}
              </div>

              <AnimatePresence>
                {expanded === threat.id && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="overflow-hidden"
                  >
                    <div className="px-4 pb-3 pt-1" style={{ borderTop: '1px solid rgba(255,255,255,0.04)' }}>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3 text-[11px]">
                        <div>
                          <span style={{ color: 'rgba(255,255,255,0.25)' }}>ID</span>
                          <p className="font-mono" style={{ color: 'rgba(255,255,255,0.6)' }}>{threat.id.slice(0, 8)}</p>
                        </div>
                        <div>
                          <span style={{ color: 'rgba(255,255,255,0.25)' }}>Category</span>
                          <p style={{ color: 'rgba(255,255,255,0.6)' }}>{threat.category}</p>
                        </div>
                        <div>
                          <span style={{ color: 'rgba(255,255,255,0.25)' }}>Time</span>
                          <p style={{ color: 'rgba(255,255,255,0.6)' }}>{new Date(threat.timestamp).toLocaleString()}</p>
                        </div>
                        <div>
                          <span style={{ color: 'rgba(255,255,255,0.25)' }}>Status</span>
                          <p style={{ color: threat.acknowledged ? '#FACC15' : '#F87171' }}>
                            {threat.acknowledged ? 'Acknowledged' : 'Active'}
                          </p>
                        </div>
                      </div>
                      <p className="text-xs leading-relaxed mb-3" style={{ color: 'rgba(255,255,255,0.4)' }}>
                        {threat.description}
                      </p>
                      <div className="flex items-center gap-2">
                        {!threat.acknowledged && (
                          <button onClick={() => handleAcknowledge(threat.id)} className="sx-btn-ghost text-[11px] h-7">
                            Acknowledge
                          </button>
                        )}
                        <button onClick={() => handleResolve(threat.id)} className="sx-btn-ghost text-[11px] h-7"
                          style={{ color: '#4ADE80' }}>
                          Resolve
                        </button>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
