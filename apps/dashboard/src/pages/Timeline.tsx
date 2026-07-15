import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Clock, AlertTriangle, ChevronDown, ChevronUp } from 'lucide-react';
import { fetchTimeline } from '../api';

interface TimelineEvent {
  timestamp: string;
  event: {
    id: string;
    severity: string;
    category: string;
    title: string;
    description: string;
    source_detector: string;
  };
  related_pids: number[];
  related_inodes: number[];
}

const severityColor: Record<string, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#EAB308',
  low: '#3B82F6',
  info: '#22C55E',
};

export default function Timeline() {
  const [entries, setEntries] = useState<TimelineEvent[]>([]);
  const [filter, setFilter] = useState('all');
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    fetchTimeline().then((data) => setEntries(data as unknown as TimelineEvent[])).catch((e) => setError(String(e)));
  }, []);

  const filtered = filter === 'all' ? entries : entries.filter((e) => e.event.severity === filter);

  const filters = ['all', 'critical', 'high', 'medium', 'low', 'info'];

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
        <div className="flex items-center gap-1 p-0.5 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
          {filters.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className="px-2.5 py-1 rounded-md text-[11px] font-medium transition-all"
              style={{
                background: filter === f ? 'rgba(59,130,246,0.15)' : 'transparent',
                color: filter === f ? '#60A5FA' : 'rgba(255,255,255,0.35)',
              }}
            >
              {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
        <span className="text-[11px] ml-auto" style={{ color: 'rgba(255,255,255,0.25)' }}>
          {filtered.length} event{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-[18px] top-0 bottom-0 w-px" style={{ background: 'rgba(255,255,255,0.06)' }} />

        <div className="space-y-1">
          {filtered.map((entry, i) => {
            const color = severityColor[entry.event.severity] || 'rgba(255,255,255,0.2)';
            const isOpen = expanded === i;
            return (
              <motion.div
                key={`${entry.event.id}-${i}`}
                initial={{ opacity: 0, x: -5 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.02 }}
                className="relative pl-10 py-1"
              >
                {/* Dot */}
                <div
                  className="absolute left-[14px] top-3.5 w-[9px] h-[9px] rounded-full z-10"
                  style={{ background: color, boxShadow: `0 0 8px ${color}44` }}
                />

                <div
                  className="sx-card overflow-hidden cursor-pointer transition-all"
                  onClick={() => setExpanded(isOpen ? null : i)}
                >
                  <div className="flex items-center gap-3 p-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-[10px] font-medium px-1.5 py-0.5 rounded"
                          style={{ background: `${color}15`, color }}>
                          {entry.event.severity}
                        </span>
                        <span className="text-[10px] font-mono" style={{ color: 'rgba(255,255,255,0.2)' }}>
                          {entry.event.category}
                        </span>
                        <span style={{ color: 'rgba(255,255,255,0.1)' }}>·</span>
                        <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.2)' }}>
                          {entry.event.source_detector}
                        </span>
                      </div>
                      <p className="text-sm font-medium" style={{ color: 'rgba(255,255,255,0.8)' }}>
                        {entry.event.title}
                      </p>
                    </div>
                    <span className="text-[10px] whitespace-nowrap" style={{ color: 'rgba(255,255,255,0.2)' }}>
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </span>
                    {isOpen ? <ChevronUp size={12} style={{ color: 'rgba(255,255,255,0.2)' }} /> : <ChevronDown size={12} style={{ color: 'rgba(255,255,255,0.2)' }} />}
                  </div>

                  {isOpen && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      className="px-3 pb-3"
                      style={{ borderTop: '1px solid rgba(255,255,255,0.04)' }}
                    >
                      <p className="text-xs leading-relaxed mt-2" style={{ color: 'rgba(255,255,255,0.4)' }}>
                        {entry.event.description}
                      </p>
                      {entry.related_pids.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 mt-2">
                          {entry.related_pids.map((pid) => (
                            <span key={pid} className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                              style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.35)' }}>
                              PID {pid}
                            </span>
                          ))}
                        </div>
                      )}
                    </motion.div>
                  )}
                </div>
              </motion.div>
            );
          })}

          {filtered.length === 0 && (
            <div className="flex items-center justify-center py-20">
              <div className="text-center">
                <Clock size={32} className="mx-auto mb-3" style={{ color: 'rgba(255,255,255,0.08)' }} />
                <p className="text-sm" style={{ color: 'rgba(255,255,255,0.25)' }}>No timeline events</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
