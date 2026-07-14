import { useState, useEffect } from 'react';
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
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-green-500',
};

const severityRing: Record<string, string> = {
  critical: 'ring-red-500/30',
  high: 'ring-orange-500/30',
  medium: 'ring-yellow-500/30',
  low: 'ring-blue-500/30',
  info: 'ring-green-500/30',
};

export default function Timeline() {
  const [entries, setEntries] = useState<TimelineEvent[]>([]);
  const [filter, setFilter] = useState('all');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchTimeline().then((data) => setEntries(data as unknown as TimelineEvent[])).catch((e) => setError(String(e)));
  }, []);

  const filtered = filter === 'all' ? entries : entries.filter((e) => e.event.severity === filter);

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-300">
          Failed to load timeline: {error}
        </div>
      )}
      <div className="flex items-center gap-3">
        {['all', 'critical', 'high', 'medium', 'low', 'info'].map((level) => (
          <button
            key={level}
            onClick={() => setFilter(level)}
            className={`px-3 py-1.5 text-sm rounded-lg font-medium transition-colors ${
              filter === level
                ? 'bg-blue-600 text-white'
                : 'bg-slate-800/50 text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
            }`}
          >
            {level === 'all' ? 'All' : level.charAt(0).toUpperCase() + level.slice(1)}
          </button>
        ))}
        <span className="text-sm text-slate-500 ml-auto">
          {filtered.length} event{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="relative">
        <div className="absolute left-5 top-0 bottom-0 w-px bg-slate-700/50" />

        <div className="space-y-1">
          {filtered.map((entry, i) => (
            <div key={`${entry.event.id}-${i}`} className="relative flex items-start gap-4 pl-12 py-3 group">
              <div
                className={`absolute left-3.5 top-4 w-3 h-3 rounded-full ring-4 ${
                  severityColor[entry.event.severity] || 'bg-slate-500'
                } ${severityRing[entry.event.severity] || 'ring-slate-500/30'}`}
              />

              <div className="flex-1 card p-4 group-hover:border-slate-600/50 transition-colors">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs text-slate-500 font-mono">{entry.event.category}</span>
                      <span className="text-xs text-slate-600">&middot;</span>
                      <span className="text-xs text-slate-500">{entry.event.source_detector}</span>
                    </div>
                    <h4 className="text-sm font-medium text-slate-200">{entry.event.title}</h4>
                    <p className="text-xs text-slate-400 mt-1">{entry.event.description}</p>
                    {entry.related_pids.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-2">
                        {entry.related_pids.map((pid) => (
                          <span key={pid} className="text-xs bg-slate-800/60 text-slate-400 px-2 py-0.5 rounded">
                            PID: {pid}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <span className="text-xs text-slate-500 whitespace-nowrap">
                    {new Date(entry.timestamp).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="flex items-center justify-center py-20 text-slate-500 text-sm">
              No timeline events
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
