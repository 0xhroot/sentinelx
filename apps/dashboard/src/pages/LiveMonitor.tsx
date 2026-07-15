import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Radio, Pause, Play, Search, Filter, AlertTriangle, Shield, Cpu, Network as NetworkIcon, Clock } from 'lucide-react';
import { fetchTimeline } from '../api';

interface LiveEvent {
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
}

const severityStyle: Record<string, { bg: string; color: string; border: string }> = {
  critical: { bg: 'rgba(239,68,68,0.06)', color: '#F87171', border: 'rgba(239,68,68,0.12)' },
  high: { bg: 'rgba(249,115,22,0.06)', color: '#FB923C', border: 'rgba(249,115,22,0.12)' },
  medium: { bg: 'rgba(234,179,8,0.06)', color: '#FACC15', border: 'rgba(234,179,8,0.12)' },
  low: { bg: 'rgba(59,130,246,0.06)', color: '#60A5FA', border: 'rgba(59,130,246,0.12)' },
  info: { bg: 'rgba(34,197,94,0.06)', color: '#4ADE80', border: 'rgba(34,197,94,0.12)' },
};

const categoryIcon: Record<string, typeof Shield> = {
  process: Cpu,
  network: NetworkIcon,
  kernel: Shield,
};

export default function LiveMonitor() {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const load = () => {
      fetchTimeline()
        .then((data) => {
          if (!paused) setEvents((data as unknown as LiveEvent[]).slice(0, 50));
        })
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, [paused]);

  const filtered = events.filter((e) => {
    if (filter !== 'all' && e.event.severity !== filter) return false;
    if (search) {
      const q = search.toLowerCase();
      return e.event.title.toLowerCase().includes(q) || e.event.source_detector.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="space-y-4 h-full flex flex-col">
      {/* Controls */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="flex items-center gap-2 h-9 px-3 rounded-lg sx-input max-w-xs">
          <Search size={14} style={{ color: 'rgba(255,255,255,0.25)' }} />
          <input type="text" placeholder="Filter events..." value={search} onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent border-none outline-none text-xs flex-1" style={{ color: 'rgba(255,255,255,0.87)' }} />
        </div>
        <div className="flex items-center gap-1 p-0.5 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
          {['all', 'critical', 'high', 'medium', 'low', 'info'].map((f) => (
            <button key={f} onClick={() => setFilter(f)}
              className="px-2 py-1 rounded-md text-[10px] font-medium transition-all"
              style={{
                background: filter === f ? 'rgba(59,130,246,0.15)' : 'transparent',
                color: filter === f ? '#60A5FA' : 'rgba(255,255,255,0.3)',
              }}>
              {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 ml-auto">
          <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.2)' }}>{filtered.length} events</span>
          <button onClick={() => setPaused(!paused)}
            className="flex items-center gap-1.5 h-7 px-2.5 rounded-lg text-[11px] font-medium transition-all"
            style={{
              background: paused ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)',
              color: paused ? '#F87171' : '#4ADE80',
              border: `1px solid ${paused ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.15)'}`,
            }}>
            {paused ? <Play size={11} /> : <Pause size={11} />}
            {paused ? 'Resume' : 'Live'}
          </button>
        </div>
      </div>

      {/* Event feed */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto space-y-1.5 pr-1">
        <AnimatePresence initial={false}>
          {filtered.map((entry, i) => {
            const s = severityStyle[entry.event.severity] || severityStyle.info;
            const Icon = categoryIcon[entry.event.category] || Shield;
            const isOpen = expanded === entry.event.id;
            return (
              <motion.div
                key={entry.event.id + entry.timestamp}
                initial={{ opacity: 0, y: -10, height: 0 }}
                animate={{ opacity: 1, y: 0, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2 }}
                className="rounded-xl overflow-hidden cursor-pointer transition-all"
                style={{ background: isOpen ? s.bg : 'rgba(255,255,255,0.02)', border: `1px solid ${isOpen ? s.border : 'rgba(255,255,255,0.04)'}` }}
                onClick={() => setExpanded(isOpen ? null : entry.event.id)}
              >
                <div className="flex items-center gap-3 p-2.5">
                  <div className="flex items-center justify-center w-7 h-7 rounded-lg shrink-0"
                    style={{ background: s.bg }}>
                    <Icon size={13} style={{ color: s.color }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-medium px-1.5 py-0.5 rounded"
                        style={{ background: s.bg, color: s.color, border: `1px solid ${s.border}` }}>
                        {entry.event.severity}
                      </span>
                      <span className="text-xs font-medium truncate" style={{ color: 'rgba(255,255,255,0.8)' }}>
                        {entry.event.title}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.2)' }}>{entry.event.source_detector}</span>
                      <span style={{ color: 'rgba(255,255,255,0.1)' }}>·</span>
                      <span className="text-[10px] font-mono" style={{ color: 'rgba(255,255,255,0.15)' }}>{entry.event.category}</span>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono shrink-0" style={{ color: 'rgba(255,255,255,0.15)' }}>
                    {new Date(entry.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                {isOpen && (
                  <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }}
                    className="px-3 pb-2.5 pt-0.5" style={{ borderTop: `1px solid ${s.border}` }}>
                    <p className="text-[11px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.35)' }}>
                      {entry.event.description}
                    </p>
                    {entry.related_pids.length > 0 && (
                      <div className="flex gap-1.5 mt-2">
                        {entry.related_pids.map((pid) => (
                          <span key={pid} className="text-[9px] font-mono px-1.5 py-0.5 rounded"
                            style={{ background: 'rgba(255,255,255,0.04)', color: 'rgba(255,255,255,0.3)' }}>
                            PID {pid}
                          </span>
                        ))}
                      </div>
                    )}
                  </motion.div>
                )}
              </motion.div>
            );
          })}
        </AnimatePresence>

        {filtered.length === 0 && (
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <Radio size={32} className="mx-auto mb-3" style={{ color: 'rgba(255,255,255,0.06)' }} />
              <p className="text-sm" style={{ color: 'rgba(255,255,255,0.2)' }}>No live events</p>
              <p className="text-[10px] mt-1" style={{ color: 'rgba(255,255,255,0.12)' }}>Events will appear as they are detected</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
