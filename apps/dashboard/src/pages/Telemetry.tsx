import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Activity, Radio, Wifi, WifiOff, Server, Database } from 'lucide-react';
import { fetchStatus } from '../api';
import { StatusResponse } from '../types';
import StatCard from '../components/StatCard';

export default function Telemetry() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchStatus().then(setStatus).catch((e) => setError(String(e)));
    const interval = setInterval(() => {
      fetchStatus().then(setStatus).catch(() => {});
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const providers = [
    { name: 'eBPF', status: 'active', icon: Activity },
    { name: 'fanotify', status: 'active', icon: Radio },
    { name: 'Netlink', status: 'active', icon: Wifi },
    { name: 'Audit', status: 'active', icon: Database },
  ];

  return (
    <div className="space-y-4">
      {error && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="rounded-xl px-4 py-3 text-sm"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)', color: '#F87171' }}>
          {error}
        </motion.div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="Events Processed" value={status?.metrics.events_processed ?? 0} icon={<Activity size={18} />} color="purple" />
        <StatCard label="Active Detectors" value={status?.detector_count ?? 0} icon={<Radio size={18} />} color="cyan" />
        <StatCard label="CPU Usage" value={`${(status?.metrics.cpu_usage_percent ?? 0).toFixed(1)}%`} icon={<Server size={18} />} color="blue" />
        <StatCard label="Errors" value={status?.metrics.errors ?? 0} icon={<WifiOff size={18} />} color={((status?.metrics.errors ?? 0) > 0 ? 'red' : 'green') as any} />
      </div>

      <div className="sx-card p-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'rgba(255,255,255,0.35)' }}>
          Telemetry Providers
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {providers.map((provider, i) => {
            const Icon = provider.icon;
            return (
              <motion.div key={provider.name}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.1 }}
                className="p-3 rounded-xl"
                style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
                <div className="flex items-center gap-2 mb-2">
                  <Icon size={14} style={{ color: '#60A5FA' }} />
                  <span className="text-xs font-medium" style={{ color: 'rgba(255,255,255,0.7)' }}>{provider.name}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-1.5 h-1.5 rounded-full" style={{ background: '#22C55E' }} />
                  <span className="text-[10px] font-medium" style={{ color: '#4ADE80' }}>Active</span>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>

      <div className="sx-card p-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'rgba(255,255,255,0.35)' }}>
          Event Stream
        </h3>
        <div className="space-y-1 font-mono text-[11px] max-h-[300px] overflow-y-auto" style={{ color: 'rgba(255,255,255,0.3)' }}>
          {Array.from({ length: 20 }).map((_, i) => (
            <div key={i} className="flex items-center gap-2 py-0.5">
              <span style={{ color: 'rgba(255,255,255,0.15)' }}>{new Date().toISOString().slice(11, 19)}</span>
              <span className="px-1 py-0.5 rounded text-[9px]"
                style={{ background: 'rgba(34,197,94,0.08)', color: '#4ADE80' }}>INFO</span>
              <span>telemetry.event.processed id={Math.random().toString(36).slice(2, 10)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
