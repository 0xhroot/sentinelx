import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Settings as SettingsIcon, CheckCircle2, AlertCircle } from 'lucide-react';
import { fetchDetectors, fetchStatus } from '../api';
import { StatusResponse, DetectorInfo } from '../types';

export default function Settings() {
  const [detectors, setDetectors] = useState<DetectorInfo[]>([]);
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [notifications, setNotifications] = useState(true);
  const [autoScan, setAutoScan] = useState(true);
  const [scanInterval, setScanInterval] = useState('300');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDetectors().then((d) => setDetectors(d.detectors)).catch((e) => setError(String(e)));
    fetchStatus().then(setStatus).catch((e) => setError(String(e)));
  }, []);

  const Toggle = ({ enabled, onToggle }: { enabled: boolean; onToggle: () => void }) => (
    <button onClick={onToggle} className="relative w-10 h-[22px] rounded-full transition-colors"
      style={{ background: enabled ? '#3B82F6' : 'rgba(255,255,255,0.1)' }}>
      <motion.div animate={{ x: enabled ? 19 : 3 }} transition={{ type: 'spring', stiffness: 500, damping: 30 }}
        className="absolute top-[3px] w-4 h-4 rounded-full bg-white" />
    </button>
  );

  return (
    <div className="space-y-4 max-w-3xl">
      {error && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="rounded-xl px-4 py-3 text-sm"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)', color: '#F87171' }}>
          {error}
        </motion.div>
      )}

      {/* System Info */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="sx-card p-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'rgba(255,255,255,0.35)' }}>System Information</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Status', value: status ? 'Connected' : 'Disconnected', color: status ? '#4ADE80' : '#F87171' },
            { label: 'Scans', value: status?.metrics.scans_completed ?? 0, color: 'rgba(255,255,255,0.87)' },
            { label: 'Threats', value: status?.metrics.threats_detected ?? 0, color: '#F87171' },
            { label: 'Events', value: status?.metrics.events_processed?.toLocaleString() ?? '0', color: 'rgba(255,255,255,0.87)' },
          ].map((item) => (
            <div key={item.label} className="p-3 rounded-lg" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
              <p className="text-[10px] uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.25)' }}>{item.label}</p>
              <p className="text-sm font-semibold mt-1" style={{ color: item.color }}>{item.value}</p>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Configuration */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="sx-card p-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'rgba(255,255,255,0.35)' }}>Configuration</h3>
        <div className="space-y-4">
          {[
            { label: 'Desktop Notifications', desc: 'Show notifications for critical threats', enabled: notifications, onToggle: () => setNotifications(!notifications) },
            { label: 'Automatic Scanning', desc: 'Run periodic system scans', enabled: autoScan, onToggle: () => setAutoScan(!autoScan) },
          ].map((item) => (
            <div key={item.label} className="flex items-center justify-between py-2"
              style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <div>
                <p className="text-xs font-medium" style={{ color: 'rgba(255,255,255,0.7)' }}>{item.label}</p>
                <p className="text-[10px] mt-0.5" style={{ color: 'rgba(255,255,255,0.25)' }}>{item.desc}</p>
              </div>
              <Toggle enabled={item.enabled} onToggle={item.onToggle} />
            </div>
          ))}
          <div className="py-2">
            <p className="text-xs font-medium mb-2" style={{ color: 'rgba(255,255,255,0.7)' }}>Scan Interval</p>
            <select value={scanInterval} onChange={(e) => setScanInterval(e.target.value)} disabled={!autoScan}
              className="sx-input max-w-[200px] text-xs disabled:opacity-40">
              <option value="60">60 seconds</option>
              <option value="300">5 minutes</option>
              <option value="600">10 minutes</option>
              <option value="1800">30 minutes</option>
              <option value="3600">1 hour</option>
            </select>
          </div>
        </div>
      </motion.div>

      {/* Active Detectors */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="sx-card p-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'rgba(255,255,255,0.35)' }}>
          Active Detectors ({detectors.length})
        </h3>
        <div className="space-y-2">
          {detectors.map((detector, i) => (
            <motion.div key={detector.name}
              initial={{ opacity: 0, x: -5 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.03 }}
              className="flex items-center justify-between p-3 rounded-lg"
              style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
              <div className="flex items-center gap-3">
                <CheckCircle2 size={14} style={{ color: '#4ADE80' }} />
                <div>
                  <p className="text-xs font-medium" style={{ color: 'rgba(255,255,255,0.7)' }}>{detector.name}</p>
                  <p className="text-[10px] mt-0.5" style={{ color: 'rgba(255,255,255,0.25)' }}>{detector.description}</p>
                </div>
              </div>
              <div className="text-right">
                <span className="sx-badge-blue text-[10px]">{detector.category}</span>
                <p className="text-[10px] mt-1" style={{ color: 'rgba(255,255,255,0.2)' }}>{detector.severity}</p>
              </div>
            </motion.div>
          ))}
          {detectors.length === 0 && (
            <div className="text-center py-8 text-xs" style={{ color: 'rgba(255,255,255,0.2)' }}>No detector data</div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
