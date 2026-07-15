import { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Search, Bell, Radar, TerminalSquare, Cpu, MemoryStick,
  Play, Moon, Clock,
} from 'lucide-react';
import { fetchStatus, runScan } from '../api';
import { StatusResponse } from '../types';

const pageTitle: Record<string, string> = {
  '/': 'Overview',
  '/live': 'Live Monitor',
  '/threats': 'Threats',
  '/timeline': 'Timeline',
  '/intelligence': 'Intelligence',
  '/processes': 'Processes',
  '/network': 'Network',
  '/memory': 'Memory',
  '/modules': 'Kernel Modules',
  '/kernel': 'Kernel Integrity',
  '/telemetry': 'Telemetry',
  '/response': 'Response',
  '/fleet': 'Fleet Management',
  '/forensics': 'Forensics',
  '/policies': 'Policies',
  '/settings': 'Settings',
};

export default function Header() {
  const location = useLocation();
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [scanning, setScanning] = useState(false);
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    fetchStatus().then(setStatus).catch(() => {});
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const handleScan = async () => {
    setScanning(true);
    try { await runScan(); } catch { /* ignore */ } finally { setScanning(false); }
  };

  return (
    <header
      className="flex items-center justify-between h-14 px-5 shrink-0"
      style={{ background: '#070707', borderBottom: '1px solid rgba(255,255,255,0.06)' }}
    >
      {/* Left: Title */}
      <div className="flex items-center gap-4">
        <h1 className="text-base font-semibold" style={{ color: 'rgba(255,255,255,0.92)' }}>
          {pageTitle[location.pathname] || 'SentinelX'}
        </h1>
      </div>

      {/* Right: Controls */}
      <div className="flex items-center gap-2">
        {/* Search */}
        <div className="hidden md:flex items-center gap-2 h-8 px-3 rounded-lg text-xs"
          style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.25)' }}>
          <Search size={13} />
          <span>Search...</span>
          <kbd className="ml-4 px-1.5 py-0.5 rounded text-[10px]"
            style={{ background: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.25)' }}>⌘K</kbd>
        </div>

        {/* Status indicators */}
        <div className="hidden lg:flex items-center gap-3 ml-2 text-[11px]">
          <div className="flex items-center gap-1.5" style={{ color: 'rgba(255,255,255,0.3)' }}>
            <Cpu size={12} />
            <span>{(status?.metrics.cpu_usage_percent ?? 0).toFixed(0)}%</span>
          </div>
          <div className="flex items-center gap-1.5" style={{ color: 'rgba(255,255,255,0.3)' }}>
            <MemoryStick size={12} />
            <span>{status ? `${Math.round((status.metrics.memory_usage_bytes || 0) / 1048576)}MB` : '--'}</span>
          </div>
        </div>

        {/* Clock */}
        <div className="hidden md:flex items-center gap-1.5 text-[11px] font-mono px-2 py-1 rounded-lg"
          style={{ color: 'rgba(255,255,255,0.3)', background: 'rgba(255,255,255,0.02)' }}>
          <Clock size={11} />
          {now.toLocaleTimeString('en-US', { hour12: false })}
        </div>

        {/* Notifications */}
        <button className="relative flex items-center justify-center w-8 h-8 rounded-lg transition-colors"
          style={{ color: 'rgba(255,255,255,0.4)' }}>
          <Bell size={16} />
          <div className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full" style={{ background: '#EF4444' }} />
        </button>

        {/* Connection status */}
        <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg text-[11px]"
          style={{ background: 'rgba(255,255,255,0.02)' }}>
          <motion.div
            animate={{ scale: [1, 1.3, 1] }}
            transition={{ duration: 2, repeat: Infinity }}
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: status ? '#22C55E' : '#EF4444' }}
          />
          <span style={{ color: status ? '#4ADE80' : '#F87171' }}>
            {status ? 'Connected' : 'Offline'}
          </span>
        </div>

        {/* Theme toggle */}
        <button className="flex items-center justify-center w-8 h-8 rounded-lg transition-colors"
          style={{ color: 'rgba(255,255,255,0.3)' }}>
          <Moon size={15} />
        </button>

        {/* Scan button */}
        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={handleScan}
          disabled={scanning}
          className="sx-btn-primary h-8 text-xs ml-1 disabled:opacity-50"
        >
          {scanning ? (
            <>
              <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}>
                <Radar size={14} />
              </motion.div>
              Scanning
            </>
          ) : (
            <>
              <Play size={13} />
              Run Scan
            </>
          )}
        </motion.button>
      </div>
    </header>
  );
}
