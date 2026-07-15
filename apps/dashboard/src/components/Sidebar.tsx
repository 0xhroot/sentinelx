import { useState } from 'react';
import { useLocation, Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard, ShieldAlert, Clock, Cpu, Network, HardDrive,
  Box, Lock, BrainCircuit, Search, Settings, ChevronLeft, ChevronRight,
  Radio, Activity, Users, FileSearch, Siren, BookOpen,
} from 'lucide-react';

interface NavItem {
  path: string;
  label: string;
  icon: typeof LayoutDashboard;
  section?: string;
}

const navItems: NavItem[] = [
  { path: '/', label: 'Overview', icon: LayoutDashboard, section: 'MONITOR' },
  { path: '/live', label: 'Live Monitor', icon: Radio, section: 'MONITOR' },
  { path: '/threats', label: 'Threats', icon: ShieldAlert, section: 'ANALYZE' },
  { path: '/timeline', label: 'Timeline', icon: Clock, section: 'ANALYZE' },
  { path: '/intelligence', label: 'Intelligence', icon: BrainCircuit, section: 'ANALYZE' },
  { path: '/processes', label: 'Processes', icon: Cpu, section: 'SYSTEM' },
  { path: '/network', label: 'Network', icon: Network, section: 'SYSTEM' },
  { path: '/memory', label: 'Memory', icon: HardDrive, section: 'SYSTEM' },
  { path: '/modules', label: 'Modules', icon: Box, section: 'SYSTEM' },
  { path: '/kernel', label: 'Kernel', icon: Lock, section: 'SYSTEM' },
  { path: '/telemetry', label: 'Telemetry', icon: Activity, section: 'OPS' },
  { path: '/response', label: 'Response', icon: Siren, section: 'OPS' },
  { path: '/fleet', label: 'Fleet', icon: Users, section: 'OPS' },
  { path: '/forensics', label: 'Forensics', icon: FileSearch, section: 'OPS' },
  { path: '/policies', label: 'Policies', icon: BookOpen, section: 'OPS' },
  { path: '/settings', label: 'Settings', icon: Settings, section: 'CONFIG' },
];

const sections = ['MONITOR', 'ANALYZE', 'SYSTEM', 'OPS', 'CONFIG'] as const;

export default function Sidebar() {
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <motion.aside
      animate={{ width: collapsed ? 64 : 240 }}
      transition={{ duration: 0.2, ease: 'easeInOut' }}
      className="flex flex-col h-screen overflow-hidden shrink-0"
      style={{ background: '#070707', borderRight: '1px solid rgba(255,255,255,0.06)' }}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-14 shrink-0" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <div className="flex items-center justify-center w-8 h-8 rounded-lg shrink-0"
          style={{ background: 'linear-gradient(135deg, #3B82F6, #8B5CF6)' }}>
          <ShieldAlert size={16} className="text-white" />
        </div>
        <AnimatePresence>
          {!collapsed && (
            <motion.div
              initial={{ opacity: 0, width: 0 }}
              animate={{ opacity: 1, width: 'auto' }}
              exit={{ opacity: 0, width: 0 }}
              className="overflow-hidden whitespace-nowrap"
            >
              <span className="text-sm font-bold tracking-tight" style={{ color: 'rgba(255,255,255,0.92)' }}>
                SentinelX
              </span>
              <span className="text-[10px] font-medium ml-1.5 px-1.5 py-0.5 rounded"
                style={{ background: 'rgba(59,130,246,0.12)', color: '#60A5FA' }}>
                SOC
              </span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-2">
        {sections.map((section) => {
          const items = navItems.filter((n) => n.section === section);
          if (items.length === 0) return null;
          return (
            <div key={section} className="mb-3">
              <AnimatePresence>
                {!collapsed && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="px-2 mb-1.5 text-[10px] font-semibold uppercase tracking-widest"
                    style={{ color: 'rgba(255,255,255,0.2)' }}
                  >
                    {section}
                  </motion.div>
                )}
              </AnimatePresence>
              {items.map((item) => {
                const isActive = location.pathname === item.path;
                const Icon = item.icon;
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className="relative flex items-center gap-2.5 rounded-lg mb-0.5 transition-all duration-150"
                    style={{
                      padding: collapsed ? '8px 0' : '8px 10px',
                      justifyContent: collapsed ? 'center' : 'flex-start',
                      background: isActive ? 'rgba(59,130,246,0.08)' : 'transparent',
                      color: isActive ? '#60A5FA' : 'rgba(255,255,255,0.45)',
                    }}
                    title={collapsed ? item.label : undefined}
                  >
                    {isActive && (
                      <motion.div
                        layoutId="sidebar-active"
                        className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 rounded-r-full"
                        style={{ background: '#3B82F6' }}
                        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                      />
                    )}
                    <Icon size={18} strokeWidth={isActive ? 2 : 1.5} className="shrink-0" />
                    <AnimatePresence>
                      {!collapsed && (
                        <motion.span
                          initial={{ opacity: 0, width: 0 }}
                          animate={{ opacity: 1, width: 'auto' }}
                          exit={{ opacity: 0, width: 0 }}
                          className="text-[13px] font-medium overflow-hidden whitespace-nowrap"
                        >
                          {item.label}
                        </motion.span>
                      )}
                    </AnimatePresence>
                  </Link>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* Status & Collapse */}
      <div className="shrink-0 px-3 py-3" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
        <AnimatePresence>
          {!collapsed && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-2 mb-3 px-1"
            >
              {[
                { label: 'Daemon', ok: true },
                { label: 'Backend', ok: true },
                { label: 'Telemetry', ok: true },
                { label: 'Database', ok: true },
              ].map((s) => (
                <div key={s.label} className="flex items-center justify-between text-[11px]">
                  <span style={{ color: 'rgba(255,255,255,0.3)' }}>{s.label}</span>
                  <div className="flex items-center gap-1.5">
                    <div className="w-1.5 h-1.5 rounded-full" style={{ background: s.ok ? '#22C55E' : '#EF4444' }} />
                    <span style={{ color: s.ok ? '#4ADE80' : '#F87171' }}>{s.ok ? 'OK' : 'ERR'}</span>
                  </div>
                </div>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center justify-center w-full h-8 rounded-lg transition-colors"
          style={{ background: 'rgba(255,255,255,0.03)', color: 'rgba(255,255,255,0.3)' }}
        >
          {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>
      </div>
    </motion.aside>
  );
}
