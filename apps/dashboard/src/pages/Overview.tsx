import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  PieChart, Pie, Cell, AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar,
} from 'recharts';
import {
  ShieldAlert, Cpu, Activity, Radar, Clock, AlertTriangle,
  ShieldCheck, Zap,
} from 'lucide-react';
import StatCard from '../components/StatCard';
import ThreatBadge from '../components/ThreatBadge';
import { fetchStatus, fetchThreats, fetchDetectors } from '../api';
import { StatusResponse, ThreatRow, DetectorInfo } from '../types';

const COLORS: Record<string, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#EAB308',
  low: '#3B82F6',
  info: '#22C55E',
};

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="sx-glass rounded-lg px-3 py-2 text-xs" style={{ background: 'rgba(14,14,14,0.95)' }}>
      <p style={{ color: 'rgba(255,255,255,0.5)' }}>{label}</p>
      {payload.map((p: any, i: number) => (
        <p key={i} style={{ color: p.color || '#60A5FA' }}>{p.name}: {p.value}</p>
      ))}
    </div>
  );
};

export default function Overview() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [threats, setThreats] = useState<ThreatRow[]>([]);
  const [detectors, setDetectors] = useState<DetectorInfo[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchStatus().then(setStatus).catch((e) => setError(String(e)));
    fetchThreats().then(setThreats).catch((e) => setError(String(e)));
    fetchDetectors().then((d) => setDetectors(d.detectors)).catch((e) => setError(String(e)));
  }, []);

  const severityCounts = threats.reduce((acc, t) => {
    acc[t.severity] = (acc[t.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const pieData = Object.entries(severityCounts).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
  }));

  const recentThreats = threats.slice(0, 6);

  // Mock sparkline data
  const sparkline1 = [3, 5, 2, 8, 4, 6, 3, 7, 5, 9, 4, 6];
  const sparkline2 = [45, 42, 48, 44, 46, 43, 47, 45, 44, 46, 43, 45];
  const sparkline3 = [1200, 1350, 1280, 1400, 1320, 1450, 1380, 1500, 1420, 1550, 1480, 1600];
  const sparkline4 = [8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8];

  const timelineData = Array.from({ length: 24 }, (_, i) => ({
    hour: `${i}:00`,
    threats: Math.floor(Math.random() * 10),
    events: Math.floor(Math.random() * 500 + 100),
  }));

  const barData = detectors.map((d) => ({
    name: d.name.length > 10 ? d.name.slice(0, 10) + '...' : d.name,
    count: threats.filter((t) => t.source_detector === d.name).length,
  }));

  const threatScore = threats.length > 0
    ? Math.min(100, Math.round(
        (severityCounts.critical || 0) * 40 +
        (severityCounts.high || 0) * 25 +
        (severityCounts.medium || 0) * 15 +
        (severityCounts.low || 0) * 5 +
        (severityCounts.info || 0) * 1
      ))
    : 0;

  const riskLevel = threatScore > 60 ? 'Critical' : threatScore > 30 ? 'Elevated' : threatScore > 0 ? 'Moderate' : 'Normal';
  const riskColor = threatScore > 60 ? 'red' : threatScore > 30 ? 'orange' : threatScore > 0 ? 'yellow' : 'green';

  return (
    <div className="space-y-5">
      {error && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          className="rounded-xl px-4 py-3 text-sm"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)', color: '#F87171' }}>
          {error}
        </motion.div>
      )}

      {/* Row 1: Hero Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
        <StatCard
          label="Threat Score"
          value={threatScore}
          icon={<ShieldAlert size={18} />}
          color={riskColor as any}
          sparkline={sparkline1}
        />
        <StatCard
          label="Risk Level"
          value={riskLevel}
          icon={<AlertTriangle size={18} />}
          color={riskColor as any}
        />
        <StatCard
          label="Host Health"
          value={`${(status?.metrics.cpu_usage_percent ?? 0).toFixed(0)}%`}
          icon={<Cpu size={18} />}
          color="blue"
          sparkline={sparkline2}
        />
        <StatCard
          label="System Integrity"
          value="Secure"
          icon={<ShieldCheck size={18} />}
          color="green"
        />
        <StatCard
          label="Events"
          value={status?.metrics.events_processed ?? 0}
          icon={<Activity size={18} />}
          color="purple"
          sparkline={sparkline3}
        />
        <StatCard
          label="Detectors"
          value={status?.detector_count ?? 0}
          icon={<Radar size={18} />}
          color="cyan"
          sparkline={sparkline4}
        />
      </div>

      {/* Row 2: Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {/* Threat Timeline */}
        <div className="sx-card p-4 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.35)' }}>
              Threat Timeline
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded-full"
              style={{ background: 'rgba(59,130,246,0.1)', color: '#60A5FA' }}>24h</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timelineData}>
              <defs>
                <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#3B82F6" stopOpacity={0.2} />
                  <stop offset="100%" stopColor="#3B82F6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="hour" tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="threats" stroke="#3B82F6" fill="url(#threatGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Threat Distribution */}
        <div className="sx-card p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4"
            style={{ color: 'rgba(255,255,255,0.35)' }}>
            Distribution
          </h3>
          {pieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={140}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={35} outerRadius={55} paddingAngle={3} dataKey="value">
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={COLORS[entry.name.toLowerCase()] || '#3B82F6'} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-wrap gap-2 mt-2">
                {pieData.map((entry) => (
                  <div key={entry.name} className="flex items-center gap-1.5 text-[10px]" style={{ color: 'rgba(255,255,255,0.4)' }}>
                    <div className="w-2 h-2 rounded-full" style={{ background: COLORS[entry.name.toLowerCase()] || '#3B82F6' }} />
                    {entry.name} ({entry.value})
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-[200px] text-xs" style={{ color: 'rgba(255,255,255,0.2)' }}>
              No threat data
            </div>
          )}
        </div>
      </div>

      {/* Row 3: Bottom section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {/* Detector Activity */}
        <div className="sx-card p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4"
            style={{ color: 'rgba(255,255,255,0.35)' }}>
            Detector Activity
          </h3>
          {barData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={barData} layout="vertical">
                <XAxis type="number" tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" width={80} tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="#3B82F6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[200px] text-xs" style={{ color: 'rgba(255,255,255,0.2)' }}>
              No detector data
            </div>
          )}
        </div>

        {/* Live Telemetry */}
        <div className="sx-card p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4"
            style={{ color: 'rgba(255,255,255,0.35)' }}>
            Live Telemetry
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timelineData}>
              <defs>
                <linearGradient id="eventGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#8B5CF6" stopOpacity={0.2} />
                  <stop offset="100%" stopColor="#8B5CF6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="hour" tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="events" stroke="#8B5CF6" fill="url(#eventGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Recent Threats */}
        <div className="sx-card p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider"
              style={{ color: 'rgba(255,255,255,0.35)' }}>
              Recent Threats
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded-full"
              style={{ background: 'rgba(239,68,68,0.1)', color: '#F87171' }}>
              {threats.length}
            </span>
          </div>
          <div className="space-y-2">
            {recentThreats.length > 0 ? (
              recentThreats.map((threat) => (
                <motion.div
                  key={threat.id}
                  initial={{ opacity: 0, x: -5 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="flex items-center gap-3 p-2.5 rounded-lg transition-colors cursor-pointer"
                  style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}
                >
                  <ThreatBadge severity={threat.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate" style={{ color: 'rgba(255,255,255,0.8)' }}>
                      {threat.title}
                    </p>
                    <p className="text-[10px] flex items-center gap-1 mt-0.5" style={{ color: 'rgba(255,255,255,0.25)' }}>
                      <Clock size={9} />
                      {new Date(threat.timestamp).toLocaleTimeString()}
                    </p>
                  </div>
                </motion.div>
              ))
            ) : (
              <div className="flex items-center justify-center h-[160px] text-xs"
                style={{ color: 'rgba(255,255,255,0.2)' }}>
                <div className="text-center">
                  <Zap size={24} className="mx-auto mb-2" style={{ color: 'rgba(255,255,255,0.1)' }} />
                  <p>No threats detected</p>
                  <p className="text-[10px] mt-1" style={{ color: 'rgba(255,255,255,0.15)' }}>System is clean</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
