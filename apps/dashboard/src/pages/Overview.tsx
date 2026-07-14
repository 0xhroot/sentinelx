import { useState, useEffect } from 'react';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts';
import StatCard from '../components/StatCard';
import ThreatBadge from '../components/ThreatBadge';
import {
  fetchStatus, fetchThreats, fetchDetectors,
} from '../api';
import { StatusResponse, ThreatRow, DetectorInfo } from '../types';

const COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#22c55e',
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

  const severityCounts = threats.reduce(
    (acc, t) => {
      acc[t.severity] = (acc[t.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  const pieData = Object.entries(severityCounts).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
  }));

  const recentThreats = threats.slice(0, 5);

  const barData = detectors.map((d) => ({
    name: d.name.length > 12 ? d.name.slice(0, 12) + '...' : d.name,
    events: threats.filter((t) => t.source_detector === d.name).length,
  }));

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-300">
          Failed to load data: {error}
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Threats Detected"
          value={status?.metrics.threats_detected ?? 0}
          color="red"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
          }
        />
        <StatCard
          label="CPU Usage"
          value={`${(status?.metrics.cpu_usage_percent ?? 0).toFixed(1)}%`}
          color="blue"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 002.25-2.25V6.75a2.25 2.25 0 00-2.25-2.25H6.75A2.25 2.25 0 004.5 6.75v10.5a2.25 2.25 0 002.25 2.25zm.75-12h9v9h-9v-9z" />
            </svg>
          }
        />
        <StatCard
          label="Events Processed"
          value={status?.metrics.events_processed ?? 0}
          color="purple"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 7.5l-2.25-1.313M21 7.5v2.25m0-2.25l-2.25 1.313M3 7.5l2.25-1.313M3 7.5l2.25 1.313M3 7.5v2.25m9 3l2.25-1.313M12 12.75l-2.25-1.313M12 12.75V15m0 6.75l2.25-1.313M12 21.75V19.5m0 2.25l-2.25-1.313m0-16.875L12 2.25l2.25 1.313M21 14.25v2.25l-2.25 1.313m-13.5 0L3 16.5v-2.25" />
            </svg>
          }
        />
        <StatCard
          label="Active Detectors"
          value={status?.detector_count ?? 0}
          color="cyan"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
            </svg>
          }
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Threat Distribution</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pieData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={COLORS[entry.name.toLowerCase()] || '#3b82f6'}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#e2e8f0',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[220px] text-slate-500 text-sm">
              No threat data
            </div>
          )}
          <div className="flex flex-wrap gap-3 mt-3">
            {pieData.map((entry) => (
              <div key={entry.name} className="flex items-center gap-1.5 text-xs text-slate-400">
                <div
                  className="w-2.5 h-2.5 rounded-full"
                  style={{
                    backgroundColor: COLORS[entry.name.toLowerCase()] || '#3b82f6',
                  }}
                />
                {entry.name} ({entry.value})
              </div>
            ))}
          </div>
        </div>

        <div className="card p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Detectors</h3>
          {barData.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={barData}>
                <XAxis
                  dataKey="name"
                  tick={{ fill: '#64748b', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: '#64748b', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#e2e8f0',
                  }}
                />
                <Bar dataKey="events" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[260px] text-slate-500 text-sm">
              No detector data
            </div>
          )}
        </div>

        <div className="card p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Recent Threats</h3>
          <div className="space-y-3">
            {recentThreats.length > 0 ? (
              recentThreats.map((threat) => (
                <div
                  key={threat.id}
                  className="flex items-start gap-3 p-3 rounded-lg bg-slate-800/40 border border-slate-700/30"
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-slate-200 truncate">{threat.title}</p>
                    <p className="text-xs text-slate-500 mt-0.5">
                      {new Date(threat.timestamp).toLocaleString()}
                    </p>
                  </div>
                  <ThreatBadge severity={threat.severity} />
                </div>
              ))
            ) : (
              <div className="flex items-center justify-center h-[200px] text-slate-500 text-sm">
                No recent threats
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
