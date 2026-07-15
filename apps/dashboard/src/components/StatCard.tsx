import { ReactNode } from 'react';
import { motion } from 'framer-motion';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: ReactNode;
  color?: 'blue' | 'cyan' | 'purple' | 'green' | 'yellow' | 'orange' | 'red';
  trend?: { value: number; isUp: boolean };
  sparkline?: number[];
}

const colorMap = {
  blue: { bg: 'rgba(59,130,246,0.08)', border: 'rgba(59,130,246,0.15)', text: '#60A5FA' },
  cyan: { bg: 'rgba(6,182,212,0.08)', border: 'rgba(6,182,212,0.15)', text: '#22D3EE' },
  purple: { bg: 'rgba(139,92,246,0.08)', border: 'rgba(139,92,246,0.15)', text: '#A78BFA' },
  green: { bg: 'rgba(34,197,94,0.08)', border: 'rgba(34,197,94,0.15)', text: '#4ADE80' },
  yellow: { bg: 'rgba(234,179,8,0.08)', border: 'rgba(234,179,8,0.15)', text: '#FACC15' },
  orange: { bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.15)', text: '#FB923C' },
  red: { bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.15)', text: '#F87171' },
};

export default function StatCard({ label, value, icon, color = 'blue', trend, sparkline }: StatCardProps) {
  const c = colorMap[color];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="sx-card-hover group relative overflow-hidden p-5"
    >
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.35)' }}>
            {label}
          </p>
          <p className="mt-2 text-2xl font-bold tracking-tight" style={{ color: 'rgba(255,255,255,0.92)' }}>
            {value}
          </p>
          {trend && (
            <div className="mt-2 flex items-center gap-1.5 text-xs">
              <span style={{ color: trend.isUp ? '#4ADE80' : '#F87171' }}>
                {trend.isUp ? '↑' : '↓'} {Math.abs(trend.value)}%
              </span>
              <span style={{ color: 'rgba(255,255,255,0.25)' }}>vs last hour</span>
            </div>
          )}
        </div>
        <div
          className="flex items-center justify-center w-10 h-10 rounded-xl transition-transform group-hover:scale-110"
          style={{ background: c.bg, border: `1px solid ${c.border}` }}
        >
          <div style={{ color: c.text }}>{icon}</div>
        </div>
      </div>
      {sparkline && sparkline.length > 0 && (
        <div className="mt-4 h-8 flex items-end gap-px">
          {sparkline.map((val, i) => {
            const max = Math.max(...sparkline);
            const height = max > 0 ? (val / max) * 100 : 0;
            return (
              <div
                key={i}
                className="flex-1 rounded-sm transition-all duration-300"
                style={{
                  height: `${Math.max(height, 8)}%`,
                  background: `linear-gradient(to top, ${c.text}22, ${c.text}44)`,
                }}
              />
            );
          })}
        </div>
      )}
    </motion.div>
  );
}
