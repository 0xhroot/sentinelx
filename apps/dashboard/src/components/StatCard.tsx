import { ReactNode } from 'react';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: ReactNode;
  trend?: { value: number; isUp: boolean };
  color?: string;
}

export default function StatCard({ label, value, icon, trend, color = 'blue' }: StatCardProps) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    red: 'bg-red-500/10 text-red-400 border-red-500/20',
    orange: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    green: 'bg-green-500/10 text-green-400 border-green-500/20',
    yellow: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    purple: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    cyan: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  };

  return (
    <div className="card card-hover p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="stat-label">{label}</p>
          <p className="stat-value mt-1 text-white">{value}</p>
        </div>
        <div className={`flex items-center justify-center w-10 h-10 rounded-lg border ${colorMap[color] || colorMap.blue}`}>
          {icon}
        </div>
      </div>
      {trend && (
        <div className="mt-3 flex items-center gap-1 text-sm">
          <span className={trend.isUp ? 'text-green-400' : 'text-red-400'}>
            {trend.isUp ? '↑' : '↓'} {Math.abs(trend.value)}%
          </span>
          <span className="text-slate-500">vs last hour</span>
        </div>
      )}
    </div>
  );
}
