interface ThreatBadgeProps {
  severity: string;
}

const severityConfig: Record<string, { bg: string; text: string; label: string }> = {
  critical: { bg: 'bg-red-500/10 border border-red-500/30', text: 'text-red-400', label: 'Critical' },
  high: { bg: 'bg-orange-500/10 border border-orange-500/30', text: 'text-orange-400', label: 'High' },
  medium: { bg: 'bg-yellow-500/10 border border-yellow-500/30', text: 'text-yellow-400', label: 'Medium' },
  low: { bg: 'bg-blue-500/10 border border-blue-500/30', text: 'text-blue-400', label: 'Low' },
  info: { bg: 'bg-green-500/10 border border-green-500/30', text: 'text-green-400', label: 'Info' },
};

export default function ThreatBadge({ severity }: ThreatBadgeProps) {
  const config = severityConfig[severity] || severityConfig.info;

  return (
    <span className={`badge ${config.bg} ${config.text}`}>
      {config.label}
    </span>
  );
}
