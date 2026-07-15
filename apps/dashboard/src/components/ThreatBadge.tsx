const severityConfig: Record<string, { className: string; label: string }> = {
  critical: { className: 'sx-badge-critical', label: 'Critical' },
  high: { className: 'sx-badge-high', label: 'High' },
  medium: { className: 'sx-badge-medium', label: 'Medium' },
  low: { className: 'sx-badge-low', label: 'Low' },
  info: { className: 'sx-badge-info', label: 'Info' },
};

interface ThreatBadgeProps {
  severity: string;
}

export default function ThreatBadge({ severity }: ThreatBadgeProps) {
  const config = severityConfig[severity] || severityConfig.info;
  return <span className={config.className}>{config.label}</span>;
}
