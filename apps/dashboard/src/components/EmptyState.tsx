import { motion } from 'framer-motion';
import { LucideIcon } from 'lucide-react';

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: { label: string; onClick: () => void };
}

export default function EmptyState({ icon: Icon, title, description, action }: EmptyStateProps) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="flex flex-col items-center justify-center py-20"
    >
      <div
        className="flex items-center justify-center w-16 h-16 rounded-2xl mb-5"
        style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}
      >
        <Icon size={28} style={{ color: 'rgba(255,255,255,0.2)' }} />
      </div>
      <h3 className="text-base font-medium mb-1.5" style={{ color: 'rgba(255,255,255,0.7)' }}>
        {title}
      </h3>
      <p className="text-sm text-center max-w-sm" style={{ color: 'rgba(255,255,255,0.3)' }}>
        {description}
      </p>
      {action && (
        <button onClick={action.onClick} className="sx-btn-primary mt-5">
          {action.label}
        </button>
      )}
    </motion.div>
  );
}
