import { motion } from 'framer-motion';

interface SkeletonProps {
  className?: string;
  count?: number;
}

export default function LoadingSkeleton({ className = '', count = 1 }: SkeletonProps) {
  return (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0.5 }}
          animate={{ opacity: [0.5, 0.8, 0.5] }}
          transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
          className={`rounded-xl ${className}`}
          style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.04)' }}
        />
      ))}
    </>
  );
}

export function SkeletonCard() {
  return (
    <div className="sx-card p-5 space-y-3">
      <LoadingSkeleton className="h-3 w-24" />
      <LoadingSkeleton className="h-7 w-16" />
      <LoadingSkeleton className="h-4 w-32" />
    </div>
  );
}

export function SkeletonTable({ rows = 5 }: { rows?: number }) {
  return (
    <div className="sx-card p-4 space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-4">
          <LoadingSkeleton className="h-4 flex-1" />
          <LoadingSkeleton className="h-4 w-20" />
          <LoadingSkeleton className="h-4 w-16" />
        </div>
      ))}
    </div>
  );
}
