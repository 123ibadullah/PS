import { motion } from 'framer-motion';
import { Loader2, Radar } from 'lucide-react';
import { usePrefersReducedMotion } from '@/lib/motion';
import { cn } from '@/lib/utils';

interface ScanLoadingPanelProps {
  message: string;
  stage: number;
  totalStages: number;
}

export function ScanLoadingPanel({ message, stage, totalStages }: ScanLoadingPanelProps) {
  const prefersReducedMotion = usePrefersReducedMotion();
  const progress = Math.min(100, Math.max(8, Math.round(((stage + 1) / Math.max(totalStages, 1)) * 100)));

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }}
      transition={{ duration: 0.24, ease: 'easeOut' }}
      role="status"
      aria-live="polite"
      className="relative overflow-hidden rounded-2xl border border-primary/30 bg-[linear-gradient(145deg,rgba(212,175,55,0.10),rgba(17,24,39,0.92))] p-5 shadow-[0_16px_44px_rgba(2,6,23,0.22)]"
    >
      <div className="pointer-events-none absolute inset-0 shimmer opacity-50" />
      <div className="relative z-10 flex flex-col gap-4">
        <div className="flex items-start gap-4">
          <div className="relative flex h-11 w-11 items-center justify-center rounded-xl border border-primary/30 bg-background/70">
            <Radar className="h-5 w-5 text-primary" />
            {!prefersReducedMotion && <span className="absolute inset-0 rounded-xl border border-primary/35 animate-ping" />}
          </div>

          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin text-primary" />
              <p className="text-sm font-semibold text-foreground">Deep scan in progress</p>
            </div>
            <p className="mt-1 text-sm text-muted-foreground">{message}</p>
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-[11px] text-muted-foreground">
            <span>Pipeline stage {Math.min(totalStages, stage + 1)} of {totalStages}</span>
            <span className="font-mono text-foreground">{progress}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-secondary/70">
            <motion.div
              className="h-full rounded-full bg-primary"
              initial={{ width: '8%' }}
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.28, ease: 'easeOut' }}
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, idx) => (
            <div
              key={`skeleton-${idx}`}
              className={cn(
                'h-10 rounded-lg border border-white/10 bg-background/40',
                idx <= stage % 4 ? 'shimmer' : 'opacity-70',
              )}
            />
          ))}
        </div>
      </div>
    </motion.div>
  );
}