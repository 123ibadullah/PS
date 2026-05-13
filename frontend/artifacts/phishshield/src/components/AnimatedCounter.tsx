import { useEffect, useRef, useState } from 'react';
import { usePrefersReducedMotion } from '@/lib/motion';

interface AnimatedCounterProps {
  value: number;
  durationMs?: number;
  formatter?: (value: number) => string;
  className?: string;
}

export function AnimatedCounter({
  value,
  durationMs = 520,
  formatter = (next) => `${Math.round(next)}`,
  className,
}: AnimatedCounterProps) {
  const prefersReducedMotion = usePrefersReducedMotion();
  const [displayValue, setDisplayValue] = useState(value);
  const previousValueRef = useRef(value);

  useEffect(() => {
    if (prefersReducedMotion) {
      setDisplayValue(value);
      previousValueRef.current = value;
      return;
    }

    const start = previousValueRef.current;
    const end = value;
    const delta = end - start;
    if (delta === 0) return;

    let raf = 0;
    const startTime = performance.now();

    const tick = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(1, elapsed / durationMs);
      const eased = 1 - Math.pow(1 - progress, 3);
      const next = start + delta * eased;
      setDisplayValue(next);

      if (progress < 1) {
        raf = requestAnimationFrame(tick);
      } else {
        previousValueRef.current = end;
      }
    };

    raf = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(raf);
      previousValueRef.current = value;
    };
  }, [durationMs, prefersReducedMotion, value]);

  return <span className={className}>{formatter(displayValue)}</span>;
}