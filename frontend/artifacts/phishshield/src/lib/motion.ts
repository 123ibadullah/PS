import { useEffect, useState } from 'react';

export const RESULT_REVEAL_MS = {
  verdict: 0,
  indicators: 180,
  recommendations: 340,
  details: 520,
} as const;

export const SCAN_STAGE_MESSAGES = [
  'Analyzing language patterns...',
  'Checking impersonation signals...',
  'Inspecting domain reputation...',
  'Evaluating social engineering indicators...',
  'Scanning urgency patterns...',
] as const;

export function getResultRevealDelay(phase: keyof typeof RESULT_REVEAL_MS) {
  return RESULT_REVEAL_MS[phase];
}

export function formatRelativeTimestamp(iso?: string) {
  if (!iso) return '--';
  const now = Date.now();
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return '--';

  const seconds = Math.max(0, Math.floor((now - then) / 1000));
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function usePrefersReducedMotion() {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }

    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const syncPreference = () => setPrefersReducedMotion(mediaQuery.matches);
    syncPreference();

    mediaQuery.addEventListener('change', syncPreference);
    return () => mediaQuery.removeEventListener('change', syncPreference);
  }, []);

  return prefersReducedMotion;
}