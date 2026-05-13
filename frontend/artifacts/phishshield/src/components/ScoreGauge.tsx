// Semi-circular gauge showing the 0–100 risk score. The arc fills left-to-right
// and changes colour based on whether the email is safe, suspicious, or phishing.
import React from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface ScoreGaugeProps {
  score: number; // 0–100
  classification: 'safe' | 'uncertain' | 'suspicious' | 'phishing';
  label?: string;
  detail?: string;
}

export function ScoreGauge({ score, classification, label, detail }: ScoreGaugeProps) {
  const normalizedScore = Math.max(0, Math.min(100, Math.round(score)));
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  const tones = {
    safe: {
      stroke: 'stroke-safe',
      text: 'text-safe',
      glow: 'bg-[radial-gradient(circle,rgba(0,200,83,0.28),transparent_70%)]',
    },
    uncertain: {
      stroke: 'stroke-warning',
      text: 'text-warning',
      glow: 'bg-[radial-gradient(circle,rgba(255,165,0,0.28),transparent_70%)]',
    },
    suspicious: {
      stroke: 'stroke-warning',
      text: 'text-warning',
      glow: 'bg-[radial-gradient(circle,rgba(255,165,0,0.28),transparent_70%)]',
    },
    phishing: {
      stroke: 'stroke-destructive',
      text: 'text-destructive',
      glow: 'bg-[radial-gradient(circle,rgba(255,76,76,0.28),transparent_70%)]',
    },
  };

  const { stroke, text, glow } = tones[classification] ?? tones.safe;

  return (
    <div className="relative flex h-[220px] w-[220px] items-center justify-center">
      <div className={cn('absolute inset-2 rounded-full blur-2xl opacity-80', glow)} />
      <svg width="220" height="220" viewBox="0 0 120 120" className="relative z-10 -rotate-90 overflow-visible">
        <circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          className="stroke-white/10"
        />
        <motion.circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          className={cn(stroke, 'drop-shadow-[0_0_10px_currentColor]')}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset }}
          transition={{ duration: 1.2, ease: 'easeOut' }}
        />
      </svg>
      <div className="absolute inset-6 z-20 flex flex-col items-center justify-center rounded-full border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.08),rgba(255,255,255,0.04))] text-center shadow-[inset_0_1px_0_rgba(255,255,255,0.08)] backdrop-blur-xl">
        <motion.span
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className={cn('text-4xl font-bold tracking-tight', text)}
        >
          {normalizedScore}%
        </motion.span>
        <span className="mt-1 text-[10px] uppercase tracking-[0.24em] text-[#B0B8C1]">
          {label ?? 'Confidence'}
        </span>
        {detail ? <span className="mt-2 text-[11px] font-medium text-white/80">{detail}</span> : null}
      </div>
    </div>
  );
}
