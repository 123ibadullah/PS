import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  History,
  Mail,
  RefreshCw,
  ScanSearch,
  Shield,
  Sparkles,
  Trash2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import {
  useAnalyzeEmail,
  useClearScanHistory,
  useGetModelMetrics,
  useGetScanHistory,
} from '@workspace/api-client-react';

const SAMPLE_EMAILS = [
  {
    id: 'finance-bec',
    sender: 'CFO Office',
    subject: 'Release this confidential vendor transfer today',
    preview: 'Urgent payment diversion attempt with secrecy pressure and finance language.',
    text:
      'From: CFO Office <ceo-finance@vendor-payments.co>\nSubject: Confidential: release urgent vendor transfer today\n\nHi, I need you to process the attached vendor bank transfer today. Keep this confidential and do not call back until it is done. Update the beneficiary to the new account in the invoice and confirm once the payment is released.',
  },
  {
    id: 'bank-otp',
    sender: 'HDFC Security',
    subject: 'Your account will be suspended in 24 hours',
    preview: 'Classic credential-harvesting flow with urgency and a suspicious link.',
    text:
      'Dear customer, we detected unusual login attempts on your HDFC account. To avoid suspension, verify immediately at http://hdfc-verify.xyz/login and enter your OTP and password to restore access.',
  },
  {
    id: 'legit-safe',
    sender: 'Google Security',
    subject: 'Security alert for your account',
    preview: 'A normal security notice that does not ask you to send credentials.',
    text:
      'Your Google Account was just signed in to from a new Windows device. If this was you, you can safely ignore this email. If this was not you, open your Google account directly to review the activity.',
  },
];

type VisualState = 'safe' | 'suspicious' | 'phishing';

function getVisualState(classification?: string): VisualState {
  if (classification === 'phishing') return 'phishing';
  if (classification === 'uncertain' || classification === 'suspicious') return 'suspicious';
  return 'safe';
}

function getStateCopy(state: VisualState) {
  if (state === 'phishing') {
    return {
      title: 'HIGH RISK',
      badge: 'HIGH RISK',
      text: 'text-[#ef4444]',
      softText: 'text-red-100',
      surface: 'border-[#ef4444]/35 bg-[#ef4444]/10',
      chip: 'border-[#ef4444]/35 bg-[#ef4444]/12 text-[#fecaca]',
      glow: 'from-[#ef4444]/18 via-[#ef4444]/6 to-transparent',
      accent: 'bg-[#ef4444]',
    };
  }

  if (state === 'suspicious') {
    return {
      title: 'SUSPICIOUS',
      badge: 'SUSPICIOUS',
      text: 'text-[#f59e0b]',
      softText: 'text-amber-100',
      surface: 'border-[#f59e0b]/35 bg-[#f59e0b]/10',
      chip: 'border-[#f59e0b]/35 bg-[#f59e0b]/12 text-[#fde68a]',
      glow: 'from-[#f59e0b]/18 via-[#f59e0b]/6 to-transparent',
      accent: 'bg-[#f59e0b]',
    };
  }

  return {
    title: 'SAFE',
    badge: 'SAFE',
    text: 'text-[#22c55e]',
    softText: 'text-emerald-100',
    surface: 'border-[#22c55e]/35 bg-[#22c55e]/10',
    chip: 'border-[#22c55e]/35 bg-[#22c55e]/12 text-[#bbf7d0]',
    glow: 'from-[#22c55e]/16 via-[#22c55e]/5 to-transparent',
    accent: 'bg-[#22c55e]',
  };
}

function clampDisplayedConfidence(percent = 0) {
  const rounded = Math.round(percent);
  if (rounded <= 0) return 5;
  return Math.max(5, Math.min(95, rounded));
}

function formatConfidence(confidence?: number, riskScore = 0) {
  const normalized = typeof confidence === 'number'
    ? (confidence <= 1 ? confidence * 100 : confidence)
    : Math.max(5, 100 - riskScore);

  return `Confidence: ${clampDisplayedConfidence(normalized)}%`;
}

function compactExplanation(text?: string, fallbackState: VisualState = 'safe') {
  const fallback =
    fallbackState === 'phishing'
      ? 'Detected brand impersonation with suspicious domain and phishing link.'
      : fallbackState === 'suspicious'
        ? 'This email needs manual review before you click, reply, or sign in.'
        : 'No strong phishing signals detected. Always verify sensitive actions via official apps.';

  const source = (text || fallback).replace(/\s+/g, ' ').trim();
  const parts = source.split(/(?<=[.!?])\s+/).slice(0, 2);
  return parts.join(' ');
}

function deriveSignals(result: any, state: VisualState) {
  const mapped = new Set<string>();
  const reasons = Array.isArray(result?.reasons) ? result.reasons : [];
  const flags = Array.isArray(result?.flags) ? result.flags : [];
  const attackType = String(result?.attackType || '').toLowerCase();

  for (const reason of reasons) {
    const category = String(reason?.category || '').toLowerCase();
    const description = String(reason?.description || '').toLowerCase();

    if (category === 'social_engineering' && /otp|password|credential|pin|identity/.test(description)) mapped.add('Credential Request');
    else if (category === 'social_engineering') mapped.add('Suspicious Request');
    else if (category === 'url' || category === 'domain') mapped.add('Suspicious Link');
    else if (category === 'urgency' || /urgent|suspend|deadline|immediately|rush/.test(description)) mapped.add('Urgency');
    else if (category === 'financial' && /invoice|payment|transfer|billing|refund/.test(description)) mapped.add('Money Request');
    else if (category === 'financial' && /reward|prize|cashback|bonus/.test(description)) mapped.add('Reward Lure');
    else if (category === 'header' || category === 'india_specific') mapped.add('Impersonation');
  }

  flags.forEach((flag: string) => {
    if (/credential|otp|password|pin/i.test(flag)) mapped.add('Credential Request');
    else if (/link|domain|url/i.test(flag)) mapped.add('Suspicious Link');
    else if (/urgent|pressure|deadline|suspend/i.test(flag)) mapped.add('Urgency');
    else if (/bank|brand|spoof|imperson/i.test(flag)) mapped.add('Impersonation');
  });

  if (state === 'phishing') {
    if (/reward/.test(attackType)) mapped.add('Reward Lure');
    if (/bank/.test(attackType)) mapped.add('Impersonation');
    if (/credential|otp/.test(attackType)) mapped.add('Credential Request');
  }

  const list = Array.from(mapped).slice(0, 3);
  if (list.length > 0) return list;

  if (state === 'phishing') return ['Credential Request', 'Suspicious Link', 'Urgency'];
  if (state === 'suspicious') return ['Needs Verification', 'Review Carefully'];
  return ['Trusted Sender', 'No Strong Phishing Signals'];
}

function signalTone(signal: string) {
  const normalized = signal.toLowerCase();

  if (/(trusted|safe|verified|no strong signals|no strong phishing signals|informational|routine)/i.test(normalized)) {
    return {
      icon: '🟢',
      className: 'border-[#00C853]/35 bg-[#00C853]/12 text-[#bbf7d0]',
    };
  }

  if (/(credential|suspicious link|urgency|impersonation|spoof|money request)/i.test(normalized)) {
    return {
      icon: '🔴',
      className: 'border-[#FF4C4C]/35 bg-[#FF4C4C]/12 text-[#fecaca]',
    };
  }

  return {
    icon: '⚠️',
    className: 'border-[#FFA500]/35 bg-[#FFA500]/12 text-[#fde68a]',
  };
}

export default function PremiumDashboard() {
  const [emailText, setEmailText] = useState('');
  const [selectedSampleId, setSelectedSampleId] = useState<string | null>(null);

  const { mutate: analyzeEmail, data: result, isPending, error, reset } = useAnalyzeEmail();
  const { data: history = [], refetch: refetchHistory } = useGetScanHistory();
  const { data: metrics, refetch: refetchMetrics } = useGetModelMetrics();
  const { mutate: clearHistory } = useClearScanHistory();

  const visualState = getVisualState(result?.classification);
  const stateCopy = getStateCopy(visualState);
  const score = Math.max(0, Math.min(100, Math.round(result?.riskScore ?? 0)));
  const confidence = formatConfidence(result?.confidence, score);
  const summary = compactExplanation(result?.scamStory || (result as any)?.explanation, visualState);
  const signals = deriveSignals(result, visualState);
  const topReasons = visualState === 'safe'
    ? ['Trusted Sender', 'No Strong Phishing Signals', 'Normal Informational Language']
    : signals.slice(0, 3);
  const recentHistory = Array.isArray(history) ? history.slice(0, 5) : [];
  const hasHeaderSpoofing = Boolean(
    result && (
      /header spoofing|spoof/i.test(String(result?.attackType || '')) ||
      (Array.isArray((result as any)?.reasons) && (result as any).reasons.some((reason: any) => String(reason?.category || '').toLowerCase() === 'header'))
    )
  );

  const topStats = useMemo(() => {
    return [
      {
        label: 'High risk',
        value: metrics?.phishingDetected ?? 0,
        tone: 'border-[#ef4444]/25 bg-[#ef4444]/10 text-[#fecaca]',
      },
      {
        label: 'Suspicious',
        value: metrics?.suspiciousDetected ?? 0,
        tone: 'border-[#f59e0b]/25 bg-[#f59e0b]/10 text-[#fde68a]',
      },
      {
        label: 'Safe',
        value: metrics?.safeDetected ?? 0,
        tone: 'border-[#22c55e]/25 bg-[#22c55e]/10 text-[#bbf7d0]',
      },
    ];
  }, [metrics]);

  const handleScan = (text = emailText) => {
    const payload = text.trim();
    if (!payload) return;

    analyzeEmail(
      { data: { emailText: payload } },
      {
        onSuccess: () => {
          refetchHistory();
          refetchMetrics();
        },
      },
    );
  };

  const handleLoadSample = (sample: (typeof SAMPLE_EMAILS)[number]) => {
    setSelectedSampleId(sample.id);
    setEmailText(sample.text);
    handleScan(sample.text);
  };

  const handleDismiss = () => {
    reset();
    setSelectedSampleId(null);
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-50">
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -left-20 top-0 h-72 w-72 rounded-full bg-sky-500/15 blur-3xl" />
        <div className="absolute right-0 top-24 h-80 w-80 rounded-full bg-violet-500/12 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-72 w-72 rounded-full bg-emerald-500/10 blur-3xl" />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        <motion.header
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6 flex flex-col gap-4 rounded-3xl border border-white/10 bg-slate-950/60 px-5 py-4 backdrop-blur-xl sm:flex-row sm:items-center sm:justify-between"
        >
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-sky-400/30 bg-sky-500/15 shadow-[0_0_32px_rgba(56,189,248,0.18)]">
              <Shield className="h-5 w-5 text-sky-300" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-black tracking-tight">PhishShield</h1>
                <Badge className="border-0 bg-sky-400 text-slate-950 shadow-none">PREMIUM</Badge>
              </div>
              <p className="text-sm text-slate-300">Modern phishing defense for Gmail, browser links, and security teams.</p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="border-emerald-400/30 bg-emerald-500/10 text-emerald-200">
              Live protection
            </Badge>
            <Badge variant="outline" className="border-white/10 bg-white/5 text-slate-200">
              {metrics?.totalScans ?? 0} scans analyzed
            </Badge>
          </div>
        </motion.header>

        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="overflow-hidden rounded-[28px] border border-white/10 bg-[linear-gradient(135deg,rgba(15,23,42,0.96),rgba(15,23,42,0.86))] shadow-[0_24px_80px_rgba(2,6,23,0.45)]"
        >
          <div className="grid gap-6 px-5 py-6 lg:grid-cols-[1.2fr_0.8fr] lg:px-8 lg:py-8">
            <div>
              <Badge className="mb-3 border-0 bg-white/8 text-slate-200 shadow-none">Security-grade clarity</Badge>
              <h2 className="max-w-2xl text-3xl font-black tracking-tight text-white sm:text-5xl">
                Premium phishing detection with a <span className="text-sky-300">serious security feel</span>.
              </h2>
              <p className="mt-3 max-w-xl text-sm leading-6 text-slate-300 sm:text-base">
                Scan suspicious emails instantly, surface only the strongest signals, and deliver a verdict that feels clean, powerful, and trustworthy.
              </p>

              <div className="mt-5 flex flex-wrap gap-3">
                <Button size="lg" className="bg-sky-500 text-slate-950 hover:bg-sky-400" onClick={() => handleScan()}>
                  Scan now <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
                <Button size="lg" variant="outline" className="border-white/15 bg-white/5 text-white hover:bg-white/10" onClick={handleDismiss}>
                  Reset view
                </Button>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-1">
              {[
                {
                  title: 'HIGH RISK',
                  scoreLabel: '87/100',
                  note: 'Credential theft or payment fraud likely.',
                  tone: 'border-[#ef4444]/35 bg-[#ef4444]/10 text-[#fecaca]',
                },
                {
                  title: 'SUSPICIOUS',
                  scoreLabel: '54/100',
                  note: 'Verify independently before acting.',
                  tone: 'border-[#f59e0b]/35 bg-[#f59e0b]/10 text-[#fde68a]',
                },
                {
                  title: 'SAFE',
                  scoreLabel: '14/100',
                  note: 'Routine message with low-risk signals.',
                  tone: 'border-[#22c55e]/35 bg-[#22c55e]/10 text-[#bbf7d0]',
                },
              ].map((item) => (
                <motion.div
                  whileHover={{ scale: 1.02 }}
                  key={item.title}
                  className={cn('rounded-[20px] border p-4 shadow-[0_10px_30px_rgba(15,23,42,0.28)]', item.tone)}
                >
                  <p className="text-xs font-black uppercase tracking-[0.2em] text-white/70">Threat state</p>
                  <div className="mt-2 flex items-end justify-between gap-3">
                    <div>
                      <p className="text-base font-bold text-white">{item.title}</p>
                      <p className="mt-1 text-xs leading-5">{item.note}</p>
                    </div>
                    <span className="text-lg font-black text-white">{item.scoreLabel}</span>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </motion.section>

        <div id="scanner" className="mt-6 grid gap-6 xl:grid-cols-[1.08fr_0.92fr]">
          <motion.section
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.08 }}
            className="rounded-3xl border border-white/10 bg-slate-950/65 p-5 shadow-[0_16px_60px_rgba(2,6,23,0.32)] backdrop-blur-xl"
          >
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-black uppercase tracking-[0.24em] text-slate-400">Live scanner</p>
                <h3 className="mt-1 text-xl font-bold text-white">Paste an email and get a premium verdict.</h3>
              </div>
              <div className="rounded-2xl border border-sky-400/25 bg-sky-500/10 p-2">
                <ScanSearch className="h-5 w-5 text-sky-300" />
              </div>
            </div>

            <div className="mb-4 grid gap-3 md:grid-cols-3">
              {SAMPLE_EMAILS.map((sample) => (
                <motion.button
                  whileHover={{ scale: 1.01 }}
                  key={sample.id}
                  onClick={() => handleLoadSample(sample)}
                  className={cn(
                    'rounded-[18px] border p-3 text-left transition-all',
                    selectedSampleId === sample.id
                      ? 'border-sky-400/45 bg-sky-500/10 shadow-[0_0_0_1px_rgba(56,189,248,0.12)]'
                      : 'border-white/10 bg-white/5 hover:border-white/20 hover:bg-white/[0.07]',
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-white">{sample.sender}</span>
                    <Badge variant="outline" className="border-white/10 bg-white/5 text-slate-300">
                      Demo
                    </Badge>
                  </div>
                  <p className="mt-2 text-sm font-semibold text-slate-100">{sample.subject}</p>
                  <p className="mt-1 text-xs leading-5 text-slate-400">{sample.preview}</p>
                </motion.button>
              ))}
            </div>

            <label className="mb-2 block text-xs font-black uppercase tracking-[0.22em] text-slate-400">
              Email content
            </label>
            <textarea
              value={emailText}
              onChange={(event) => {
                setEmailText(event.target.value);
                setSelectedSampleId(null);
              }}
              placeholder="Paste the email body, subject, or suspicious message here..."
              className="min-h-64 w-full rounded-[20px] border border-white/10 bg-[#09101d] px-4 py-4 text-sm text-slate-100 outline-none transition focus:border-sky-400/45 focus:ring-2 focus:ring-sky-400/20"
            />

            <div className="mt-3 flex items-center justify-between gap-3 text-xs text-slate-400">
              <span>{emailText.trim() ? `${emailText.trim().length.toLocaleString()} characters loaded` : 'No email loaded yet'}</span>
              <span>Private local workflow</span>
            </div>

            {error && (
              <div className="mt-4 rounded-[18px] border border-[#ef4444]/30 bg-[#ef4444]/10 px-4 py-3 text-sm text-red-100">
                {error instanceof Error ? error.message : 'The scan could not be completed.'}
              </div>
            )}

            <div className="mt-5 flex flex-wrap gap-3">
              <Button size="lg" onClick={() => handleScan()} disabled={isPending || !emailText.trim()} className="min-w-40 bg-sky-500 text-slate-950 hover:bg-sky-400">
                {isPending ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <Mail className="mr-2 h-4 w-4" />}
                {isPending ? 'Scanning…' : 'Analyze Email'}
              </Button>
              <Button size="lg" variant="outline" onClick={handleDismiss} className="border-white/12 bg-white/5 text-white hover:bg-white/10">
                Dismiss
              </Button>
            </div>
          </motion.section>

          <motion.aside
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.12 }}
            className="rounded-3xl border border-white/10 bg-slate-950/65 p-5 shadow-[0_16px_60px_rgba(2,6,23,0.32)] backdrop-blur-xl xl:sticky xl:top-6"
          >
            <div className="mb-4 flex items-center justify-between">
              <div>
                <p className="text-xs font-black uppercase tracking-[0.24em] text-slate-400">Verdict</p>
                <h3 className="mt-1 text-xl font-bold text-white">Front-and-center risk summary</h3>
              </div>
              <Badge className={cn('border', stateCopy.surface, stateCopy.text)}>{stateCopy.badge}</Badge>
            </div>

            <div className={cn('relative overflow-hidden rounded-[22px] border p-4 sm:p-5', stateCopy.surface)}>
              <div className={cn('absolute inset-0 bg-linear-to-br', stateCopy.glow)} />
              <div className="relative">
                <div className="mb-4 flex items-start justify-between gap-3">
                  <div>
                    <p className={cn('text-xs font-black uppercase tracking-[0.24em]', stateCopy.text)}>Final verdict</p>
                    <h4 className="mt-2 text-2xl font-black tracking-[0.18em] text-white">{result ? stateCopy.title : 'READY'}</h4>
                    <p className="mt-1 text-sm text-slate-300">{result ? confidence : 'Paste an email to generate a live score.'}</p>
                    {hasHeaderSpoofing && (
                      <Badge className="mt-3 border border-[#FF4C4C]/30 bg-[#FF4C4C]/10 text-[#fecaca]">
                        ⚠️ Header Spoofing Detected
                      </Badge>
                    )}
                  </div>
                  <div className="rounded-[18px] border border-white/10 bg-slate-950/65 px-4 py-3 text-right shadow-inner">
                    <div className={cn('text-4xl font-black leading-none sm:text-5xl', result ? stateCopy.text : 'text-slate-200')}>
                      {result ? score : 0}
                    </div>
                    <div className="mt-1 text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">/100</div>
                  </div>
                </div>

                <div className="rounded-[18px] border border-white/10 bg-slate-950/70 p-4">
                  <p className="text-xs font-black uppercase tracking-[0.22em] text-slate-400">Summary</p>
                  <p className="mt-2 text-sm leading-6 text-slate-100">
                    {summary}
                  </p>
                </div>

                <div className="mt-4">
                  <p className="text-xs font-black uppercase tracking-[0.22em] text-slate-400">Primary Risk Indicators</p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {signals.slice(0, 4).map((signal) => {
                      const tone = signalTone(signal);
                      return (
                        <span key={signal} className={cn('rounded-full border px-3 py-1 text-xs font-semibold', tone.className)}>
                          <span className="mr-1">{tone.icon}</span>
                          {signal}
                        </span>
                      );
                    })}
                  </div>
                </div>

                <div className="mt-4">
                  <p className="text-xs font-black uppercase tracking-[0.22em] text-slate-400">Top 3 Reasons</p>
                  <div className="mt-2 grid gap-2 sm:grid-cols-3">
                    {topReasons.map((reason) => {
                      const tone = signalTone(reason);
                      return (
                        <div key={reason} className="rounded-2xl border border-white/10 bg-slate-950/70 px-3 py-2">
                          <p className={cn('text-xs font-semibold', tone.className.replace('border-[#FF4C4C]/35 bg-[#FF4C4C]/12 ', '').replace('border-[#00C853]/35 bg-[#00C853]/12 ', '').replace('border-[#FFA500]/35 bg-[#FFA500]/12 ', ''))}>
                            <span className="mr-1">{tone.icon}</span>
                            {reason}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="mt-4 flex gap-3">
                  <Button onClick={() => handleScan()} disabled={isPending || !emailText.trim()} className="flex-1 bg-sky-500 text-slate-950 hover:bg-sky-400">
                    Re-scan
                  </Button>
                  <Button onClick={handleDismiss} variant="outline" className="flex-1 border-white/12 bg-white/5 text-white hover:bg-white/10">
                    Dismiss
                  </Button>
                </div>
              </div>
            </div>
          </motion.aside>
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
          <motion.section
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.16 }}
            className="rounded-3xl border border-white/10 bg-slate-950/65 p-5 shadow-[0_16px_60px_rgba(2,6,23,0.32)] backdrop-blur-xl"
          >
            <div className="mb-4 flex items-center justify-between">
              <div>
                <p className="text-xs font-black uppercase tracking-[0.24em] text-slate-400">Operations</p>
                <h3 className="mt-1 text-xl font-bold text-white">Security posture at a glance</h3>
              </div>
              <Sparkles className="h-5 w-5 text-sky-300" />
            </div>

            <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-1">
              {topStats.map((stat) => (
                <div key={stat.label} className={cn('rounded-[18px] border p-4', stat.tone)}>
                  <p className="text-[11px] font-black uppercase tracking-[0.22em]">{stat.label}</p>
                  <p className="mt-2 text-3xl font-black text-white">{stat.value}</p>
                </div>
              ))}
            </div>

            <div className="mt-4 rounded-[18px] border border-white/10 bg-white/5 p-4">
              <p className="text-xs font-black uppercase tracking-[0.22em] text-slate-400">Model health</p>
              <div className="mt-3 grid grid-cols-2 gap-3 text-sm text-slate-200">
                <div>
                  <span className="block text-slate-400">Accuracy</span>
                  <strong>{Math.round((metrics?.accuracy ?? 0) * 100)}%</strong>
                </div>
                <div>
                  <span className="block text-slate-400">F1 score</span>
                  <strong>{Math.round((metrics?.f1Score ?? 0) * 100)}%</strong>
                </div>
              </div>
            </div>
          </motion.section>

          <motion.section
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.18 }}
            className="rounded-3xl border border-white/10 bg-slate-950/65 p-5 shadow-[0_16px_60px_rgba(2,6,23,0.32)] backdrop-blur-xl"
          >
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-black uppercase tracking-[0.24em] text-slate-400">Recent activity</p>
                <h3 className="mt-1 text-xl font-bold text-white">Latest scan history</h3>
              </div>
              <Button
                variant="ghost"
                onClick={() => clearHistory(undefined, { onSuccess: () => { refetchHistory(); refetchMetrics(); } })}
                className="text-slate-300 hover:bg-white/10 hover:text-white"
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Clear
              </Button>
            </div>

            {recentHistory.length === 0 ? (
              <div className="rounded-[18px] border border-dashed border-white/12 bg-white/5 px-4 py-8 text-center text-slate-300">
                <History className="mx-auto mb-3 h-5 w-5 text-slate-400" />
                Your premium activity feed will appear here after the first scan.
              </div>
            ) : (
              <div className="space-y-3">
                {recentHistory.map((item: any) => {
                  const rowState = getVisualState(item?.classification);
                  const rowCopy = getStateCopy(rowState);

                  return (
                    <div key={item.id} className="flex items-start justify-between gap-3 rounded-[18px] border border-white/10 bg-white/5 p-4">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className={cn('h-2.5 w-2.5 rounded-full', rowCopy.accent)} />
                          <p className="truncate text-sm font-semibold text-white">{item.emailPreview}</p>
                        </div>
                        <p className="mt-1 text-xs text-slate-400">{item.detectedLanguage?.toUpperCase?.() || 'EN'} · {item.reasonCount} signals</p>
                      </div>
                      <div className="text-right">
                        <Badge className={cn('border', rowCopy.surface, rowCopy.text)}>{rowCopy.badge}</Badge>
                        <p className="mt-2 text-sm font-black text-white">{Math.round(item.riskScore ?? 0)}/100</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </motion.section>
        </div>

        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mt-6 rounded-[22px] border border-sky-400/20 bg-sky-500/10 px-5 py-4 text-sm text-slate-100"
        >
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-sky-300" />
              <span className="font-semibold">Designed to feel premium, clean, and powerful at first glance.</span>
            </div>
            <span className="text-slate-300">Built for serious email security workflows.</span>
          </div>
        </motion.section>
      </div>
    </div>
  );
}
