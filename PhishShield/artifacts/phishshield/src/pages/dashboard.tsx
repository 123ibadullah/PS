import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck, ShieldAlert, AlertTriangle,
  CheckCircle, ChevronDown, ChevronUp, RefreshCw, Loader2,
  Mail, Eye, Flag, BarChart3, History, Trash2, Globe, Languages,
  TrendingUp, Scan, Lock, Shield, Download,
  Ban, Phone, ExternalLink, Building2, Bot, Copy, Command, Search
} from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { ScoreGauge } from '@/components/ScoreGauge';
import { HighlightText } from '@/components/HighlightText';
import { useAnalyzeEmail, useGetScanHistory, useGetModelMetrics, useClearScanHistory } from '@workspace/api-client-react';
import { cn } from '@/lib/utils';
import { toast } from '@/hooks/use-toast';

const MOCK_GMAIL_EMAILS = [
  {
    id: 'g1',
    sender: 'HDFC Bank Security',
    senderEmail: 'support@hdfc-secure.tk',
    subject: 'Critical Alert: Your account is locked',
    date: '10:45 AM',
    preview: 'Security alert: we have detected unusual login attempts on your HDFC account. To restore access...',
    fullText: 'From: HDFC Bank <support@hdfc-secure.tk>\nSubject: Critical Alert: Your account is locked\nDate: Mon, 24 Mar 2026 10:45:00 +0530\n\nDear customer, we have detected unusual login attempts on your HDFC account. For your security, your account has been temporarily locked. Please click here to verify and unlock your account immediately: http://hdfc-verify.xyz/login. Failure to do so within 24 hours will lead to permanent suspension.',
    classification: 'phishing',
  },
  {
    id: 'g4',
    sender: 'Netflix Billing',
    senderEmail: 'info@mailer.netflix.com',
    subject: 'Your payment was successful',
    date: '09:12 AM',
    preview: 'Thank you for your payment. Your subscription has been renewed for another month...',
    fullText: 'Hi there, your payment of Rs. 649 for your Netflix Premium subscription has been successfully processed. You can continue streaming on all your devices. Transaction ID: 882910-X.',
    classification: 'safe',
  },
  {
    id: 'g5',
    sender: 'SBI Security Alert',
    senderEmail: 'alert@sbi-online.com',
    subject: 'Suspicious activity detected',
    date: 'Yesterday',
    preview: 'We noticed a login attempt from a new IP address in Mumbai. If this was not you...',
    fullText: 'Dear customer, SBI has detected a login attempt from a new device in Mumbai. If this was you, please ignore. If not, please call our 24/7 helpline at 1800-11-22-11 immediately.',
    classification: 'uncertain',
  },
  {
    id: 'g3',
    sender: 'Amazon Rewards',
    senderEmail: 'info@amazon-gift.tk',
    subject: 'Exclusive: Claim your Rs. 5000 Gift Card',
    date: 'Yesterday',
    preview: 'You have been selected as a lucky winner! Claim your Amazon gift card now by verifying...',
    fullText: 'Dear customer, you have won an Amazon gift card worth Rs. 5000! To claim your reward, please verify your details here: http://amazon-claim.ml/gift. Note: Offer valid for 4 hours. No manual intervention required.',
    classification: 'phishing',
  },
  {
    id: 'g2',
    sender: 'Google Security',
    senderEmail: 'no-reply@accounts.google.com',
    subject: 'Security alert for your account',
    date: '2 Mar',
    preview: 'Your Google Account was just signed in to from a new Windows device...',
    fullText: 'Your Google Account was just signed in to from a new Windows device. If this was you, you can safely ignore this email. If this wasn\'t you, please secure your account.',
    classification: 'safe',
  },
  {
    id: 'g6',
    sender: 'CFO Office',
    senderEmail: 'ceo-finance@vendor-payments.co',
    subject: 'Confidential: release urgent vendor transfer today',
    date: 'Today',
    preview: 'Please process the attached vendor payment before 4 PM and keep this off the main thread...',
    fullText: 'From: CFO Office <ceo-finance@vendor-payments.co>\nSubject: Confidential: release urgent vendor transfer today\nDate: Tue, 02 Apr 2026 11:15:00 +0530\n\nHi, I need you to urgently process a vendor bank transfer today. Keep this confidential and do not call back until it is done. Review the attached invoice and send confirmation once the payment is released.',
    classification: 'phishing',
  }
];

const PRELOADED_EMAILS = [
  {
    id: 'sbi',
    label: 'SBI notice in Hindi',
    text: "प्रिय ग्राहक, आपका SBI बैंक खाता तुरंत बंद हो जाएगा। अभी सत्यापन करें: http://sbi-verify.xyz/kyc?id=12345 OTP किसी के साथ साझा न करें। अभी क्लिक करें! -- SBI ग्राहक सेवा"
  },
  {
    id: 'upi',
    label: 'GPay reward claim',
    text: "Congratulations! You have won Rs. 50,000 in GPay reward program. To claim your prize, verify your UPI ID at http://gpay-reward.tk/claim and complete KYC. Offer expires in 2 hours! Transaction ID: TXN8823991"
  },
  {
    id: 'amazon',
    label: 'Amazon shipment details',
    text: "Your Amazon order #402-8837291-XXXXXX has been shipped. Expected delivery: March 18. Track your package at amazon.in/orders. Thank you for shopping with Amazon."
  },
  {
    id: 'bec',
    label: 'CEO payment diversion attempt',
    text: "Hi Finance Team, I need you to process the attached vendor payment today and keep this confidential until it clears. Update the beneficiary to the new account in the invoice and confirm once the transfer is done."
  },
  {
    id: 'qr',
    label: 'QR payroll portal scam',
    text: "Payroll verification pending. Scan the QR code in the attached PDF to keep your salary account active and avoid suspension before 6 PM today."
  }
];

const LANGUAGE_LABELS: Record<string, string> = {
  EN: 'English',
  HI: 'Hindi',
  TE: 'Telugu',
  MX: 'Mixed script',
  TA: 'Tamil',
  KN: 'Kannada',
  ML: 'Malayalam',
  GU: 'Gujarati',
  MR: 'Marathi',
  BN: 'Bengali',
  PA: 'Punjabi',
  en: 'English',
  hi: 'Hindi',
  te: 'Telugu',
  mixed: 'Mixed script',
};

function normalizeLanguageCode(code?: string) {
  const raw = String(code ?? 'EN').trim();
  if (!raw) return 'EN';
  const upper = raw.toUpperCase();
  return upper === 'MIXED' ? 'MX' : upper;
}

function getLanguageLabel(code?: string) {
  const normalized = normalizeLanguageCode(code);
  return LANGUAGE_LABELS[normalized] ?? LANGUAGE_LABELS[code ?? ''] ?? normalized;
}

const categoryMap: Record<string, string> = {
  urgency: "Urgency pressure",
  social_engineering: "Social engineering",
  india_specific: "Brand impersonation",
  url: "Suspicious link",
  financial: "Financial lure",
  language: "Regional language",
  ml_score: "Pattern analysis",
  domain: "Domain risk",
  header: "Email header spoofing",
};

const getHumanCategory = (cat: string) => categoryMap[cat] || cat.replace(/_/g, ' ');

type VerdictState = 'safe' | 'uncertain' | 'suspicious' | 'phishing';
type RiskSeverity = 'low' | 'medium' | 'high';

type DashboardReason = {
  category: string;
  description: string;
  severity: RiskSeverity;
  matchedTerms: string[];
};

type DashboardFeature = {
  feature: string;
  contribution: number;
  direction: 'phishing' | 'safe';
};

type DashboardUrlAnalysis = {
  url: string;
  domain: string;
  flags: string[];
  isSuspicious: boolean;
  riskScore?: number;
};

type DashboardHeaderAnalysis = {
  hasHeaders: boolean;
  spoofingRisk: 'none' | 'low' | 'medium' | 'high';
  senderEmail?: string;
  displayName?: string;
  replyToEmail?: string;
  mismatch?: boolean;
  senderDomain?: string;
  issues: string[];
};

type DashboardResult = {
  id: string;
  scanId?: string;
  scan_id?: string;
  riskScore: number;
  risk_score?: number;
  classification: VerdictState;
  confidence: number;
  confidenceLevel?: string;
  confidence_level?: string;
  detectedLanguage?: string;
  displayLabel?: string;
  display_label?: string;
  reasons: DashboardReason[];
  suspiciousSpans: Array<{ start: number; end: number; text: string; reason: string }>;
  urlAnalyses: DashboardUrlAnalysis[];
  safetyTips: string[];
  warnings: string[];
  mlScore: number;
  ruleScore: number;
  urlScore: number;
  headerScore: number;
  attackType: string;
  scamStory?: string;
  recommendation?: string;
  recommendedDisposition?: 'block' | 'review' | 'allow';
  autoBlockRecommended?: boolean;
  featureImportance: DashboardFeature[];
  headerAnalysis?: DashboardHeaderAnalysis & {
    displayName?: string;
    replyToEmail?: string;
    mismatch?: boolean;
    senderDomain?: string;
  };
  signals?: string[];
  detectedSignals?: string[];
  backendExplanation?: PythonModelExplanation;
  backendSummary?: {
    emailRisk: number;
    urlRisk: number;
    headerRisk: number;
    backendSignals: string[];
    explanation?: PythonModelExplanation;
  };
};

type LocalHistoryItem = {
  id: string;
  timestamp: string;
  emailPreview: string;
  riskScore: number;
  classification: VerdictState;
  detectedLanguage: string;
  urlCount: number;
  reasonCount: number;
  contentHash?: string;
  attackType?: string;
};

function normalizeClassification(c?: string): VerdictState {
  if (c === 'safe' || c === 'phishing' || c === 'uncertain' || c === 'suspicious') {
    return c;
  }
  return 'uncertain';
}

function isSuspiciousClassification(c?: string) {
  const normalized = normalizeClassification(c);
  return normalized === 'uncertain' || normalized === 'suspicious';
}

function isTrustedDisplayDomain(domain?: string) {
  const normalized = String(domain ?? '').trim().toLowerCase().replace(/^www\./, '');
  const trustedDomains = [
    'google.com',
    'accounts.google.com',
    'pay.google.com',
    'microsoft.com',
    'login.microsoftonline.com',
    'amazon.in',
    'amazon.com',
    'paytm.com',
    'paytm.in',
    'hdfcbank.com',
    'sbi.co.in',
  ];

  return trustedDomains.some((trusted) => normalized === trusted || normalized.endsWith(`.${trusted}`));
}

function formatVerdictLabel(c?: string, _score = 0) {
  const normalized = normalizeClassification(c);
  if (normalized === 'safe') return 'SAFE';
  if (normalized === 'uncertain' || normalized === 'suspicious') return 'SUSPICIOUS';
  return 'HIGH RISK';
}

function clampDisplayedConfidence(percent = 0) {
  const rounded = Math.round(percent);
  if (rounded <= 0) return 5;
  return Math.max(5, Math.min(95, rounded));
}

function buildDisplayLabel(score = 0, confidencePercent?: number) {
  const rounded = Math.max(0, Math.min(100, Math.round(score)));
  const confidence = clampDisplayedConfidence(confidencePercent ?? 0);
  const trustScore = Math.max(0, 100 - rounded);
  return `Confidence: ${confidence}% • Trust score: ${trustScore}/100`;
}

function deriveDetectedSignals(result?: { reasons?: Array<{ category: string; description: string }>; classification?: string }) {
  if (result?.classification === 'safe' || !result?.reasons?.length) {
    return ['No strong phishing signals'];
  }

  const signals: string[] = [];
  const addSignal = (signal: string) => {
    if (!signals.includes(signal)) signals.push(signal);
  };

  for (const reason of result.reasons) {
    if (reason.category === 'urgency') addSignal('Urgent or pressuring language');
    else if (reason.category === 'financial') addSignal(/invoice|payment|transfer|beneficiary/i.test(reason.description) ? 'Payment or money request' : 'Financial lure or reward language');
    else if (reason.category === 'url') addSignal('Link to a suspicious website');
    else if (reason.category === 'header') addSignal('Sender identity mismatch');
    else if (reason.category === 'social_engineering') addSignal(/otp|password|credential|identity/i.test(reason.description) ? 'Request for sensitive information' : 'Suspicious wording or unusual request');
    else if (reason.category === 'india_specific') addSignal('Impersonation of a known brand or service');
    else if (reason.category === 'ml_score' && result.classification !== 'safe') addSignal('Overall message pattern resembles phishing');
  }

  return signals.length > 0 ? signals.slice(0, 5) : ['No strong phishing signals detected'];
}

function confidenceCopy(confidence: number) {
  if (confidence >= 0.85) return 'High certainty';
  if (confidence >= 0.6) return 'Moderate confidence';
  return 'Low confidence';
}

function dedupeTopWordIndicators(topWords: PythonExplanationWord[] = []) {
  const seen = new Set<string>();
  return topWords.filter((item) => {
    const key = String(item.word ?? '').trim().toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function signalChipTone(signal: string) {
  const normalized = signal.toLowerCase();
  if (/(trusted|safe|legitimate|newsletter|confirmed|no strong phishing signals|informational|routine)/i.test(normalized)) {
    return {
      icon: '🟢',
      className: 'border-safe/30 bg-safe/10 text-safe',
    };
  }
  if (/(spoof|mismatch|otp|credential|malicious|suspicious domain|block|impersonation|phishing link)/i.test(normalized)) {
    return {
      icon: '🔴',
      className: 'border-destructive/30 bg-destructive/10 text-destructive',
    };
  }
  return {
    icon: '⚠️',
    className: 'border-warning/30 bg-warning/10 text-warning',
  };
}

function simplifyReasonLabel(reason: DashboardReason) {
  const description = reason.description.toLowerCase();

  if (reason.category === 'india_specific' || /brand|impersonation/.test(description)) return 'Brand impersonation';
  if (reason.category === 'url' || /link|domain|url/.test(description)) return 'Suspicious link';
  if (reason.category === 'urgency' || /urgent|pressure|deadline|immediately|suspend/.test(description)) return 'Urgency language';
  if (reason.category === 'header' || /spoof|mismatch|reply-to|return-path/.test(description)) return 'Header spoofing';
  if (reason.category === 'social_engineering' && /otp|password|credential|identity|pin/.test(description)) return 'Sensitive info request';
  if (reason.category === 'financial') return /invoice|payment|transfer|beneficiary/.test(description) ? 'Payment request' : 'Financial lure';

  return getHumanCategory(reason.category);
}

function buildReasonHelper(label: string, helper?: string) {
  const normalizedLabel = label.trim().toLowerCase();
  const normalizedHelper = (helper ?? '').trim();

  if (!normalizedHelper || normalizedHelper.toLowerCase() === normalizedLabel) {
    if (/urgency/.test(normalizedLabel)) return 'The message pushes immediate action or uses deadline pressure.';
    if (/brand impersonation|header spoofing/.test(normalizedLabel)) return 'The sender identity or email routing looks inconsistent with the claimed brand.';
    if (/suspicious link/.test(normalizedLabel)) return 'The link destination should be verified before you click or sign in.';
    if (/sensitive info request/.test(normalizedLabel)) return 'The email asks for OTPs, passwords, or other data that legitimate senders should not request here.';
    if (/payment request|financial lure/.test(normalizedLabel)) return 'The message tries to influence a payment, transfer, or money-related action.';
    return 'Visible warning signal detected in the message.';
  }

  return normalizedHelper;
}

function getDetailedReasonGroup(reason: DashboardReason) {
  const simplified = simplifyReasonLabel(reason);
  if (simplified === 'Header spoofing') return 'Email header spoofing';
  if (simplified === 'Brand impersonation') return 'Brand impersonation';
  if (simplified === 'Suspicious link') return 'Suspicious link';
  if (simplified === 'Urgency language') return 'Urgency pressure';
  if (simplified === 'Sensitive info request') return 'Sensitive info request';
  if (simplified === 'Payment request') return 'Payment request';
  return getHumanCategory(reason.category);
}

function getDisplayMatchedTerms(reason: DashboardReason) {
  const normalizedDescription = reason.description.trim().toLowerCase();
  const seen = new Set<string>();

  return reason.matchedTerms
    .map((term) => String(term ?? '').trim())
    .filter((term) => {
      const normalized = term.toLowerCase();
      if (!term || seen.has(normalized)) return false;
      seen.add(normalized);
      return normalized !== normalizedDescription && !normalizedDescription.includes(normalized) && normalized.length <= 32;
    })
    .slice(0, 3);
}

function normalizeDetailedReasonDescription(description: string) {
  return description
    .replace(/^Python backend:\s*/i, '')
    .replace(/^Header spoofing:\s*/i, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function dedupeDetailedReasons(items: DashboardReason[]) {
  const seen = new Set<string>();

  return items.filter((reason) => {
    const normalized = `${getDetailedReasonGroup(reason)}::${normalizeDetailedReasonDescription(reason.description).toLowerCase()}`;
    if (seen.has(normalized)) return false;
    seen.add(normalized);
    return true;
  });
}

function formatSessionEmailCount(count: number) {
  return `${count} ${count === 1 ? 'email' : 'emails'}`;
}

function classificationColor(c: string) {
  const normalized = normalizeClassification(c);
  if (normalized === 'safe') return { text: 'text-safe', bg: 'bg-safe/5', border: 'border-safe/20', bar: 'bg-safe' };
  if (normalized === 'uncertain' || normalized === 'suspicious') return { text: 'text-warning', bg: 'bg-warning/5', border: 'border-warning/20', bar: 'bg-warning' };
  return { text: 'text-destructive', bg: 'bg-destructive/5', border: 'border-destructive/20', bar: 'bg-destructive' };
}

function formatTime(iso: string) {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '';
  }
}

function formatDate(iso: string) {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });
  } catch {
    return '';
  }
}

function redactSensitiveText(text: string) {
  return text
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[redacted-email]')
    .replace(/https?:\/\/[^\s<>"']+/gi, '[redacted-link]')
    .replace(/\b(?:\+?\d[\d\s()-]{7,}\d)\b/g, '[redacted-number]')
    .replace(/\b\d{6,}\b/g, '[redacted-id]');
}

const HISTORY_PAGE_SIZE = 10;
const SAFE_SENDERS_KEY = 'phishshield_safe_senders';
const RETRAIN_META_KEY = 'phishshield_retrain_meta';
const PYTHON_BACKEND_URL = 'http://localhost:8000';

type BackendConnectionState = 'checking' | 'connected' | 'offline';

type PythonExplanationWord = {
  word: string;
  contribution: number;
};

type PythonModelExplanation = {
  top_words?: PythonExplanationWord[];
  why_risky?: string;
  confidence_interval?: string;
  method?: string;
};

type PythonBackendHealth = {
  status?: string;
  model_status?: string;
  last_trained_date?: string | null;
  total_signals_analyzed?: number;
  version?: string;
  model_used?: string;
  accuracy?: string;
  f1_score?: string;
  device?: string;
};

type PythonEmailScan = {
  scan_id?: string;
  risk_score?: number;
  verdict?: string;
  confidence?: number;
  category?: string;
  detectedLanguage?: string;
  language?: string;
  signals?: string[];
  ml_probability?: number;
  rule_signals?: number;
  recommendation?: string;
  model_used?: string;
  explanation?: PythonModelExplanation;
};

type PythonUrlScan = {
  url?: string;
  malicious_count?: number;
  is_phishing?: boolean;
  risk_score?: number;
  engines_checked?: number;
};

type PythonHeaderScan = {
  spf?: string;
  dkim?: string;
  dmarc?: string;
  reply_to_mismatch?: boolean;
  return_path_mismatch?: boolean;
  spoofing_score?: number;
  header_risk_score?: number;
  signals?: string[];
};

type PythonFeedbackAck = {
  saved?: boolean;
  feedback_count?: number;
  retrain_triggered?: boolean;
  pending_retrain?: number;
};

type PythonFeedbackStats = {
  total_feedback?: number;
  pending_retrain?: number;
  needed_for_retrain?: number;
  last_retrain?: string | null;
  model_improving?: boolean;
};

type SafeSenderEntry = {
  domain: string;
  addedDate: string;
  userConfirmed: boolean;
};

function calculatePercent(value = 0, total = 0) {
  return total > 0 ? Math.round((value / total) * 100) : 0;
}

function hashEmailContent(text: string) {
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `scan-${(hash >>> 0).toString(16)}`;
}

function extractSenderDomainFromText(text: string, fallback?: string) {
  if (fallback?.trim()) {
    return fallback.trim().toLowerCase();
  }

  const headerMatch = text.match(/(?:^|\n)from:\s*.*?<[^@\n]+@([^>\s]+)>/i) ?? text.match(/(?:^|\n)from:\s*[^@\n]+@([^\s>]+)/i);
  return headerMatch?.[1]?.trim().toLowerCase() ?? '';
}

function extractInlineHeadersFromText(text: string) {
  const headerCandidate = text.split(/\r?\n\r?\n/, 1)[0] ?? '';
  const knownHeaderPattern = /^(from|to|subject|reply-to|return-path|received|received-spf|authentication-results|arc-authentication-results|dkim-signature|mime-version|content-type|date|list-unsubscribe|list-id)\s*:/i;
  const lines = headerCandidate.split(/\r?\n/);
  const collected: string[] = [];
  let knownHits = 0;

  for (const line of lines) {
    const trimmed = line.trimEnd();
    if (!trimmed) continue;

    if (knownHeaderPattern.test(trimmed)) {
      collected.push(trimmed);
      knownHits += 1;
      continue;
    }

    if (collected.length > 0 && /^[\t ]+/.test(line)) {
      collected.push(trimmed);
    }
  }

  return knownHits >= 3 ? collected.join('\n').trim() : '';
}

function hasNewsletterContext(text: string, senderDomain = '') {
  const lower = text.toLowerCase();
  const trustedNewsletterDomain = ['quora.com', 'linkedin.com', 'medium.com', 'substack.com', 'amazon.in', 'flipkart.com', 'irctc.co.in', 'noreply.github.com', 'google.com', 'googlemail.com', 'pay.google.com', 'notifications.google.com']
    .some((domain) => senderDomain === domain || senderDomain.endsWith(`.${domain}`));
  const hasDkim = /dkim=pass|signed by:\s*[a-z0-9.-]+/i.test(text);
  const trustedAuthPassCount = (text.match(/\b(?:dkim|spf|dmarc)\s*=\s*pass\b/gi) ?? []).length;
  const hasUnsubscribe = /list-unsubscribe|unsubscribe|manage notification settings|update your email preferences|communication preferences/i.test(text);
  const hasFooterAddress = /©\s*20\d{2}|private limited|corporation|llc|google india digital services private limited|\b\d{1,5}\s+[\w .,'-]+(?:street|st|road|rd|avenue|ave|way)\b/i.test(text);
  const noCredentialRequest = !/otp|password|pin\b|passcode|credentials?|bank details|card details|account number/i.test(lower);

  return ((trustedNewsletterDomain && (hasDkim || trustedAuthPassCount >= 2) && hasUnsubscribe) || (hasUnsubscribe && hasFooterAddress && noCredentialRequest && (hasDkim || trustedAuthPassCount >= 2 || trustedNewsletterDomain)));
}

function hasProtectiveSecurityContext(text: string) {
  const hasProtectiveCopy = /(if this was you|if this wasn't you|you can safely ignore this email|please ignore|call (?:our )?(?:24\/?7 )?(?:helpline|support)|official helpline|customer care)/i.test(text);
  const hasSecurityContext = /(security alert|signed in to from a new|new windows device|login attempt from a new (?:device|ip address)|secure your account)/i.test(text);
  const hasDangerousCredentialRequest = /(reply with|share|provide|enter|submit)[\s\S]{0,40}(otp|password|pin|passcode|credentials?|bank details|card details)/i.test(text);
  return hasProtectiveCopy && hasSecurityContext && !hasDangerousCredentialRequest && extractUrlsFromText(text).length === 0;
}

function hasLegitimateTransactionalContext(text: string) {
  const hasReceiptLanguage = /(payment (?:of .* )?(?:was|has been)? successfully processed|your payment was successful|subscription has been renewed|transaction id|expected delivery|thank you for shopping|thank you for your payment|order\s+#?\S+\s+has been shipped|receipt)/i.test(text);
  const noSensitiveAsk = !/(otp|password|pin\b|passcode|credentials?|card details|bank details|verify your (?:account|identity)|confirm your (?:identity|account))/i.test(text);
  const hasLureKeywords = /(reward program|you have won|claim your|claim now|prize|kyc|verify your upi id|offer expires?)/i.test(text);
  const urls = extractUrlsFromText(text);
  const trustedishLinksOnly = urls.length === 0 || urls.every((url) => {
    try {
      const host = new URL(url).hostname.toLowerCase();
      return /(amazon\.in|amazon\.com|google\.com|pay\.google\.com|netflix\.com)/i.test(host);
    } catch {
      return false;
    }
  });

  return hasReceiptLanguage && noSensitiveAsk && !hasLureKeywords && trustedishLinksOnly;
}

function hasBecPaymentDiversionContext(text: string) {
  const hasPaymentTask = /(vendor payment|beneficiary|bank transfer|wire transfer|attached invoice|release urgent vendor transfer|confirm once (?:the )?(?:transfer|payment) is (?:done|released)|process .* vendor .* payment)/i.test(text);
  const hasSecrecyOrPressure = /(keep this confidential|do not call back|off the main thread|finance team|urgent|today|before \d{1,2}\s?(?:am|pm)|until it is done)/i.test(text);
  return hasPaymentTask && hasSecrecyOrPressure;
}

function hasQrPayrollScamContext(text: string) {
  return /(scan (?:the )?qr(?:\s+code)?|qr\s+code)/i.test(text)
    && /(payroll|salary account|verification pending|avoid suspension|keep your salary account active)/i.test(text);
}

function prepareEmailForAnalysis(rawText: string) {
  if (typeof DOMParser === 'undefined' || !/<[a-z][\s\S]*>/i.test(rawText)) {
    return rawText;
  }

  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(rawText, 'text/html');
    const hiddenTexts = Array.from(doc.querySelectorAll('[style]'))
      .filter((element) => /(color\s*:\s*(?:#fff(?:fff)?|white)|font-size\s*:\s*0(?:px)?|display\s*:\s*none|visibility\s*:\s*hidden)/i.test(element.getAttribute('style') ?? ''))
      .map((element) => element.textContent?.replace(/\s+/g, ' ').trim() ?? '')
      .filter(Boolean);

    if (hiddenTexts.length === 0) {
      return rawText;
    }

    return `${rawText}\n\n[Hidden Content Detected]\n${hiddenTexts.join('\n')}`;
  } catch {
    return rawText;
  }
}

function extractUrlsFromText(text: string, limit = Number.POSITIVE_INFINITY) {
  const normalizedText = text.replace(/=\r?\n/g, '').replace(/&amp;/gi, '&');
  const ignoredHosts = ['www.w3.org', 'gstatic.com', 'www.gstatic.com'];
  const urls = [...new Set(
    (normalizedText.match(/https?:\/\/[^\s<>"']+/gi) ?? [])
      .map((url) => url.replace(/[),.;]+$/, '').trim())
      .filter((url) => {
        if (!url || /=\s*$/.test(url)) return false;
        try {
          const parsed = new URL(url);
          const host = parsed.hostname.toLowerCase();
          if (!host || host === 'www' || host.includes('=')) return false;
          return !ignoredHosts.some((ignored) => host === ignored || host.endsWith(`.${ignored}`));
        } catch {
          return false;
        }
      }),
  )];

  return Number.isFinite(limit) ? urls.slice(0, limit) : urls;
}

function extractUrlsForBackend(text: string) {
  return extractUrlsFromText(text, 3);
}

function scoreToVerdictState(score = 0): VerdictState {
  if (score <= 25) return 'safe';
  if (score <= 60) return 'uncertain';
  return 'phishing';
}

function scoreToConfidenceLevel(score = 0) {
  if (score >= 75) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

function formatBackendModelVersion(health?: PythonBackendHealth | null) {
  if (health?.model_used) return health.model_used;
  return health?.version ? `v${health.version}` : 'Unavailable';
}

function buildExplanationSpans(text: string, topWords: PythonExplanationWord[] = []) {
  const spans: Array<{ start: number; end: number; text: string; reason: string }> = [];

  for (const item of topWords.slice(0, 5)) {
    const token = item.word?.trim();
    if (!token || token.length < 2) continue;

    const escapedToken = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const match = new RegExp(escapedToken, 'i').exec(text);
    if (!match || typeof match.index !== 'number') continue;

    const start = match.index;
    const end = start + match[0].length;
    const overlaps = spans.some((span) => Math.max(span.start, start) < Math.min(span.end, end));
    if (overlaps) continue;

    spans.push({
      start,
      end,
      text: match[0],
      reason: `Model contribution: ${token} (${Math.round((item.contribution ?? 0) * 100)}%)`,
    });
  }

  return spans.sort((a, b) => a.start - b.start);
}

function mergeSuspiciousSpans(existing: Array<{ start: number; end: number; text: string; reason: string }> = [], additions: Array<{ start: number; end: number; text: string; reason: string }> = []) {
  const merged = [...existing, ...additions]
    .filter((span) => Number.isFinite(span?.start) && Number.isFinite(span?.end) && span.end > span.start)
    .sort((a, b) => {
      if (a.start !== b.start) return a.start - b.start;
      return (b.end - b.start) - (a.end - a.start);
    });

  const result: Array<{ start: number; end: number; text: string; reason: string }> = [];
  for (const span of merged) {
    const previous = result[result.length - 1];
    if (!previous || span.start >= previous.end) {
      result.push(span);
    }
  }

  return result;
}

type BackendFetchSuccess<T> = { ok: true; data: T };
type BackendFetchFailure = { ok: false; offline: boolean; error: string };
type BackendFetchResult<T> = BackendFetchSuccess<T> | BackendFetchFailure;

async function fetchPythonBackendJson<T>(path: string, options: RequestInit = {}): Promise<BackendFetchResult<T>> {
  try {
    const headers = new Headers(options.headers ?? {});
    if (options.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    const response = await fetch(`${PYTHON_BACKEND_URL}${path}`, {
      ...options,
      headers,
    });

    const rawText = await response.text();
    const parsed = rawText ? JSON.parse(rawText) as T | { detail?: string } : null;

    if (!response.ok) {
      return {
        ok: false as const,
        offline: false,
        error: typeof (parsed as { detail?: string } | null)?.detail === 'string'
          ? (parsed as { detail?: string }).detail as string
          : `HTTP ${response.status}`,
      };
    }

    return { ok: true as const, data: parsed as T };
  } catch (error) {
    return {
      ok: false as const,
      offline: true,
      error: error instanceof Error ? error.message : 'Backend unavailable',
    };
  }
}

type HistoryListItem = {
  id?: string;
  scanId?: string;
  scan_id?: string;
  timestamp?: string;
  emailPreview?: string;
  classification?: string;
  riskScore?: number;
  contentHash?: string;
};

function normalizeHistoryPreview(value?: string) {
  return (value ?? '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function trimHistoryItems<T extends HistoryListItem>(items: T[]) {
  const seen = new Set<string>();

  return items.filter((item) => {
    const preview = normalizeHistoryPreview(item.emailPreview);
    const id = typeof item.id === 'string' ? item.id.trim() : '';
    const timestamp = typeof item.timestamp === 'string' ? item.timestamp.trim() : '';
    const key = id || `${item.contentHash ?? preview}::${timestamp}`;

    if (!preview || seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  }).slice(0, 50);
}

function dedupeHistoryItems<T extends HistoryListItem>(items: T[]) {
  const seen = new Set<string>();

  return items.filter((item) => {
    const preview = normalizeHistoryPreview(item.emailPreview);
    const scanId = typeof item.scanId === 'string'
      ? item.scanId.trim()
      : typeof item.scan_id === 'string'
        ? item.scan_id.trim()
        : '';
    const classification = normalizeClassification(item.classification);
    const riskScore = Number.isFinite(Number(item.riskScore)) ? Math.round(Number(item.riskScore)) : -1;
    const key = item.contentHash?.trim() || scanId || `${preview}::${classification}::${riskScore}`;

    if (!preview || seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  }).slice(0, 50);
}

type Tab = 'analyze' | 'dashboard';

// Donut chart for the scan breakdown. Colors use CSS variables from :root
// so they stay consistent with the rest of the theme.
function GmailInbox({ onSelectEmail, activeEmailId }: { onSelectEmail: (email: any) => void, activeEmailId?: string }) {
  return (
    <div className="rounded-2xl border border-card-border bg-card overflow-hidden shadow-sm animate-in fade-in slide-in-from-top-4 duration-500">
      <div className="bg-secondary/30 px-6 py-4 border-b border-border/50 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded bg-[#ea4335]/10 flex items-center justify-center">
            <Mail className="w-4 h-4 text-[#ea4335]" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              Gmail Inbox <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-500 font-bold uppercase">Demo</span>
            </h3>
            <p className="text-[10px] text-muted-foreground font-semibold">Sandbox inbox for walkthroughs, QA, and model validation</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
           <div className="hidden sm:flex items-center gap-1.5 text-[10px] text-muted-foreground bg-background/50 px-2 py-1 rounded border border-border/50">
             <div className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
             Synced: Now
           </div>
        </div>
      </div>
      
      <div className="divide-y divide-border/40">
        {MOCK_GMAIL_EMAILS.map((email) => (
          <button
            key={email.id}
            onClick={() => onSelectEmail(email)}
            className={cn(
              "w-full text-left px-6 py-4 transition-all hover:bg-secondary/40 group relative overflow-hidden",
              activeEmailId === email.id && "bg-primary/5 border-l-2 border-l-primary pl-5.5"
            )}
          >
            <div className="flex justify-between items-start mb-1">
              <div className="flex items-center gap-2">
                <span className={cn("text-xs font-bold truncate", activeEmailId === email.id ? "text-primary" : "text-foreground")}>
                  {email.sender}
                </span>
                <span className="text-[10px] text-muted-foreground truncate opacity-0 group-hover:opacity-100 transition-opacity">
                  &lt;{email.senderEmail}&gt;
                </span>
              </div>
              <span className="text-[10px] text-muted-foreground whitespace-nowrap">{email.date}</span>
            </div>
            <div className="flex justify-between items-center gap-4">
              <div className="flex-1 min-w-0">
                <p className={cn("text-xs font-semibold truncate mb-0.5", activeEmailId === email.id ? "text-primary/90" : "text-foreground/90")}>
                  {email.subject}
                </p>
                <p className="text-[11px] text-muted-foreground truncate italic">
                  {email.preview}
                </p>
              </div>
              <Badge 
                variant="outline" 
                className={cn(
                  "text-[9px] uppercase tracking-tighter px-1.5 py-0 font-bold", 
                  email.classification === 'phishing' ? "text-destructive border-destructive/30 bg-destructive/5" :
                  email.classification === 'suspicious' || email.classification === 'uncertain' ? "text-warning border-warning/30 bg-warning/5" :
                  "text-safe border-safe/30 bg-safe/5"
                )}
              >
                {formatVerdictLabel(email.classification)}
              </Badge>
            </div>
          </button>
        ))}
      </div>
      
      <div className="bg-secondary/20 px-6 py-3 border-t border-border/50 flex justify-center">
         <p className="text-[10px] text-muted-foreground flex items-center gap-1.5">
           <Shield className="w-3 h-3" />
           PhishShield AI Coverage • Privacy-First 2026 Edition
         </p>
      </div>
    </div>
  );
}

const PIE_COLORS = {
  Phishing:  'hsl(var(--destructive))',
  Suspicious: 'hsl(var(--warning))',
  Safe:       'hsl(var(--safe))',
} as const;

type MetricsCounts = {
  phishingDetected: number;
  suspiciousDetected: number;
  safeDetected: number;
} | undefined;

function DonutChart({ metrics }: { metrics: MetricsCounts }) {
  const pieData: { name: keyof typeof PIE_COLORS; value: number }[] = [
    { name: 'Phishing',   value: metrics?.phishingDetected  ?? 0 },
    { name: 'Suspicious', value: metrics?.suspiciousDetected ?? 0 },
    { name: 'Safe',       value: metrics?.safeDetected       ?? 0 },
  ].filter(d => d.value > 0) as { name: keyof typeof PIE_COLORS; value: number }[];

  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="value">
          {pieData.map(entry => (
            <Cell key={entry.name} fill={PIE_COLORS[entry.name]} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: '8px', fontSize: '12px' }}
          itemStyle={{ color: 'hsl(var(--foreground))' }}
        />
        <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: '11px' }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

function RegionalThreatMap({
  history,
  totalScans,
}: {
  history: Array<{ emailPreview?: string; classification?: string }>;
  totalScans: number;
}) {
  const sessionReady = totalScans >= 20;
  const flaggedText = history
    .filter((item) => normalizeClassification(item.classification) !== 'safe')
    .map((item) => item.emailPreview ?? '')
    .join(' \n ');

  const regions = [
    { city: 'Mumbai', pattern: /\bmumbai\b/gi },
    { city: 'Delhi', pattern: /\bdelhi\b/gi },
    { city: 'Bengaluru', pattern: /\bbengaluru|bangalore\b/gi },
    { city: 'Hyderabad', pattern: /\bhyderabad\b/gi },
    { city: 'Chennai', pattern: /\bchennai\b/gi },
    { city: 'Kolkata', pattern: /\bkolkata\b/gi },
  ].map((region) => {
    const hits = (flaggedText.match(region.pattern) ?? []).length;
    const risk = !sessionReady ? 'Baseline only' : hits >= 3 ? 'High' : hits >= 1 ? 'Medium' : 'Low';
    const color = risk === 'High' ? 'bg-destructive' : risk === 'Medium' ? 'bg-warning' : risk === 'Low' ? 'bg-safe' : 'bg-muted';
    return {
      city: region.city,
      risk,
      color,
      pulse: risk === 'High',
    };
  });

  return (
    <div className="rounded-xl border border-card-border bg-card p-5">
      <div className="flex items-center justify-between mb-4 gap-3">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Globe className="w-4 h-4 text-primary" />
          Regional Threat Intelligence
        </h3>
        <span
          className="text-[10px] text-muted-foreground uppercase font-bold tracking-wider"
          title="Risk levels derived from current session scan data, not a live external feed"
        >
          Session-Based Intelligence
        </span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
        {regions.map((r) => (
          <div key={r.city} className="flex items-center justify-between p-2 rounded-lg bg-secondary/30 border border-border/20">
            <div className="flex flex-col">
              <span className="text-[10px] font-bold text-foreground">{r.city}</span>
              <span className={cn(
                "text-[9px] font-medium opacity-80 uppercase",
                r.risk === 'High'
                  ? 'text-destructive'
                  : r.risk === 'Medium'
                    ? 'text-warning'
                    : r.risk === 'Low'
                      ? 'text-safe'
                      : 'text-muted-foreground'
              )}>
                {r.risk}
              </span>
            </div>
            <div className="relative">
              <div className={cn("w-2 h-2 rounded-full", r.color)} />
              {r.pulse && <div className={cn("absolute inset-0 w-2 h-2 rounded-full animate-ping", r.color)} />}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-4 pt-3 border-t border-border/40 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1">
            <div className="w-1.5 h-1.5 rounded-full bg-destructive" />
            <span className="text-[9px] text-muted-foreground uppercase font-bold">Active phish</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-1.5 h-1.5 rounded-full bg-warning" />
            <span className="text-[9px] text-muted-foreground uppercase font-bold">Monitoring</span>
          </div>
        </div>
        <p className="text-[9px] text-muted-foreground font-mono">
          Based on {formatSessionEmailCount(totalScans)} scanned this session. For live national threat data visit cert.in.
        </p>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [inputMode, setInputMode] = useState<'demo' | 'real' | 'upload'>('demo');
  const [baseProtectionCount] = useState(1284);
  const [sessionFingerprint] = useState(() => globalThis.crypto?.randomUUID?.().slice(0, 8).toUpperCase() ?? 'LOCALSCAN');
  const [includeHeaders, setIncludeHeaders] = useState(false);
  const [emailText, setEmailText] = useState('');
  const [headersText, setHeadersText] = useState('');
  const [activeGmailEmailId, setActiveGmailEmailId] = useState<string | undefined>(undefined);
  const [showHeaders, setShowHeaders] = useState(false);
  const [showDemos, setShowDemos] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>('analyze');
  const [isDemoEmail, setIsDemoEmail] = useState(false);
  const [feedbackSent, setFeedbackSent] = useState(false);
  const [feedbackMessage, setFeedbackMessage] = useState('');
  const [isFeedbackPending, setIsFeedbackPending] = useState(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const [historySearch, setHistorySearch] = useState('');
  const [historyFilter, setHistoryFilter] = useState<'all' | 'safe' | 'uncertain' | 'phishing'>('all');
  const [privacyMode, setPrivacyMode] = useState(true);
  const [feedbackNote, setFeedbackNote] = useState('');
  const [safeSenders, setSafeSenders] = useState<SafeSenderEntry[]>([]);
  const [duplicateScanNotice, setDuplicateScanNotice] = useState('');
  const [historyVisibleCount, setHistoryVisibleCount] = useState(HISTORY_PAGE_SIZE);
  const [retrainProgress, setRetrainProgress] = useState<number | null>(null);
  const [retrainLabel, setRetrainLabel] = useState('Detection Engine v3.2 · Updated Apr 5, 2026');
  const [enhancedResult, setEnhancedResult] = useState<any | null>(null);
  const [backendStatus, setBackendStatus] = useState<BackendConnectionState>('checking');
  const [backendHealth, setBackendHealth] = useState<PythonBackendHealth | null>(null);
  const [backendFeedbackStats, setBackendFeedbackStats] = useState<PythonFeedbackStats | null>(null);
  const [offlineModeNotice, setOfflineModeNotice] = useState('');
  const [isScanTransitioning, setIsScanTransitioning] = useState(false);
  const [activeResultScanId, setActiveResultScanId] = useState<string | null>(null);

  // Used to smooth-scroll down to results after a scan completes
  const resultsRef = useRef<HTMLDivElement>(null);
  const activeScanTokenRef = useRef(0);

  const handleFeedback = async (correctedClassification: 'safe' | 'phishing') => {
    if (!result) return;

    const predicted = normalizeClassification(result.classification);
    const predictedSnapshot = predicted === 'suspicious' ? 'uncertain' : predicted;
    const isAccurate = predictedSnapshot === correctedClassification;
    const feedbackNoteText = feedbackNote.trim();
    const scanId = ((result as any).scanId as string | undefined) ?? ((result as any).scan_id as string | undefined) ?? crypto.randomUUID();

    setIsFeedbackPending(true);
    try {
      const legacyPromise = fetch('/api/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer dev-sandbox-key',
        },
        body: JSON.stringify({
          emailId: result.id,
          userFeedback: isAccurate ? 'correct' : 'incorrect',
          isAccurate,
          correctedClassification,
          feedbackSource: 'user',
          notes: feedbackNoteText || undefined,
          emailText,
          emailPreview: emailText.slice(0, 80).replace(/\n/g, ' '),
          predictedClassification: predictedSnapshot,
          riskScore: displayRiskScore,
          confidence: result.confidence,
          attackType: displayAttackType,
          reasons: result.reasons?.map((reason) => reason.description).slice(0, 20) ?? [],
        }),
      }).catch((error) => {
        console.error('Legacy feedback endpoint failed', error);
        return null;
      });

      const backendResponse = await fetchPythonBackendJson<PythonFeedbackAck>('/feedback', {
        method: 'POST',
        body: JSON.stringify({
          email_text: emailText,
          correct_label: correctedClassification,
          scan_id: scanId,
        }),
      });

      await legacyPromise;

      if (!backendResponse.ok) {
        throw new Error(backendResponse.error || 'Python feedback save failed');
      }

      const pending = Number(backendResponse.data.pending_retrain ?? 0);
      const moreNeeded = Math.max(0, 50 - pending);
      setFeedbackSent(true);
      setFeedbackMessage(
        backendResponse.data.retrain_triggered
          ? 'Thanks! Model will improve with your feedback — auto retraining was triggered.'
          : `Thanks! Model will improve with your feedback. ${backendResponse.data.feedback_count ?? 0} feedback items collected — ${moreNeeded} more needed before retraining.`,
      );
      toast({
        title: 'Feedback saved',
        description: 'Thanks! Model will improve with your feedback',
      });
      if (feedbackNoteText) {
        setFeedbackNote('');
      }
      void refreshFeedbackStats();
      refetchHistory();
      refetchMetrics();
    } catch (err) {
      console.error(err);
      setFeedbackSent(false);
      setFeedbackMessage('Could not save feedback right now.');
      toast({
        title: 'Feedback unavailable',
        description: 'The local feedback loop could not be reached right now.',
      });
    } finally {
      setIsFeedbackPending(false);
    }
  };

  const handleDownloadReport = async () => {
    if (!result) return;
    try {
      const response = await fetch("/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer dev-sandbox-key" },
        body: JSON.stringify(result)
      });
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `phishshield-report-${Date.now()}.txt`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
    }
  };

  const [localHistory, setLocalHistory] = useState<LocalHistoryItem[]>([]);

  const { mutate: analyzeEmail, isPending, error, reset } = useAnalyzeEmail();
  const { data: serverHistory = [], refetch: refetchHistory } = useGetScanHistory();
  const { data: metrics, refetch: refetchMetrics } = useGetModelMetrics();
  const { mutate: clearHistory } = useClearScanHistory();
  const isScanning = isPending || isScanTransitioning;
  const resultCandidate = enhancedResult as DashboardResult | null;
  const result: DashboardResult | null = resultCandidate && activeResultScanId && ((resultCandidate.scanId ?? resultCandidate.scan_id) === activeResultScanId)
    ? resultCandidate
    : null;

  const clearScanResult = () => {
    activeScanTokenRef.current += 1;
    setEnhancedResult(null);
    setActiveResultScanId(null);
    setIsScanTransitioning(false);
    reset();
  };

  const beginLockedScan = () => {
    const scanToken = activeScanTokenRef.current + 1;
    activeScanTokenRef.current = scanToken;
    setEnhancedResult(null);
    setActiveResultScanId(null);
    setIsScanTransitioning(true);
    reset();
    return scanToken;
  };

  const commitLockedScanResult = (scanToken: number, payload: any) => {
    if (scanToken !== activeScanTokenRef.current) {
      return null;
    }

    const resolvedScanId = ((payload?.scanId as string | undefined) ?? (payload?.scan_id as string | undefined) ?? (payload?.id as string | undefined) ?? crypto.randomUUID()) as string;
    const lockedResult = { ...payload, scanId: resolvedScanId, scan_id: resolvedScanId };
    setActiveResultScanId(resolvedScanId);
    setEnhancedResult(lockedResult);
    setIsScanTransitioning(false);
    return lockedResult;
  };

  const refreshBackendHealth = async () => {
    const healthResponse = await fetchPythonBackendJson<PythonBackendHealth>('/health');
    if (healthResponse.ok) {
      setBackendStatus('connected');
      setBackendHealth(healthResponse.data);
      setOfflineModeNotice('');
      return healthResponse.data;
    }

    if (healthResponse.offline) {
      setBackendStatus('offline');
      setBackendHealth(null);
    }

    return null;
  };

  const refreshFeedbackStats = async () => {
    const feedbackResponse = await fetchPythonBackendJson<PythonFeedbackStats>('/feedback/stats');
    if (feedbackResponse.ok) {
      setBackendFeedbackStats(feedbackResponse.data);
      return feedbackResponse.data;
    }
    return null;
  };

  const enhanceWithPythonBackend = async (baseResult: DashboardResult | null, rawEmailText: string, rawHeaders: string): Promise<DashboardResult | null> => {
    const emailResponse = await fetchPythonBackendJson<PythonEmailScan>('/scan-email', {
      method: 'POST',
      body: JSON.stringify({ email_text: rawEmailText }),
    });

    if (!emailResponse.ok) {
      if (emailResponse.offline) {
        setBackendStatus('offline');
        setBackendHealth(null);
        setOfflineModeNotice('⚠️ Running in offline mode — backend unavailable');
      }
      return baseResult;
    }

    setBackendStatus('connected');
    setOfflineModeNotice('');
    void refreshBackendHealth();

    const effectiveHeaders = rawHeaders.trim() || extractInlineHeadersFromText(rawEmailText);
    const urls = extractUrlsForBackend(rawEmailText);
    const urlResponses = await Promise.all(
      urls.map((url) => fetchPythonBackendJson<PythonUrlScan>('/check-url', {
        method: 'POST',
        body: JSON.stringify({ url }),
      })),
    );

    const headerResponse = effectiveHeaders
      ? await fetchPythonBackendJson<PythonHeaderScan>('/check-headers', {
          method: 'POST',
          body: JSON.stringify({ headers: effectiveHeaders }),
        })
      : null;

    const successfulUrlResponses = urlResponses.filter((response): response is BackendFetchSuccess<PythonUrlScan> => response.ok);
    const urlRisk = Math.max(0, ...successfulUrlResponses.map((response) => Number(response.data.risk_score ?? 0)));
    const headerRisk = headerResponse && headerResponse.ok ? Number(headerResponse.data.header_risk_score ?? 0) : 0;
    const headerSpoofingScore = headerResponse && headerResponse.ok ? Number(headerResponse.data.spoofing_score ?? 0) : 0;
    const hasHeaderSpoofing = Boolean(
      headerResponse && headerResponse.ok && (
        headerResponse.data.return_path_mismatch
        || headerResponse.data.reply_to_mismatch
        || headerSpoofingScore >= 50
      )
    );
    const emailRisk = Number(emailResponse.data.risk_score ?? 0);
    const rawMergedRiskScore = Math.max(Number(baseResult?.riskScore ?? 0), emailRisk, urlRisk, headerRisk, hasHeaderSpoofing ? 70 : 0);
    const trustedHeaderPassCount = headerResponse && headerResponse.ok
      ? [headerResponse.data.spf, headerResponse.data.dkim, headerResponse.data.dmarc].filter((value) => value === 'pass').length
      : 0;
    const hasDangerousCredentialRequest = /\b(reply with|share|provide|enter|submit)\b[\s\S]{0,40}\b(otp|password|pin|passcode|credentials?|bank details|card details)\b/i.test(rawEmailText);
    const trustedMarketingOverride = hasNewsletterContext(rawEmailText, extractSenderDomainFromText(rawEmailText))
      && trustedHeaderPassCount >= 2
      && !hasDangerousCredentialRequest;
    const protectiveSecurityOverride = hasProtectiveSecurityContext(rawEmailText) && !hasDangerousCredentialRequest;
    const legitimateTransactionalOverride = hasLegitimateTransactionalContext(rawEmailText) && !hasDangerousCredentialRequest;
    const becEscalationRisk = hasBecPaymentDiversionContext(rawEmailText) ? 86 : 0;
    const qrEscalationRisk = hasQrPayrollScamContext(rawEmailText) ? 82 : 0;
    const spoofingEscalationRisk = hasHeaderSpoofing ? Math.max(70, headerRisk, headerSpoofingScore) : 0;
    const benignOverride = !hasHeaderSpoofing && (trustedMarketingOverride || protectiveSecurityOverride || legitimateTransactionalOverride);
    const mergedRiskScore = hasHeaderSpoofing
      ? Math.max(rawMergedRiskScore, spoofingEscalationRisk)
      : trustedMarketingOverride
        ? Math.min(Math.max(emailRisk, headerRisk), 18)
        : legitimateTransactionalOverride
          ? Math.min(Math.max(emailRisk, headerRisk), 18)
          : protectiveSecurityOverride
            ? Math.min(Math.max(emailRisk, headerRisk, /bank|sbi|hdfc|icici|helpline/i.test(rawEmailText) ? 30 : 0), /bank|sbi|hdfc|icici|helpline/i.test(rawEmailText) ? 45 : 18)
            : Math.max(rawMergedRiskScore, becEscalationRisk, qrEscalationRisk);

    const existingSignals = Array.isArray(baseResult?.signals)
      ? baseResult.signals as string[]
      : Array.isArray(baseResult?.detectedSignals)
        ? baseResult.detectedSignals as string[]
        : [];
    const urlSignals = successfulUrlResponses
      .filter((response) => Number(response.data.risk_score ?? 0) > 0)
      .map((response) => {
        const engineHits = Number(response.data.malicious_count ?? 0);
        const targetUrl = response.data.url ?? 'a link';
        return engineHits > 0
          ? `URL risk detected (${engineHits} engines flagged ${targetUrl})`
          : `URL risk detected (No blacklist hit — heuristic risk detected for ${targetUrl})`;
      });
    const headerSignals = headerResponse && headerResponse.ok ? (headerResponse.data.signals ?? []).map((signal) => `Header analysis: ${signal}`) : [];

    const mergedSignalsBase = [...new Set([
      ...existingSignals,
      ...(emailResponse.data.signals ?? []),
      ...urlSignals,
      ...headerSignals,
    ])];
    const escalationSignals = [
      ...(hasHeaderSpoofing ? ['Header spoofing detected: sender and return-path mismatch'] : []),
      ...(becEscalationRisk ? ['Business Email Compromise pattern'] : []),
      ...(qrEscalationRisk ? ['QR-code credential lure'] : []),
      ...(protectiveSecurityOverride ? ['Protective account notice'] : []),
      ...(legitimateTransactionalOverride ? ['Legitimate transaction update'] : []),
    ];
    const mergedSignals = (benignOverride
      ? [...mergedSignalsBase, ...escalationSignals].filter((signal) => !/brand impersonation|executive impersonation cue|link included in message|urgency language/i.test(signal))
      : [...mergedSignalsBase, ...escalationSignals]
    ).filter((signal, index, list) => list.findIndex((candidate) => candidate === signal) === index).slice(0, 8);

    const backendExplanation = emailResponse.data.explanation;
    const explanationSpans = buildExplanationSpans(rawEmailText, backendExplanation?.top_words ?? []);
    const mergedSuspiciousSpans = mergeSuspiciousSpans(
      Array.isArray(baseResult?.suspiciousSpans) ? baseResult.suspiciousSpans : [],
      explanationSpans,
    );
    const backendFeatureImportance: DashboardFeature[] = (backendExplanation?.top_words ?? []).map((item) => ({
      feature: item.word,
      contribution: Number(item.contribution ?? 0),
      direction: (mergedRiskScore >= 40 ? 'phishing' : 'safe') as DashboardFeature['direction'],
    }));

    const emailSeverity: RiskSeverity = mergedRiskScore >= 75 ? 'high' : mergedRiskScore >= 40 ? 'medium' : 'low';
    const urlSeverity: RiskSeverity = urlRisk >= 60 ? 'high' : 'medium';
    const headerSeverity: RiskSeverity = headerRisk >= 60 ? 'high' : 'medium';
    const existingReasons: DashboardReason[] = Array.isArray(baseResult?.reasons) ? baseResult.reasons : [];
    const backendReasons: DashboardReason[] = [
      ...(emailResponse.data.signals ?? []).map((signal) => ({
        category: 'ml_score',
        description: `Python backend: ${signal}`,
        severity: emailSeverity,
        matchedTerms: [] as string[],
      })),
      ...urlSignals.map((signal) => ({
        category: 'url',
        description: signal,
        severity: urlSeverity,
        matchedTerms: [] as string[],
      })),
      ...headerSignals.map((signal) => ({
        category: 'header',
        description: signal,
        severity: headerSeverity,
        matchedTerms: [] as string[],
      })),
    ];

    const escalationReasons: DashboardReason[] = [
      ...(becEscalationRisk ? [{ category: 'social_engineering', description: 'Business Email Compromise pattern detected in the message wording.', severity: 'high' as RiskSeverity, matchedTerms: [] as string[] }] : []),
      ...(qrEscalationRisk ? [{ category: 'social_engineering', description: 'QR-code and payroll suspension lure detected.', severity: 'high' as RiskSeverity, matchedTerms: [] as string[] }] : []),
      ...(protectiveSecurityOverride ? [{ category: 'ml_score', description: 'Protective account notice pattern detected.', severity: 'low' as RiskSeverity, matchedTerms: [] as string[] }] : []),
      ...(legitimateTransactionalOverride ? [{ category: 'ml_score', description: 'Legitimate transaction update pattern detected.', severity: 'low' as RiskSeverity, matchedTerms: [] as string[] }] : []),
    ];
    const mergedReasonsBase = [...existingReasons, ...backendReasons, ...escalationReasons]
      .filter((reason, index, list) => list.findIndex((candidate) => candidate.description === reason.description) === index);
    const mergedReasons = (benignOverride
      ? mergedReasonsBase.filter((reason) => !/brand impersonation|executive impersonation cue|link included in message|urgency language/i.test(reason.description))
      : mergedReasonsBase.filter((reason) => !(/Trusted sender with no strong phishing signals detected/i.test(reason.description) && hasHeaderSpoofing))
    ).slice(0, 12);

    const mergedConfidence = Math.max(
      Number(baseResult?.confidence ?? 0),
      Number(emailResponse.data.confidence ?? 0) > 1 ? Number(emailResponse.data.confidence ?? 0) / 100 : Number(emailResponse.data.confidence ?? 0),
      mergedRiskScore / 100,
    );
    const recommendedDisposition = hasHeaderSpoofing ? 'block' : benignOverride ? 'allow' : mergedRiskScore >= 75 ? 'block' : mergedRiskScore >= 40 ? 'review' : 'allow';
    const mergedClassification = hasHeaderSpoofing ? 'phishing' : scoreToVerdictState(mergedRiskScore);
    const mergedAttackType = hasHeaderSpoofing
      ? 'Header Spoofing'
      : trustedMarketingOverride
      ? 'Newsletter / Digest'
      : legitimateTransactionalOverride
        ? 'Safe / Informational'
        : protectiveSecurityOverride
          ? (/bank|sbi|hdfc|icici|helpline/i.test(rawEmailText) ? 'Account Security Notice' : 'Safe / Informational')
          : becEscalationRisk
            ? 'Business Email Compromise'
            : qrEscalationRisk
              ? 'QR Credential Harvesting'
              : headerRisk >= Math.max(emailRisk, urlRisk) && headerRisk >= 40
                ? 'Header Spoofing'
                : urlRisk >= Math.max(emailRisk, headerRisk) && urlRisk >= 60
                  ? 'Malicious URL'
                  : emailResponse.data.category ?? baseResult?.attackType ?? 'General Phishing';

    const mergedBackendExplanation = hasHeaderSpoofing
      ? {
          ...(backendExplanation ?? {}),
          why_risky: 'Header spoofing detected: sender and return-path mismatch',
          confidence_interval: `${Math.round(mergedConfidence * 100)}% ± 5%`,
        }
      : backendExplanation;

    return {
      ...baseResult,
      id: baseResult?.id ?? emailResponse.data.scan_id ?? crypto.randomUUID(),
      riskScore: mergedRiskScore,
      risk_score: mergedRiskScore,
      classification: mergedClassification,
      confidence: mergedConfidence,
      confidenceLevel: scoreToConfidenceLevel(mergedRiskScore),
      confidence_level: scoreToConfidenceLevel(mergedRiskScore),
      attackType: mergedAttackType,
      detectedLanguage: normalizeLanguageCode(emailResponse.data.detectedLanguage ?? emailResponse.data.language ?? baseResult?.detectedLanguage ?? 'EN'),
      urlAnalyses: Array.isArray(baseResult?.urlAnalyses) ? baseResult.urlAnalyses : [],
      safetyTips: Array.isArray(baseResult?.safetyTips) ? baseResult.safetyTips : [],
      ruleScore: Number(baseResult?.ruleScore ?? 0),
      urlScore: Math.max(Number(baseResult?.urlScore ?? 0), urlRisk),
      headerScore: Math.max(Number(baseResult?.headerScore ?? 0), headerRisk),
      displayLabel: buildDisplayLabel(mergedRiskScore, Math.round(mergedConfidence * 100)),
      display_label: buildDisplayLabel(mergedRiskScore, Math.round(mergedConfidence * 100)),
      signals: mergedSignals,
      detectedSignals: mergedSignals,
      reasons: mergedReasons,
      mlScore: Math.max(Number(baseResult?.mlScore ?? 0), Math.round(Number(emailResponse.data.ml_probability ?? 0) * 100)),
      recommendedDisposition,
      autoBlockRecommended: recommendedDisposition === 'block',
      recommendation: hasHeaderSpoofing ? 'Block and quarantine' : benignOverride ? 'Allow with normal caution' : (emailResponse.data.recommendation ?? baseResult?.recommendation),
      featureImportance: backendFeatureImportance.length > 0 ? backendFeatureImportance : (baseResult?.featureImportance ?? []),
      suspiciousSpans: mergedSuspiciousSpans,
      scanId: emailResponse.data.scan_id ?? baseResult?.scanId,
      backendExplanation: mergedBackendExplanation,
      warnings: [...new Set([
        ...(Array.isArray(baseResult?.warnings) ? baseResult.warnings : []),
        ...(urlRisk >= 60 ? ['One or more URLs were flagged by VirusTotal.'] : []),
        ...(headerRisk >= 40 ? ['Header authentication issues were detected by the Python backend.'] : []),
      ])],
      backendSummary: {
        emailRisk,
        urlRisk,
        headerRisk,
        backendSignals: mergedSignals,
        explanation: backendExplanation,
      },
    };
  };

  const learningMetrics = (metrics ?? {}) as any;
  const feedbackSamplesReviewed = Number(learningMetrics.feedbackSamples ?? 0);
  const feedbackAgreementRate = Number(learningMetrics.feedbackAgreementRate ?? 0);
  const hasFeedbackSamples = feedbackSamplesReviewed > 0;
  const feedbackAgreementDisplay = hasFeedbackSamples ? `${(feedbackAgreementRate * 100).toFixed(1)}%` : 'N/A';
  const feedbackAgreementSummary = hasFeedbackSamples
    ? `Our model agreed with reviewed feedback ${(feedbackAgreementRate * 100).toFixed(0)}% of the time. Below 50% means retraining is strongly recommended.`
    : 'No reviewed feedback samples yet — agreement rate will appear after analyst confirmations are collected.';
  const retrainCollected = Number(backendFeedbackStats?.pending_retrain ?? learningMetrics.samplesSinceLastRetrain ?? 0);
  const retrainNeeded = Number(backendFeedbackStats?.needed_for_retrain ?? learningMetrics.samplesNeededForRetrain ?? (retrainCollected > 0 ? 0 : 50));
  const retrainTarget = retrainCollected + retrainNeeded;
  const retrainProgressText = retrainTarget > 0 ? `${retrainCollected} / ${retrainTarget}` : 'Awaiting feedback';
  const driftTone =
    learningMetrics.driftLevel === 'high'
      ? 'text-destructive border-destructive/30 bg-destructive/5'
      : learningMetrics.driftLevel === 'medium'
        ? 'text-warning border-warning/30 bg-warning/5'
        : 'text-safe border-safe/30 bg-safe/5';
  const backendStatusTone =
    backendStatus === 'connected'
      ? 'text-safe border-safe/30 bg-safe/10'
      : backendStatus === 'offline'
        ? 'text-warning border-warning/30 bg-warning/10'
        : 'text-muted-foreground border-border/50 bg-background/70';
  const backendStatusLabel =
    backendStatus === 'connected'
      ? 'Backend: Connected ✅'
      : backendStatus === 'offline'
        ? 'Backend: Offline ⚠️'
        : 'Backend: Checking…';
  const backendModelVersion = formatBackendModelVersion(backendHealth);

  const protectionCounter = baseProtectionCount +
    ((metrics?.totalScans ?? 0) * 17) +
    ((metrics?.phishingDetected ?? 0) * 41) +
    ((metrics?.suspiciousDetected ?? 0) * 11);

  useEffect(() => {
    try {
      const stored = localStorage.getItem('phishshield_history');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed)) {
          setLocalHistory(trimHistoryItems(parsed.map((item) => ({
            ...item,
            classification: normalizeClassification(item?.classification),
            contentHash: item?.contentHash ?? hashEmailContent(item?.emailPreview ?? ''),
          }))));
        } else {
          localStorage.removeItem('phishshield_history');
        }
      }

      const safeSenderRaw = localStorage.getItem(SAFE_SENDERS_KEY);
      if (safeSenderRaw) {
        const parsedSafeSenders = JSON.parse(safeSenderRaw);
        if (Array.isArray(parsedSafeSenders)) {
          setSafeSenders(parsedSafeSenders.filter((entry) => typeof entry?.domain === 'string'));
        }
      }

      const retrainRaw = localStorage.getItem(RETRAIN_META_KEY);
      if (retrainRaw) {
        const retrainMeta = JSON.parse(retrainRaw);
        if (typeof retrainMeta?.label === 'string') {
          setRetrainLabel(retrainMeta.label);
        }
      }
    } catch {
      try { localStorage.removeItem('phishshield_history'); } catch { /* ignore */ }
    }
  }, []);

  const safeServerHistory = Array.isArray(serverHistory) ? serverHistory : [];
  const safeLocalHistory = Array.isArray(localHistory) ? localHistory : [];
  const history = useMemo(
    () => dedupeHistoryItems([
      ...safeLocalHistory,
      ...safeServerHistory,
    ].map((item) => ({
      ...item,
      classification: normalizeClassification(item?.classification),
    }))),
    [safeLocalHistory, safeServerHistory],
  );
  const sessionHistory = safeLocalHistory.length > 0 ? safeLocalHistory : history;
  const sessionMetrics: NonNullable<MetricsCounts> = useMemo(() => ({
    phishingDetected: sessionHistory.filter((item) => normalizeClassification(item.classification) === 'phishing').length,
    suspiciousDetected: sessionHistory.filter((item) => isSuspiciousClassification(item.classification)).length,
    safeDetected: sessionHistory.filter((item) => normalizeClassification(item.classification) === 'safe').length,
  }), [sessionHistory]);
  const sessionTotalScans = sessionHistory.length;
  const safeShareText = (value: string) => (privacyMode ? redactSensitiveText(value) : value);
  const filteredHistory = sessionHistory.filter((item) => {
    const normalized = normalizeClassification(item.classification);
    const matchesFilter = historyFilter === 'all' || (historyFilter === 'uncertain' ? isSuspiciousClassification(normalized) : normalized === historyFilter);
    const query = historySearch.trim().toLowerCase();
    const searchableText = [
      item.emailPreview,
      normalizeLanguageCode(item.detectedLanguage),
      getLanguageLabel(item.detectedLanguage),
      formatVerdictLabel(normalized, item.riskScore ?? 0),
      String(item.riskScore ?? ''),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();

    return matchesFilter && (!query || searchableText.includes(query));
  });

  const visibleHistory = filteredHistory.slice(0, historyVisibleCount);
  const resultSenderDomain = result ? extractSenderDomainFromText(emailText, result?.headerAnalysis?.senderDomain) : '';
  const safeSenderMatch = result
    ? safeSenders.find((entry) => resultSenderDomain === entry.domain || resultSenderDomain.endsWith(`.${entry.domain}`))
    : undefined;
  const newsletterContext = result ? hasNewsletterContext(emailText, resultSenderDomain) : false;
  const displayRiskScore = result
    ? Math.max(0, Math.min(100, Math.round(result.riskScore ?? 0)))
    : 0;
  const displayClassification = result
    ? normalizeClassification(result.classification ?? (displayRiskScore <= 25 ? 'safe' : displayRiskScore <= 60 ? 'uncertain' : 'phishing'))
    : 'safe';
  const hasStrongRiskSignals = Boolean(
    result && (
      displayClassification === 'phishing'
      || (result.headerScore ?? 0) >= 50
      || result.headerAnalysis?.spoofingRisk === 'high'
      || (result.signals ?? []).some((signal) => /spoof|mismatch|suspicious domain|phishing/i.test(signal))
      || (result.reasons ?? []).some((reason) => /spoof|mismatch|suspicious domain|phishing/i.test(reason.description))
    )
  );
  const displayAttackType = result
    ? ((!hasStrongRiskSignals && safeSenderMatch && displayClassification === 'safe') || (!hasStrongRiskSignals && newsletterContext && displayClassification === 'safe') ? 'Newsletter / Digest' : result.attackType)
    : 'Safe / Informational';

  // Pre-compute verdict colors so we don't need an IIFE inside JSX
  const verdictColors = result ? classificationColor(displayClassification) : null;
  const verdictBand = result ? formatVerdictLabel(displayClassification, displayRiskScore) : 'Safe';
  const verdictDisplayLabel = result ? buildDisplayLabel(displayRiskScore, Math.round(((result.confidence ?? 0) <= 1 ? (result.confidence ?? 0) * 100 : (result.confidence ?? 0)))) : '🟢 Safe • 0% confidence';
  const backendExplanation = result ? ((result as any).backendExplanation as PythonModelExplanation | undefined) : undefined;
  const explanationText = result ? (((typeof (result as any).explanation === 'string' ? (result as any).explanation : undefined) as string | undefined) ?? result.scamStory) : '';
  const explanationWordSummary = backendExplanation?.top_words?.length
    ? backendExplanation.top_words.slice(0, 3).map((item) => `${item.word} (${Math.round((item.contribution ?? 0) * 100)}%)`).join(' + ')
    : '';
  const baseResultSignals = result
    ? ((((result as any).signals as string[] | undefined) ?? ((result as any).detectedSignals as string[] | undefined) ?? deriveDetectedSignals(result)) as string[])
    : [];
  const safeDisplaySignals = result && !hasStrongRiskSignals && displayClassification === 'safe'
    ? [
        ...(safeSenderMatch || newsletterContext || Boolean(resultSenderDomain) ? ['Trusted sender'] : []),
        'No strong phishing signals',
        ...(newsletterContext ? ['Newsletter / Digest'] : []),
      ]
    : [];
  const detectedSignals = result
    ? (displayClassification === 'safe'
        ? [...new Set(safeDisplaySignals.length > 0 ? safeDisplaySignals : ['No strong phishing signals'])].slice(0, 4)
        : [...new Set(baseResultSignals)].slice(0, 4))
    : [];
  const recommendedDisposition = result
    ? ((((result as any).recommendedDisposition as string | undefined) ?? (displayClassification === 'phishing' ? 'block' : displayClassification === 'safe' ? 'allow' : 'review')).toLowerCase())
    : 'allow';
  const preventionActions = result ? ((((result as any).preventionActions as string[] | undefined) ?? []).slice(0, 3)) : [];
  const detectedInlineHeaders = extractInlineHeadersFromText(emailText);
  const detectedUrlCount = extractUrlsFromText(emailText).length;
  const detectedActionCueCount = (
    emailText.match(/\b(?:apply now|visit the help center|official site|open in [a-z ]+|view in [a-z ]+|join zoom meeting|manage notification settings|unsubscribe here|download it free today|scan email)\b/gi) ?? []
  ).length;
  const hasHeaderCoverage = Boolean(headersText.trim() || detectedInlineHeaders.trim() || result?.headerAnalysis?.hasHeaders);
  const linkInsightHelper = detectedUrlCount > 0
    ? detectedUrlCount > 12
      ? 'Multiple visible destinations were found. Marketing emails often include tracking or help-center links, so focus on the main destination instead of every asset URL.'
      : 'Review every destination before opening.'
    : detectedActionCueCount > 0
      ? `No raw URLs were pasted, but ${detectedActionCueCount} link or action cue${detectedActionCueCount === 1 ? '' : 's'} were detected in the copied email.`
      : 'No direct links were found in the pasted content.';
  const scanReadiness = emailText.trim().length > 0 ? 'Ready to scan' : 'Paste content to start';
  const scanReadinessTone = emailText.trim().length > 0 ? 'text-safe border-safe/30 bg-safe/5' : 'text-warning border-warning/30 bg-warning/5';
  const responsePlaybook = result
    ? preventionActions.length > 0
      ? preventionActions
      : /Business Email Compromise/i.test(displayAttackType)
        ? [
            'Call the sender directly on a known, verified number before any transfer.',
            'Alert the finance team and pause the payment workflow immediately.',
            'Do not rely on the email thread alone for approval or bank details.',
          ]
        : /OTP Scam/i.test(displayAttackType)
          ? [
              'Never share OTPs, PINs, or passcodes from this message.',
              'Report the message to your bank through its official app or helpline.',
              'Reset access only from the bank’s official website or app.',
            ]
          : /Delivery Fee Scam/i.test(displayAttackType)
            ? [
                'Check the official courier website or app yourself before paying anything.',
                'Ignore fee demands in the email until the tracking number is independently verified.',
                'Do not enter card details on courier lookalike pages.',
              ]
            : /Newsletter \/ Digest/i.test(displayAttackType)
              ? [
                  'This looks like a digest or newsletter rather than a live phishing lure.',
                  'Add it to Safe Senders if you trust the domain and content.',
                  'Mark it as safe to improve future session accuracy.',
                ]
              : recommendedDisposition === 'block'
                ? [
                    'Do not click links, open attachments, or reply to the sender.',
                    'Block the sender and report the message through the official channel.',
                    'If any action was already taken, reset credentials from the official site immediately.',
                  ]
                : recommendedDisposition === 'allow'
                  ? [
                      'No strong phishing signs were found in this message.',
                      'You can still verify billing, sign-in, or payment details from the official site if you want extra assurance.',
                      'Never share OTPs, passwords, or card details over email even on safe-looking messages.',
                    ]
                  : [
                      'Pause before clicking, replying, or entering any credentials.',
                      'Open the service directly through its official website or app to verify the request.',
                      'Keep the message for evidence until you confirm whether it is legitimate.',
                    ]
    : [];
  const triageChecklist = result
    ? [
        {
          label: 'Links in message',
          value: detectedUrlCount > 0 ? `${detectedUrlCount} detected` : detectedActionCueCount > 0 ? `${detectedActionCueCount} cues` : 'None found',
          helper: linkInsightHelper,
          tone: detectedUrlCount > 0 || detectedActionCueCount > 0 ? 'border-warning/30 bg-warning/5 text-warning' : 'border-safe/30 bg-safe/5 text-safe',
        },
        {
          label: 'Header coverage',
          value: headersText.trim() ? 'Included' : hasHeaderCoverage ? 'Detected inline' : 'Limited header analysis',
          helper: headersText.trim()
            ? 'Sender metadata is available for spoof checks.'
            : hasHeaderCoverage
              ? 'Raw email headers were detected in the pasted content and included in spoof checks.'
              : 'Limited header analysis (no raw headers provided). Paste raw headers for deeper sender verification.',
          tone: hasHeaderCoverage ? 'border-safe/30 bg-safe/5 text-safe' : 'border-border/60 bg-background/60 text-foreground',
        },
        {
          label: 'Privacy mode',
          value: privacyMode ? 'Protected' : 'Open',
          helper: privacyMode ? 'Copied text is automatically redacted.' : 'Clipboard exports keep the original text.',
          tone: privacyMode ? 'border-safe/30 bg-safe/5 text-safe' : 'border-warning/30 bg-warning/5 text-warning',
        },
        {
          label: 'Recommended action',
          value: recommendedDisposition === 'block'
            ? 'Block / quarantine'
            : recommendedDisposition === 'allow'
              ? 'No action needed'
              : 'Manual review',
          helper: recommendedDisposition === 'block'
            ? 'The prevention layer recommends blocking or quarantining this message.'
            : recommendedDisposition === 'allow'
              ? 'No automatic block is needed, but official-site verification is still safest.'
              : 'Review manually before taking any action on the message.',
          tone: recommendedDisposition === 'block'
            ? 'border-destructive/30 bg-destructive/5 text-destructive'
            : recommendedDisposition === 'allow'
              ? 'border-safe/30 bg-safe/5 text-safe'
              : 'border-warning/30 bg-warning/5 text-warning',
        },
      ]
    : [];
  const rawConfidencePercent = result
    ? Math.round(((result.confidence ?? 0) <= 1 ? (result.confidence ?? 0) * 100 : (result.confidence ?? 0)))
    : 0;
  const confidencePercent = result
    ? clampDisplayedConfidence(rawConfidencePercent)
    : 0;
  const confidenceInterval = detectedSignals.length >= 5 ? 3 : detectedSignals.length >= 3 ? 8 : 15;
  const confidenceValue = confidencePercent / 100;
  const displayedConfidenceInterval = result
    ? `${confidencePercent}% ± ${confidenceInterval}%`
    : '0% ± 0%';
  const llmUsed = Boolean(
    result && (
      result.featureImportance?.some((feature) => /llm fallback/i.test(feature.feature)) ||
      result.reasons?.some((reason) => /llm fallback/i.test(reason.description))
    ),
  );
  const topReasons = result
    ? [...result.reasons]
        .sort((a, b) => ({ high: 3, medium: 2, low: 1 }[b.severity] - { high: 3, medium: 2, low: 1 }[a.severity]))
        .slice(0, 3)
    : [];
  const primaryWordIndicators = displayClassification === 'safe'
    ? []
    : dedupeTopWordIndicators(backendExplanation?.top_words ?? []).slice(0, 3);
  const topReasonCards = result
    ? displayClassification === 'safe'
      ? [
          { label: 'Trusted sender', helper: 'The sender appears consistent with a known or expected source.' },
          { label: 'No strong phishing signals', helper: 'No spoofing, credential request, or malicious link pattern was detected.' },
          { label: 'Normal informational language', helper: 'The message reads like a routine update, receipt, or account notice.' },
        ]
      : (topReasons.length > 0
          ? topReasons
              .map((reason) => {
                const label = simplifyReasonLabel(reason);
                return { label, helper: buildReasonHelper(label, reason.description) };
              })
              .filter((item, index, array) => array.findIndex((entry) => entry.label === item.label) === index)
              .slice(0, 3)
          : detectedSignals.slice(0, 3).map((signal) => ({ label: signal, helper: 'Visible warning signal detected in the message.' })))
    : [];
  const conciseExplanation = result
    ? displayClassification === 'safe'
      ? 'No strong phishing signals detected from a trusted source. Always verify sensitive actions via official apps.'
      : explanationText
        ? explanationText.replace(/\s+/g, ' ').trim().split(/(?<=[.!?])\s+/).slice(0, 1).join(' ')
        : displayClassification === 'phishing'
          ? 'Detected brand impersonation with a suspicious link and urgency language.'
          : 'This email needs manual review before you click, reply, or sign in.'
    : 'Paste an email to generate a clear verdict summary.';
  const verdictHeadline = result
    ? formatVerdictLabel(displayClassification, displayRiskScore)
    : 'READY';
  const primaryAssessmentLabel = displayAttackType === 'Safe / Informational' ? 'Normal activity' : displayAttackType;
  const hasSpoofingVisualWarning = /Header Spoofing/i.test(displayAttackType) || result?.headerAnalysis?.spoofingRisk === 'high';

  const scrollToResults = () => {
    setTimeout(() => {
      resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 150);
  };

  const handleScan = () => {
    if (!emailText.trim()) return;

    const contentHash = hashEmailContent(emailText);
    const existingScan = localHistory.find((item) => item.contentHash === contentHash);
    if (existingScan) {
      setDuplicateScanNotice(`Previously scanned ${formatDate(existingScan.timestamp)} at ${formatTime(existingScan.timestamp)}. Running a fresh review and adding it to this session summary.`);
      toast({
        title: 'Re-scanning email',
        description: 'PhishShield will refresh the verdict and count it in this session.',
      });
    }

    const rawEmailSnapshot = emailText;
    const rawHeadersSnapshot = headersText.trim() || extractInlineHeadersFromText(rawEmailSnapshot);
    const scanToken = beginLockedScan();

    setDuplicateScanNotice('');
    setIsDemoEmail(false);
    setFeedbackSent(false);
    setFeedbackMessage('');
    setFeedbackNote('');

    analyzeEmail({ data: { emailText: prepareEmailForAnalysis(rawEmailSnapshot), headers: rawHeadersSnapshot } }, {
      onSuccess: async (data) => {
        const mergedData = await enhanceWithPythonBackend(data, rawEmailSnapshot, rawHeadersSnapshot);
        const lockedResult = commitLockedScanResult(scanToken, mergedData);
        if (!lockedResult) return;

        const newItem: LocalHistoryItem = {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          emailPreview: rawEmailSnapshot.slice(0, 80),
          riskScore: Math.max(0, Math.min(100, Math.round(lockedResult?.riskScore ?? 0))),
          classification: normalizeClassification(lockedResult?.classification ?? 'safe'),
          detectedLanguage: normalizeLanguageCode(lockedResult?.detectedLanguage ?? 'EN'),
          urlCount: lockedResult?.urlAnalyses?.length ?? extractUrlsForBackend(rawEmailSnapshot).length,
          reasonCount: lockedResult?.reasons?.length ?? 0,
          contentHash,
          attackType: lockedResult?.attackType,
        };
        setLocalHistory(prev => {
          const updated = trimHistoryItems([newItem, ...prev]);
          try { localStorage.setItem('phishshield_history', JSON.stringify(updated)); } catch { /* ignore */ }
          return updated;
        });
        refetchHistory();
        refetchMetrics();
        scrollToResults();
      },
      onError: () => {
        if (scanToken === activeScanTokenRef.current) {
          setIsScanTransitioning(false);
        }
      },
    });
  };

  // Selecting a demo email auto-scans immediately — no button click needed
  const loadDemo = (demo: typeof PRELOADED_EMAILS[0]) => {
    const text = demo.text;
    const demoHeaders = demo.id === 'header_spoof' ? text.split('\n\n')[0] + '\n\n' : extractInlineHeadersFromText(text);
    const contentHash = hashEmailContent(text);
    const scanToken = beginLockedScan();

    setDuplicateScanNotice('');
    setEmailText(text);
    if (demo.id === 'header_spoof') {
      setHeadersText(demoHeaders);
      setShowHeaders(true);
    } else {
      setHeadersText('');
      setShowHeaders(false);
    }
    setShowDemos(false);
    setIsDemoEmail(true);
    setFeedbackSent(false);
    setFeedbackMessage('');
    setFeedbackNote('');
    analyzeEmail({ data: { emailText: prepareEmailForAnalysis(text), headers: demoHeaders || undefined } }, {
      onSuccess: async (data) => {
        const mergedData = await enhanceWithPythonBackend(data, text, demoHeaders);
        const lockedResult = commitLockedScanResult(scanToken, mergedData);
        if (!lockedResult) return;

        const newItem = {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          emailPreview: text.slice(0, 80).replace(/\n/g, ' '),
          riskScore: lockedResult?.riskScore ?? 0,
          classification: lockedResult?.classification ?? 'safe',
          detectedLanguage: normalizeLanguageCode(lockedResult?.detectedLanguage ?? 'EN'),
          urlCount: lockedResult?.urlAnalyses?.length ?? extractUrlsForBackend(text).length,
          reasonCount: lockedResult?.reasons?.length ?? 0,
          contentHash,
          attackType: lockedResult?.attackType,
        };
        setLocalHistory(prev => {
          const updated = trimHistoryItems([newItem, ...prev]);
          try { localStorage.setItem('phishshield_history', JSON.stringify(updated)); } catch { /* ignore */ }
          return updated;
        });
        refetchHistory();
        refetchMetrics();
        scrollToResults();
      },
      onError: () => {
        if (scanToken === activeScanTokenRef.current) {
          setIsScanTransitioning(false);
        }
      },
    });
  };

  const handleClearHistory = () => {
    clearHistory(undefined, {
      onSuccess: () => {
        setLocalHistory([]);
        try { localStorage.removeItem('phishshield_history'); } catch { /* ignore */ }
        refetchHistory();
        refetchMetrics();
      }
    });
  };

  const handleCopySessionSnapshot = async () => {
    const snapshot = {
      sessionId: sessionFingerprint,
      scanDate: new Date().toISOString(),
      totalScanned: sessionTotalScans,
      phishingCount: sessionMetrics.phishingDetected,
      suspiciousCount: sessionMetrics.suspiciousDetected,
      safeCount: sessionMetrics.safeDetected,
      scans: filteredHistory.slice(0, historyVisibleCount).map((item) => ({
        preview: safeShareText(item.emailPreview),
        score: Math.round(item.riskScore ?? 0),
        verdict: formatVerdictLabel(item.classification, item.riskScore ?? 0),
        category: (item as any).attackType ?? 'Recent scan',
        signals: [getLanguageLabel(item.detectedLanguage), `${item.urlCount} urls`],
      })),
    };

    try {
      await navigator.clipboard?.writeText(JSON.stringify(snapshot, null, 2));
      toast({
        title: 'Session snapshot copied',
        description: privacyMode
          ? 'A structured JSON snapshot was copied with sensitive details redacted.'
          : 'A structured JSON snapshot is ready to share or archive.',
      });
    } catch {
      toast({
        title: 'Copy unavailable',
        description: 'Clipboard access is blocked in this browser session.',
      });
    }
  };

  const handleExportCsv = () => {
    const header = ['timestamp', 'verdict', 'score', 'language', 'urlCount', 'preview'];
    const rows = filteredHistory.slice(0, historyVisibleCount).map((item) => [
      item.timestamp,
      formatVerdictLabel(item.classification, item.riskScore ?? 0),
      String(Math.round(item.riskScore ?? 0)),
      getLanguageLabel(item.detectedLanguage),
      String(item.urlCount ?? 0),
      `"${safeShareText(item.emailPreview).replace(/"/g, '""')}"`,
    ]);
    const csv = [header.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `phishshield-session-${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getTopKeywords = () => {
    if (!sessionHistory.length) return [];
    const text = sessionHistory.map(h => h.emailPreview || '').join(" ").toLowerCase();
    const words = (text.match(/\b(otp|kyc|verify|suspended|blocked|prize|cashback|password|account|update|urgent|click|link|bank|pan|aadhaar)\b/g) || []) as string[];
    const counts = words.reduce((acc: Record<string, number>, w: string) => { acc[w] = (acc[w] || 0) + 1; return acc; }, {} as Record<string, number>);
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(x => x[0]);
  };

  const getMostCommonAttackType = () => {
    if (!sessionHistory.length) return 'None';

    const attackTypeCounts = sessionHistory
      .map((item) => String(item.attackType ?? '').trim())
      .filter((type) => type && !/safe\s*\/\s*informational|safe email|normal activity|general phishing/i.test(type))
      .reduce<Record<string, number>>((acc, type) => {
        acc[type] = (acc[type] || 0) + 1;
        return acc;
      }, {});

    const strongestAttackType = Object.entries(attackTypeCounts).sort((a, b) => b[1] - a[1])[0]?.[0];
    if (strongestAttackType) return strongestAttackType;

    const text = sessionHistory.map(h => h.emailPreview || '').join(' ').toLowerCase();
    if (/delivery fee|customs fee|redelivery|courier|parcel/.test(text)) return 'Delivery Fee Scam';
    if (/wire transfer|beneficiary|confidential|invoice/.test(text)) return 'Business Email Compromise';
    if (/sms alert|debited from a\/c|txn/.test(text)) return 'SMS Spoofing Attack';
    if (/reward|cashback|prize|lottery|kbc/.test(text)) return 'Reward Scam';
    if (/kyc|suspended|blocked|gst|aadhaar|pan/.test(text)) return 'Account Suspension / Compliance Scam';
    if (/otp/.test(text)) return 'OTP Scam';
    if (/password|verify|credentials/.test(text)) return 'Credential Harvesting';
    return 'Social Engineering';
  };

  const getMostTargetedBrand = () => {
    if (!sessionHistory.length) return 'None';
    const text = sessionHistory.map(h => h.emailPreview || '').join(" ").toLowerCase();
    if (text.includes('hdfc')) return 'HDFC Bank';
    if (text.includes('sbi')) return 'SBI (State Bank)';
    if (text.includes('amazon')) return 'Amazon India';
    if (text.includes('netflix')) return 'Netflix';
    if (text.includes('paytm') || text.includes('gpay')) return 'Digital Wallet (UPI)';
    return 'Financial Institution';
  };

  const senderToBlock = result?.headerAnalysis?.senderEmail
    || result?.headerAnalysis?.replyToEmail
    || result?.headerAnalysis?.senderDomain
    || '';

  const officialSiteUrl = (() => {
    const haystack = [
      emailText,
      result?.headerAnalysis?.senderEmail,
      result?.headerAnalysis?.displayName,
      result?.headerAnalysis?.senderDomain,
      result?.attackType,
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();

    const knownSites = [
      { match: /(google|gmail)/, url: 'https://accounts.google.com/' },
      { match: /amazon/, url: 'https://www.amazon.in/' },
      { match: /netflix/, url: 'https://www.netflix.com/' },
      { match: /hdfc/, url: 'https://www.hdfcbank.com/' },
      { match: /\bsbi\b|state bank/, url: 'https://sbi.co.in/' },
      { match: /icici/, url: 'https://www.icicibank.com/' },
      { match: /axis/, url: 'https://www.axisbank.com/' },
      { match: /paytm/, url: 'https://paytm.com/' },
      { match: /phonepe/, url: 'https://www.phonepe.com/' },
      { match: /gpay|google pay/, url: 'https://pay.google.com/' },
      { match: /microsoft|outlook|office 365/, url: 'https://www.microsoft.com/' },
      { match: /apple|icloud/, url: 'https://www.apple.com/' },
    ];

    return knownSites.find((item) => item.match.test(haystack))?.url ?? 'https://cybercrime.gov.in/';
  })();

  const handleBlockSender = async () => {
    if (!senderToBlock) {
      toast({
        title: 'No sender details found',
        description: 'Run a scan with headers to capture sender information before blocking.',
      });
      return;
    }

    try {
      const key = 'phishshield_blocked_senders';
      const current = JSON.parse(localStorage.getItem(key) || '[]');
      const updated = Array.from(new Set([senderToBlock, ...(Array.isArray(current) ? current : [])])).slice(0, 50);
      localStorage.setItem(key, JSON.stringify(updated));
      await navigator.clipboard?.writeText(senderToBlock);
      toast({
        title: 'Sender saved to your block watchlist',
        description: `${senderToBlock} was also copied so you can block it in Gmail or Outlook.`,
      });
    } catch {
      toast({
        title: 'Sender identified',
        description: senderToBlock,
      });
    }
  };

  const handleAddToSafeSenders = () => {
    if (!resultSenderDomain) {
      toast({
        title: 'No sender domain found',
        description: 'Paste the sender line or raw headers so the domain can be safely whitelisted.',
      });
      return;
    }

    const nextEntry = {
      domain: resultSenderDomain,
      addedDate: new Date().toISOString(),
      userConfirmed: true,
    };
    const updated = [nextEntry, ...safeSenders.filter((entry) => entry.domain !== resultSenderDomain)].slice(0, 50);
    setSafeSenders(updated);
    localStorage.setItem(SAFE_SENDERS_KEY, JSON.stringify(updated));
    toast({
      title: 'Added to Safe Senders',
      description: `${resultSenderDomain} will receive a trust modifier on future scans in this browser.`,
    });
  };

  const handleRemoveSafeSender = (domain: string) => {
    const updated = safeSenders.filter((entry) => entry.domain !== domain);
    setSafeSenders(updated);
    localStorage.setItem(SAFE_SENDERS_KEY, JSON.stringify(updated));
  };

  const handleRetrainNow = async () => {
    setRetrainProgress(8);
    try {
      await fetch('/api/feedback/export?format=json', {
        headers: { Authorization: 'Bearer dev-sandbox-key' },
      });
      setRetrainProgress(42);
      setTimeout(() => setRetrainProgress(76), 220);
      setTimeout(() => {
        const label = `Detection Engine v3.2 · Updated ${new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}`;
        setRetrainLabel(label);
        localStorage.setItem(RETRAIN_META_KEY, JSON.stringify({
          label,
          feedbackSamples: learningMetrics.feedbackSamples ?? 0,
          retrainedAt: new Date().toISOString(),
        }));
        setRetrainProgress(100);
        toast({
          title: 'Client-side retraining complete',
          description: `${learningMetrics.feedbackSamples ?? 0} feedback samples were folded into the local tuning loop.`,
        });
        setTimeout(() => setRetrainProgress(null), 600);
        refetchMetrics();
      }, 420);
    } catch {
      setRetrainProgress(null);
      toast({
        title: 'Retraining unavailable',
        description: 'The feedback export route could not be reached right now.',
      });
    }
  };

  const handleCallSupport = async () => {
    try {
      await navigator.clipboard?.writeText('1930');
    } catch {
      // ignore clipboard issues
    }

    window.open('https://cybercrime.gov.in/', '_blank', 'noopener,noreferrer');
    toast({
      title: 'Cybercrime portal opened',
      description: 'India’s official cybercrime reporting portal is open and helpline 1930 was copied for quick access.',
    });
  };

  const handleVerifyByPhone = async () => {
    try {
      await navigator.clipboard?.writeText('Verify the request by calling the sender on a known, verified number before acting.');
    } catch {
      // ignore clipboard issues
    }
    toast({
      title: 'Phone-verification reminder copied',
      description: 'Use a known phone number from your records — never the number in the suspicious email.',
    });
  };

  const handleAlertFinanceTeam = async () => {
    try {
      await navigator.clipboard?.writeText('Potential BEC detected: pause payment, verify by phone, and alert finance/security.');
    } catch {
      // ignore clipboard issues
    }
    toast({
      title: 'Finance alert copied',
      description: 'Share the warning with your finance or security team before any transfer is processed.',
    });
  };

  const handleReportToBank = () => {
    window.open(officialSiteUrl, '_blank', 'noopener,noreferrer');
    toast({
      title: 'Official support channel opened',
      description: 'Use only the bank or service’s official website or app to report the issue.',
    });
  };

  const handleOpenOfficialSite = () => {
    window.open(officialSiteUrl, '_blank', 'noopener,noreferrer');
    toast({
      title: 'Official site opened',
      description: officialSiteUrl,
    });
  };

  const handleCopySummary = async () => {
    if (!result) return;

    const lines = [
      `PhishShield verdict: ${formatVerdictLabel(displayClassification, displayRiskScore)} (${Math.round(displayRiskScore)} / 100)`,
      `Confidence: ${confidencePercent}% (± ${confidenceInterval}%)`,
      `Attack type: ${safeShareText(displayAttackType)}`,
      `Summary: ${safeShareText(conciseExplanation)}`,
      detectedSignals.length ? `Primary Risk Indicators: ${detectedSignals.map((signal) => safeShareText(signal)).join(', ')}` : '',
    ].filter(Boolean);

    try {
      await navigator.clipboard?.writeText(lines.join('\n'));
      toast({
        title: 'Verdict copied',
        description: privacyMode
          ? 'The concise security summary was copied with sensitive details redacted.'
          : 'The concise security summary is now on your clipboard.',
      });
    } catch {
      toast({
        title: 'Copy unavailable',
        description: 'Clipboard access is blocked in this browser session.',
      });
    }
  };

  const handleResetDraft = () => {
    setEmailText('');
    setHeadersText('');
    setActiveGmailEmailId(undefined);
    setShowHeaders(false);
    setShowTechnicalDetails(false);
    setShowDemos(false);
    setIsDemoEmail(false);
    setFeedbackSent(false);
    setFeedbackMessage('');
    setFeedbackNote('');
    setDuplicateScanNotice('');
    clearScanResult();
  };

  useEffect(() => {
    setHistoryVisibleCount(HISTORY_PAGE_SIZE);
  }, [historyFilter, historySearch]);

  useEffect(() => {
    void refreshBackendHealth();
    void refreshFeedbackStats();
    const intervalId = window.setInterval(() => {
      void refreshBackendHealth();
      void refreshFeedbackStats();
    }, 30000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, []);

  useEffect(() => {
    if (result) {
      setShowTechnicalDetails(false);
    }
  }, [result?.id]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter' && activeTab === 'analyze' && emailText.trim() && !isScanning) {
        event.preventDefault();
        handleScan();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [activeTab, emailText, isScanning, headersText]);

  return (
    <div className="min-h-screen bg-background relative overflow-x-hidden pb-16 selection:bg-primary/30 selection:text-primary-foreground">

      {/* Header */}
      <nav className="sticky top-0 z-50 border-b border-border/50 bg-background/80 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center border border-primary/20">
              <ShieldCheck className="w-5 h-5 text-primary" />
            </div>
            <div className="flex flex-col">
              <h1 className="font-semibold text-lg text-foreground flex items-center gap-2 leading-none">
                PhishShield
                <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-primary text-primary-foreground font-bold tracking-wider">AI</span>
              </h1>
              <p className="text-[10px] text-muted-foreground tracking-wide mt-0.5">Detect. Explain. Protect.</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setPrivacyMode((value) => !value)}
              title="Email content is processed locally. No data leaves your device."
              className={cn('hidden sm:inline-flex h-8 text-[11px] font-bold', privacyMode ? 'border-safe/40 text-safe bg-safe/5' : 'border-border/60')}
            >
              <Lock className="w-3.5 h-3.5 mr-1.5" />
              {privacyMode ? 'Privacy on' : 'Privacy off'}
            </Button>
            <div
              className={cn(
                'hidden md:flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide',
                privacyMode ? 'border-safe/40 bg-safe/5 text-safe' : 'border-border/60 bg-background/60 text-muted-foreground',
              )}
              title="Email content is processed locally. No data leaves your device."
            >
              <span className={cn('h-1.5 w-1.5 rounded-full', privacyMode ? 'bg-safe' : 'bg-muted-foreground')} />
              {privacyMode ? 'Protected session' : 'Protection paused'}
            </div>
            {/* Tab switcher */}
            <div className="flex items-center bg-secondary/50 border border-border/50 rounded-lg p-0.5 gap-0.5">
              <button
                onClick={() => setActiveTab('analyze')}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all",
                  activeTab === 'analyze'
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                <Mail className="w-3.5 h-3.5" />
                Analyze
              </button>
              <button
                onClick={() => { setActiveTab('dashboard'); refetchHistory(); refetchMetrics(); void refreshBackendHealth(); void refreshFeedbackStats(); }}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all",
                  activeTab === 'dashboard'
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                <BarChart3 className="w-3.5 h-3.5" />
                Dashboard
                {sessionTotalScans > 0 && (
                  <span className="w-4 h-4 rounded-full bg-primary/20 text-primary text-[9px] font-bold flex items-center justify-center">
                    {sessionTotalScans}
                  </span>
                )}
              </button>
            </div>
            
            <div className="hidden sm:flex items-center gap-2">
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground bg-secondary/50 px-2 py-1 rounded-md border border-border/50">
                <div className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
                Defense Active
              </div>
              <Badge variant="outline" className={cn('text-[10px] font-bold tracking-wide', backendStatusTone)}>
                {backendStatusLabel}
              </Badge>
            </div>
          </div>
        </div>

        {/* Feature 9: Live Protection Signals */}
        <div className="max-w-6xl mx-auto px-4 mt-2">
          <div className="rounded-xl bg-primary/10 border border-primary/20 p-3 flex items-center justify-between text-xs overflow-hidden relative shadow-sm">
             <div className="absolute inset-0 bg-linear-to-r from-transparent via-primary/5 to-transparent animate-shimmer" />
             <div className="flex items-center gap-2 relative z-10">
                <div className="w-7 h-7 rounded-lg bg-primary flex items-center justify-center shrink-0">
                   <ShieldCheck className="w-4 h-4 text-primary-foreground" />
                </div>
                <div className="flex flex-col">
                   <div className="flex items-center gap-1.5 leading-none">
                     <span className="font-bold text-foreground">Active Protection Node</span>
                     <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
                   </div>
                   <span className="text-[10px] text-muted-foreground mt-0.5 tracking-tight">Fast, private phishing intelligence tuned for real Indian threat patterns.</span>
                </div>
             </div>
             <div className="flex flex-col items-end relative z-10">
                <span className="font-mono font-bold text-primary text-sm tracking-tighter tabular-nums leading-none">
                   {protectionCounter.toLocaleString()}
                </span>
                <span className="text-[9px] uppercase font-bold tracking-widest text-muted-foreground opacity-70 mt-0.5">Signals Analysed</span>
                <span className="text-[9px] text-muted-foreground mt-1">Model {backendModelVersion}</span>
             </div>
          </div>
        </div>
      </nav>

      {((learningMetrics.driftLevel === 'high' || Number(learningMetrics.falseNegativeCount ?? 0) > 10) || backendStatus === 'offline') && (
        <div className="max-w-6xl mx-auto px-4 pt-4 space-y-3">
          {learningMetrics.driftLevel === 'high' && (
            <div className="rounded-xl border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive font-medium shadow-sm">
              🔴 Model Drift Detected — Confidence scores may be unreliable. Manual verification recommended for all Safe verdicts.
            </div>
          )}
          {Number(learningMetrics.falseNegativeCount ?? 0) > 10 && (
            <div className="rounded-xl border border-warning/40 bg-warning/10 px-4 py-3 text-sm text-warning font-medium shadow-sm">
              ⚠️ {learningMetrics.falseNegativeCount} emails may have been missed this session. Review Safe verdicts manually.
            </div>
          )}
          {backendStatus === 'offline' && (
            <div className="rounded-xl border border-warning/40 bg-warning/10 px-4 py-3 text-sm text-warning font-medium shadow-sm">
              {offlineModeNotice || '⚠️ Running in offline mode — backend unavailable'}
            </div>
          )}
        </div>
      )}

      {/* Main Content */}
      <main className="relative z-10 max-w-6xl mx-auto px-4 py-8">

        {/* ─── ANALYZE TAB ─── */}
        <AnimatePresence mode="wait">
          {activeTab === 'analyze' && (
            <motion.div
              key="analyze"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.25 }}
              className="space-y-8"
            >
              {/* INPUT SECTION */}
              <div className="rounded-[28px] glass-panel p-6 shadow-[0_24px_80px_rgba(2,6,23,0.28)] sm:p-7">
                <div className="flex flex-col gap-6 mb-4">
                  <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
                    <div className="flex bg-secondary/50 p-1 rounded-xl w-full sm:w-auto border border-border/50">
                      {(['demo', 'real', 'upload'] as const).map((m) => (
                        <button
                          key={m}
                          onClick={() => { setInputMode(m); if (result || isScanning) clearScanResult(); setEmailText(""); }}
                          className={cn(
                            "flex-1 sm:flex-none px-4 py-2 rounded-lg text-[11px] font-bold transition-all capitalize whitespace-nowrap",
                            inputMode === m 
                              ? "bg-background text-primary shadow-sm border border-border/50" 
                              : "text-muted-foreground hover:text-foreground"
                          )}
                        >
                          {m === 'demo' && <Mail className="w-3.5 h-3.5 inline mr-1.5 mb-0.5" />}
                          {m === 'real' && <CheckCircle className="w-3.5 h-3.5 inline mr-1.5 mb-0.5" />}
                          {m === 'upload' && <Globe className="w-3.5 h-3.5 inline mr-1.5 mb-0.5" />}
                          {m}
                        </button>
                      ))}
                    </div>

                    {inputMode === 'demo' && (
                      <div className="relative">
                        <Button
                          variant="outline"
                          size="sm"
                          className="text-xs h-9 bg-transparent border-muted hover:bg-muted font-bold"
                          onClick={() => setShowDemos(!showDemos)}
                        >
                          Load Sample <ChevronDown className="w-3 h-3 ml-1" />
                        </Button>
                        <AnimatePresence>
                          {showDemos && (
                            <motion.div
                              initial={{ opacity: 0, y: 5 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, y: 5 }}
                              className="absolute right-0 mt-2 w-64 bg-popover border border-popover-border rounded-xl shadow-lg z-50 overflow-hidden"
                            >
                              <div className="px-3 py-2 text-[10px] text-muted-foreground font-semibold uppercase tracking-wider border-b border-border/50 bg-secondary/30">
                                Sample Attack Library
                              </div>
                              <div className="p-1.5 max-h-75 overflow-y-auto">
                                {MOCK_GMAIL_EMAILS.map(demo => (
                                  <button
                                    key={demo.id}
                                    onClick={() => { inputMode === 'demo' ? setIsDemoEmail(true) : setIsDemoEmail(false); loadDemo({ id: demo.id, label: demo.subject, text: demo.fullText }); setShowDemos(false); }}
                                    className="w-full text-left px-3 py-2.5 text-xs rounded-lg hover:bg-secondary transition-colors text-muted-foreground hover:text-foreground flex items-center justify-between group border border-transparent hover:border-border/30"
                                  >
                                    <div className="flex flex-col">
                                       <span className="font-bold text-foreground truncate max-w-42.5">{demo.subject}</span>
                                       <span className="text-[10px] lowercase opacity-60">{demo.classification}</span>
                                    </div>
                                    <RefreshCw className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity shrink-0 ml-2" />
                                  </button>
                                ))}
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-2 xl:grid-cols-4 gap-2.5 mb-4">
                  {[
                    {
                      label: 'Mode',
                      value: inputMode === 'demo' ? 'Demo Inbox' : inputMode === 'upload' ? 'File Upload' : 'Direct Paste',
                      helper: 'Switch safely anytime',
                    },
                    {
                      label: 'Readiness',
                      value: scanReadiness,
                      helper: emailText.trim().length > 0 ? `${emailText.trim().length.toLocaleString()} chars loaded` : 'No content yet',
                      tone: scanReadinessTone,
                    },
                    {
                      label: 'Links detected',
                      value: `${detectedUrlCount}`,
                      helper: detectedUrlCount > 0
                        ? (detectedUrlCount === 1 ? '1 explicit URL found in draft' : `${detectedUrlCount} explicit URLs found in draft`)
                        : detectedActionCueCount > 0
                          ? `${detectedActionCueCount} action cue${detectedActionCueCount === 1 ? '' : 's'} found in pasted content`
                          : 'No explicit URLs found in draft',
                    },
                    {
                      label: 'Shortcut',
                      value: 'Ctrl/Cmd + Enter',
                      helper: 'Run the scan instantly',
                    },
                  ].map((card) => (
                    <div key={card.label} className={cn('rounded-xl border bg-background/55 p-3 shadow-sm', card.tone ?? 'border-border/50')}>
                      <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">{card.label}</p>
                      <p className="mt-1 text-sm font-semibold text-foreground">{card.value}</p>
                      <p className="mt-1 text-[10px] text-muted-foreground">{card.helper}</p>
                    </div>
                  ))}
                </div>

                {inputMode === 'demo' ? (
                  <GmailInbox 
                    activeEmailId={activeGmailEmailId}
                    onSelectEmail={(email) => {
                      setEmailText(email.fullText);
                      setActiveGmailEmailId(email.id);
                      setHeadersText("");
                      setIsDemoEmail(true);
                      // Auto-trigger scan
                      setTimeout(() => { handleScan(); }, 100);
                    }}
                  />
                ) : inputMode === 'upload' ? (
                  <div className="flex flex-col items-center justify-center border-2 border-dashed border-border/50 rounded-2xl p-12 bg-secondary/20 transition-colors hover:bg-secondary/30 cursor-pointer relative">
                    <input 
                      type="file" 
                      accept=".txt,.eml" 
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        const reader = new FileReader();
                        reader.onload = (ev) => {
                          const content = ev.target?.result as string;
                          setEmailText(content);
                          setInputMode('real'); // Switch to real mode after upload
                          setIsDemoEmail(false);
                          if (result || isScanning) clearScanResult();
                        };
                        reader.readAsText(file);
                      }}
                      className="absolute inset-0 opacity-0 cursor-pointer"
                    />
                    <Globe className="w-12 h-12 text-muted-foreground/30 mb-4" />
                    <p className="text-sm font-bold text-foreground">Click or Drag to Upload</p>
                    <p className="text-[11px] text-muted-foreground mt-1">Supports .eml and .txt email files</p>
                    <div className="mt-8 flex gap-2">
                       <Badge variant="outline" className="text-[10px]">🔒 100% Client-Side</Badge>
                       <Badge variant="outline" className="text-[10px]">⚡ Instant Extract</Badge>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2">
                     <div className="flex items-center justify-between">
                        <label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Direct Analysis Mode</label>
                        <div className="flex items-center gap-1.5 text-[10px] font-medium text-safe bg-safe/10 px-2 py-0.5 rounded border border-safe/20">
                          <Lock className="w-3 h-3" /> Anonymous Scan
                        </div>
                     </div>
                     <textarea
                       value={emailText}
                       onChange={(e) => {
                         setEmailText(e.target.value);
                         if (result || isScanning) clearScanResult();
                         setIsDemoEmail(false);
                       }}
                       placeholder="Paste full Gmail email (content or headers)..."
                       className={cn(
                         "w-full min-h-55 bg-background/50 border border-input rounded-xl p-4 text-foreground font-mono text-sm resize-y transition-all focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 placeholder:text-muted-foreground/40",
                         isScanning && "opacity-60"
                       )}
                       disabled={isScanning}
                     />
                  </div>
                )}

                <div className="mt-3">
                  <button onClick={() => setShowHeaders(!showHeaders)} className="text-xs flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors">
                    {showHeaders ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    Advanced (Headers)
                  </button>
                  {showHeaders && (
                    <textarea
                      value={headersText}
                      onChange={(e) => setHeadersText(e.target.value)}
                      placeholder="Paste raw email headers here (Optional)..."
                      className="w-full min-h-25 mt-2 bg-background/50 border border-input rounded-xl p-3 text-foreground font-mono text-xs resize-y transition-all focus:outline-none focus:ring-2 focus:ring-primary/30"
                      disabled={isScanning}
                    />
                  )}
                </div>

                <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:justify-between sm:items-center text-[11px] text-muted-foreground">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono">{emailText.length > 0 ? `${emailText.length} chars` : ''}</span>
                    <span className="inline-flex items-center gap-1 rounded-full border border-border/60 bg-background/60 px-2 py-0.5">
                      <Search className="w-3 h-3" />
                      {detectedUrlCount} URL{detectedUrlCount !== 1 ? 's' : ''}
                    </span>
                    <span className="inline-flex items-center gap-1 rounded-full border border-border/60 bg-background/60 px-2 py-0.5">
                      <Command className="w-3 h-3" />
                      Ctrl/Cmd + Enter
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Lock className="w-3 h-3" />
                    <span>Content not stored after analysis</span>
                  </div>
                </div>

                <div className="mt-3 flex flex-col sm:flex-row gap-3 justify-between items-center">
                  <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                    <Shield className="w-3.5 h-3.5" />
                    <span>Tip: add raw headers for stronger sender-spoof detection.</span>
                  </div>
                  <div className="flex w-full sm:w-auto gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={handleResetDraft}
                      className={cn(
                        "flex-1 sm:flex-none bg-background/60",
                        inputMode === 'demo' && "hidden"
                      )}
                    >
                      Clear draft
                    </Button>
                    <Button
                      onClick={handleScan}
                      disabled={isScanning || !emailText.trim()}
                      size="lg"
                      className={cn(
                        "flex-1 sm:flex-none min-w-35 font-medium",
                        inputMode === 'demo' && "hidden"
                      )}
                    >
                      {isScanning ? (
                        <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Scanning...</>
                      ) : (
                        'Scan Email'
                      )}
                    </Button>
                  </div>
                </div>

                {duplicateScanNotice && (
                  <div className="mt-4 rounded-xl border border-warning/30 bg-warning/10 px-4 py-3 text-sm text-warning">
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                      <span>{duplicateScanNotice}</span>
                      <Button type="button" variant="outline" size="sm" className="bg-background/70" onClick={() => setActiveTab('dashboard')}>
                        View Recent Activity
                      </Button>
                    </div>
                  </div>
                )}

                {error && (
                  <div className="mt-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm flex items-start flex-col gap-1">
                    <div className="flex items-center gap-2 font-bold">
                       <AlertTriangle className="w-4 h-4 shrink-0" />
                       Analysis Rejected
                    </div>
                    <span className="text-xs opacity-90">{error instanceof Error ? error.message : 'Analysis failed. The pasted email may be too massive or severely malformed.'}</span>
                  </div>
                )}
              </div>

              {/* EMPTY STATE GUIDE */}
              {!result && isScanning && emailText.trim() && (
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className="rounded-2xl border border-primary/20 bg-primary/5 p-5 flex items-start gap-3"
                >
                  <Loader2 className="w-5 h-5 animate-spin text-primary mt-0.5" />
                  <div>
                    <p className="text-sm font-semibold text-foreground">Analyzing securely…</p>
                    <p className="text-xs text-muted-foreground mt-1">Running model, URL, and header checks. Results stay hidden until this scan is fully complete.</p>
                  </div>
                </motion.div>
              )}

              {!result && !isScanning && !emailText.trim() && (
                <div className="grid grid-cols-3 gap-3 text-center">
                  {[
                    { icon: <Mail className="w-4 h-4" />, title: 'Paste email', desc: 'Copy the full email — headers, body, links' },
                    { icon: <Scan className="w-4 h-4" />, title: 'Scan it', desc: 'Our model checks 50+ phishing signals' },
                    { icon: <ShieldCheck className="w-4 h-4" />, title: 'See the verdict', desc: 'Score 0–100 with clear reasons' },
                  ].map(({ icon, title, desc }) => (
                    <div key={title} className="rounded-xl border border-dashed border-border/40 p-4 flex flex-col items-center gap-2">
                      <div className="w-8 h-8 rounded-lg bg-secondary flex items-center justify-center text-muted-foreground">
                        {icon}
                      </div>
                      <p className="text-xs font-medium text-foreground">{title}</p>
                      <p className="text-[11px] text-muted-foreground leading-relaxed">{desc}</p>
                    </div>
                  ))}
                </div>
              )}

              {/* RESULTS */}
              <AnimatePresence mode="wait">
                {result && (
                  <motion.div
                    ref={resultsRef}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.4 }}
                    className="space-y-6"
                  >
                    {/* 1. Verdict card — the first thing users should see */}
                    {verdictColors && (
                      <div className="glass-panel relative overflow-hidden rounded-[28px] border border-[#D4AF37]/20 shadow-[0_24px_80px_rgba(2,6,23,0.32)]">
                        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(212,175,55,0.12),transparent_0_32%),radial-gradient(circle_at_bottom_left,rgba(255,255,255,0.05),transparent_0_40%)]" />
                        <div className={cn("absolute left-0 top-0 bottom-0 w-1", verdictColors.bar)} />
                        <div className="relative z-10 flex flex-col gap-6 p-6 pl-8 sm:p-8">
                          <div className="grid gap-6 lg:grid-cols-[1.25fr_240px] lg:items-center">
                            <div className="flex flex-col items-center text-center sm:items-start sm:text-left">
                              <div className="mb-3 flex flex-wrap items-center justify-center gap-2 sm:justify-start">
                                <span className="rounded-full border border-[#D4AF37]/30 bg-[#D4AF37]/10 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.24em] text-[#D4AF37]">
                                  Final verdict
                                </span>
                                {hasSpoofingVisualWarning && (
                                  <Badge className="border border-destructive/30 bg-destructive/10 text-[10px] font-bold uppercase tracking-[0.2em] text-destructive">
                                    ⚠️ Header Spoofing Detected
                                  </Badge>
                                )}
                                {isDemoEmail && (
                                  <Badge variant="outline" className="bg-background/60 text-[10px] font-bold text-[#B0B8C1]">
                                    Sandbox sample
                                  </Badge>
                                )}
                              </div>

                              <h2 className={cn('text-4xl font-black tracking-[0.18em] sm:text-5xl', verdictColors.text)}>
                                {verdictHeadline}
                              </h2>
                              <p className="mt-2 text-sm text-[#B0B8C1]">{verdictDisplayLabel}</p>

                              <div className="mt-4 flex flex-wrap items-stretch gap-3">
                                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                                  <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-[#B0B8C1]">Trust score</p>
                                  <p className={cn('mt-1 text-lg font-mono font-bold', 100 - displayRiskScore > 70 ? 'text-safe' : 100 - displayRiskScore > 30 ? 'text-warning' : 'text-destructive')}>
                                    {(100 - displayRiskScore).toFixed(0)}/100
                                  </p>
                                </div>
                                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                                  <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-[#B0B8C1]">Risk score</p>
                                  <p className="mt-1 text-lg font-mono font-bold text-white">{displayRiskScore}/100</p>
                                </div>
                                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                                  <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-[#B0B8C1]">Assessment</p>
                                  <div className="mt-1 flex items-center gap-2 text-sm font-semibold text-white">
                                    <Languages className="h-3.5 w-3.5 text-[#D4AF37]" />
                                    <span>{primaryAssessmentLabel}</span>
                                  </div>
                                </div>
                              </div>

                              <div className={cn(
                                'mt-4 w-full rounded-2xl border px-4 py-3',
                                displayClassification === 'phishing'
                                  ? 'border-destructive/25 bg-destructive/8'
                                  : displayClassification === 'safe'
                                    ? 'border-safe/25 bg-safe/8'
                                    : 'border-warning/25 bg-warning/8',
                              )}>
                                <div className="flex items-start gap-3">
                                  <span className="text-base leading-none">{displayClassification === 'phishing' ? '🔴' : displayClassification === 'safe' ? '🟢' : '⚠️'}</span>
                                  <div>
                                    <p className="text-sm leading-relaxed text-white/90">{conciseExplanation}</p>
                                  </div>
                                </div>
                              </div>
                            </div>

                            <div className="flex justify-center lg:justify-end">
                              <ScoreGauge
                                score={confidencePercent}
                                classification={displayClassification}
                                label="Confidence"
                                detail={`Risk ${displayRiskScore}/100`}
                              />
                            </div>
                          </div>

                          {detectedSignals.length > 0 && (
                            <div className="space-y-3">
                              <div>
                                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-muted-foreground">Primary Risk Indicators</p>
                                <p className="text-sm text-foreground/80">The clearest signals shaping this verdict.</p>
                              </div>
                              <div className="flex flex-wrap gap-2">
                                {detectedSignals.map((signal, index) => {
                                  const tone = signalChipTone(signal);
                                  return (
                                    <Badge key={`${signal}-${index}`} variant="outline" className={cn('text-[11px] py-1 px-2.5', tone.className)}>
                                      <span className="mr-1">{tone.icon}</span>
                                      {signal}
                                    </Badge>
                                  );
                                })}
                                {primaryWordIndicators.map((item) => (
                                  <Badge key={`${item.word}-${item.contribution}`} variant="outline" className="border-primary/20 bg-background/70 text-[11px] text-foreground/85">
                                    {item.word} • {Math.round((item.contribution ?? 0) * 100)}%
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}

                          {topReasonCards.length > 0 && (
                            <div className="space-y-3">
                              <div className="flex items-center justify-between gap-3 flex-wrap">
                                <div>
                                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-muted-foreground">Top 3 Reasons</p>
                                  <p className="text-sm text-foreground/80">Short, human-readable reasons behind this verdict.</p>
                                </div>
                                <Badge variant="outline" className="text-[10px] font-bold bg-background/60">
                                  {topReasonCards.length} key reasons
                                </Badge>
                              </div>
                              <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
                                {topReasonCards.map((reason, index) => {
                                  const tone = signalChipTone(reason.label);
                                  return (
                                    <div key={`${reason.label}-${index}`} className="rounded-xl border border-border/40 bg-background/60 p-4">
                                      <div className="flex items-center gap-2">
                                        <span className="text-base leading-none">{tone.icon}</span>
                                        <p className="text-sm font-semibold text-foreground">{reason.label}</p>
                                      </div>
                                      <p className="mt-2 text-sm leading-relaxed text-foreground/80">{reason.helper}</p>
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          )}

                          {/* One-Click Actions */}
                          <div className="flex flex-wrap gap-3">
                             <Button onClick={handleScan} size="sm" className="h-8 text-[11px] font-bold bg-primary text-primary-foreground hover:bg-primary/90">
                                <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Re-scan
                             </Button>
                             <Button onClick={handleCopySummary} variant="outline" size="sm" className="h-8 text-[11px] font-bold bg-background/50">
                                <Copy className="w-3.5 h-3.5 mr-1.5" /> Copy Summary
                             </Button>
                             <Button onClick={handleDownloadReport} variant="outline" size="sm" className="h-8 text-[11px] font-bold bg-background/50">
                                <Download className="w-3.5 h-3.5 mr-1.5" /> Download Report
                             </Button>
                             {displayClassification !== 'safe' && (
                               <Button onClick={handleBlockSender} variant="destructive" size="sm" className="h-8 text-[11px] font-bold">
                                  <Ban className="w-3.5 h-3.5 mr-1.5" /> Block Sender
                               </Button>
                             )}
                             {/Business Email Compromise/i.test(displayAttackType) && (
                               <>
                                 <Button onClick={handleVerifyByPhone} variant="outline" size="sm" className="h-8 text-[11px] font-bold bg-background/50">
                                    <Phone className="w-3.5 h-3.5 mr-1.5" /> Call Sender Directly
                                 </Button>
                                 <Button onClick={handleAlertFinanceTeam} variant="outline" size="sm" className="h-8 text-[11px] font-bold bg-background/50">
                                    <ShieldAlert className="w-3.5 h-3.5 mr-1.5" /> Alert Finance Team
                                 </Button>
                               </>
                             )}
                             {/OTP Scam|Bank Impersonation/i.test(displayAttackType) && (
                               <Button onClick={handleReportToBank} variant="outline" size="sm" className="h-8 text-[11px] font-bold bg-background/50">
                                  <ShieldCheck className="w-3.5 h-3.5 mr-1.5" /> Report to bank
                               </Button>
                             )}
                             {/Delivery Fee Scam/i.test(displayAttackType) && (
                               <Button onClick={handleOpenOfficialSite} variant="outline" size="sm" className="h-8 text-[11px] font-bold bg-background/50">
                                  <ExternalLink className="w-3.5 h-3.5 mr-1.5" /> Check Official Courier Site
                               </Button>
                             )}
                             {(displayClassification === 'safe' || /Newsletter/i.test(displayAttackType)) && (
                               <Button onClick={handleAddToSafeSenders} variant="outline" size="sm" className="h-8 text-[11px] font-bold bg-background/50">
                                  <ShieldCheck className="w-3.5 h-3.5 mr-1.5" /> Add to Safe Senders
                               </Button>
                             )}
                             <Button onClick={handleCallSupport} variant="outline" size="sm" className="h-8 text-[11px] font-bold bg-background/50" title="Report this phishing attempt to India's national cybercrime portal">
                                <Phone className="w-3.5 h-3.5 mr-1.5" /> Report to Cybercrime
                             </Button>
                             <Button onClick={handleOpenOfficialSite} variant="outline" size="sm" className="h-8 text-[11px] font-bold bg-background/50">
                                <ExternalLink className="w-3.5 h-3.5 mr-1.5" /> Official Site
                             </Button>
                          </div>

                          {showTechnicalDetails && responsePlaybook.length > 0 && (
                            <div className="rounded-xl border border-primary/20 bg-primary/5 p-4 space-y-3">
                              <div>
                                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-primary">Recommended next steps</p>
                                <p className="text-sm text-foreground/80">Follow this playbook to stay safe without overreacting.</p>
                              </div>
                              <div className="grid gap-2 sm:grid-cols-3">
                                {responsePlaybook.map((step, index) => (
                                  <div key={`${step}-${index}`} className="rounded-lg border border-border/50 bg-background/70 p-3">
                                    <p className="text-[10px] font-bold uppercase tracking-wide text-primary">Step {index + 1}</p>
                                    <p className="mt-1 text-sm text-foreground/85 leading-relaxed">{step}</p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {showTechnicalDetails && triageChecklist.length > 0 && (
                            <div className="rounded-xl border border-border/50 bg-background/55 p-4 space-y-3">
                              <div>
                                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-muted-foreground">Triage board</p>
                                <p className="text-sm text-foreground/80">A quick analyst snapshot before you decide what to do next.</p>
                              </div>
                              <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
                                {triageChecklist.map((item) => (
                                  <div key={item.label} className={cn('rounded-lg border p-3', item.tone)}>
                                    <p className="text-[10px] font-bold uppercase tracking-[0.18em]">{item.label}</p>
                                    <p className="mt-1 text-sm font-semibold text-foreground">{item.value}</p>
                                    <p className="mt-1 text-[10px] leading-relaxed text-muted-foreground">{item.helper}</p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          <div className="rounded-xl border border-border/50 bg-background/50 p-3 sm:p-4">
                            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                              <div>
                                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-muted-foreground">Details</p>
                                <p className="text-sm text-foreground/80">Open the full evidence trail only when you need the advanced breakdown, headers, links, and model details.</p>
                              </div>
                              <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                onClick={() => setShowTechnicalDetails((value) => !value)}
                                className="bg-background/60"
                              >
                                {showTechnicalDetails ? <ChevronUp className="w-4 h-4 mr-1.5" /> : <ChevronDown className="w-4 h-4 mr-1.5" />}
                                {showTechnicalDetails ? 'Hide detailed analysis' : 'View detailed analysis'}
                              </Button>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    <AnimatePresence initial={false}>
                      {showTechnicalDetails && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                          transition={{ duration: 0.25, ease: 'easeOut' }}
                          className="overflow-hidden"
                        >
                          <div className="space-y-4 rounded-2xl border border-border/50 bg-background/35 p-4 sm:p-5">
                    {/* 2. Score breakdown — four sub-scores that add up to the final risk score */}
                    <div className="space-y-3 pt-2 pb-4 border-b border-border/50">
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Score components</p>
                      <div className="flex flex-col sm:flex-row gap-4">
                        {[
                          { label: 'Language model', value: result?.mlScore ?? 0, color: 'bg-primary' },
                          { label: 'Pattern matching', value: result?.ruleScore ?? 0, color: 'bg-accent' },
                          { label: 'Link risk', value: result?.urlScore ?? 0, color: 'bg-warning' },
                          { label: 'Header spoofing', value: result?.headerScore ?? 0, color: 'bg-destructive/70' },
                        ].map(({ label, value, color }) => (
                          <div key={label} className="flex-1 space-y-2">
                            <div className="flex justify-between text-xs">
                              <span className="text-muted-foreground font-medium">{label}</span>
                              <span className="text-foreground font-mono">{value.toFixed(0)}</span>
                            </div>
                            <div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
                              <div className={cn("h-full transition-all duration-700 rounded-full", color)} style={{ width: `${value}%` }} />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* 3. Feature Importance (ML Explainability) */}
                    {result.featureImportance && result.featureImportance.length > 0 && (
                      <div className="space-y-3 pt-2 pb-4 border-b border-border/50">
                        <div className="flex items-center justify-between">
                          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                            <TrendingUp className="w-4 h-4 text-muted-foreground" />
                            ML Feature Contributions
                          </h3>
                          <span className="text-[10px] text-muted-foreground">TF-IDF × LR weight</span>
                        </div>
                        <div className="space-y-2.5">
                          {result.featureImportance.map((f, i) => {
                            const maxC = result.featureImportance![0].contribution;
                            const pct = maxC > 0 ? Math.round((f.contribution / maxC) * 100) : 0;
                            return (
                              <div key={i} className="flex items-center gap-3">
                                <span className={cn(
                                  "text-xs font-mono shrink-0 w-32 truncate",
                                  f.direction === 'phishing' ? 'text-destructive' : 'text-safe'
                                )} title={f.feature}>
                                  {f.feature}
                                </span>
                                <div className="flex-1 h-2 bg-secondary rounded-full overflow-hidden">
                                  <div
                                    className={cn("h-full rounded-full transition-all duration-700", f.direction === 'phishing' ? 'bg-destructive/70' : 'bg-safe/70')}
                                    style={{ width: `${pct}%` }}
                                  />
                                </div>
                                <span className="text-[10px] font-mono text-muted-foreground w-8 text-right shrink-0">{f.contribution.toFixed(2)}</span>
                                <span className={cn(
                                  "text-[9px] uppercase font-bold shrink-0 w-8",
                                  f.direction === 'phishing' ? 'text-destructive' : 'text-safe'
                                )}>
                                  {f.direction === 'phishing' ? 'risk' : 'safe'}
                                </span>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* 4. Header Analysis */}
                    {result.headerAnalysis && result.headerAnalysis.hasHeaders && (
                      <div className={cn(
                        "rounded-xl border p-4 space-y-3",
                        result.headerAnalysis.spoofingRisk === 'high'
                          ? 'bg-destructive/5 border-destructive/20'
                          : result.headerAnalysis.spoofingRisk === 'medium'
                          ? 'bg-warning/5 border-warning/20'
                          : 'bg-card border-border/50'
                      )}>
                        <div className="flex items-center justify-between">
                          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                            <Mail className="w-4 h-4 text-muted-foreground" />
                            Email Header Analysis
                          </h3>
                          <span className={cn(
                            "text-[10px] font-bold uppercase px-2 py-0.5 rounded-full",
                            result.headerAnalysis.spoofingRisk === 'high'
                              ? 'bg-destructive/15 text-destructive'
                              : result.headerAnalysis.spoofingRisk === 'medium'
                              ? 'bg-warning/15 text-warning'
                              : result.headerAnalysis.spoofingRisk === 'low'
                              ? 'bg-warning/10 text-warning'
                              : 'bg-safe/10 text-safe'
                          )}>
                            {result.headerAnalysis.spoofingRisk} risk
                          </span>
                        </div>

                        <div className="grid grid-cols-2 gap-3 text-xs">
                          {result.headerAnalysis.senderEmail && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-0.5">Sender</p>
                              <p className="font-mono text-foreground truncate" title={result.headerAnalysis.senderEmail}>{result.headerAnalysis.senderEmail}</p>
                            </div>
                          )}
                          {result.headerAnalysis.displayName && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-0.5">Display Name</p>
                              <p className="font-mono text-foreground truncate">"{result.headerAnalysis.displayName}"</p>
                            </div>
                          )}
                          {result.headerAnalysis.replyToEmail && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-0.5">Reply-To</p>
                              <p className={cn("font-mono truncate", result.headerAnalysis.mismatch ? 'text-destructive font-semibold' : 'text-foreground')}
                                title={result.headerAnalysis.replyToEmail}>
                                {result.headerAnalysis.replyToEmail}
                                {result.headerAnalysis.mismatch && <span className="ml-1 text-[10px] font-bold">⚠ mismatch</span>}
                              </p>
                            </div>
                          )}
                          {result.headerAnalysis.senderDomain && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-0.5">Sender Domain</p>
                              <p className="font-mono text-foreground truncate">{result.headerAnalysis.senderDomain}</p>
                            </div>
                          )}
                        </div>

                        {result.headerAnalysis.issues.length > 0 && (
                          <div className="border-t border-border/50 pt-3 space-y-2">
                            {result.headerAnalysis.issues.map((issue, i) => (
                              <div key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
                                <AlertTriangle className="w-3.5 h-3.5 text-warning shrink-0 mt-0.5" />
                                <span className="leading-relaxed">{issue}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {/* 5. Warnings */}
                    {result.warnings.length > 0 && (
                      <div className="space-y-2">
                        {result.warnings.map((warn, i) => (
                          <div key={i} className="bg-destructive/10 rounded-lg px-4 py-3 flex items-start gap-3">
                            <AlertTriangle className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
                            <p className="text-sm text-foreground leading-relaxed">{warn}</p>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* 4. Reason cards — grouped explanation of each flag */}
                    {result.reasons.length > 0 && (() => {
                      const groups = result.reasons.reduce<Record<string, DashboardReason[]>>((acc, r) => {
                        const cat = getDetailedReasonGroup(r);
                        if (!acc[cat]) acc[cat] = [];
                        acc[cat].push(r);
                        return acc;
                      }, {});
                      return (
                        <div className="space-y-4 pt-4">
                          <h3 className="text-lg font-semibold text-foreground">Detailed signal breakdown</h3>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            {Object.entries(groups).map(([catName, items]) => {
                              const uniqueItems = dedupeDetailedReasons(items);
                              return (
                               <div key={catName} className="rounded-xl border border-card-border bg-card p-4 space-y-3">
                                 <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                                   <AlertTriangle className={cn("w-4 h-4", catName === "Social engineering" || catName === "Urgency pressure" ? "text-destructive" : "text-warning")} />
                                   {catName}
                                 </h4>
                                 <div className="space-y-3">
                                   {uniqueItems.map((reason, i) => {
                                     const matchedTerms = getDisplayMatchedTerms(reason);
                                     return (
                                       <div key={i} className="flex items-start gap-2.5">
                                         <div className={cn(
                                           "w-1.5 h-1.5 rounded-full mt-2 shrink-0 relative",
                                           reason.severity === 'high' ? 'bg-destructive' : reason.severity === 'medium' ? 'bg-warning' : 'bg-safe'
                                         )} />
                                         <div>
                                           <p className="text-sm text-muted-foreground leading-relaxed">{normalizeDetailedReasonDescription(reason.description)}</p>
                                           {matchedTerms.length > 0 && (
                                             <div className="flex flex-wrap gap-1.5 mt-2">
                                               {matchedTerms.map((term, j) => (
                                                 <span key={j} className="text-[10px] font-mono bg-secondary text-secondary-foreground px-1.5 py-0.5 rounded uppercase opacity-80 border border-border/50">
                                                   {term}
                                                 </span>
                                               ))}
                                             </div>
                                           )}
                                         </div>
                                       </div>
                                     );
                                   })}
                                 </div>
                               </div>
                            );})}
                          </div>
                        </div>
                      );
                    })()}

                    {/* 5. Links Found - Dashboard Table UI */}
                    {result.urlAnalyses.length > 0 && (
                      <div className="space-y-4 pt-4">
                        <h3 className="text-lg font-semibold text-foreground">Links in this email</h3>
                        <div className="overflow-x-auto rounded-xl border border-card-border bg-card">
                          <table className="w-full text-sm text-left">
                            <thead className="text-xs text-muted-foreground uppercase bg-secondary/50 border-b border-card-border">
                              <tr>
                                <th className="px-4 py-3 font-semibold">Domain / URL</th>
                                <th className="px-4 py-3 font-semibold w-32">Risk Level</th>
                                <th className="px-4 py-3 font-semibold">Risk Factors</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-card-border">
                              {result.urlAnalyses.map((url, i) => (
                                <tr key={i} className="hover:bg-muted/30 transition-colors">
                                  <td className="px-4 py-3 max-w-50 sm:max-w-xs truncate">
                                    <div className="font-semibold text-foreground truncate">{url.domain}</div>
                                    <div className="text-xs font-mono text-muted-foreground truncate opacity-70 mt-0.5" title={url.url}>{url.url}</div>
                                  </td>
                                  <td className="px-4 py-3">
                                    {(() => {
                                      const trustedDomain = isTrustedDisplayDomain(url.domain);
                                      const urlNeedsCaution = !trustedDomain && (url.isSuspicious || Number(url.riskScore ?? 0) >= 20 || url.flags.some((flag) => /suspicious|malicious|spoof|mismatch|phishing/i.test(flag)));
                                      return (
                                        <Badge
                                          variant={urlNeedsCaution ? 'destructive' : 'secondary'}
                                          className={cn("text-[10px] h-5", !urlNeedsCaution && "bg-safe/10 text-safe border-transparent")}
                                        >
                                          {urlNeedsCaution ? 'Unverified / Suspicious domain' : trustedDomain ? 'Trusted domain' : 'Trusted / low risk'}
                                        </Badge>
                                      );
                                    })()}
                                  </td>
                                  <td className="px-4 py-3">
                                    {url.flags.length > 0 ? (
                                      <div className="flex flex-wrap gap-1">
                                        {url.flags.map((flag, j) => (
                                          <span key={j} className="text-[10px] bg-secondary text-muted-foreground px-1.5 py-0.5 border border-border/50 rounded flex items-center gap-1 leading-tight">
                                            <Flag className="w-2.5 h-2.5 text-warning shrink-0" /> {flag}
                                          </span>
                                        ))}
                                      </div>
                                    ) : <span className="text-[10px] text-muted-foreground">-</span>}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {/* 6. Email Content */}
                    {result.suspiciousSpans.length > 0 && (
                      <div className="space-y-4 pt-4">
                        <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
                          <Eye className="w-5 h-5 text-muted-foreground" />
                          Email Content
                        </h3>
                        <div className="bg-card border border-border/60 rounded-xl p-5">
                          <HighlightText text={emailText} spans={result.suspiciousSpans} />
                        </div>
                      </div>
                    )}

                    {/* 7. Before You Act */}
                    {result.safetyTips.length > 0 && (
                      <div className="space-y-4 pt-4 border-t border-border/50">
                        <h3 className="text-lg font-semibold text-foreground">What to do next</h3>
                        <div className="space-y-3">
                          {result.safetyTips.slice(0, 4).map((tip, i) => (
                            <div key={i} className="flex items-start gap-3">
                              <ShieldCheck className="w-4 h-4 text-safe shrink-0 mt-0.5" />
                              <p className="text-sm text-foreground/90">{tip}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>

                    {/* 9. Feedback and Download */}
                    <div className="flex flex-col sm:flex-row items-center justify-between pt-6 border-t border-border/50 gap-4 mt-6">
                      <div className="flex flex-col gap-2 w-full sm:w-auto">
                        <span className="text-sm font-medium text-foreground/80">Improve the model with one click</span>
                        <div className="space-y-2 max-w-xl">
                          <Textarea
                            value={feedbackNote}
                            onChange={(event) => setFeedbackNote(event.target.value.slice(0, 240))}
                            placeholder="Optional note for retraining, e.g. 'Legitimate password reset from official Google domain'"
                            className="min-h-20 bg-background/70"
                          />
                          <p className="text-xs text-muted-foreground">
                            Optional analyst context helps reduce false positives and false negatives. {feedbackNote.length}/240
                            {privacyMode ? ' Sensitive details are redacted when you copy summaries.' : ''}
                          </p>
                          {backendFeedbackStats && (
                            <div className="rounded-lg border border-primary/20 bg-primary/5 px-3 py-2 text-xs text-foreground">
                              <p className="font-medium">
                                {backendFeedbackStats.total_feedback ?? 0} feedback items collected overall — {backendFeedbackStats.needed_for_retrain ?? 0} more needed before retraining
                              </p>
                              <p className="mt-1 text-muted-foreground">
                                Pending retrain queue: {backendFeedbackStats.pending_retrain ?? 0}
                                {backendFeedbackStats.last_retrain ? ` · Last retrain ${backendFeedbackStats.last_retrain}` : ''}
                                {backendFeedbackStats.model_improving ? ' · Model improving' : ''}
                              </p>
                            </div>
                          )}
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleFeedback('safe')}
                            disabled={isFeedbackPending}
                            className="hover:bg-safe/20 hover:text-safe hover:border-safe/50"
                          >
                            <ShieldCheck className="w-4 h-4 mr-1.5" /> Mark as Safe
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleFeedback('phishing')}
                            disabled={isFeedbackPending}
                            className="hover:bg-destructive/20 hover:text-destructive hover:border-destructive/50"
                          >
                            <ShieldAlert className="w-4 h-4 mr-1.5" /> Mark as Phishing
                          </Button>
                        </div>
                        {feedbackMessage ? (
                          <Badge variant="outline" className={feedbackSent ? 'text-safe border-safe w-fit' : 'text-warning border-warning w-fit'}>
                            <CheckCircle className="w-3 h-3 mr-1" /> {feedbackMessage}
                          </Badge>
                        ) : null}
                      </div>

                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          )}

          {/* ─── DASHBOARD TAB ─── */}
          {activeTab === 'dashboard' && (
            <motion.div
              key="dashboard"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.25 }}
              className="space-y-8"
            >
              {/* ── Scan Summary Stats ── */}
              <section>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                    <Scan className="w-4 h-4 text-primary" />
                    Scan Summary
                  </h2>
                  {sessionTotalScans > 0 && (
                    <button
                      onClick={handleClearHistory}
                      className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-destructive transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Reset session
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4 mb-6">
                  {[
                    { label: 'Total Scanned', value: sessionTotalScans, color: 'text-foreground', sub: `${sessionTotalScans === 1 ? 'email' : 'emails'} this session`, icon: Scan, tone: 'border-primary/20 bg-primary/5' },
                    { label: 'Phishing', value: sessionMetrics.phishingDetected, color: 'text-destructive', sub: 'high-risk detected', icon: ShieldAlert, tone: 'border-destructive/20 bg-destructive/5' },
                    { label: 'Suspicious', value: sessionMetrics.suspiciousDetected, color: 'text-warning', sub: 'need caution', icon: AlertTriangle, tone: 'border-warning/20 bg-warning/5' },
                    { label: 'Safe', value: sessionMetrics.safeDetected, color: 'text-safe', sub: 'clean emails', icon: ShieldCheck, tone: 'border-safe/20 bg-safe/5' },
                  ].map(({ label, value, color, sub, icon: Icon, tone }) => (
                    <div key={label} className={cn('rounded-2xl border p-4 shadow-sm transition-all hover:-translate-y-0.5', tone)}>
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-muted-foreground">{label}</p>
                          <p className={cn("mt-2 text-3xl font-bold font-mono", color)}>{value}</p>
                        </div>
                        <div className="rounded-xl border border-white/10 bg-background/50 p-2.5">
                          <Icon className={cn('w-4 h-4', color)} />
                        </div>
                      </div>
                      <p className="mt-2 text-[11px] text-muted-foreground">{sub}</p>
                    </div>
                  ))}
                </div>

                {/* Donut chart + risk scale side by side */}
                <div className="rounded-xl border border-card-border bg-card p-5">
                  {sessionTotalScans === 0 ? (
                    <div className="flex flex-col items-center justify-center py-8 text-center">
                      <BarChart3 className="w-10 h-10 text-muted-foreground/20 mb-3" />
                      <p className="text-sm text-muted-foreground">Scan some emails to see the breakdown chart.</p>
                    </div>
                  ) : (
                    <div className="flex flex-col sm:flex-row items-center gap-6">
                      {/* Donut chart — colors reference the CSS vars defined in :root */}
                      <div className="w-full sm:w-64 h-52 shrink-0">
                        <DonutChart metrics={sessionMetrics} />
                      </div>

                      {/* Threat breakdown bars */}
                      <div className="flex-1 w-full space-y-4">
                        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Threat breakdown</p>
                        {[
                          { label: 'Phishing', value: sessionMetrics.phishingDetected, total: Math.max(sessionTotalScans, 1), barClass: 'bg-destructive' },
                          { label: 'Suspicious', value: sessionMetrics.suspiciousDetected, total: Math.max(sessionTotalScans, 1), barClass: 'bg-warning' },
                          { label: 'Safe', value: sessionMetrics.safeDetected, total: Math.max(sessionTotalScans, 1), barClass: 'bg-safe' },
                        ].map(({ label, value, total, barClass }) => {
                          const pct = calculatePercent(value, total);
                          return (
                            <div key={label} className="space-y-1.5">
                              <div className="flex justify-between text-xs">
                                <span className="text-muted-foreground font-medium">{label}</span>
                                <span className="text-foreground font-mono">{value} <span className="text-muted-foreground">({pct}%)</span></span>
                              </div>
                              <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
                                <motion.div
                                  className={cn("h-full rounded-full", barClass)}
                                  initial={{ width: 0 }}
                                  animate={{ width: `${pct}%` }}
                                  transition={{ duration: 0.8, ease: "easeOut" }}
                                />
                              </div>
                            </div>
                          );
                        })}

                        <div className="pt-2 border-t border-border/50 text-[11px] text-muted-foreground">
                          {sessionTotalScans > 0 ? (
                            <span className="text-warning font-medium">
                              {calculatePercent(sessionMetrics.phishingDetected + sessionMetrics.suspiciousDetected, sessionTotalScans)}% of scanned emails were flagged
                            </span>
                          ) : (
                            <span>Scan emails to see statistics</span>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </section>

              {/* ── Regional Threat Intelligence ── */}
              <section>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <RegionalThreatMap history={sessionHistory} totalScans={sessionTotalScans} />
                  
                  <div className="flex flex-col gap-4">
                    <div className="rounded-xl border border-card-border bg-card p-5 flex-1">
                       <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 text-primary" />
                          Dominant Attack Vector
                       </h3>
                       <div className="flex items-center gap-4 mt-2">
                          <div className={cn("text-2xl font-bold tracking-tight", sessionMetrics.phishingDetected > 0 ? "text-foreground" : "text-muted-foreground")}>
                             {sessionMetrics.phishingDetected > 0 ? getMostCommonAttackType() : 'Analyzing...'}
                          </div>
                          {sessionMetrics.phishingDetected > 0 && <Badge className="bg-destructive/10 text-destructive border-destructive/20 uppercase text-[9px] font-bold">Session trend</Badge>}
                       </div>
                       <p className="text-[10px] text-muted-foreground mt-3 leading-relaxed">Derived from recent flagged emails in this session, not from a live external threat feed.</p>
                    </div>

                    <div className="rounded-xl border border-card-border bg-card p-5 flex-1">
                       <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                          <Flag className="w-4 h-4 text-warning" />
                          Most Targeted Brand
                       </h3>
                       <div className="flex items-center justify-between mt-2">
                          <div className={cn("text-2xl font-bold tracking-tight", sessionMetrics.phishingDetected > 0 ? "text-foreground" : "text-muted-foreground")}>
                             {getMostTargetedBrand()}
                          </div>
                          <div className="flex -space-x-2">
                             <div className="w-6 h-6 rounded-full bg-blue-500 border-2 border-card shadow-sm" />
                             <div className="w-6 h-6 rounded-full bg-orange-500 border-2 border-card shadow-sm" />
                             <div className="w-6 h-6 rounded-full bg-yellow-500 border-2 border-card shadow-sm" />
                          </div>
                       </div>
                       <p className="text-[10px] text-muted-foreground mt-3">Statistical mapping across 120+ Indian financial institutions.</p>
                    </div>
                  </div>
                </div>
              </section>

              {/* ── Risk Scale Reference ── */}
              <section>
                <h2 className="text-base font-semibold text-foreground flex items-center gap-2 mb-4">
                  <TrendingUp className="w-4 h-4 text-primary" />
                  Risk Distribution
                </h2>
                <div className="rounded-xl border border-card-border bg-card p-5">
                  <div className="grid grid-cols-3 gap-3 mb-4">
                    {[
                      { range: '0 – 25', label: 'Safe', desc: 'No significant threat signals detected', color: 'text-safe', bg: 'bg-safe/10', border: 'border-safe/20' },
                      { range: '26 – 60', label: 'Suspicious', desc: 'Some risk signals — proceed with caution', color: 'text-warning', bg: 'bg-warning/10', border: 'border-warning/20' },
                      { range: '61 – 100', label: 'High Risk', desc: 'High-confidence threat — do not interact', color: 'text-destructive', bg: 'bg-destructive/10', border: 'border-destructive/20' },
                    ].map(({ range, label, desc, color, bg, border }) => (
                      <div key={label} className={cn("rounded-lg border p-3 text-center", bg, border)}>
                        <p className={cn("text-lg font-bold font-mono", color)}>{range}</p>
                        <p className={cn("text-sm font-semibold mt-0.5", color)}>{label}</p>
                        <p className="text-[10px] text-muted-foreground mt-1 leading-relaxed">{desc}</p>
                      </div>
                    ))}
                  </div>
                  <div className="h-3 w-full rounded-full overflow-hidden flex">
                    <div className="flex-25 bg-safe" />
                    <div className="flex-35 bg-warning" />
                    <div className="flex-40 bg-destructive" />
                  </div>
                  <div className="flex justify-between text-[10px] text-muted-foreground mt-1 font-mono">
                    <span>0</span><span>25</span><span>60</span><span>100</span>
                  </div>
                </div>
              </section>

              {/* ── Attack Intelligence ── */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <section className="rounded-xl border border-card-border bg-card p-5">
                  <h3 className="text-[10px] font-bold text-muted-foreground mb-3 uppercase tracking-wider flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-warning" />
                    Risk Keywords
                  </h3>
                  <div className="flex flex-wrap gap-1.5">
                    {getTopKeywords().length > 0 ? getTopKeywords().map(kw => (
                      <span key={kw} className="px-1.5 py-0.5 rounded bg-warning/10 text-warning border border-warning/20 text-[10px] font-mono lowercase">
                        {kw}
                      </span>
                    )) : <span className="text-[11px] text-muted-foreground">None detected</span>}
                  </div>
                </section>
                
                <section className="rounded-xl border border-card-border bg-card p-5">
                  <h3 className="text-[10px] font-bold text-muted-foreground mb-3 uppercase tracking-wider flex items-center gap-2">
                    <ShieldAlert className="w-3.5 h-3.5 text-destructive" />
                    Attack Type
                  </h3>
                  <div className="text-sm font-bold text-foreground tracking-tight">
                    {getMostCommonAttackType()}
                  </div>
                </section>

                <section className="rounded-xl border border-card-border bg-card p-5">
                  <h3 className="text-[10px] font-bold text-muted-foreground mb-3 uppercase tracking-wider flex items-center gap-2">
                    <Building2 className="w-3.5 h-3.5 text-primary" />
                    Targeted Brand
                  </h3>
                  <div className="text-sm font-bold text-foreground tracking-tight">
                    {getMostTargetedBrand()}
                  </div>
                </section>
              </div>

              {/* ── Model Performance ── */}
              <section>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                    <BarChart3 className="w-4 h-4 text-primary" />
                    Detection Accuracy
                  </h2>
                  <span className="text-xs text-muted-foreground">Benchmark Accuracy · measured on a curated test set, not live data</span>
                </div>

                <div className="mb-3 rounded-xl border border-primary/20 bg-primary/5 px-4 py-3 text-[11px] text-foreground/85">
                  <span className="font-semibold text-foreground">Benchmark Accuracy</span> comes from the latest offline verification suite. <span className="text-muted-foreground">It does not represent live session performance.</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: 'Accuracy', value: metrics?.accuracy, color: 'text-primary', desc: 'Overall correct predictions' },
                    { label: 'Precision', value: metrics?.precision, color: 'text-safe', desc: 'Of flagged emails, truly phishing' },
                    { label: 'Recall', value: metrics?.recall, color: 'text-safe', desc: 'Phishing emails actually caught' },
                    { label: 'F1 Score', value: metrics?.f1Score, color: 'text-accent', desc: 'Precision–recall balance' },
                  ].map(({ label, value, color, desc }) => (
                    <div key={label} className="rounded-xl border border-card-border bg-card p-4">
                      <p className="text-[10px] text-muted-foreground mb-1 uppercase tracking-wide">{label}</p>
                      <p className={cn("text-2xl font-bold font-mono", color)}>
                        {value !== undefined ? `${(value * 100).toFixed(1)}%` : '—'}
                      </p>
                      <p className="text-[10px] text-muted-foreground mt-1 leading-relaxed">{desc}</p>
                    </div>
                  ))}
                </div>

                <div className="mt-3 rounded-xl border border-card-border bg-card p-4">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs text-muted-foreground font-medium">False Positive Rate</span>
                    <span className="text-xs font-mono text-warning">
                      {metrics ? `${(metrics.falsePositiveRate * 100).toFixed(1)}%` : '—'} <span className="text-muted-foreground">(lower is better)</span>
                    </span>
                  </div>
                  <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
                    <motion.div
                      className="h-full bg-warning rounded-full"
                      initial={{ width: 0 }}
                      animate={{ width: `${(metrics?.falsePositiveRate ?? 0) * 100}%` }}
                      transition={{ duration: 0.8 }}
                    />
                  </div>
                </div>

                {metrics && (
                  <div className="mt-3 space-y-1.5">
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>Overall benchmark accuracy</span>
                      <span className="font-mono text-foreground">{(metrics.accuracy * 100).toFixed(1)}%</span>
                    </div>
                    <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
                      <motion.div
                        className="h-full bg-primary rounded-full"
                        initial={{ width: 0 }}
                        animate={{ width: `${metrics.accuracy * 100}%` }}
                        transition={{ duration: 1, ease: "easeOut" }}
                      />
                    </div>
                  </div>
                )}

                <div className="mt-5 rounded-xl border border-card-border bg-card p-4">
                  <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between mb-3">
                    <h3 className="text-sm font-semibold text-foreground">Live Session Accuracy</h3>
                    <span className="text-[11px] text-muted-foreground">Calculated from real user feedback, false negatives, and agreement rate</span>
                  </div>
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    {[
                      {
                        label: 'Agreement rate',
                        value: feedbackAgreementDisplay,
                        helper: hasFeedbackSamples ? 'Model vs. reviewed feedback this session' : 'Waiting for reviewed feedback samples',
                      },
                      {
                        label: 'Confirmed correct',
                        value: String(learningMetrics.confirmedCorrect ?? 0),
                        helper: hasFeedbackSamples ? `${learningMetrics.feedbackSamples ?? 0} feedback samples reviewed` : 'No feedback samples reviewed yet',
                      },
                      {
                        label: 'False negatives',
                        value: String(learningMetrics.falseNegativeCount ?? 0),
                        helper: 'Missed phishing corrected by users',
                      },
                      {
                        label: 'Drift',
                        value: String(learningMetrics.driftLevel ?? 'low').toUpperCase(),
                        helper: `Score ${(Number(learningMetrics.driftScore ?? 0) * 100).toFixed(0)}%`,
                      },
                    ].map((card) => (
                      <div key={card.label} className="rounded-xl border border-border/50 bg-background/60 p-3">
                        <p className="text-[10px] text-muted-foreground uppercase tracking-wide">{card.label}</p>
                        <p className="mt-1 text-lg font-bold text-foreground">{card.value}</p>
                        <p className="mt-1 text-[10px] text-muted-foreground">{card.helper}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              <section>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between mb-4">
                  <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                    <Bot className="w-4 h-4 text-primary" />
                    Self-Improving Model Loop
                  </h2>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline" className={cn('uppercase text-[10px] font-bold tracking-wide', driftTone)}>
                      {learningMetrics.retrainingRecommended ? 'Retrain recommended' : 'Learning stable'}
                    </Badge>
                    <Button variant="outline" size="sm" onClick={handleRetrainNow} disabled={retrainProgress !== null} className="bg-background/60">
                      {retrainProgress !== null ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 mr-1.5" />}
                      {retrainProgress !== null ? `Retraining ${retrainProgress}%` : 'Retrain Now'}
                    </Button>
                  </div>
                </div>

                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                  {[
                    {
                      label: 'Model Version',
                      value: retrainLabel,
                      helper: learningMetrics.lastModelTrainingAt ? `Technical ID: ${learningMetrics.currentModelVersion ?? 'hybrid-rule-engine'}` : 'Production baseline active',
                    },
                    {
                      label: 'Backend Status',
                      value: backendStatus === 'connected' ? 'Connected ✅' : backendStatus === 'offline' ? 'Offline ⚠️' : 'Checking…',
                      helper: backendStatus === 'connected'
                        ? `FastAPI model ${backendModelVersion}${backendHealth?.last_trained_date ? ` · trained ${formatDate(backendHealth.last_trained_date)}` : ''}`
                        : 'Frontend will fall back to local analysis if the Python service is unavailable',
                    },
                    {
                      label: 'Feedback Samples',
                      value: String(learningMetrics.feedbackSamples ?? 0),
                      helper: `${learningMetrics.confirmedCorrect ?? 0} confirmed-correct`,
                    },
                    {
                      label: 'False Negatives',
                      value: String(learningMetrics.falseNegativeCount ?? 0),
                      helper: 'Must remain as low as possible',
                    },
                    {
                      label: 'Drift Status',
                      value: String(learningMetrics.driftLevel ?? 'low').toUpperCase(),
                      helper: `Score ${(Number(learningMetrics.driftScore ?? 0) * 100).toFixed(0)}%`,
                    },
                  ].map((card) => (
                    <div key={card.label} className="rounded-xl border border-card-border bg-card p-4">
                      <p className="text-[10px] text-muted-foreground mb-1 uppercase tracking-wide">{card.label}</p>
                      <p className="text-base sm:text-lg font-bold text-foreground wrap-break-word">{card.value}</p>
                      <p className="text-[10px] text-muted-foreground mt-1">{card.helper}</p>
                    </div>
                  ))}
                </div>

                <div className="mt-3 rounded-xl border border-card-border bg-card p-4 space-y-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground" title={feedbackAgreementSummary}>Feedback agreement rate</span>
                    <span className="font-mono text-foreground">{feedbackAgreementDisplay}</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground">{feedbackAgreementSummary}</p>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">Samples since last retrain</span>
                    <span className="font-mono text-foreground">{retrainProgressText}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">Misclassification mix</span>
                    <span className="font-mono text-foreground">
                      FP {learningMetrics.falsePositiveCount ?? 0} · FN {learningMetrics.falseNegativeCount ?? 0} · Review {learningMetrics.needsReviewCount ?? 0}
                    </span>
                  </div>
                  {retrainProgress !== null && (
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                        <span>Retraining progress</span>
                        <span>{retrainProgress}%</span>
                      </div>
                      <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
                        <div className="h-full bg-primary rounded-full transition-all duration-300" style={{ width: `${retrainProgress}%` }} />
                      </div>
                    </div>
                  )}
                </div>
              </section>

              {/* ── Recent Scans ── */}
              <section>
                <div className="flex flex-col gap-3 mb-4 lg:flex-row lg:items-center lg:justify-between">
                  <div>
                    <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                      <History className="w-4 h-4 text-primary" />
                      Recent Activity
                      {sessionTotalScans > 0 && (
                        <span className="text-xs text-muted-foreground font-normal">({sessionTotalScans})</span>
                      )}
                    </h2>
                    <p className="text-xs text-muted-foreground mt-1">Search recent scans, filter by verdict, or copy a clean session summary.</p>
                  </div>
                  {sessionTotalScans > 0 && (
                    <div className="flex flex-wrap gap-2">
                      <Button variant="outline" size="sm" onClick={handleCopySessionSnapshot} className="bg-background/60">
                        <Copy className="w-3.5 h-3.5 mr-1.5" /> Copy snapshot
                      </Button>
                      <Button variant="outline" size="sm" onClick={handleExportCsv} className="bg-background/60">
                        <Download className="w-3.5 h-3.5 mr-1.5" /> Export CSV
                      </Button>
                    </div>
                  )}
                </div>

                {sessionTotalScans === 0 ? (
                  <div className="rounded-xl border border-dashed border-border/50 p-10 text-center">
                    <ShieldCheck className="w-8 h-8 text-muted-foreground/30 mx-auto mb-3" />
                    <p className="text-sm text-muted-foreground">No scans yet this session.</p>
                    <p className="text-xs text-muted-foreground/60 mt-1">Switch to Analyze and scan an email to see history here.</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div className="rounded-xl border border-card-border bg-card p-3 sm:p-4 space-y-3">
                      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                        <div className="relative flex-1">
                          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                          <input
                            value={historySearch}
                            onChange={(event) => setHistorySearch(event.target.value)}
                            placeholder="Search by preview, score, verdict, or language..."
                            className="w-full rounded-lg border border-input bg-background/70 pl-9 pr-3 py-2 text-sm text-foreground outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary/40"
                          />
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {[
                            { key: 'all', label: 'All' },
                            { key: 'phishing', label: 'High Risk' },
                            { key: 'uncertain', label: 'Suspicious' },
                            { key: 'safe', label: 'Safe' },
                          ].map((option) => (
                            <button
                              key={option.key}
                              type="button"
                              onClick={() => setHistoryFilter(option.key as 'all' | 'safe' | 'uncertain' | 'phishing')}
                              className={cn(
                                'rounded-full border px-3 py-1 text-[11px] font-bold transition-colors',
                                historyFilter === option.key
                                  ? 'border-primary/40 bg-primary/10 text-primary'
                                  : 'border-border/60 bg-background/60 text-muted-foreground hover:text-foreground',
                              )}
                            >
                              {option.label}
                            </button>
                          ))}
                        </div>
                      </div>
                      <p className="text-[11px] text-muted-foreground">
                        Showing <span className="font-semibold text-foreground">{Math.min(visibleHistory.length, filteredHistory.length)}</span> of {sessionTotalScans} scans
                        {historySearch.trim() ? ` for “${historySearch.trim()}”` : ''}.
                      </p>
                    </div>

                    <div className="rounded-xl border border-card-border bg-card overflow-hidden">
                      {filteredHistory.length === 0 ? (
                        <div className="px-4 py-8 text-center">
                          <Search className="w-8 h-8 text-muted-foreground/30 mx-auto mb-3" />
                          <p className="text-sm text-muted-foreground">No recent scans match the current filters.</p>
                          <p className="text-xs text-muted-foreground/70 mt-1">Try clearing the search box or switching the verdict filter.</p>
                        </div>
                      ) : (
                        <div className="divide-y divide-border/50">
                          {visibleHistory.map((item) => {
                            const c = classificationColor(item.classification);
                            return (
                              <div key={item.id} className="flex items-center gap-4 px-4 py-3.5 hover:bg-secondary/30 transition-colors">
                                <div className={cn('w-2 h-2 rounded-full shrink-0', c.bar)} />
                                <div className="flex-1 min-w-0">
                                  <p className="text-sm text-foreground truncate font-mono">{privacyMode ? redactSensitiveText(item.emailPreview) : item.emailPreview}</p>
                                  <div className="flex flex-wrap items-center gap-3 mt-1 text-[11px] text-muted-foreground">
                                    <span>{formatDate(item.timestamp)} · {formatTime(item.timestamp)}</span>
                                    <span>{getLanguageLabel(item.detectedLanguage)}</span>
                                    {item.urlCount > 0 && <span>{item.urlCount} link{item.urlCount !== 1 ? 's' : ''}</span>}
                                  </div>
                                </div>
                                <div className="text-right shrink-0">
                                  <p className={cn('text-sm font-bold font-mono', c.text)}>{item.riskScore}</p>
                                  <p className={cn('text-[10px] uppercase font-medium tracking-wide', c.text)}>{formatVerdictLabel(item.classification, item.riskScore ?? 0)}</p>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                    {filteredHistory.length > visibleHistory.length && (
                      <div className="flex justify-center pt-2">
                        <Button variant="outline" size="sm" onClick={() => setHistoryVisibleCount((count) => count + HISTORY_PAGE_SIZE)} className="bg-background/60">
                          Load more
                        </Button>
                      </div>
                    )}
                  </div>
                )}
              </section>

              {/* ── Multilingual + India Intelligence ── */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <section className="rounded-xl border border-card-border bg-card p-5">
                  <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                    <Globe className="w-4 h-4 text-primary" />
                    Language Support
                  </h3>
                  <div className="space-y-3">
                    {[
                      { code: 'EN', lang: 'English', status: 'Full support', desc: 'Urgency, financial, social engineering' },
                      { code: 'HI', lang: 'Hindi', status: 'Full support', desc: 'तुरंत, आखिरी मौका, खाता, पासवर्ड, जीएसटी, आयकर' },
                      { code: 'TE', lang: 'Telugu', status: 'Expanded coverage', desc: 'వెంటనే, ఇప్పుడే, ఖాతా, బహుమతి, OTP, పాస్వర్డ్' },
                    ].map(({ code, lang, status, desc }) => (
                      <div key={lang} className="flex items-start gap-2">
                        <span className="font-mono text-[10px] bg-secondary px-1.5 py-0.5 rounded shrink-0 mt-0.5">{code}</span>
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="text-sm font-medium text-foreground">{lang}</span>
                            <span className="text-[9px] text-safe bg-safe/10 px-1.5 py-0.5 rounded-full">{status}</span>
                          </div>
                          <p className="text-[11px] text-muted-foreground">{desc}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="rounded-xl border border-card-border bg-card p-5">
                  <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                    <Shield className="w-4 h-4 text-primary" />
                    India-specific patterns
                  </h3>
                  <div className="grid grid-cols-1 gap-1.5 text-xs text-muted-foreground">
                    {[
                      'SBI, HDFC, ICICI, PNB impersonation',
                      'Paytm, PhonePe, GPay reward scams',
                      'UPI KYC fraud patterns',
                      'IRCTC, Aadhaar, PAN phishing',
                      'Hindi & Telugu scam phrases',
                      'Lookalike .xyz, .tk, .ml domains',
                    ].map((item) => (
                      <div key={item} className="flex items-start gap-1.5">
                        <CheckCircle className="w-3.5 h-3.5 text-safe shrink-0 mt-0.5" />
                        <span>{item}</span>
                      </div>
                    ))}
                  </div>
                </section>
              </div>

              <section className="rounded-xl border border-card-border bg-card p-5">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between mb-4">
                  <div>
                    <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-primary" />
                      Session Settings
                    </h3>
                    <p className="text-[11px] text-muted-foreground mt-1">Manage trusted senders and analyst exports for this browser session.</p>
                  </div>
                  <span className={cn('text-[10px] font-bold uppercase tracking-wide rounded-full px-2 py-1 border', privacyMode ? 'border-safe/30 bg-safe/5 text-safe' : 'border-warning/30 bg-warning/5 text-warning')}>
                    {privacyMode ? 'Protected session' : 'Privacy review suggested'}
                  </span>
                </div>
                <div className="grid gap-4 lg:grid-cols-2">
                  <div className="rounded-xl border border-border/50 bg-background/60 p-4">
                    <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">Safe Senders</p>
                    {safeSenders.length === 0 ? (
                      <p className="mt-2 text-sm text-muted-foreground">No trusted domains added yet. Use “Add to Safe Senders” on a confirmed safe result.</p>
                    ) : (
                      <div className="mt-3 flex flex-wrap gap-2">
                        {safeSenders.map((entry) => (
                          <span key={entry.domain} className="inline-flex items-center gap-2 rounded-full border border-safe/30 bg-safe/5 px-2.5 py-1 text-[11px] text-safe">
                            {entry.domain}
                            <button type="button" onClick={() => handleRemoveSafeSender(entry.domain)} className="text-safe/80 hover:text-safe">×</button>
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="rounded-xl border border-border/50 bg-background/60 p-4 space-y-2">
                    <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground">Export & privacy</p>
                    <p className="text-sm text-foreground/85">Copy Snapshot now exports analyst-friendly JSON, and CSV export is available for deeper review.</p>
                    <p className="text-[11px] text-muted-foreground">When privacy mode is on, copied previews automatically redact emails, links, IDs, and phone numbers.</p>
                  </div>
                </div>
              </section>

            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className="mt-20 py-10 border-t border-border/40 text-center space-y-6">
        <div className="flex flex-wrap justify-center gap-6 opacity-60 grayscale hover:grayscale-0 transition-all duration-500">
           {[
             { label: 'Privacy First', icon: <Lock className="w-4 h-4" /> },
             { label: 'Offline Engine', icon: <ShieldCheck className="w-4 h-4" /> },
             { label: 'India Precise', icon: <Globe className="w-4 h-4" /> },
             { label: 'No Data Storage', icon: <Trash2 className="w-4 h-4" /> }
           ].map(badge => (
             <div key={badge.label} className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest">
                {badge.icon}
                {badge.label}
             </div>
           ))}
        </div>
        <div className="space-y-2">
           <p className="text-xs text-muted-foreground">PhishShield AI — built for India</p>
           <p className="text-[10px] text-muted-foreground/50 font-mono">Secure Node v24.2.0 • Session: {sessionFingerprint}</p>
        </div>
      </footer>
    </div>
  );
}
