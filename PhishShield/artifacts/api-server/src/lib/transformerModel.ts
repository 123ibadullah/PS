/**
 * Fast phishing intelligence scorer.
 *
 * Goals:
 * - deterministic and explainable outputs
 * - no startup crashes from optional native dependencies
 * - low-latency scoring suitable for a product experience
 * - optional transformer enrichment when explicitly enabled
 */

import axios from "axios";
import { tfidfLRScore } from "./tfidfModel.js";
import { logger } from "./logger.js";

export type FeatureContribution = {
  feature: string;
  contribution: number;
  direction: "phishing" | "safe";
};

type SignalRule = {
  label: string;
  weight: number;
  direction: "phishing" | "safe";
  patterns: RegExp[];
  cap?: number;
};

const TRANSFORMER_SERVICE_URL =
  process.env.PHISHSHIELD_TRANSFORMER_URL?.trim();
const TRANSFORMER_TIMEOUT_MS = Number(
  process.env.PHISHSHIELD_TRANSFORMER_TIMEOUT_MS ?? "1200",
);

const transformerClient = axios.create({
  timeout: TRANSFORMER_TIMEOUT_MS,
  headers: {
    "Content-Type": "application/json",
  },
});

let hasLoggedTransformerFallbackWarning = false;

type TransformerServiceResponse = {
  label?: "phishing" | "safe";
  score?: number;
};

const SIGNAL_RULES: SignalRule[] = [
  {
    label: "Credential request",
    weight: 18,
    direction: "phishing",
    cap: 3,
    patterns: [
      /\botp\b/i,
      /\bpassword\b/i,
      /\bpin\b/i,
      /\bcvv\b/i,
      /\bcredentials?\b/i,
      /\baadhaar\b/i,
      /\bpan\b/i,
      /\bbank details?\b/i,
      /verify (?:your )?identity|confirm (?:your )?identity/i,
      /enter (?:your )?(?:pin|otp|password|details)|submit (?:your )?details/i,
    ],
  },
  {
    label: "Urgency pressure",
    weight: 12,
    direction: "phishing",
    cap: 3,
    patterns: [
      /urgent|urgently|immediately|act now|verify now|confirm now|final notice|last chance|right away/i,
      /within \d+ hours?|24 hours|48 hours|expires? today|deadline/i,
      /blocked|suspended|locked|terminate|reactivate|restore access/i,
      /तुरंत|अभी|जल्दी|బ్లాక్|వెంటనే/i,
    ],
  },
  {
    label: "Reward or refund bait",
    weight: 14,
    direction: "phishing",
    cap: 3,
    patterns: [
      /winner|won|prize|lottery|jackpot|lucky draw/i,
      /reward|cashback|gift card|free money|claim now|bonus|lottery/i,
      /refund pending|refund available|claim refund|tax refund|cash reward|selected winner/i,
    ],
  },
  {
    label: "Advance-fee job scam",
    weight: 16,
    direction: "phishing",
    cap: 2,
    patterns: [
      /candidate|job selection|offer letter|interview|recruitment/i,
      /registration fee|processing fee|security deposit|confirm your job selection/i,
      /\bpay\b.*(?:₹|rs\.?|rupees|\d{2,6})|(?:₹|rs\.?|rupees)\s*\d{2,6}/i,
    ],
  },
  {
    label: "Brand impersonation",
    weight: 8,
    direction: "phishing",
    cap: 2,
    patterns: [
      /\bsbi\b|state bank/i,
      /\bhdfc\b|\bicici\b|axis bank|kotak|pnb/i,
      /paytm|phonepe|gpay|google pay|bhim/i,
      /amazon|netflix|paypal|microsoft|google/i,
    ],
  },
  {
    label: "BEC or invoice fraud",
    weight: 16,
    direction: "phishing",
    cap: 2,
    patterns: [
      /wire transfer|bank transfer|transfer funds?|transfer money|gift cards?/i,
      /vendor payment|payment details updated|new beneficiary|(?:confirm|approve|process)\s+(?:the\s+)?(?:payment|invoice|transfer)/i,
      /attached invoice|overdue invoice|remittance advice/i,
      /keep this confidential|only you can do this|ceo request/i,
      /payroll update|salary account change|direct deposit update|i(?:'m| am) in a meeting|will explain later|small help/i,
    ],
  },
  {
    label: "Attachment or malware lure",
    weight: 15,
    direction: "phishing",
    cap: 2,
    patterns: [
      /open the attachment|download the file|see attached html/i,
      /enable content|enable macros?|docm|xlsm|zip attachment/i,
      /scan (the )?qr code|qr code attached/i,
      /browser extension|install plugin|vpn reconnect/i,
    ],
  },
  {
    label: "OAuth or shared-document lure",
    weight: 14,
    direction: "phishing",
    cap: 2,
    patterns: [
      /microsoft 365|sharepoint|onedrive|docusign|dropbox|google docs/i,
      /shared document|shared file|review document|view document|sign document/i,
      /authorize app|grant consent|approve sign-?in|secure document/i,
    ],
  },
  {
    label: "Crypto wallet theft",
    weight: 18,
    direction: "phishing",
    cap: 3,
    patterns: [
      /seed phrase|recovery phrase|private key|wallet key|passphrase/i,
      /connect wallet|metamask|trust wallet|coinbase|binance|usdt/i,
      /wallet verification|crypto transfer|wallet suspended/i,
      /btc|bitcoin|crypto|wallet/i,
      /double (?:your )?(?:money|btc|bitcoin)|instant return|guaranteed return/i,
    ],
  },
  {
    label: "URL obfuscation",
    weight: 15,
    direction: "phishing",
    cap: 3,
    patterns: [
      /https?:\/\//i,
      /bit\.ly|tinyurl\.com|t\.co|cutt\.ly|is\.gd/i,
      /xn--|https?:\/\/[^\s]*@[a-z0-9.-]+\./i,
      /\.(tk|ml|ga|cf|gq|xyz|top|click|work|site|icu)\b/i,
    ],
  },
  {
    label: "Unicode or obfuscation anomaly",
    weight: 10,
    direction: "phishing",
    cap: 2,
    patterns: [
      /[\u200B-\u200D\uFEFF]/,
      /p\s+a\s+s\s+s\s+w\s+o\s+r\s+d/i,
      /o\s+t\s+p/i,
    ],
  },
  {
    label: "Phone callback scam",
    weight: 9,
    direction: "phishing",
    cap: 2,
    patterns: [
      /call this number|call immediately|helpline/i,
      /whatsapp us|contact support on telegram/i,
      /toll[ -]?free/i,
    ],
  },
  {
    label: "Safe notification context",
    weight: 14,
    direction: "safe",
    cap: 2,
    patterns: [
      /ignore if not you|if this was not you|if this wasn't you/i,
      /do not share|never share|we will never ask/i,
      /automated message|do not reply|standard notification/i,
    ],
  },
  {
    label: "Routine business language",
    weight: 10,
    direction: "safe",
    cap: 2,
    patterns: [
      /meeting|agenda|conference room|project update/i,
      /thanks|thank you|regards|best wishes|sincerely/i,
      /as discussed|please review|attached report/i,
    ],
  },
  {
    label: "Transactional receipt context",
    weight: 12,
    direction: "safe",
    cap: 2,
    patterns: [
      /order shipped|tracking number|delivery update/i,
      /payment successful|subscription renewed|invoice paid/i,
      /receipt|transaction id|your order/i,
    ],
  },
];

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function roundContribution(value: number): number {
  return Math.round(value * 100) / 100;
}

function normalizeText(text: string): string {
  return text
    .toLowerCase()
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function countRuleHits(text: string, patterns: RegExp[]): number {
  let hits = 0;
  for (const pattern of patterns) {
    if (pattern.test(text)) hits++;
  }
  return hits;
}

function mergeFeatures(
  ...featureSets: FeatureContribution[][]
): FeatureContribution[] {
  const featureMap = new Map<string, FeatureContribution>();

  for (const set of featureSets) {
    for (const feature of set) {
      const key = `${feature.direction}:${feature.feature}`;
      const existing = featureMap.get(key);
      if (!existing || existing.contribution < feature.contribution) {
        featureMap.set(key, feature);
      }
    }
  }

  return [...featureMap.values()]
    .sort((a, b) => b.contribution - a.contribution)
    .slice(0, 8);
}

export function intelligenceScore(text: string): {
  score: number;
  topFeatures: FeatureContribution[];
} {
  if (!text || text.trim().length === 0) {
    return { score: 0, topFeatures: [] };
  }

  const normalized = normalizeText(text);
  let score = 8;
  const features: FeatureContribution[] = [];

  for (const rule of SIGNAL_RULES) {
    const hits = countRuleHits(normalized, rule.patterns);
    if (hits === 0) continue;

    const appliedHits = Math.min(rule.cap ?? hits, hits);
    const delta = appliedHits * rule.weight;

    if (rule.direction === "phishing") {
      score += delta;
    } else {
      score -= delta;
    }

    features.push({
      feature: rule.label,
      contribution: roundContribution(Math.max(0.2, delta / 12)),
      direction: rule.direction,
    });
  }

  const hasCredentialRequest = /otp|password|pin|cvv|credentials?|aadhaar|pan/i.test(
    normalized,
  );
  const hasUrgency =
    /urgent|immediately|act now|final notice|blocked|suspended|within \d+ hours?/i.test(
      normalized,
    );
  const hasSuspiciousUrl =
    /https?:\/\//i.test(normalized) &&
    /(bit\.ly|tinyurl|xn--|@|\.(tk|ml|ga|cf|gq|xyz|top|click|site|icu)\b)/i.test(
      normalized,
    );
  const hasSafeContext =
    /ignore if not you|we will never ask|do not share|automated message/i.test(
      normalized,
    );
  const hasBenignBillingPortalNotice =
    /(could(?:n't| not) process payment|issue processing (?:your |the )?(?:subscription )?payment|subscription payment|billing issue|billing notice|payment method)/i.test(
      normalized,
    ) &&
    /(dashboard|billing (?:&|and) invoices|billing settings|subscription settings|account dashboard|official (?:site|website|app))/i.test(
      normalized,
    ) &&
    !/(reply with|send|share|provide|enter|submit|update (?:card|billing|bank|payment) details|transfer funds?|wire transfer|approve payment|confirm payment|gift cards?|crypto|wallet|otp|password|pin\b|cvv|credentials?)/i.test(
      normalized,
    );
  if (hasBenignBillingPortalNotice) {
    score = Math.max(0, score - 16);
    const filteredFeatures = features.filter(
      (feature) => !(feature.direction === "phishing" && feature.feature === "BEC or invoice fraud"),
    );
    features.length = 0;
    features.push(...filteredFeatures);
  }
  const hasBecPattern =
    !hasBenignBillingPortalNotice &&
    /wire transfer|transfer funds?|transfer money|vendor payment|(?:confirm|approve|process)\s+(?:the\s+)?(?:payment|invoice|transfer)|gift cards?|keep this confidential|ceo request|payroll update|salary account change|(?:attached|overdue)\s+invoice|remittance advice|i(?:'m| am) in a meeting|will explain later|small help/i.test(
      normalized,
    );
  const hasOAuthDocLure =
    /microsoft 365|sharepoint|onedrive|docusign|dropbox|shared document|review document|grant consent|approve sign-?in/i.test(
      normalized,
    );
  const hasFinancialLure =
    /reward|cashback|gift card|free money|claim now|won|prize|bonus|refund|kyc|wallet|btc|bitcoin|crypto|double (?:money|btc)|instant return|candidate|job selection|offer letter|registration fee|processing fee|security deposit/i.test(
      normalized,
    );
  const hasJobFeeScam =
    /candidate|job selection|offer letter|interview|recruitment/i.test(normalized) &&
    /\bpay\b|registration fee|processing fee|security deposit|confirm your job selection/i.test(normalized);
  const hasRegionalBankThreat =
    /(?:बैंक|खाता|खाते).*(?:बंद|सत्यापन|तुरंत|निलंबित)|(?:బ్యాంక్|ఖాతా).*(?:నిలిపివేయబడింది|ధృవీకరించండి|వెంటనే|బ్లాక్)/i.test(
      normalized,
    );
  const hasShortDangerPhrase =
    normalized.length <= 80 && /verify now|act now|confirm now|send otp|urgent|immediately/i.test(normalized);
  const hasCryptoLure =
    /seed phrase|recovery phrase|private key|wallet key|connect wallet|metamask|coinbase|binance|wallet verification|btc|bitcoin|crypto|double (?:money|btc)|instant return/i.test(
      normalized,
    );

  if (hasCredentialRequest && hasUrgency) {
    score += 12;
    features.push({
      feature: "Credential theft pressure combo",
      contribution: 2.4,
      direction: "phishing",
    });
  }

  if (
    hasCredentialRequest &&
    (/verify identity|confirm identity|enter your pin|enter your otp|security code/i.test(normalized) ||
      hasUrgency)
  ) {
    score += 18;
    features.push({
      feature: "Credential entry request pattern",
      contribution: 3.2,
      direction: "phishing",
    });
  }

  if (hasCredentialRequest && hasSuspiciousUrl) {
    score += 14;
    features.push({
      feature: "Credential + URL harvesting combo",
      contribution: 2.8,
      direction: "phishing",
    });
  }

  if (hasFinancialLure && (hasUrgency || /claim now|wallet|kyc|btc|bitcoin|crypto|job selection|registration fee/i.test(normalized))) {
    score += 14;
    features.push({
      feature: "Financial lure pressure combo",
      contribution: 2.9,
      direction: "phishing",
    });
  }

  if (hasJobFeeScam) {
    score += 18;
    features.push({
      feature: "Advance-fee job scam pattern",
      contribution: 3.0,
      direction: "phishing",
    });
  }

  if (hasRegionalBankThreat) {
    score += 18;
    features.push({
      feature: "Regional bank-closure phishing pattern",
      contribution: 3.0,
      direction: "phishing",
    });
  }

  if (hasBecPattern) {
    score += 10;
    features.push({
      feature: "Business email compromise pattern",
      contribution: 2.2,
      direction: "phishing",
    });
  }

  if (hasOAuthDocLure && (hasSuspiciousUrl || hasUrgency)) {
    score += 12;
    features.push({
      feature: "Cloud-share or OAuth consent lure",
      contribution: 2.5,
      direction: "phishing",
    });
  }

  if (hasCryptoLure) {
    score += 16;
    features.push({
      feature: "Crypto wallet theft pattern",
      contribution: 3.1,
      direction: "phishing",
    });
  }

  if (hasShortDangerPhrase) {
    score = Math.max(score, hasCredentialRequest || hasFinancialLure ? 72 : 38);
    features.push({
      feature: "Short-form phishing command",
      contribution: hasCredentialRequest || hasFinancialLure ? 3.0 : 1.9,
      direction: "phishing",
    });
  }

  if ((hasSafeContext || hasBenignBillingPortalNotice) && !hasSuspiciousUrl && !hasCredentialRequest) {
    score -= hasBenignBillingPortalNotice ? 14 : 10;
    features.push({
      feature: hasBenignBillingPortalNotice
        ? "Official billing dashboard guidance"
        : "Protective safe-context wording",
      contribution: hasBenignBillingPortalNotice ? 2.1 : 1.8,
      direction: "safe",
    });
  }

  return {
    score: clamp(Math.round(score), 0, 100),
    topFeatures: features.sort((a, b) => b.contribution - a.contribution).slice(0, 8),
  };
}

export async function getTransformerScore(emailText: string): Promise<number> {
  if (!emailText || emailText.trim().length === 0) {
    return 0;
  }

  const fallbackScore = intelligenceScore(emailText).score;

  if (!TRANSFORMER_SERVICE_URL) {
    return fallbackScore;
  }

  try {
    const response = await transformerClient.post<TransformerServiceResponse>(
      TRANSFORMER_SERVICE_URL,
      {
        email_text: emailText.slice(0, 20000),
      },
    );

    const label = response.data?.label === "phishing" ? "phishing" : "safe";
    const confidence = clamp(Number(response.data?.score ?? 0.5), 0, 1);

    return label === "phishing"
      ? Math.round(confidence * 100)
      : Math.round((1 - confidence) * 100);
  } catch (error) {
    if (!hasLoggedTransformerFallbackWarning) {
      hasLoggedTransformerFallbackWarning = true;

      if (axios.isAxiosError(error)) {
        logger.warn("Transformer service request failed; using default score", {
          url: TRANSFORMER_SERVICE_URL,
          code: error.code,
          status: error.response?.status,
          message: error.message,
          suppressingRepeatedWarnings: true,
        });
      } else {
        logger.warn("Transformer service request failed; using default score", {
          url: TRANSFORMER_SERVICE_URL,
          error: (error as Error).message,
          suppressingRepeatedWarnings: true,
        });
      }
    }

    return fallbackScore;
  }
}

export async function transformerScore(text: string): Promise<{
  score: number;
  topFeatures: FeatureContribution[];
}> {
  const intelligence = intelligenceScore(text);
  const serviceConfigured = Boolean(TRANSFORMER_SERVICE_URL);
  const serviceScore = await getTransformerScore(text);

  if (!serviceConfigured) {
    return {
      score: intelligence.score,
      topFeatures: intelligence.topFeatures,
    };
  }

  const serviceFeature: FeatureContribution = {
    feature: "Python ML transformer service",
    contribution: roundContribution(Math.max(0.4, Math.abs(serviceScore - 50) / 18)),
    direction: serviceScore >= 50 ? "phishing" : "safe",
  };

  return {
    score: Math.round(intelligence.score * 0.7 + serviceScore * 0.3),
    topFeatures: mergeFeatures(intelligence.topFeatures, [serviceFeature]),
  };
}

export async function hybridScore(text: string, ruleScore = 0): Promise<{
  score: number;
  mlScore: number;
  transformerScore: number;
  classification: "safe" | "uncertain" | "phishing";
  confidence: number;
  topFeatures: FeatureContribution[];
  modelUsed: "transformer" | "tfidf" | "hybrid";
}> {
  if (!text || text.trim().length === 0) {
    return {
      score: 0,
      mlScore: 0,
      transformerScore: 0,
      classification: "safe",
      confidence: 0.99,
      topFeatures: [],
      modelUsed: "hybrid",
    };
  }

  let tfidfResult: { score: number; topFeatures: FeatureContribution[] } = {
    score: 0,
    topFeatures: [],
  };
  let intelligenceResult: { score: number; topFeatures: FeatureContribution[] } = {
    score: 0,
    topFeatures: [],
  };
  let enrichedResult: { score: number; topFeatures: FeatureContribution[] } = {
    score: clamp(ruleScore, 0, 100),
    topFeatures: [],
  };

  try {
    tfidfResult = tfidfLRScore(text);
  } catch (error) {
    logger.warn("TF-IDF scoring failed; continuing with fallback scoring", {
      error: error instanceof Error ? error.message : String(error),
    });
  }

  try {
    intelligenceResult = intelligenceScore(text);
  } catch (error) {
    logger.warn("Intelligence scoring failed; continuing with remaining signals", {
      error: error instanceof Error ? error.message : String(error),
    });
  }

  try {
    enrichedResult = await transformerScore(text);
  } catch (error) {
    logger.warn("Transformer enrichment failed; continuing with local scoring", {
      error: error instanceof Error ? error.message : String(error),
    });
  }

  const mlScore = clamp(
    Math.round(tfidfResult.score * 0.6 + intelligenceResult.score * 0.4),
    0,
    100,
  );
  const transformerScoreValue = clamp(enrichedResult.score, 0, 100);
  const score = clamp(
    Math.round(ruleScore * 0.6 + transformerScoreValue * 0.4),
    0,
    100,
  );

  const classification = score >= 61 ? "phishing" : score <= 25 ? "safe" : "uncertain";
  const confidence = clamp(
    Math.round((0.58 + (Math.abs(score - 43) / 57) * 0.38) * 100) / 100,
    0.58,
    0.96,
  );

  const modelUsed: "transformer" | "tfidf" | "hybrid" = "hybrid";

  return {
    score,
    mlScore,
    transformerScore: transformerScoreValue,
    classification,
    confidence,
    topFeatures: mergeFeatures(
      tfidfResult.topFeatures,
      intelligenceResult.topFeatures,
      enrichedResult.topFeatures,
    ),
    modelUsed,
  };
}