import type { DetectionReason } from "@workspace/api-zod";

export const TRUSTED_NEWSLETTER_DOMAINS = [
  "quora.com",
  "linkedin.com",
  "medium.com",
  "substack.com",
  "amazon.in",
  "flipkart.com",
  "irctc.co.in",
  "noreply.github.com",
];

const TRUSTED_LOW_RISK_DOMAINS = [
  ...TRUSTED_NEWSLETTER_DOMAINS,
  "hdfcbank.com",
  "icicibank.com",
  "axisbank.com",
  "sbi.co.in",
  "amazon.com",
  "google.com",
  "onedrive.com",
  "dropbox.com",
  "zoom.us",
  "docusign.net",
  "huggingface.co",
] as const;

const SMS_PATTERNS = [
  /[A-Z]{2,8}BANK:\s*Rs\.?[\d,]+/i,
  /debited from A\/c\s*[Xx*]{2,}\d{2,4}/i,
  /Not done by you\?/i,
  /\[HDFC BANK SMS ALERT\]/i,
  /txn[:\s#][A-Z0-9]{6,}/i,
] as const;

const GST_PHISHING_SIGNALS = [
  /GSTIN:\s*\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z][A-Z\d]/i,
  /non-compliance|suspended|penalty|show cause/i,
  /Ministry of Finance|GST department|GSTN portal/i,
  /upload.*documents|submit.*returns/i,
] as const;

const DELIVERY_SCAM_SIGNALS = [
  /customs fee|clearance fee|delivery fee|handling charge|redelivery fee|reschedule fee/i,
  /Rs\.?\s*[1-9]\d{0,2}(?:\b|[^,\d])/i,
  /package|parcel|shipment|courier|tracking/i,
  /fedex|dhl|india post|bluedart|ekart|ups/i,
] as const;

const HIGH_RISK_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq"] as const;

const SUSPICIOUS_DOMAIN_PATTERNS = [
  /sbi[-.]?(secure|verify|alert|update|login)/i,
  /hdfc[-.]?(bank|secure|net|alert)/i,
  /income[-.]?tax|incometax[-.]?(refund|india|gov)/i,
  /gst[-.]?(portal|india|compliance|notice)/i,
  /phonepe[-.]?(support|helpdesk|upi)/i,
  /paytm[-.]?(kyc|verify|reward)/i,
] as const;

const PHISHING_FAMILIES: Record<string, RegExp[]> = {
  "SBI-KYC-2024": [/sbi/i, /kyc/i, /expire|blocked|suspend/i, /update|verify/i],
  "HDFC-SMS-SPOOF": [/hdfc/i, /debited/i, /A\/c\s*[Xx*]{2,}\d{2,4}/i],
  "IT-REFUND-CLASSIC": [/income tax/i, /refund/i, /pan/i, /claim/i],
  "KBC-LOTTERY": [/kbc/i, /lucky draw/i, /crore|lakh/i],
  "FEDEX-CUSTOMS": [/fedex|dhl|india post|bluedart|ups/i, /customs|clearance|delivery fee/i],
  "CEO-WIRE-FRAUD": [/wire transfer|bank transfer|neft|rtgs/i, /confidential/i, /ifsc|beneficiary|account number/i],
};

const HINDI_PHISHING_SIGNALS = {
  urgency: ["तुरंत", "अभी", "जल्दी", "आखिरी मौका", "समय सीमा"],
  account: ["खाता", "बैंक खाता", "बंद", "निलंबित", "ब्लॉक"],
  reward: ["इनाम", "जीत", "लॉटरी", "करोड़", "लाख"],
  credential: ["पासवर्ड", "OTP", "पिन", "आधार", "पैन"],
  authority: ["सरकार", "आयकर", "जीएसटी", "पुलिस", "कोर्ट"],
} as const;

const TELUGU_PHISHING_SIGNALS = {
  urgency: ["వెంటనే", "ఇప్పుడే", "చివరి అవకాశం"],
  account: ["ఖాతా", "బ్యాంక్", "నిలిపివేయబడింది"],
  reward: ["బహుమతి", "లాటరీ", "గెలుపు"],
  credential: ["పాస్వర్డ్", "OTP", "పిన్"],
} as const;

const AADHAAR_PATTERN = /\b\d{4}\s?\d{4}\s?\d{4}\b/;
const PAN_PATTERN = /\b[A-Z]{5}\d{4}[A-Z]\b/;
const GSTIN_PATTERN = /\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z][A-Z\d]\b/;
const UPI_PATTERN = /\b[\w.-]+@(ybl|okicici|okhdfcbank|paytm|upi)\b/i;

export type IndiaThreatHeuristicsResult = {
  normalizedText: string;
  scoreDelta: number;
  scoreFloor: number;
  scoreCap?: number;
  weightedScore: number;
  reasons: DetectionReason[];
  matchedTerms: string[];
  warnings: string[];
  signals: string[];
  attackTypeOverride?: string;
  attackFamily?: string;
  confidenceInterval: number;
  flags: {
    newsletterContext: boolean;
    smsSpoofing: boolean;
    bec: boolean;
    deliveryScam: boolean;
    gstScam: boolean;
    phoneLure: boolean;
    hiddenText: boolean;
    shortFinancialUrl: boolean;
  };
};

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function extractSenderDomain(rawText: string, explicitSenderDomain?: string): string {
  if (explicitSenderDomain?.trim()) {
    return explicitSenderDomain.trim().toLowerCase();
  }

  const fromMatch = rawText.match(/(?:^|\n)from:\s*.*?<[^@\n]+@([^>\s]+)>/i) ?? rawText.match(/(?:^|\n)from:\s*[^@\n]+@([^\s>]+)/i);
  return fromMatch?.[1]?.trim().toLowerCase() ?? "";
}

function extractHostname(candidate: string): string {
  const rawValue = candidate.trim().toLowerCase();
  if (!rawValue) {
    return "";
  }

  const normalizedValue = rawValue.startsWith("http://") || rawValue.startsWith("https://") ? rawValue : `https://${rawValue}`;
  try {
    return new URL(normalizedValue).hostname.replace(/^www\./, "");
  } catch {
    return rawValue
      .replace(/^mailto:/, "")
      .replace(/^.*@/, "")
      .replace(/[>\s].*$/, "")
      .replace(/^www\./, "");
  }
}

function isTrustedLowRiskDomain(candidate: string): boolean {
  const hostname = extractHostname(candidate);
  return TRUSTED_LOW_RISK_DOMAINS.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
}

function collectMatches(text: string, patterns: readonly RegExp[]): string[] {
  const hits: string[] = [];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[0]) {
      hits.push(match[0]);
    }
  }
  return unique(hits);
}

function extractHiddenHtmlContent(rawText: string): {
  detected: boolean;
  normalizedText: string;
  matchedTerms: string[];
  containsUrl: boolean;
  containsCredentialRequest: boolean;
  scoreDelta: number;
} {
  const hiddenTerms: string[] = [];
  const hiddenBlocks: string[] = [];
  const hiddenPattern = /<([a-z0-9]+)(?=[^>]*style=["'][^"']*(?:color\s*:\s*(?:#fff(?:fff)?|white)|font-size\s*:\s*0(?:px)?|display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'])[^>]*>([\s\S]*?)<\/\1>/gi;

  for (const match of rawText.matchAll(hiddenPattern)) {
    const content = String(match[2] ?? "")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    if (content) {
      hiddenBlocks.push(content);
      hiddenTerms.push("hidden content detected");
    }
  }

  if (hiddenBlocks.length === 0) {
    return {
      detected: false,
      normalizedText: rawText,
      matchedTerms: [],
      containsUrl: false,
      containsCredentialRequest: false,
      scoreDelta: 0,
    };
  }

  const combined = hiddenBlocks.join(" \n");
  const containsUrl = /https?:\/\/|www\./i.test(combined);
  const containsCredentialRequest = /password|otp|pin\b|credential|login|sign(?:-|\s)?in|verify your (?:account|identity)|confirm your (?:identity|credentials)/i.test(combined);
  let scoreDelta = 12;
  if (containsUrl) scoreDelta += 25;
  if (containsCredentialRequest) scoreDelta += 30;

  const normalizedText = `${rawText}\n\n[Hidden Content Detected]\n${combined}`;
  const matchedTerms = unique([
    ...hiddenTerms,
    ...(containsUrl ? ["hidden url"] : []),
    ...(containsCredentialRequest ? ["hidden credential prompt"] : []),
  ]);

  return {
    detected: true,
    normalizedText,
    matchedTerms,
    containsUrl,
    containsCredentialRequest,
    scoreDelta,
  };
}

function extractPhoneNumbers(text: string): string[] {
  return unique(
    (text.match(/(?:\+\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d(?:[\s()-]?\d){7,13}/g) ?? [])
      .map((value) => value.trim())
      .filter((value) => value.replace(/\D/g, "").length >= 10),
  );
}

function detectAttackFamily(text: string): string | undefined {
  const lowered = text.toLowerCase();
  for (const [family, patterns] of Object.entries(PHISHING_FAMILIES)) {
    const hits = patterns.filter((pattern) => pattern.test(lowered)).length;
    const requiredHits = patterns.length >= 4 ? 3 : Math.min(2, patterns.length);
    if (hits >= requiredHits) {
      return family;
    }
  }
  return undefined;
}

export function calculateRiskScore(signals: Record<string, boolean>): number {
  const weights = {
    suspiciousURL: 30,
    credentialRequest: 25,
    brandImpersonation: 20,
    urgencyLanguage: 15,
    smsFormat: 20,
    hiddenText: 25,
    foreignPhone: 15,
    shortEmail: 10,
    newsletterModifier: -40,
    whitelistedDomain: -30,
    dkimVerified: -15,
    unsubscribePresent: -10,
  } as const;

  let score = 0;
  for (const [signal, present] of Object.entries(signals)) {
    if (present && signal in weights) {
      score += weights[signal as keyof typeof weights];
    }
  }

  return clamp(score, 0, 100);
}

export function analyzeIndiaThreatHeuristics(
  rawText: string,
  options?: {
    senderDomain?: string;
    existingUrls?: string[];
  },
): IndiaThreatHeuristicsResult {
  const senderDomain = extractSenderDomain(rawText, options?.senderDomain);
  const lower = rawText.toLowerCase();
  const urls = options?.existingUrls ?? [];
  const reasons: DetectionReason[] = [];
  const warnings: string[] = [];
  const signals: string[] = [];
  const matchedTerms: string[] = [];
  let attackTypeOverride: string | undefined;
  let scoreDelta = 0;
  let scoreFloor = 0;
  let scoreCap: number | undefined;

  const hiddenContent = extractHiddenHtmlContent(rawText);
  const normalizedText = hiddenContent.normalizedText;

  if (hiddenContent.detected) {
    scoreDelta += hiddenContent.scoreDelta;
    scoreFloor = Math.max(scoreFloor, hiddenContent.containsUrl && hiddenContent.containsCredentialRequest ? 82 : 46);
    matchedTerms.push(...hiddenContent.matchedTerms);
    signals.push("Hidden content detected");
    warnings.push("Hidden HTML content was found. Attackers use invisible text to hide malicious instructions or URLs.");
    reasons.push({
      category: hiddenContent.containsUrl || hiddenContent.containsCredentialRequest ? "social_engineering" : "url",
      description: hiddenContent.containsUrl && hiddenContent.containsCredentialRequest
        ? "Hidden text was detected in the HTML, and it contains a URL or credential request. This is a strong phishing indicator."
        : "Hidden or invisible HTML text was detected. Attackers often use this to evade visual inspection and spam filters.",
      severity: hiddenContent.containsUrl || hiddenContent.containsCredentialRequest ? "high" : "medium",
      matchedTerms: hiddenContent.matchedTerms,
    });
  }

  const hasDkimPass = /dkim=pass|signed by:\s*[a-z0-9.-]+/i.test(rawText);
  const hasUnsubscribe = /unsubscribe|update your email preferences|manage notification settings/i.test(rawText);
  const hasFooterAddress = /©\s*20\d{2}|private limited|corporation|llc|\b\d{1,5}\s+[\w .,'-]+(?:street|st|road|rd|avenue|ave|way)\b/i.test(rawText);
  const hasCredentialRequest = /otp|password|pin\b|passcode|credentials?|bank details|card details|account number|wire transfer|beneficiary|login details/i.test(lower);
  const trustedNewsletterSender = TRUSTED_NEWSLETTER_DOMAINS.some((domain) => senderDomain === domain || senderDomain.endsWith(`.${domain}`));
  const newsletterContext =
    (trustedNewsletterSender && hasDkimPass && hasUnsubscribe) ||
    (hasUnsubscribe && hasFooterAddress && !hasCredentialRequest);

  if (newsletterContext) {
    scoreDelta -= trustedNewsletterSender && hasDkimPass && hasUnsubscribe ? 40 : 18;
    signals.push("Newsletter / Digest");
    reasons.push({
      category: "informational",
      description: "This message matches a newsletter or digest pattern with unsubscribe controls and sender-footer metadata, which lowers phishing risk.",
      severity: "low",
      matchedTerms: unique([
        ...(trustedNewsletterSender ? [senderDomain || "trusted newsletter sender"] : []),
        ...(hasUnsubscribe ? ["unsubscribe"] : []),
        ...(hasDkimPass ? ["dkim pass"] : []),
      ]).slice(0, 4),
    });
    if (!attackTypeOverride) {
      attackTypeOverride = "Newsletter / Digest";
    }
  }

  const hasProtectiveOtpNotice =
    /otp|verification code|security code|one(?:-|\s)?time(?: password| code)?/i.test(lower) &&
    /do not share|don'?t share|never share|including bank staff|if this was not you|if this wasn't you|ignore this (?:message|email|notice)/i.test(lower) &&
    !/\b(?:reply|send|share|provide|enter|submit|click|login|visit|call)\b/i.test(
      lower.replace(/(?:do not|don'?t|never)\s+share\b[^.!?\n]*/gi, " "),
    );
  const trustedProtectiveOtpNotice = hasProtectiveOtpNotice && isTrustedLowRiskDomain(senderDomain);
  if (trustedProtectiveOtpNotice) {
    scoreDelta -= 10;
    scoreCap = Math.min(scoreCap ?? 100, 24);
    signals.push("Trusted OTP safety notice");
    reasons.push({
      category: "informational",
      description: "This appears to be a legitimate OTP safety notice from a trusted sender reminding the user not to share a code.",
      severity: "low",
      matchedTerms: unique([senderDomain || "trusted sender", "do not share", "otp"]).slice(0, 4),
    });
  }

  const smsMatches = collectMatches(rawText, SMS_PATTERNS);
  const isSmsSpoofing = smsMatches.length >= 2;
  if (isSmsSpoofing) {
    scoreDelta += 35;
    scoreFloor = Math.max(scoreFloor, 74);
    attackTypeOverride = "SMS Spoofing Attack";
    signals.push("SMS bank-alert spoofing pattern");
    warnings.push("This email mimics an SMS bank alert — a common Indian banking fraud technique.");
    reasons.push({
      category: "social_engineering",
      description: "This email mimics an SMS banking alert rather than a normal email, which is a common Indian phishing tactic used to create urgency and fear.",
      severity: "high",
      matchedTerms: smsMatches.slice(0, 4),
    });
    matchedTerms.push(...smsMatches);
  }

  const phoneNumbers = extractPhoneNumbers(rawText);
  const indianContext = /india|indian|sbi|hdfc|icici|upi|aadhaar|pan|gst|kbc|lottery|refund|bank|paytm|phonepe|gpay|irctc/i.test(lower);
  const foreignPhoneHits = phoneNumbers.filter((phone) => /^\+(44|1|971)/.test(phone.replace(/\s+/g, "")));
  const whatsappPrizeLure = /whatsapp|contact on whatsapp|message on whatsapp/i.test(lower) && /prize|lottery|kbc|refund|cashback|winner|reward|draw/i.test(lower);
  const hasPhoneLure = (foreignPhoneHits.length > 0 && indianContext) || whatsappPrizeLure;

  if (hasPhoneLure) {
    scoreDelta += whatsappPrizeLure ? 30 : 20;
    matchedTerms.push(...phoneNumbers.slice(0, 2));
    signals.push("Phone-based lure detected");
    reasons.push({
      category: "social_engineering",
      description: whatsappPrizeLure
        ? "The email tries to move the scam to WhatsApp or phone chat while promising a prize or refund — a common bypass tactic when attackers want to avoid suspicious links."
        : "The message uses phone-based social engineering in an Indian context, including foreign callback numbers or off-platform contact instructions.",
      severity: whatsappPrizeLure ? "high" : "medium",
      matchedTerms: unique([
        ...(foreignPhoneHits.length > 0 ? foreignPhoneHits : []),
        ...(whatsappPrizeLure ? ["WhatsApp"] : []),
      ]).slice(0, 4),
    });
  }

  const becSignals = {
    noURL: urls.length === 0,
    hasBankDetails: /IFSC|NEFT|RTGS|account number|wire transfer|beneficiary/i.test(rawText),
    hasConfidential: /confidential|do not discuss|between us|keep this private/i.test(rawText),
    hasUrgentTransfer: /transfer|wire|send money|payment urgent|release the payment|process the payment/i.test(rawText),
    sentFromMobile: /sent from my iPhone|sent from my Samsung|sent from my mobile/i.test(rawText),
    ceoTitle: /CEO|CFO|Director|MD|Managing Director|Finance Head/i.test(rawText),
  };
  const becHitCount = Object.values(becSignals).filter(Boolean).length;
  const isBec = becHitCount >= 3;
  if (isBec) {
    scoreDelta += 40;
    scoreFloor = Math.max(scoreFloor, 78);
    attackTypeOverride = "Business Email Compromise";
    signals.push("Possible business email compromise pattern");
    warnings.push("Do NOT transfer funds. Call the sender directly on a known, verified phone number before any action.");
    reasons.push({
      category: "social_engineering",
      description: "This message fits a Business Email Compromise (BEC) pattern: it pressures someone to move funds or handle a confidential payment without normal verification.",
      severity: "high",
      matchedTerms: Object.entries(becSignals)
        .filter(([, value]) => value)
        .map(([key]) => key.replace(/([A-Z])/g, " $1").toLowerCase())
        .slice(0, 4),
    });
  }

  const deliveryMatches = collectMatches(rawText, DELIVERY_SCAM_SIGNALS);
  const isDeliveryScam = deliveryMatches.length >= 2;
  if (isDeliveryScam) {
    scoreDelta += 25;
    attackTypeOverride = "Delivery Fee Scam";
    signals.push("Delivery or customs fee lure");
    reasons.push({
      category: "financial",
      description: "This message asks for a small delivery or customs fee to lower your guard before stealing payment information.",
      severity: "high",
      matchedTerms: deliveryMatches.slice(0, 4),
    });
  }

  const mentionsGst = /\bgst\b|जीएसटी/i.test(rawText);
  const gstMatches = collectMatches(rawText, GST_PHISHING_SIGNALS);
  const isGstScam = mentionsGst && gstMatches.length >= 2;
  const hasSoftGstMention = mentionsGst && gstMatches.length === 0 && newsletterContext;
  if (isGstScam) {
    scoreDelta += 35;
    attackTypeOverride = "GST Compliance Scam";
    reasons.push({
      category: "financial",
      description: "The email uses GST compliance language, penalties, or document requests consistent with GST phishing scams targeting Indian businesses and taxpayers.",
      severity: "high",
      matchedTerms: gstMatches.slice(0, 4),
    });
    matchedTerms.push(...gstMatches);
  } else if (hasSoftGstMention) {
    scoreCap = Math.min(scoreCap ?? 100, 24);
  }

  const identityRequest =
    (AADHAAR_PATTERN.test(rawText) || PAN_PATTERN.test(rawText) || GSTIN_PATTERN.test(rawText) || UPI_PATTERN.test(rawText)) &&
    /update|verify|confirm|submit|share|send/i.test(rawText);
  if (identityRequest) {
    scoreDelta += 35;
    matchedTerms.push(...unique([
      ...(AADHAAR_PATTERN.test(rawText) ? ["Aadhaar"] : []),
      ...(PAN_PATTERN.test(rawText) ? ["PAN"] : []),
      ...(GSTIN_PATTERN.test(rawText) ? ["GSTIN"] : []),
      ...(UPI_PATTERN.test(rawText) ? ["UPI"] : []),
    ]));
    signals.push("Indian identity document requested");
    reasons.push({
      category: "social_engineering",
      description: "The message asks you to update, verify, or confirm Indian identity or payment identifiers such as Aadhaar, PAN, GSTIN, or UPI IDs.",
      severity: "high",
      matchedTerms: unique([
        ...(AADHAAR_PATTERN.test(rawText) ? ["Aadhaar"] : []),
        ...(PAN_PATTERN.test(rawText) ? ["PAN"] : []),
        ...(GSTIN_PATTERN.test(rawText) ? ["GSTIN"] : []),
        ...(UPI_PATTERN.test(rawText) ? ["UPI"] : []),
      ]),
    });
  }

  const shortFinancialUrl = rawText.length < 400 && /sbi|hdfc|icici|axis|kotak|bank/i.test(lower) && /(https?:\/\/|www\.)/i.test(rawText);
  if (shortFinancialUrl) {
    scoreDelta += 10;
    signals.push("Unusually short message with financial content");
  }

  const candidateDomains = unique([
    senderDomain,
    ...urls.map((url) => extractHostname(url)),
    ...(rawText.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi) ?? []).map((domain) => extractHostname(domain)),
  ]).filter(Boolean);
  const suspiciousDomainHits = unique(
    candidateDomains.filter((domain) => {
      if (isTrustedLowRiskDomain(domain)) {
        return false;
      }

      return (
        SUSPICIOUS_DOMAIN_PATTERNS.some((pattern) => pattern.test(domain)) ||
        HIGH_RISK_TLDS.some((tld) => domain.endsWith(tld))
      );
    }),
  );
  const hasLookalikeDomain = suspiciousDomainHits.length > 0;
  if (hasLookalikeDomain) {
    scoreDelta += 30;
    attackTypeOverride = attackTypeOverride ?? "Lookalike Domain Phishing";
    signals.push("Lookalike domain detected");
    reasons.push({
      category: "url",
      description: "The email contains a lookalike or low-trust domain pattern often used to imitate Indian banking, tax, or wallet brands.",
      severity: "high",
      matchedTerms: suspiciousDomainHits.slice(0, 4),
    });
  }

  const hindiHits = unique(Object.values(HINDI_PHISHING_SIGNALS).flatMap((terms) => terms.filter((term) => rawText.includes(term))));
  const teluguHits = unique(Object.values(TELUGU_PHISHING_SIGNALS).flatMap((terms) => terms.filter((term) => rawText.includes(term))));
  if (hindiHits.length >= 2) {
    scoreDelta += 10;
    matchedTerms.push(...hindiHits.slice(0, 4));
  }
  if (teluguHits.length >= 2) {
    scoreDelta += 10;
    matchedTerms.push(...teluguHits.slice(0, 4));
  }

  const attackFamily = detectAttackFamily(rawText);
  if (attackFamily) {
    scoreDelta += 20;
    signals.push(`Known attack pattern: ${attackFamily}`);
    reasons.push({
      category: "ml_score",
      description: `Known attack pattern matched: ${attackFamily}. This family signature has been seen in repeated phishing campaigns.`,
      severity: /CEO|HDFC|SBI/i.test(attackFamily) ? "high" : "medium",
      matchedTerms: [attackFamily],
    });
  }

  const weightedScore = calculateRiskScore({
    suspiciousURL: hasLookalikeDomain || urls.some((url) => HIGH_RISK_TLDS.some((tld) => url.toLowerCase().includes(tld))),
    credentialRequest: (hasCredentialRequest || identityRequest) && !trustedProtectiveOtpNotice,
    brandImpersonation:
      /sbi|hdfc|icici|paytm|phonepe|gst|income tax|uidai|irctc/i.test(lower) &&
      !isTrustedLowRiskDomain(senderDomain) &&
      !trustedProtectiveOtpNotice,
    urgencyLanguage: /urgent|immediately|now|today|deadline|तुरंत|అత్యవసరం|వెంటనే/i.test(rawText),
    smsFormat: isSmsSpoofing,
    hiddenText: hiddenContent.detected,
    foreignPhone: foreignPhoneHits.length > 0 || whatsappPrizeLure,
    shortEmail: shortFinancialUrl,
    newsletterModifier: newsletterContext,
    whitelistedDomain: trustedNewsletterSender || trustedProtectiveOtpNotice,
    dkimVerified: hasDkimPass,
    unsubscribePresent: hasUnsubscribe,
  });

  const positiveSignalCount = [
    hiddenContent.detected,
    isSmsSpoofing,
    hasPhoneLure,
    isBec,
    isDeliveryScam,
    isGstScam,
    identityRequest,
    hasLookalikeDomain,
    Boolean(attackFamily),
    shortFinancialUrl,
  ].filter(Boolean).length;

  const confidenceInterval = positiveSignalCount >= 5 ? 3 : positiveSignalCount >= 3 ? 8 : 15;

  return {
    normalizedText,
    scoreDelta,
    scoreFloor,
    scoreCap,
    weightedScore,
    reasons,
    matchedTerms: unique(matchedTerms).slice(0, 16),
    warnings: unique(warnings),
    signals: unique(signals),
    attackTypeOverride,
    attackFamily,
    confidenceInterval,
    flags: {
      newsletterContext,
      smsSpoofing: isSmsSpoofing,
      bec: isBec,
      deliveryScam: isDeliveryScam,
      gstScam: isGstScam,
      phoneLure: hasPhoneLure,
      hiddenText: hiddenContent.detected,
      shortFinancialUrl,
    },
  };
}
