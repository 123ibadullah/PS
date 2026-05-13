type CampaignTheme =
  | "credential-reset"
  | "otp-harvest"
  | "invoice-transfer"
  | "beneficiary-change"
  | "customs-fee"
  | "oauth-doc-lure"
  | "crypto-reward"
  | "job-fee"
  | "generic-phish";

export interface PolymorphicAnalysisResult {
  familyKey: string;
  theme: CampaignTheme;
  recentVariantCount: number;
  hasActiveCampaign: boolean;
  campaignRiskScore: number;
  indicators: string[];
}

type RecentFingerprint = {
  timestamp: number;
  familyKey: string;
  theme: CampaignTheme;
  variantKey: string;
};

const RECENT_WINDOW_MS = 6 * 60 * 60 * 1000;
const MAX_RECENT_FINGERPRINTS = 500;
const recentFingerprints: RecentFingerprint[] = [];

function dedupe(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function detectTheme(textLower: string): { theme: CampaignTheme; indicators: string[] } {
  const indicators: string[] = [];

  if (/beneficiary|change (?:the )?beneficiary|send confirmation once done|i(?:'m| am) in a meeting|can't talk/i.test(textLower)) {
    indicators.push("beneficiary change or BEC tasking language");
    return { theme: "beneficiary-change", indicators };
  }

  if (/invoice|wire transfer|process the transfer|vendor payment|remittance/i.test(textLower)) {
    indicators.push("invoice or transfer request");
    return { theme: "invoice-transfer", indicators };
  }

  if (/customs|parcel|delivery fee|release fee|return to sender|courier|shipment/i.test(textLower)) {
    indicators.push("delivery or customs fee lure");
    return { theme: "customs-fee", indicators };
  }

  if (/sharepoint|onedrive|google docs|shared document|grant consent|authorize app|approve sign-?in|browser extension/i.test(textLower)) {
    indicators.push("shared-document or OAuth consent lure");
    return { theme: "oauth-doc-lure", indicators };
  }

  if (/otp|one time password|reply with your otp|send otp/i.test(textLower)) {
    indicators.push("OTP harvesting language");
    return { theme: "otp-harvest", indicators };
  }

  if (/reset password|verify your account|confirm your credentials|login required|secure your account/i.test(textLower)) {
    indicators.push("credential reset or account verification lure");
    return { theme: "credential-reset", indicators };
  }

  if (/crypto|btc|bitcoin|wallet|seed phrase|double your money|guaranteed return/i.test(textLower)) {
    indicators.push("crypto reward or wallet lure");
    return { theme: "crypto-reward", indicators };
  }

  if (/job|candidate|offer letter|registration fee|processing fee|security deposit/i.test(textLower)) {
    indicators.push("job or onboarding fee lure");
    return { theme: "job-fee", indicators };
  }

  indicators.push("generic phishing structure");
  return { theme: "generic-phish", indicators };
}

function tokenize(textLower: string): string[] {
  return (textLower.match(/[a-z]{4,}/g) || [])
    .filter((token) => !new Set(["this", "that", "with", "your", "from", "have", "will", "please", "account", "message", "email", "today"]).has(token))
    .slice(0, 80);
}

function buildFamilyKey(theme: CampaignTheme, tokens: string[]): string {
  const importantTokens = dedupe(tokens).sort().slice(0, 8);
  return `${theme}:${importantTokens.join("|")}`;
}

function buildVariantKey(theme: CampaignTheme, textLower: string): string {
  const normalized = textLower
    .replace(/\d+/g, "#")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 220);
  return `${theme}:${normalized}`;
}

function pruneRecentFingerprints(now: number): void {
  while (recentFingerprints.length > 0 && now - recentFingerprints[0]!.timestamp > RECENT_WINDOW_MS) {
    recentFingerprints.shift();
  }
  while (recentFingerprints.length > MAX_RECENT_FINGERPRINTS) {
    recentFingerprints.shift();
  }
}

export function analyzePolymorphicCampaign(emailText: string): PolymorphicAnalysisResult {
  const textLower = emailText.toLowerCase().replace(/https?:\/\/\S+/g, " ").replace(/\s+/g, " ").trim();
  const safeContext = /unsubscribe|privacy statement|newsletter|read online|no action required|if this was not you|if this was you|can safely ignore|meeting id|passcode|calendar invite|do not share|don'?t share|never share|will never ask|you requested to sign in|password changed successfully|automated receipt|subscription renewed|order confirmation|manage notification settings|shared a (?:file|folder) with you|open in dropbox|view event in google calendar|join zoom meeting/i.test(textLower);
  const highRiskContext = /urgent|immediate|reply with|send|share|provide|pay|transfer|confirm payment|approve sign-?in|authorize app|grant consent|beneficiary|wallet|reset password|verify your account|confirm your credentials|mailbox|delivery fee|customs fee/i.test(textLower);

  const { theme, indicators } = detectTheme(textLower);
  const tokens = tokenize(textLower);
  const familyKey = buildFamilyKey(theme, tokens);
  const variantKey = buildVariantKey(theme, textLower);
  const now = Date.now();

  pruneRecentFingerprints(now);

  const familyVariants = new Set(
    recentFingerprints
      .filter((entry) => entry.theme === theme || entry.familyKey === familyKey)
      .map((entry) => entry.variantKey),
  );
  const recentVariantCount = familyVariants.has(variantKey)
    ? Math.max(0, familyVariants.size - 1)
    : familyVariants.size;

  let campaignRiskScore = 0;
  if (!safeContext && highRiskContext && theme !== "generic-phish") {
    campaignRiskScore += recentVariantCount >= 3 ? 20 : recentVariantCount >= 1 ? 10 : 0;
  }

  const hasActiveCampaign = !safeContext && highRiskContext && theme !== "generic-phish" && recentVariantCount >= 1;

  const existingIndex = recentFingerprints.findIndex((entry) => entry.variantKey === variantKey);
  if (existingIndex >= 0) {
    recentFingerprints[existingIndex] = {
      ...recentFingerprints[existingIndex]!,
      timestamp: now,
      familyKey,
      theme,
      variantKey,
    };
  } else {
    recentFingerprints.push({
      timestamp: now,
      familyKey,
      theme,
      variantKey,
    });
  }

  return {
    familyKey,
    theme,
    recentVariantCount,
    hasActiveCampaign,
    campaignRiskScore,
    indicators: dedupe(indicators),
  };
}
