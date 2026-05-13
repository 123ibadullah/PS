import type { BehaviorResult } from "./behaviorEngine";
import type { DomainIntelResult } from "./domainEngine";
import type { IntentResult } from "./intentEngine";
import type { TrustResult } from "./trustEngine";

export type ConfidenceLevel = "LOW" | "MEDIUM" | "HIGH";

export interface ConfidenceSignalWeights {
  credential_request: number;
  financial_intent: number;
  urgency: number;
  authority: number;
  suspicious_url: number;
  multilingual_signal: number;
}

export interface ConfidenceScoreInput {
  text: string;
  detectedLanguage: string;
  intent: IntentResult;
  trust: TrustResult;
  domainIntel: DomainIntelResult;
  behavior: BehaviorResult;
  hasCredentialRequest: boolean;
  isFinancialScam: boolean;
  isNoLinkPhishing: boolean;
  isShortScam: boolean;
  isHindiPhishing: boolean;
  isRegionalBankThreatPhishing: boolean;
  isUrgencyPhishing: boolean;
  isSafeOtp: boolean;
  isSafeTransactional: boolean;
}

export interface ConfidenceScoreResult {
  ruleScore: number;
  confidenceLevel: ConfidenceLevel;
  matchedSignals: string[];
  signalWeights: ConfidenceSignalWeights;
  hardOverridesApplied: string[];
  shouldNeverBeSafe: boolean;
}

const SIGNAL_WEIGHTS: ConfidenceSignalWeights = {
  credential_request: 40,
  financial_intent: 35,
  urgency: 20,
  authority: 15,
  suspicious_url: 30,
  multilingual_signal: 15,
};

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

export function mapRiskScoreToConfidenceLevel(score: number): ConfidenceLevel {
  const distanceFromDecisionBoundary = Math.abs(score - 50);

  if (score <= 25 || score >= 75 || distanceFromDecisionBoundary >= 30) {
    return "HIGH";
  }

  if (distanceFromDecisionBoundary >= 15) {
    return "MEDIUM";
  }

  return "LOW";
}

export function mapConfidenceValueToLevel(confidence: number): ConfidenceLevel {
  if (confidence >= 0.85) return "HIGH";
  if (confidence >= 0.62) return "MEDIUM";
  return "LOW";
}

export function scoreToDeterministicConfidence(score: number): number {
  const normalized = clamp(score, 0, 100);

  if (normalized <= 25) {
    const safeConfidence = 0.86 + ((25 - normalized) / 25) * 0.09;
    return clamp(Number(safeConfidence.toFixed(2)), 0.05, 0.95);
  }

  if (normalized >= 75) {
    const phishingConfidence = 0.86 + ((normalized - 75) / 25) * 0.13;
    return clamp(Number(phishingConfidence.toFixed(2)), 0.05, 0.95);
  }

  const uncertaintyDistance = Math.abs(normalized - 50);
  const uncertainConfidence = 0.55 + (uncertaintyDistance / 25) * 0.22;
  return clamp(Number(uncertainConfidence.toFixed(2)), 0.05, 0.95);
}

export function computeConfidenceScore(input: ConfidenceScoreInput): ConfidenceScoreResult {
  const lower = input.text.toLowerCase();
  const matchedSignals: string[] = [];
  const hardOverridesApplied: string[] = [];

  const hasProtectiveSafeContext =
    input.isSafeOtp ||
    input.isSafeTransactional ||
    /do not share|don'?t share|never share|will never ask|if this was you|if this was not you|if this wasn't you|ignore if not you|ignore this email|ignore this message|no action required|no action is required|can safely ignore|recognized device|official (?:website|site|app)|official app|meeting invitation|join zoom meeting|meeting id|calendar invite|view completed document in docusign/i.test(
      lower,
    );

  const hasDirectMaliciousCredentialVerb =
    /reply with|send (?:your|the)|share (?:your|the)|provide (?:your|the)|enter (?:your|the)|submit (?:your|the)|reset password|secure your account|unlock your account|update (?:card|billing|bank|payment|account) details|bank details|banking details|login details|sign-?in details|mailbox ownership|confirm your credentials|validate your credentials|confirm your identity|validate your identity|re-enter|transfer funds|wire transfer|approve payment|confirm payment|make payment|pay now/i.test(
      lower,
    );

  const hasBenignBillingPortalNotice =
    (/(could(?:n'?t| not) process payment|issue processing (?:your |the )?(?:subscription )?payment|subscription payment|billing issue|billing notice|payment method(?: associated with .* account)?|authorization (?:might fail|failed|declined))/i.test(
      lower,
    ) ||
      (/amazon web services account alert/i.test(lower) && /payment method/i.test(lower))) &&
    /(dashboard|billing (?:&|and) invoices|billing settings|subscription settings|account dashboard|official (?:site|website|app)|billing home|console\.aws\.amazon\.com|support center|contact your bank|customer service|aws-account-and-billing|paymentmethods)/i.test(
      lower,
    ) &&
    !/(reply with|send (?:your|the)|share (?:your|the)|provide (?:your|the)|enter (?:your|the)|submit (?:your|the)|update (?:card|billing|bank|payment) details|re-?enter (?:your )?(?:card|bank|payment|billing) details|confirm your credentials|validate your credentials|confirm your identity|validate your identity|transfer funds?|wire transfer|approve payment|confirm payment|gift cards?|crypto|wallet)/i.test(
      lower,
    );

  const hasMfaApprovalLure =
    /(microsoft\s+authenticator|authenticator(?:\s+app)?|approval\s+request|pending\s+sign(?:-|\s)?in|sign(?:-|\s)?in\s+request|push\s+notification|okta)/i.test(
      lower,
    ) &&
    /(approve|tap\s+(?:approve|yes)|accept|confirm)/i.test(lower) &&
    /(mailbox|email|inbox|account|access|sign(?:-|\s)?in|login)/i.test(lower) &&
    !hasProtectiveSafeContext;
  const hasVoiceMessageSigninLure =
    /(svg|attached\s+(?:svg\s+)?(?:voice|voicemail|audio)\s+(?:message|recording)|voice(?:mail)?|voice\s+message|audio\s+message|recording)/i.test(
      lower,
    ) &&
    /(open|download|view|hear|listen|play)/i.test(lower) &&
    /(sign(?:-|\s)?in|log(?:-|\s)?in|authenticate|access)/i.test(lower);

  const hasBenignMeetingInvite =
    /(meeting invitation|join zoom meeting|meeting id|calendar invite|join (?:the )?meeting)/i.test(lower) &&
    /passcode[:\s]*\d+/i.test(lower) &&
    !/(confirm your (?:identity|credentials|login details)|verify your identity|keep access|maintain access|re-?enter|secure thread|update account)/i.test(lower);
  const hasPasscodeOnlyContext =
    /\bpasscode\b/i.test(lower) &&
    !/\botp\b|password|pin\b|credentials?|login details|sign-?in details|identity confirmation|confirm your identity|validate your identity/i.test(
      lower,
    );

  const rawCredentialSignal =
    input.hasCredentialRequest ||
    input.intent.hasCredentialRequest ||
    hasMfaApprovalLure ||
    hasVoiceMessageSigninLure ||
    (hasDirectMaliciousCredentialVerb &&
      /\botp\b|password|pin\b|passcode|cvv|credentials?|login details|bank details|banking details|card details|billing details|beneficiary|wallet details?|account number|aadhaar|pan\b|sign-?in details|mailbox ownership|identity confirmation|validate your identity|confirm your identity/i.test(
        lower,
      ));
  const hasCredentialSignal =
    rawCredentialSignal && (!hasProtectiveSafeContext || hasDirectMaliciousCredentialVerb) && !(hasBenignMeetingInvite && hasPasscodeOnlyContext);

  const rawFinancialIntent =
    !hasBenignBillingPortalNotice &&
    (input.isFinancialScam ||
      input.intent.hasFinancialDemand ||
      input.behavior.hasFinancialLure ||
      /₹|\brs\.?\b|rupees|payment failed|pending invoice|invoice overdue|confirm payment|approve payment|wire transfer|transfer|fee|refund|claim|prize|lottery|cashback|money|funds?|btc|bitcoin|crypto|wallet|salary|beneficiary/i.test(
        lower,
      ));
  const hasFinancialIntent = !input.isSafeTransactional && rawFinancialIntent;

  const hasEditorialNewsletterContext =
    /(newsletter|read online|update your email preferences|unsubscribe(?: here| from this sender)?|powered by beehiiv|past 24 hours|today(?:'s|’s)? newsletter|ai recap)/i.test(lower) &&
    !/reply with|send (?:your|the)|share (?:your|the)|provide (?:your|the)|enter (?:your|the)|submit (?:your|the)|otp|password|pin\b|credentials?|bank details|card details|billing details|wire transfer|bank transfer|urgent|immediate(?:ly)?|asap|final notice/i.test(lower);

  const hasUrgency =
    !hasEditorialNewsletterContext &&
    (input.isUrgencyPhishing ||
      input.intent.hasUrgencyPressure ||
      input.behavior.hasUrgency ||
      /urgent|immediate(?:ly)?|now|asap|action required|verification required|required|avoid (?:closure|suspension|disruption|penalty|action)|blocked|locked|lockout|locked\s*out|suspended|closed|closure|disabled|restriction|restricted|terminated|under review|final notice|deadline|within \d+ hours?|within \d+\s*(?:hours?|hr)|24h|24 hours|right away|right now|quickly|very important|important update|keep\s+(?:\w+\s+){0,2}access|maintain\s+(?:\w+\s+){0,2}access|restore\s+(?:\w+\s+){0,2}access|jaldi|abhi|turant|warna|nahi toh|block ho jayega|band ho jayega|band hone wala hai|service ruk jayegi|khata band|issue hoga|problem hogi|తురంత|వెంటనే|ఇప్పుడే|तुरंत|अभी|जल्दी/i.test(
        lower,
      ));

  const hasAuthority =
    input.intent.hasAuthorityImpersonation ||
    input.behavior.hasBrandMention ||
    /bank|hr|boss|support|security team|helpdesk|payroll|income tax|government|tax department|manager|customer care/i.test(
      lower,
    );

  const hasSuspiciousUrl =
    input.domainIntel.hasSuspiciousLink ||
    input.domainIntel.hasLookalikePatterns ||
    (input.domainIntel.hasAnyLink &&
      /(?:https?:\/\/|www\.)[^\s]+(?:\.xyz|\.top|\.click|\.icu|\.site|\.tk|\.ml|\.gq|\.cf)(?:\b|\/)/i.test(
        lower,
      ));
  const hasAccessMaintenanceLinkLure =
    hasSuspiciousUrl &&
    /\b(?:open|click|visit|review)\b/i.test(lower) &&
    /(keep access(?: active)?|maintain access|restore access|continue using|avoid disruption|service disruption)/i.test(
      lower,
    );

  const hasMultilingualSignal =
    input.detectedLanguage !== "en" &&
    (input.isHindiPhishing ||
      input.isRegionalBankThreatPhishing ||
      hasCredentialSignal ||
      hasUrgency);

  const shortWordCount = lower.trim().split(/\s+/).filter(Boolean).length;
  const shortText = lower.trim().length <= 90;
  const hasShortAction =
    shortText &&
    /\b(?:verify|confirm|update|reset|secure|unlock|click|submit|send|share|enter|review|check|process|handle|take action|login|required|ensure|maintain|approve|authorize|open)\b/i.test(
      lower,
    );
  const hasShortRiskyDirective =
    shortText && (/\b(?:verify|confirm|update|reset|secure|login|required)\b/i.test(lower) || /\b(?:login|account)\s+alert\b/i.test(lower));

  const hasActionContextCombo =
    !hasBenignBillingPortalNotice &&
    /\b(?:verify|verifying|update|updating|confirm|confirming|review|reviewing|check|checking|process|processing|submit|submitting|handle|handling|complete|transfer|finish|sort|secure|reset|take action|maintain|ensure|approve|approving|authorize|authorizing|open|opening|sign(?:-|\s)?in|log(?:-|\s)?in)\b/i.test(
      lower,
    ) &&
    /(account|profile|payment|invoice|service|payroll|bank|security|details?|information|identity|status|access|activity|mailbox|email|inbox)/i.test(
      lower,
    );
  const hasConsequencePressure =
    !hasEditorialNewsletterContext &&
    /urgent|urgently|immediate(?:ly)?|asap|today|tonight|before noon|24h|24 hours|(?:in|within) (?:the )?(?:next )?\d+\s*(?:hours?|hr)|next hour|time sensitive|avoid (?:closure|suspension|disruption|penalty|action)|account (?:will be )?closed|closed in 24h|disabled|restriction|restricted|terminated|unless updated|failure to respond|restore\s+(?:\w+\s+){0,2}access|keep\s+(?:\w+\s+){0,2}access|maintain\s+(?:\w+\s+){0,2}access|service disruption|payroll closes(?: today)?|i(?:'m| am) unavailable|i(?:'m| am) in a meeting|will explain later|quickly|very important|right now|jaldi|abhi|turant|warna|nahi toh|band ho jayega|block ho jayega|band hone wala hai|service ruk jayegi|khata band|issue hoga|problem hogi|తక్షణం|వెంటనే|तुरंत/i.test(
      lower,
    );
  const hasCleanLookingPhishPattern =
    shortText &&
    /for security purposes|ensure uninterrupted service|maintain access|avoid disruption/i.test(
      lower,
    );
  const hasBareLinkOnly =
    hasSuspiciousUrl &&
    /^(?:(?:https?:\/\/)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/\S*)?)$/i.test(lower.trim());
  const hasVagueUrgentTask =
    /\b(?:do\s+(?:this|it)|handle(?:\s+this)?|complete(?:\s+this)?|process(?:\s+this)?|finish(?:\s+this)?|sort(?:\s+this)?|take\s+care\s+of\s+(?:this|it))(?:\s+(?:task|request|item|payment|invoice|transfer))?\b/i.test(
      lower,
    ) &&
    (hasUrgency || hasConsequencePressure || /\b(?:jaldi\s+karo|verify\s+karo|confirm\s+karo|payment\s+karo|complete\s+karo|task\s+complete\s+karo|details\s+bhejo)\b/i.test(lower));
  const hasBecSecrecyTask =
    /\b(?:do\s+(?:this|it)|handle(?:\s+this)?|complete(?:\s+this)?|finish(?:\s+this)?|sort(?:\s+this)?|take\s+care\s+of\s+(?:this|it))\b/i.test(
      lower,
    ) &&
    /(quietly|confidential|send confirmation|confirm once done|will explain later|i can(?:not|'t) talk|cannot talk|boarding a flight|travel(?:ling|ing)|in a meeting|unavailable)/i.test(
      lower,
    );
  const hasUrgentThreat =
    (hasUrgency || hasConsequencePressure) &&
    /(account|access|profile|service|identity|login|security|khata|bank)/i.test(lower) &&
    /(blocked|suspended|closed|closure|band|block|disabled|restriction|restricted|terminated|penalty|action|issue|problem|disruption)/i.test(lower);

  const hasJobAdvanceFeePattern =
    /(job|candidate|hr|offer|onboarding|selection|remote position)/i.test(lower) &&
    /\bpay\b|payment|fee|deposit|registration/i.test(lower);
  const hasIdentityThreatPattern =
    /(suspicious|unauthorized)\s+login|confirm identity|avoid closure|account closure|avoid disruption|maintain access|restore access/i.test(
      lower,
    );
  const hasGenericSecurityPrompt = /\bsecurity (?:update|check) required\b/i.test(lower);
  const hasOfficialNoticePhishing =
    /government alert|government review pending|official notice|legal notice|income tax|aadhaar verification required|pan verification required|failure to comply may result in penalty|compliance update required|submit documents immediately/i.test(
      lower,
    );
  const hasCryptoFraudPattern =
    /wallet verification needed|limited crypto offer|send funds get return|crypto bonus available|claim crypto reward|crypto reward claim now|transfer crypto to receive bonus|double your crypto instantly|send btc get double/i.test(
      lower,
    );
  const hasAmbiguousAccountPrompt =
    !hasCredentialSignal &&
    !hasFinancialIntent &&
    !hasSuspiciousUrl &&
    /please take action regarding your account|account may require attention|immediate review is suggested|update might be needed|verify details if necessary|security might be affected|action could be required|review may help avoid issues|kindly check once|submit documents for verification|security check recommended|account alert notification|account verification recommended/i.test(
      lower,
    );
  const hasGenericAccountPrompt =
    !hasCredentialSignal &&
    !hasConsequencePressure &&
    !hasCleanLookingPhishPattern &&
    !input.behavior.hasExecutiveFraud &&
    ((/(account|security|profile|information|details|info|email address)/i.test(lower) ||
      hasGenericSecurityPrompt ||
      hasAmbiguousAccountPrompt) &&
      /\b(?:update|confirm|review|check|verify|take action)\b/i.test(lower)) &&
    !hasSuspiciousUrl &&
    !hasFinancialIntent;
  const hasBenignBillingDashboardNotice =
    (/(could(?:n't| not)|unable to|issue|problem)\s+processing[\s\S]{0,40}(?:subscription\s+|billing\s+)?payment/i.test(lower) ||
      /payment method(?: associated with .* account)?|authorization (?:might fail|failed|declined)/i.test(lower)) &&
    /(billing(?:\s*&\s*invoices?)?|dashboard|billing section|account settings|billing home|console\.aws\.amazon\.com|support center|contact your bank|customer service|paymentmethods|aws-account-and-billing)/i.test(lower) &&
    /(visit(?:ing)?|go to|open|review|check|manage|paymentmethods|support center)/i.test(lower) &&
    !/(update (?:card|billing|payment|bank|account) details|card details|billing details|bank details|reply with (?:your|the)|send (?:your|the)|share (?:your|the)|provide (?:your|the)|enter (?:your|the)|submit (?:your|the)|verify your (?:identity|account)|confirm your (?:identity|details)|transfer funds|wire transfer|urgent|immediate(?:ly)?|avoid (?:closure|disruption|suspension))/i.test(lower);

  let score = 0;

  if (hasCredentialSignal) {
    score += SIGNAL_WEIGHTS.credential_request;
    matchedSignals.push("credential_request");
  }
  if (hasFinancialIntent) {
    score += SIGNAL_WEIGHTS.financial_intent;
    matchedSignals.push("financial_intent");
  }
  if (hasUrgency) {
    score += SIGNAL_WEIGHTS.urgency;
    matchedSignals.push("urgency");
  }
  if (hasAuthority) {
    score += SIGNAL_WEIGHTS.authority;
    matchedSignals.push("authority");
  }
  if (hasSuspiciousUrl) {
    score += SIGNAL_WEIGHTS.suspicious_url;
    matchedSignals.push("suspicious_url");
  }
  if (hasMultilingualSignal) {
    score += SIGNAL_WEIGHTS.multilingual_signal;
    matchedSignals.push("multilingual_signal");
  }

  if (hasActionContextCombo || hasAmbiguousAccountPrompt) {
    score = Math.max(score, 35);
    hardOverridesApplied.push("action_context_minimum_medium");
  }

  if (
    (hasActionContextCombo && (hasUrgency || hasConsequencePressure || hasCleanLookingPhishPattern || input.behavior.hasExecutiveFraud || (hasAuthority && (hasCredentialSignal || hasFinancialIntent || hasSuspiciousUrl)))) ||
    (hasFinancialIntent && (hasConsequencePressure || input.behavior.hasExecutiveFraud))
  ) {
    score = Math.max(score, 72);
    hardOverridesApplied.push("urgency_action_context_force_high");
  }


  if (hasVagueUrgentTask || hasBecSecrecyTask || hasUrgentThreat) {
    score = Math.max(score, 74);
    hardOverridesApplied.push("urgent_task_or_threat_force_high");
  }

  if (hasOfficialNoticePhishing || hasCryptoFraudPattern) {
    score = Math.max(score, 74);
    hardOverridesApplied.push("official_or_crypto_pattern_force_high");
  }

  if (shortWordCount <= 5 && (hasShortRiskyDirective || hasVagueUrgentTask)) {
    score = Math.max(score, 35);
    hardOverridesApplied.push("short_risky_message_minimum_medium");
  }

  // This was a real blind spot in earlier QA: tiny prompts like
  // "verify now" or "update account" looked too harmless without a floor.
  if (shortWordCount <= 10 && (hasActionContextCombo || hasShortAction) && (hasUrgency || hasConsequencePressure)) {
    score = Math.max(score, 72);
    hardOverridesApplied.push("short_action_context_force_high");
  }

  if (hasCredentialSignal) {
    score = Math.max(score, 30);
    hardOverridesApplied.push("credential_request_minimum_medium");
  }

  if (hasShortAction && hasUrgency) {
    score = Math.max(score, 35);
    hardOverridesApplied.push("short_action_with_urgency_minimum_medium");
  }

  if (input.isNoLinkPhishing) {
    score = Math.max(score, 72);
    hardOverridesApplied.push("no_link_phishing_force_high");
  }

  if (hasFinancialIntent && hasUrgency) {
    score = Math.max(score, 72);
    hardOverridesApplied.push("financial_plus_urgency_force_high");
  }

  if (hasSuspiciousUrl && hasUrgency) {
    score = Math.max(score, 78);
    hardOverridesApplied.push("url_plus_urgency_force_high");
  }

  if (hasAccessMaintenanceLinkLure) {
    score = Math.max(score, 72);
    hardOverridesApplied.push("url_with_access_maintenance_force_high");
  }

  if (hasCredentialSignal && hasUrgency) {
    score = Math.max(score, 72);
    hardOverridesApplied.push("credential_plus_urgency_force_high");
  }

  if (input.behavior.hasExecutiveFraud) {
    score = Math.max(score, 74);
    hardOverridesApplied.push("executive_fraud_force_high");
  }

  if (hasMfaApprovalLure || hasVoiceMessageSigninLure) {
    score = Math.max(score, 78);
    hardOverridesApplied.push("mfa_or_voicemail_lure_force_high");
  }

  if (hasJobAdvanceFeePattern) {
    score = Math.max(score, 72);
    hardOverridesApplied.push("job_fee_pattern_force_high");
  }

  if (shortText && hasIdentityThreatPattern) {
    score = Math.max(score, 72);
    hardOverridesApplied.push("identity_threat_short_message_force_high");
  }

  if (
    shortText &&
    (/(click link|avoid suspension|secure login required|reset password|verify now|account block(?:ed)?|otp required|bank alert|confirm credentials|submit details|confirm details to avoid closure|suspicious login|confirm identity)/i.test(
      lower,
    ) || (hasShortAction && (hasCredentialSignal || hasUrgency)))
  ) {
    score = Math.max(score, 72);
    hardOverridesApplied.push("high_risk_short_message_force_high");
  }

  if ((hasGenericAccountPrompt || /\bupdate your info\b/i.test(lower)) && !hasAuthority && !hasConsequencePressure && !hasOfficialNoticePhishing && !hasCryptoFraudPattern) {
    score = clamp(Math.max(score, 35), 35, 58);
    hardOverridesApplied.push("generic_account_prompt_capped_to_medium");
  }

  const benignBusinessNote =
    /meeting|agenda|weekly|report|invoice for your purchase|delivery scheduled|subscription renewed|password changed successfully|welcome to our service|thank you for your purchase|appointment confirmed|event reminder|greetings|training session|office announcement|newsletter|feedback request|hello|how are you|catch up tomorrow|call me when free|document attached for review|attached document|review the attached document|review the document|for discussion only|informational only|thanks for the update|happy birthday|congratulations on your success|just checking in|see you soon/i.test(
      lower,
    );

  const noStrongSignals =
    !hasCredentialSignal &&
    !hasFinancialIntent &&
    !hasUrgency &&
    !hasSuspiciousUrl &&
    !hasMultilingualSignal &&
    !hasGenericAccountPrompt;

  if (hasBareLinkOnly) {
    score = Math.max(score, 32);
    hardOverridesApplied.push("bare_link_only_minimum_medium");
  } else if ((input.isSafeOtp || input.isSafeTransactional) && !hasSuspiciousUrl && !input.isNoLinkPhishing) {
    score = Math.min(score, 20);
    hardOverridesApplied.push("trusted_transaction_or_otp_force_low");
  } else if (hasBenignBillingDashboardNotice && !hasSuspiciousUrl && !hasCredentialSignal && !input.isNoLinkPhishing) {
    score = Math.min(score, input.trust.isTrustedDomain ? 20 : 24);
    hardOverridesApplied.push(
      input.trust.isTrustedDomain
        ? "trusted_billing_dashboard_force_low"
        : "billing_dashboard_context_force_low",
    );
  } else if ((hasProtectiveSafeContext || benignBusinessNote) && !hasSuspiciousUrl && !hasFinancialIntent && !input.isNoLinkPhishing) {
    score = Math.min(score, 20);
    hardOverridesApplied.push("protective_safe_context_force_low");
  } else if (noStrongSignals) {
    score = Math.min(score, 15);
    hardOverridesApplied.push("no_strong_signals_force_low");
  }

  score = clamp(score, 0, 100);

  const shouldNeverBeSafe =
    hasCredentialSignal ||
    (hasFinancialIntent && hasUrgency) ||
    hasBareLinkOnly ||
    (hasSuspiciousUrl && hasUrgency) ||
    hasAccessMaintenanceLinkLure ||
    input.isNoLinkPhishing ||
    input.isRegionalBankThreatPhishing ||
    hasVagueUrgentTask ||
    hasBecSecrecyTask ||
    hasUrgentThreat ||
    hasOfficialNoticePhishing ||
    hasCryptoFraudPattern ||
    hasMfaApprovalLure ||
    hasVoiceMessageSigninLure ||
    hasAmbiguousAccountPrompt ||
    (hasActionContextCombo && (hasUrgency || hasConsequencePressure || shortWordCount <= 10)) ||
    (shortText && (hasShortRiskyDirective || hasShortAction) && (hasUrgency || hasCredentialSignal || hasConsequencePressure || hasVagueUrgentTask));

  return {
    ruleScore: score,
    confidenceLevel: mapRiskScoreToConfidenceLevel(score),
    matchedSignals: [...new Set(matchedSignals)],
    signalWeights: SIGNAL_WEIGHTS,
    hardOverridesApplied,
    shouldNeverBeSafe,
  };
}
