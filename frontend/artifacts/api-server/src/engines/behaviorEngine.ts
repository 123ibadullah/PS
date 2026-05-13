/**
 * Behavior-level risk scoring.
 *
 * A single keyword usually is not enough. The useful patterns tend to be
 * combinations: urgency + action, payment + secrecy, brand + pressure, etc.
 */

import type { IntentResult } from "./intentEngine";
import type { TrustResult } from "./trustEngine";
import type { DomainIntelResult } from "./domainEngine";

export interface BehaviorResult {
  behaviorRiskScore: number; // 0–100
  riskCombinations: string[]; // Human-readable combos detected
  hasUrgency: boolean;
  hasFinancialLure: boolean;
  hasBrandMention: boolean;
  isTransactional: boolean;
  hasExecutiveFraud: boolean;
  hasAttachmentLure: boolean;
  hasLogisticsPaymentScam: boolean;
  hasOffPlatformRedirect: boolean;
  hasJobScamPattern: boolean;
  hasLoanOrCreditBait: boolean;
  hasSubscriptionTrap: boolean;
  hasKycOrUpiScam: boolean;
  hasCallbackScam: boolean;
  hasOAuthConsentLure: boolean;
}

export function analyzeBehavior(
  emailText: string,
  intent: IntentResult,
  trust: TrustResult,
  domainIntel: DomainIntelResult,
): BehaviorResult {
  const textLower = emailText.toLowerCase();
  const despacedText = textLower.replace(/[\u200B-\u200D\uFEFF\s]/g, "");

  let behaviorRiskScore = 0;
  const riskCombinations: string[] = [];

  // --- Detect supporting signals ---
  const hasEditorialNewsletterContext =
    /(newsletter|read online|update your email preferences|unsubscribe(?: here| from this sender)?|powered by beehiiv|past 24 hours|today(?:'s|’s)? newsletter|ai recap)/i.test(textLower) &&
    !/reply with|send (?:your|the)|share (?:your|the)|provide (?:your|the)|enter (?:your|the)|submit (?:your|the)|otp|password|pin\b|credentials?|bank details|card details|billing details|wire transfer|bank transfer|urgent|immediate(?:ly)?|asap|final notice/i.test(textLower);
  const hasUrgency =
    !hasEditorialNewsletterContext &&
    (/(?:\burgent(?:ly)?\b|\bimmediate(?:ly)?\b|\basap\b|\bnow\b|\b(?:act now|verify now|confirm now|right away|right now|today|tonight|before noon|next hour|time sensitive|deadline|final notice|last chance|24h|24 hours|(?:in|within) (?:the )?(?:next )?\d+\s*(?:hours?|hr)|quickly|very important|offer expires soon)\b|(keep|maintain|restore)\s+(?:[a-z]+\s+){0,2}access|తురంత|अभी|जल्दी|jaldi|abhi|turant|వెంటనే|త్వరగా|ఇప్పుడే)/i.test(textLower) ||
      despacedText.includes("urgent") ||
      despacedText.includes("actnow") ||
      despacedText.includes("verifynow"));

  const hasFinancialLure =
    (intent.hasFinancialDemand ||
      /win|reward|prize|cashback|gift|claim|lucky|selected|congratulations|refund|bonus|btc|bitcoin|crypto|double (?:money|btc)|instant return|guaranteed return|wallet|kyc|candidate|job|selection|offer letter|registration fee|processing fee|security deposit|refundable deposit|invoice|transfer funds?|confirm payment|credit offer|pre-?approved|loan approval|low interest|credit score|eligibility|salary\s*:\s*\$?\d+|financial services team|इनाम|बधाई|रुपये|पैसे|బహుమతి|రివార్డ్|అభినందనలు|రూపాయలు|డబ్బు/i.test(textLower) ||
      despacedText.includes("cashback") ||
      despacedText.includes("bitcoin")) &&
    !/debited|credited|payment successful|transaction completed|receipt|invoice paid|no action required/i.test(textLower);

  const hasBrandMention =
    /amazon|google|netflix|sbi|hdfc|icici|paypal|flipkart|paytm|phonepe|razorpay|microsoft|dropbox|docusign/i.test(textLower);

  const isTransactional =
    /debited|credited|order shipped|payment success|receipt|invoice paid|order (?:number|date|placed|confirmation)|successfully (?:subscribed|signed up|registered)|meeting invitation|shared a (?:file|folder) with you/i.test(textLower) &&
    !/(wish to cancel|charged automatically|refundable deposit|telegram|whatsapp|financial services team|check your eligibility now)/i.test(textLower);

  const hasVagueTaskDirective =
    /\b(?:handle|complete|process|finish|sort|take\s+care\s+of)\s+(?:this|it|the)\s+(?:task|request|item|payment|invoice|transfer)?\b|\bdo\s+(?:this|it)\b|\b(?:jaldi\s+karo|verify\s+karo|confirm\s+karo|payment\s+karo)\b/i.test(textLower);
  const hasBecPretext =
    /keep this confidential|ceo request|cfo request|finance team|payroll update|payroll closes|salary account change|direct deposit|i(?:'m| am) in a meeting|i(?:'m| am) unavailable|i can(?:not|'t) talk|cannot talk|boarding a flight|travel(?:ling|ing)|will explain later|time sensitive|urgent financial task|small help|quietly|send confirmation|confirm once done|before noon/i.test(textLower);
  const isBillingDashboardNotice =
    /(could(?:n't| not)|unable to|issue|problem)\s+processing[\s\S]{0,40}(?:subscription\s+|billing\s+)?payment/i.test(textLower) &&
    /(billing(?:\s*&\s*invoices?)?|dashboard|billing section|account settings)/i.test(textLower) &&
    !/(update (?:card|billing|payment|bank|account)|card details|billing details|bank details|wire transfer|transfer funds?|beneficiary|remittance advice|reply with|send|share|provide)/i.test(textLower);
  const hasLogisticsPaymentScam =
    /(dhl|fedex|ups|usps|courier|parcel|shipment|package|delivery|customs)/i.test(textLower) &&
    /(release fee|customs fee|delivery fee|redelivery fee|reschedule fee|import duty|pay(?:ment)?|return to sender|held at customs)/i.test(textLower) &&
    (intent.isUserAskedToAct || hasUrgency);
  const hasExecutiveFraud =
    !isBillingDashboardNotice &&
    (/wire transfer|transfer funds?|transfer money|gift cards?|vendor payment|change (?:the )?beneficiary|payment details updated|confirm payment|(?:please|kindly|can you|need you to)\s+(?:process|approve|confirm)\s+(?:the\s+)?(?:payment|invoice|transfer)|attached invoice|invoice attached|remittance advice/i.test(textLower) ||
      (hasVagueTaskDirective && (hasUrgency || hasBecPretext)));
  const hasMfaApprovalPressure =
    /(microsoft\s+authenticator|authenticator(?:\s+app)?|approval\s+request|sign(?:-|\s)?in\s+request|push\s+notification)/i.test(textLower) &&
    /(approve|tap\s+(?:approve|yes)|accept|confirm)/i.test(textLower) &&
    /(mailbox|email|inbox|account|access|sign(?:-|\s)?in|login)/i.test(textLower) &&
    !/if this was not you|if this wasn't you|ignore this email|ignore this message|do not approve/i.test(textLower);
  const hasVoiceMessageSigninLure =
    /(svg|attached\s+(?:svg\s+)?(?:voice|voicemail|audio)\s+(?:message|recording)|voice(?:mail)?|voice\s+message|audio\s+message|recording)/i.test(textLower) &&
    /(open|download|hear|listen|play|sign(?:-|\s)?in|log(?:-|\s)?in)/i.test(textLower) &&
    /(attached|attachment|sign(?:-|\s)?in|log(?:-|\s)?in|access)/i.test(textLower);

  const hasAttachmentLure =
    hasMfaApprovalPressure ||
    hasVoiceMessageSigninLure ||
    /open the attachment|download the file|attached html|enable macros?|enable content|zip file|docm|xlsm|scan (?:the )?qr code|shared document|shared file|microsoft 365|sharepoint|onedrive|docusign|dropbox|review document|view document|authorize app|grant consent|browser extension/i.test(textLower);

  const hasOffPlatformRedirect =
    /(telegram|whatsapp|signal|sms|text (?:us|me)|contact (?:our )?(?:manager|agent|recruiter|hiring manager) via|reach (?:our )?(?:manager|agent|recruiter) on)/i.test(textLower);
  const hasJobScamPattern =
    /(remote position|data entry|work from home|online profile|selected for (?:a )?(?:remote )?position|hiring manager|equipment setup|refundable deposit|registration fee|training fee|salary\s*:\s*\$?\d+)/i.test(textLower) &&
    (hasOffPlatformRedirect || /deposit|fee|telegram|whatsapp|registration|training/i.test(textLower));
  const hasLoanOrCreditBait =
    /(pre-?approved|eligibility now|credit offer|low interest|loan approval|instant loan|no impact on your credit score|check your eligibility|limited-time credit)/i.test(textLower);
  const hasSubscriptionTrap =
    /(subscription will renew|wish to cancel|charged automatically|payment method will be charged|automatic renewal|auto-?renew)/i.test(textLower) &&
    /(click|manage|cancel|renew|payment method|subscription)/i.test(textLower);
  const hasKycOrUpiScam =
    /(?:\bupi\b|collect request|\bkyc\b|\baadhaar\b|\bpan\b|wallet verification|account reactivation|refund pending)/i.test(textLower) &&
    (hasUrgency || intent.isUserAskedToAct || /click|verify|confirm|update|submit/i.test(textLower));
  const hasCallbackScam =
    /(?:call|contact)\s+(?:our\s+)?(?:billing|support|help\s*desk|customer\s*care|service|helpline|desk|team)|(?:toll[ -]?free|phone support|billing desk|customer care number)/i.test(textLower) &&
    /(?:\+?\d[\d\s().-]{6,}\d|1[-\s]?800[-\s]?\d{3}[-\s]?\d{4}|1800[-\s]?\d{3}[-\s]?\d{4})/.test(textLower) &&
    /(renew(?:al)?|subscription|invoice|order|payment|charge|charged|refund|cancel|dispute|support contract|security protection|membership)/i.test(textLower);
  const hasOAuthConsentLure =
    /(authorize app|grant consent|approve sign(?:-|\s)?in|review (?:requested )?(?:app )?permissions|allow (?:the )?app|requested (?:access|permission)s? to (?:your )?(?:gmail|drive|mailbox|calendar)|mailbox access request|oauth consent|third-party app(?:lication)? permissions?)/i.test(textLower) &&
    !/no action required|blocked a third-party app|removed app access|if this wasn't you|if this was not you|ignore this email/i.test(textLower);

  // Combination scoring is where this engine earns its keep.
  // One thing we learned the hard way: urgency and payment language also show up
  // in legit mail, so these boosts stay more conservative for trusted senders.
  if (!trust.isTrustedDomain) {
    if (hasUrgency && intent.isUserAskedToAct) {
      behaviorRiskScore += 30;
      riskCombinations.push("Urgency combined with action request — classic pressure tactic");
    }

    if (hasFinancialLure && (intent.isUserAskedToAct || hasUrgency || intent.hasAccountAlert)) {
      behaviorRiskScore += 30;
      riskCombinations.push("Financial bait combined with action request — reward scam pattern");
    }

    if (hasBrandMention && hasUrgency && intent.isUserAskedToAct) {
      behaviorRiskScore += 25;
      riskCombinations.push("Brand name + urgency + action — impersonation attack pattern");
    }

    if (hasExecutiveFraud && intent.isUserAskedToAct) {
      behaviorRiskScore += 35;
      riskCombinations.push("Executive/payment request pattern — possible BEC or invoice fraud");
    }

    if (hasLogisticsPaymentScam) {
      behaviorRiskScore += 30;
      riskCombinations.push("Shipping or customs notice unexpectedly demands payment — common delivery scam pattern");
    }

    if (hasMfaApprovalPressure) {
      behaviorRiskScore += 30;
      riskCombinations.push("Authenticator approval prompt pressures the user to grant mailbox access — MFA fatigue tactic");
    }

    if (hasVoiceMessageSigninLure) {
      behaviorRiskScore += 30;
      riskCombinations.push("Voice-message attachment pushes a sign-in step — common credential-harvest lure");
    }

    if (hasAttachmentLure) {
      behaviorRiskScore += 25;
      riskCombinations.push("Attachment, QR, or cloud-share lure detected — possible credential or malware delivery");
    }

    if (hasOffPlatformRedirect && (intent.isUserAskedToAct || hasJobScamPattern)) {
      behaviorRiskScore += 28;
      riskCombinations.push("Conversation is pushed to Telegram, WhatsApp, or SMS instead of an official channel");
    }

    if (hasJobScamPattern) {
      behaviorRiskScore += 36;
      riskCombinations.push("Unexpected remote-job message asks for off-platform contact or a deposit — common employment scam pattern");
    }

    if (hasLoanOrCreditBait && (domainIntel.hasAnyLink || intent.isUserAskedToAct)) {
      behaviorRiskScore += domainIntel.hasSuspiciousLink ? 28 : 22;
      riskCombinations.push("Pre-approved credit or low-interest loan pitch pushes a click-through action — common financial scam pattern");
    }

    if (hasSubscriptionTrap && domainIntel.hasAnyLink) {
      behaviorRiskScore += 26;
      riskCombinations.push("Subscription-renewal or cancel-now notice relies on an untrusted management link");
    }

    if (hasKycOrUpiScam) {
      behaviorRiskScore += 30;
      riskCombinations.push("KYC, UPI, or identity-update pressure detected — common India-focused scam pattern");
    }

    if (trust.senderHasRiskyTLD) {
      behaviorRiskScore += 20;
    }
  }

  if (hasCallbackScam) {
    behaviorRiskScore += trust.isTrustedDomain ? 22 : 32;
    riskCombinations.push("Phone-based callback scam pattern detected — the email pressures you to call a billing or support number about a charge or renewal");
  }

  if (hasOAuthConsentLure) {
    behaviorRiskScore += trust.isTrustedDomain ? 24 : 34;
    riskCombinations.push("App-permission or OAuth consent lure detected — a legitimate login domain can still be abused to request mailbox access");
  }

  if (intent.isSensitiveRequest && !trust.isTrustedDomain) {
    behaviorRiskScore += 35;
    riskCombinations.push("Credential request from untrusted sender — likely credential theft");
  }

  if (intent.intentRiskScore >= 60 && !trust.isTrustedDomain) {
    behaviorRiskScore += 28;
    riskCombinations.push("Multiple high-risk intent signals detected — elevated phishing intent");
  }

  if (domainIntel.hasSuspiciousLink && (intent.isUserAskedToAct || hasLoanOrCreditBait || hasSubscriptionTrap)) {
    behaviorRiskScore += 30;
    riskCombinations.push("Suspicious links combined with action request — link phishing");
  }

  if (intent.isInformational && !intent.isUserAskedToAct) {
    behaviorRiskScore -= 30;
    riskCombinations.push(
      "Informational content with no action request — standard notification",
    );
  }

  if (
    isTransactional &&
    !intent.isUserAskedToAct &&
    !domainIntel.hasSuspiciousLink
  ) {
    behaviorRiskScore -= 20;
    riskCombinations.push(
      "Transaction receipt with no action request — standard receipt",
    );
  }

  if (trust.isTrustedDomain) {
    behaviorRiskScore -= 15;
  }

  if (trust.senderHasRiskyTLD) {
    behaviorRiskScore += 20;
  }

  behaviorRiskScore = Math.max(0, Math.min(100, behaviorRiskScore));

  return {
    behaviorRiskScore,
    riskCombinations,
    hasUrgency,
    hasFinancialLure,
    hasBrandMention,
    isTransactional,
    hasExecutiveFraud,
    hasAttachmentLure,
    hasLogisticsPaymentScam,
    hasOffPlatformRedirect,
    hasJobScamPattern,
    hasLoanOrCreditBait,
    hasSubscriptionTrap,
    hasKycOrUpiScam,
    hasCallbackScam,
    hasOAuthConsentLure,
  };
}
