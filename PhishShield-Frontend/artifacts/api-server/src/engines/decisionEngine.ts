/**
 * Final classification step.
 *
 * The other engines collect evidence; this file decides how hard to lean on it.
 * We keep it deterministic on purpose so repeated runs stay stable under QA.
 */

import type { IntentResult } from "./intentEngine";
import type { TrustResult } from "./trustEngine";
import type { DomainIntelResult } from "./domainEngine";
import type { BehaviorResult } from "./behaviorEngine";

export type Classification = "safe" | "uncertain" | "phishing";
export type AttackType =
  | "Credential Theft"
  | "Brand Impersonation"
  | "Financial Scam"
  | "Link Phishing"
  | "Social Engineering"
  | "OTP Scam"
  | "Lookalike Domain Phishing"
  | "Account Alert / Social Engineering"
  | "Safe / Informational";

export interface DecisionResult {
  classification: Classification;
  riskScore: number;
  confidence: number;
  attackType: AttackType;
  decisionReason: string; // Which priority tier decided
}

export function makeDecision(
  intent: IntentResult,
  trust: TrustResult,
  domainIntel: DomainIntelResult,
  behavior: BehaviorResult,
  mlBaseScore: number,
): DecisionResult {
  let classification: Classification;
  let riskScore: number;
  let confidence: number;
  let attackType: AttackType = "Safe / Informational";
  let decisionReason: string;

  const dataExportVerbs = /send|reply|share|provide/i;
  const linkActionVerbs = /click|login|visit|access|go to|verify|update|confirm/i;
  const hasHighSensitivityTerm = intent.sensitiveTerms.some((term) =>
    /OTP|password|PIN|CVV|credentials|bank details|card details|billing details|Aadhaar|PAN|account number|beneficiary|private key|seed phrase|session token/i.test(
      term,
    ),
  );

  // Only DIRECT data export counts as a sensitive request
  const hasDirectSensitiveRequest = hasHighSensitivityTerm && intent.actionVerbs.some((v) => dataExportVerbs.test(v));
  const hasCredentialEntryRequest =
    (hasHighSensitivityTerm || intent.hasCredentialRequest) &&
    intent.actionVerbs.some((v) => /enter|confirm|verify|update|submit|approve|authorize|login|reset|secure|unlock|continue|proceed|check|review/i.test(v));
  const hasFinancialScamPattern =
    (behavior.hasFinancialLure || behavior.hasLogisticsPaymentScam) &&
    (intent.isUserAskedToAct || behavior.hasUrgency || intent.hasAccountAlert || intent.hasFinancialDemand);
  const hasCompositeHighRiskIntent =
    intent.intentRiskScore >= 65 ||
    (intent.hasFinancialDemand && intent.hasUrgencyPressure) ||
    (intent.hasCredentialRequest && (intent.hasUrgencyPressure || intent.hasAuthorityImpersonation));
  const hasBecTaskPressure =
    behavior.hasExecutiveFraud &&
    intent.hasUrgencyPressure &&
    intent.isUserAskedToAct &&
    !intent.isInformational;
  const hasJobOrOffPlatformScam =
    behavior.hasJobScamPattern ||
    (behavior.hasOffPlatformRedirect &&
      (intent.hasFinancialDemand || intent.isUserAskedToAct || behavior.hasFinancialLure));
  const hasSubscriptionOrCreditTrap =
    behavior.hasSubscriptionTrap || behavior.hasLoanOrCreditBait;
  const hasCallbackOrConsentScam =
    behavior.hasCallbackScam ||
    (behavior.hasOAuthConsentLure && (domainIntel.hasAnyLink || intent.isUserAskedToAct || trust.isTrustedDomain));

  // A malicious action is either a direct data export (send/reply with sensitive data)
  // OR a link-based action that points to a suspicious/lookalike URL.
  const hasMaliciousAction =
    hasDirectSensitiveRequest || 
    (intent.actionVerbs.some((v) => linkActionVerbs.test(v)) && 
     (domainIntel.hasSuspiciousLink || domainIntel.hasLookalikePatterns));

  // 1. SAFE OVERRIDE (Priority #1)
  // 1.1 Safe OTP / Security Override ("verify using code", "use this 123456")
  const hasExplicitSafeFallbackPhrase = intent.safeContextPhrases.some((phrase) =>
    /ignore|no action required|can safely ignore|do not share|security code|verification code|receipt|meeting|shared file/i.test(
      phrase,
    ),
  );

  if (intent.sensitiveTerms.includes("OTP") || hasExplicitSafeFallbackPhrase) {
    const trustedOtpOrSecurityNotice =
      trust.isTrustedDomain &&
      !domainIntel.hasAnyLink &&
      hasExplicitSafeFallbackPhrase;

    if (
      (intent.isInformational || trustedOtpOrSecurityNotice) &&
      !hasMaliciousAction &&
      !domainIntel.hasLookalikePatterns &&
      !domainIntel.hasSuspiciousLink &&
      !behavior.hasSubscriptionTrap &&
      !behavior.hasLoanOrCreditBait &&
      !behavior.hasCallbackScam &&
      !behavior.hasOAuthConsentLure
    ) {
      classification = "safe";
      riskScore = Math.min(20, mlBaseScore);
      confidence = 0.95;
      attackType = "Safe / Informational";
      decisionReason = "PRIORITY_1_SAFE_CONTEXT_OVERRIDE";
      return { classification, riskScore, confidence, attackType, decisionReason };
    }
  }

  // 1.2 Transactional Safe signals
  if (
    behavior.isTransactional &&
    !hasMaliciousAction &&
    !domainIntel.hasSuspiciousLink &&
    !behavior.hasCallbackScam &&
    !behavior.hasOAuthConsentLure
  ) {
    classification = "safe";
    riskScore = Math.min(20, mlBaseScore);
    confidence = 0.9;
    attackType = "Safe / Informational";
    decisionReason = "PRIORITY_1_SAFE_TRANSACTIONAL_OVERRIDE";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 1.3 Trusted Sender Context (Fix 4: Trusted domains with no malicious commands)
  if (
    trust.isTrustedDomain &&
    !hasMaliciousAction &&
    !domainIntel.hasSuspiciousLink &&
    !behavior.hasAttachmentLure &&
    !behavior.hasExecutiveFraud &&
    !behavior.hasJobScamPattern &&
    !behavior.hasSubscriptionTrap &&
    !behavior.hasLoanOrCreditBait &&
    !behavior.hasCallbackScam &&
    !behavior.hasOAuthConsentLure
  ) {
    // If it's a known brand, it's safe only when the content itself is routine and non-coercive.
    classification = "safe";
    riskScore = Math.min(20, mlBaseScore);
    confidence = 0.95;
    attackType = "Safe / Informational";
    decisionReason = "PRIORITY_1_TRUSTED_SENDER_OVERRIDE";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 2. HARD PHISHING (Priority #2)
  // Brand + link + untrusted-domain is a mandatory hard override.
  if (domainIntel.hasTrustedBrandMismatch && domainIntel.hasAnyLink) {
    classification = "phishing";
    riskScore = Math.max(85, Math.min(100, mlBaseScore + 35));
    confidence = 0.95;
    attackType = "Brand Impersonation";
    decisionReason = "PRIORITY_2_BRAND_DOMAIN_HARD_OVERRIDE";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  if (
    (domainIntel.hasSenderLinkMismatch || trust.hasHeaderSpoof || trust.spoofingScore >= 50) &&
    (domainIntel.hasSuspiciousLink || domainIntel.hasHighRiskTLD || domainIntel.hasPhishingKeywords)
  ) {
    classification = "phishing";
    riskScore = Math.max(80, Math.min(100, mlBaseScore + 30));
    confidence = 0.93;
    attackType = "Brand Impersonation";
    decisionReason = "PRIORITY_2_SENDER_LINK_MISMATCH_OVERRIDE";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // Phishing is only immediate if the sensitive request is DIRECT (send/reply) 
  // or combined with a malicious link (hasMaliciousAction)
  if (hasDirectSensitiveRequest || (intent.sensitiveTerms.length > 0 && hasMaliciousAction)) {
    classification = "phishing";
    riskScore = Math.max(80, Math.min(100, mlBaseScore + 40));
    confidence = 0.95;
    attackType = intent.sensitiveTerms.includes("OTP") ? "OTP Scam" : "Credential Theft";
    decisionReason = "PRIORITY_2_INTENT_DRIVEN_PHISHING";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  if (hasCredentialEntryRequest && !intent.isInformational && (behavior.hasUrgency || !trust.isTrustedDomain)) {
    classification = "phishing";
    riskScore = Math.max(78, Math.min(100, mlBaseScore + 30));
    confidence = 0.92;
    attackType = intent.sensitiveTerms.includes("OTP") ? "OTP Scam" : "Credential Theft";
    decisionReason = "PRIORITY_2_CREDENTIAL_ENTRY_REQUEST";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  if (hasCompositeHighRiskIntent && !intent.isInformational && (!trust.isTrustedDomain || behavior.hasUrgency || behavior.behaviorRiskScore >= 30)) {
    classification = intent.hasCredentialRequest || (intent.hasFinancialDemand && intent.hasUrgencyPressure) || hasBecTaskPressure
      ? "phishing"
      : "uncertain";
    riskScore = classification === "phishing"
      ? Math.max(74, Math.min(100, mlBaseScore + Math.round(intent.intentRiskScore * 0.45)))
      : Math.max(40, Math.min(72, mlBaseScore + Math.round(intent.intentRiskScore * 0.3)));
    confidence = classification === "phishing" ? 0.9 : 0.8;
    attackType = intent.hasCredentialRequest
      ? (intent.sensitiveTerms.includes("OTP") ? "OTP Scam" : "Credential Theft")
      : intent.hasFinancialDemand
        ? "Financial Scam"
        : hasBecTaskPressure
          ? "Social Engineering"
          : "Social Engineering";
    decisionReason = "PRIORITY_2_INTENT_COMPOSITE";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  if (hasJobOrOffPlatformScam && !trust.isTrustedDomain) {
    classification = "phishing";
    riskScore = Math.max(78, Math.min(100, mlBaseScore + 30));
    confidence = 0.94;
    attackType = "Social Engineering";
    decisionReason = "PRIORITY_2_JOB_OR_OFF_PLATFORM_SCAM";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  if (hasCallbackOrConsentScam) {
    classification = "phishing";
    riskScore = Math.max(76, Math.min(100, mlBaseScore + 28));
    confidence = 0.93;
    attackType = behavior.hasCallbackScam ? "Financial Scam" : "Social Engineering";
    decisionReason = behavior.hasCallbackScam
      ? "PRIORITY_2_CALLBACK_SCAM"
      : "PRIORITY_2_OAUTH_OR_APP_PERMISSION_LURE";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  if (
    hasSubscriptionOrCreditTrap &&
    !trust.isTrustedDomain &&
    (domainIntel.hasAnyLink || behavior.hasUrgency || domainIntel.riskScore >= 30)
  ) {
    classification =
      behavior.hasSubscriptionTrap || domainIntel.hasSuspiciousLink || behavior.hasUrgency
        ? "phishing"
        : "uncertain";
    riskScore =
      classification === "phishing"
        ? Math.max(72, Math.min(100, mlBaseScore + 24))
        : Math.max(44, Math.min(70, mlBaseScore + 14));
    confidence = classification === "phishing" ? 0.9 : 0.76;
    attackType = "Financial Scam";
    decisionReason = "PRIORITY_2_BILLING_OR_CREDIT_TRAP";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  if (hasFinancialScamPattern && !trust.isTrustedDomain) {
    classification = behavior.hasUrgency ? "phishing" : "uncertain";
    riskScore = behavior.hasUrgency
      ? Math.max(74, Math.min(100, mlBaseScore + 26))
      : Math.max(45, Math.min(75, mlBaseScore + 18));
    confidence = behavior.hasUrgency ? 0.9 : 0.78;
    attackType = "Financial Scam";
    decisionReason = "PRIORITY_2_FINANCIAL_LURE";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 2.1 BUSINESS EMAIL COMPROMISE / INVOICE FRAUD
  if (behavior.hasExecutiveFraud && (intent.isUserAskedToAct || trust.hasHeaderSpoof || !trust.isTrustedDomain)) {
    classification = "phishing";
    riskScore = Math.max(78, Math.min(100, mlBaseScore + 32));
    confidence = 0.92;
    attackType = "Financial Scam";
    decisionReason = "PRIORITY_2_BEC_FINANCIAL_FRAUD";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 2.2 ATTACHMENT / QR MALWARE LURE
  if (behavior.hasAttachmentLure && !trust.isTrustedDomain) {
    classification = "phishing";
    riskScore = Math.max(74, Math.min(100, mlBaseScore + 28));
    confidence = 0.9;
    attackType = "Social Engineering";
    decisionReason = "PRIORITY_2_ATTACHMENT_LURE";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 3. LINK / DOMAIN PHISHING (Priority #3)
  if (domainIntel.hasLookalikePatterns) {
    classification = "phishing";
    riskScore = Math.max(80, Math.min(100, mlBaseScore + 50));
    confidence = 0.95;
    attackType = "Lookalike Domain Phishing";
    decisionReason = "PRIORITY_3_LOOKALIKE_PHISHING";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  if (domainIntel.hasSuspiciousLink && (domainIntel.hasPhishingKeywords || behavior.behaviorRiskScore >= 30 || behavior.hasUrgency)) {
    classification = "phishing";
    riskScore = Math.max(75, Math.min(100, mlBaseScore + 35));
    confidence = 0.9;
    attackType = "Link Phishing";
    decisionReason = "PRIORITY_3_MALICIOUS_LINK";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 4. SPOOFING (Priority #4)
  if (trust.hasHeaderSpoof || trust.senderHasRiskyTLD) {
    classification = "phishing";
    riskScore = Math.max(80, Math.min(100, mlBaseScore + 45));
    confidence = 0.95;
    attackType = trust.hasHeaderSpoof ? "Brand Impersonation" : "Link Phishing";
    decisionReason = "PRIORITY_4_STRUCTURAL_FORGERY";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 5. ACCOUNT ALERT (Priority #5: UNCERTAIN override for untrusted domains)
  if (intent.hasAccountAlert && !domainIntel.hasAnyLink && !intent.isSensitiveRequest) {
    classification = "uncertain";
    riskScore = Math.max(30, Math.min(50, mlBaseScore + 20));
    confidence = 0.85;
    attackType = "Account Alert / Social Engineering";
    decisionReason = "PRIORITY_5_SOS_ACCOUNT_ALERT";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  // 6. DEFAULT / FALLBACK
  if (domainIntel.hasSuspiciousLink || behavior.hasUrgency || behavior.behaviorRiskScore >= 25) {
    classification = "uncertain";
    riskScore = Math.max(31, Math.min(60, mlBaseScore + 15));
    confidence = 0.6;
    attackType = "Social Engineering";
    decisionReason = "PRIORITY_6_UNCERTAIN_GENERAL";
    return { classification, riskScore, confidence, attackType, decisionReason };
  }

  classification = "safe";
  riskScore = Math.min(25, mlBaseScore);
  confidence = 0.85;
  attackType = "Safe / Informational";
  decisionReason = "PRIORITY_7_DEFAULT_SAFE";

  return {
    classification,
    riskScore,
    confidence,
    attackType,
    decisionReason,
  };
}
