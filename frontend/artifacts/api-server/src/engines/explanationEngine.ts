/**
 * EXPLANATION ENGINE — Human-readable analysis output
 *
 * Generates structured explanations based ONLY on triggered signals.
 * Zero hallucination — if a signal didn't fire, no explanation for it.
 */

import type { IntentResult } from "./intentEngine";
import type { TrustResult } from "./trustEngine";
import type { DomainIntelResult } from "./domainEngine";
import type { BehaviorResult } from "./behaviorEngine";
import type { Classification, AttackType } from "./decisionEngine";

export interface ExplanationResult {
  summary: string; // One-line verdict
  whatIsHappening: string; // What the email is doing
  whyItIsRisky: string; // Why it's dangerous (or not)
  whatAttackerWants: string; // Attacker's goal
  whatUserShouldDo: string; // Actionable advice
  impact: ImpactPrediction;
  reasons: ExplanationReason[];
  warnings: string[];
  safetyTips: string[];
}

export type ReasonCategory =
  | "urgency"
  | "financial"
  | "social_engineering"
  | "url"
  | "domain"
  | "india_specific"
  | "ml_score"
  | "language"
  | "header"
  | "informational";

export interface ExplanationReason {
  category: ReasonCategory;
  description: string;
  severity: "low" | "medium" | "high";
  matchedTerms: string[];
}

export interface ImpactPrediction {
  accountTakeover: boolean;
  financialLoss: boolean;
  identityTheft: boolean;
  summary: string;
}

export function generateExplanation(
  classification: Classification,
  attackType: AttackType,
  intent: IntentResult,
  trust: TrustResult,
  domainIntel: DomainIntelResult,
  behavior: BehaviorResult,
): ExplanationResult {
  const reasons: ExplanationReason[] = [];
  const warnings: string[] = [];

  // ─── Build reasons ONLY from triggered signals ───
  if (classification !== "safe") {
    if (domainIntel.hasSuspiciousLink) {
      reasons.push({
        category: "url",
        description: "Suspicious or high-risk URLs detected in the email.",
        severity: "high",
        matchedTerms: ["suspicious link"],
      });
    }

    if (domainIntel.hasLookalikePatterns) {
      reasons.push({
        category: "url",
        description:
          "Domain name appears to be a fake lookalike of a trusted brand.",
        severity: "high",
        matchedTerms: ["lookalike domain"],
      });
    }

    if (behavior.hasFinancialLure) {
      reasons.push({
        category: "financial",
        description:
          "The message uses a financial lure like a prize, fee, or reward to bait you into taking action.",
        severity: "high",
        matchedTerms: ["financial lure"],
      });
    }

    if (behavior.hasLogisticsPaymentScam) {
      reasons.push({
        category: "financial",
        description:
          "The email pretends to be a delivery or customs notice but unexpectedly asks for a release fee or payment confirmation — a common parcel scam pattern.",
        severity: "high",
        matchedTerms: ["delivery fee scam", "customs release fee"],
      });
    }

    if (behavior.hasJobScamPattern) {
      reasons.push({
        category: "social_engineering",
        description:
          "The message offers a remote job, pushes you to Telegram or another off-platform channel, and asks for a deposit or setup fee — a common employment scam pattern.",
        severity: "high",
        matchedTerms: ["telegram job scam", "refundable deposit"],
      });
    } else if (behavior.hasOffPlatformRedirect) {
      reasons.push({
        category: "social_engineering",
        description:
          "The sender tries to move the conversation to Telegram, WhatsApp, or SMS instead of an official support or hiring channel.",
        severity: "high",
        matchedTerms: ["off-platform redirect"],
      });
    }

    if (behavior.hasCallbackScam) {
      reasons.push({
        category: "financial",
        description:
          "The email pushes you to call a billing or support number about a fake charge, renewal, or refund — a common callback-phishing pattern.",
        severity: "high",
        matchedTerms: ["callback scam", "fake support number"],
      });
    }

    if (behavior.hasOAuthConsentLure) {
      reasons.push({
        category: "social_engineering",
        description:
          "The message asks you to approve app permissions or grant mailbox access. Attackers use legitimate login domains for this type of OAuth-consent phishing.",
        severity: "high",
        matchedTerms: ["OAuth consent lure", "app permissions"],
      });
    }

    if (behavior.hasLoanOrCreditBait) {
      reasons.push({
        category: "financial",
        description:
          "The message promises pre-approved credit or low-interest financing to lure you into clicking an untrusted application link.",
        severity: "medium",
        matchedTerms: ["credit offer lure", "loan bait"],
      });
    }

    if (behavior.hasSubscriptionTrap) {
      reasons.push({
        category: "financial",
        description:
          "The email uses a subscription-renewal or cancel-now pretext with a payment-management link, which is a common billing scam pattern.",
        severity: "high",
        matchedTerms: ["subscription renewal bait", "cancel-now billing lure"],
      });
    }

    if (behavior.hasKycOrUpiScam) {
      reasons.push({
        category: "india_specific",
        description:
          "The message uses KYC, UPI, Aadhaar, or PAN verification pressure — a common India-focused phishing pattern.",
        severity: "high",
        matchedTerms: ["KYC or UPI scam pattern"],
      });
    }

    if (behavior.hasExecutiveFraud) {
      reasons.push({
        category: "financial",
        description:
          "The email matches a possible business email compromise (BEC) pattern: vague urgent tasking or payment/invoice language often used to impersonate executives.",
        severity: "high",
        matchedTerms: ["possible business email compromise (BEC) pattern", "invoice fraud", "executive payment request"],
      });
    }

    if (behavior.hasAttachmentLure) {
      reasons.push({
        category: "social_engineering",
        description:
          "The message pressures you to open an attachment, enable content, or scan a QR code.",
        severity: "high",
        matchedTerms: ["attachment lure", "QR lure"],
      });
    }

    if (behavior.hasUrgency) {
      reasons.push({
        category: "urgency",
        description:
          "The email uses explicit urgency wording to push quick action before you can verify it.",
        severity: "medium",
        matchedTerms: ["urgent language"],
      });
    }

    if (trust.hasHeaderSpoof || trust.senderHasRiskyTLD) {
      reasons.push({
        category: "header",
        description:
          "The sender identity is spoofed or uses a disposable high-risk domain.",
        severity: "high",
        matchedTerms: ["spoofed domain"],
      });
    }

    if (intent.isSensitiveRequest) {
      reasons.push({
        category: "social_engineering",
        description: `The email asks you to ${buildSensitiveRequestPhrase(intent)}.`,
        severity: "high",
        matchedTerms: intent.sensitiveTerms,
      });
    }

    if (behavior.hasBrandMention && behavior.hasUrgency) {
      reasons.push({
        category: "india_specific",
        description:
          "A well-known brand name is used alongside urgency — possible impersonation.",
        severity: "high",
        matchedTerms: ["brand impersonation"],
      });
    }
  }

  // Default reason for clearly safe emails only
  if (reasons.length === 0 && classification === "safe") {
    reasons.push({
      category: "ml_score",
      description:
        "No threatening intent detected. This appears to be a standard communication.",
      severity: "low",
      matchedTerms: [],
    });
  }

  // ─── Build user-facing warnings ───
  if (classification === "phishing") {
    warnings.push(
      "Do not click any links or reply to this email. This appears to be a phishing attempt.",
    );
    if (domainIntel.hasSuspiciousLink) {
      warnings.push(
        "The links in this email lead to suspicious domains — not the real websites they claim to be.",
      );
    }
    warnings.push(
      "If you think your account may actually be at risk, contact the organization directly using their official number or website.",
    );
  } else if (classification === "uncertain") {
    warnings.push(
      "This email has some unusual patterns. Verify that it is genuine before clicking any links.",
    );
    warnings.push(
      "If in doubt, contact the sender through a different channel — phone or official website.",
    );
  }

  // ─── Generate human-readable story ───
  const whatIsHappening = generateWhatIsHappening(
    classification,
    attackType,
    intent,
    behavior,
  );
  const whyItIsRisky = generateWhyRisky(
    classification,
    intent,
    trust,
    domainIntel,
    behavior,
  );
  const whatAttackerWants = generateAttackerGoal(
    classification,
    attackType,
    intent,
    behavior,
  );
  const whatUserShouldDo = generateUserAdvice(classification, attackType, behavior);
  const summary = generateSummary(classification, attackType);

  // ─── Impact prediction ───
  const impact = predictImpact(classification, attackType, intent);

  // ─── Safety tips ───
  const safetyTips = [
    "Verify the sender's email address carefully — scammers use lookalike addresses",
    "Never share OTP, PIN, password, or Aadhaar/PAN details over email",
    "Your bank will NEVER ask for account details via email",
    "Call the official helpline to confirm any urgent requests",
    "Hover over links to see the real destination before clicking",
    "Enable 2-factor authentication on all accounts",
    "Report phishing emails to cybercrime.gov.in",
  ];

  return {
    summary,
    whatIsHappening,
    whyItIsRisky,
    whatAttackerWants,
    whatUserShouldDo,
    impact,
    reasons,
    warnings,
    safetyTips,
  };
}

function formatHumanList(items: string[]): string {
  const uniqueItems = [...new Set(items.map((item) => item.trim()).filter(Boolean))];

  if (uniqueItems.length === 0) return "";
  if (uniqueItems.length === 1) return uniqueItems[0];
  if (uniqueItems.length === 2) return `${uniqueItems[0]} and ${uniqueItems[1]}`;
  return `${uniqueItems.slice(0, -1).join(", ")}, and ${uniqueItems[uniqueItems.length - 1]}`;
}

function buildSensitiveObjectPhrase(sensitiveTerms: string[]): string {
  const uniqueTerms = [...new Set(sensitiveTerms.map((term) => term.trim()).filter(Boolean))];

  if (uniqueTerms.length === 0) {
    return "sensitive information";
  }

  if (uniqueTerms.length === 1) {
    return `your ${uniqueTerms[0]}`;
  }

  if (uniqueTerms.length <= 3) {
    return `sensitive information such as your ${formatHumanList(uniqueTerms)}`;
  }

  return "sensitive information such as your credentials or account details";
}

function pickSensitiveActionVerb(actionVerbs: string[]): string {
  const normalizedVerbs = [...new Set(actionVerbs.map((verb) => verb.toLowerCase()))];
  const preferredVerbs = [
    "share",
    "send",
    "provide",
    "enter",
    "submit",
    "reply",
    "confirm",
    "verify",
    "update",
    "reset",
    "secure",
  ];

  for (const verb of preferredVerbs) {
    if (normalizedVerbs.includes(verb)) {
      return verb;
    }
  }

  if (normalizedVerbs.includes("login")) {
    return "enter";
  }

  return "share";
}

function buildSensitiveRequestPhrase(intent: IntentResult): string {
  return `${pickSensitiveActionVerb(intent.actionVerbs)} ${buildSensitiveObjectPhrase(intent.sensitiveTerms)}`;
}

function generateSummary(
  classification: Classification,
  attackType: AttackType,
): string {
  if (classification === "safe")
    return "This email appears to be a legitimate communication with no threatening intent.";
  if (classification === "uncertain")
    return "This email has unusual patterns that warrant caution before taking any action.";
  if (attackType === "Credential Theft")
    return "⚠️ This email is attempting to steal your login credentials or sensitive information.";
  if (attackType === "Financial Scam")
    return "⚠️ This email uses financial bait to trick you into a scam.";
  if (attackType === "Brand Impersonation")
    return "⚠️ This email impersonates a trusted organization to deceive you.";
  if (attackType === "Link Phishing")
    return "⚠️ This email contains malicious links designed to steal your data.";
  return "⚠️ This email shows signs of a phishing or social engineering attack.";
}

function generateWhatIsHappening(
  classification: Classification,
  attackType: AttackType,
  intent: IntentResult,
  behavior: BehaviorResult,
): string {
  if (classification === "safe") {
    if (intent.sensitiveTerms.length > 0 && intent.isInformational) {
      return "This email is providing you with a security code or notification. It contains disclaimers telling you NOT to share this information.";
    }
    if (behavior.isTransactional) {
      return "This is a standard transaction receipt or notification about account activity.";
    }
    return "This appears to be a standard, non-threatening email communication.";
  }

  if (behavior.hasJobScamPattern) {
    return "This email looks like a fake recruitment message: it offers a job, pushes you to Telegram or another off-platform channel, and introduces a deposit or onboarding fee.";
  }
  if (behavior.hasCallbackScam) {
    return "This email tries to make you call a billing or support number about a fake charge, renewal, or refund. That is a classic callback-phishing pattern.";
  }
  if (behavior.hasOAuthConsentLure) {
    return "This email asks you to review app permissions or allow mailbox access. Attackers often abuse legitimate Google or Microsoft consent pages for this kind of phishing.";
  }
  if (behavior.hasSubscriptionTrap) {
    return "This email uses a subscription-renewal or cancel-now pretext to push you toward an untrusted billing-management link.";
  }
  if (behavior.hasLoanOrCreditBait) {
    return "This email advertises a pre-approved credit or loan offer and pushes you to act quickly through a low-trust application link.";
  }
  if (behavior.hasExecutiveFraud) {
    return "This email matches a possible business email compromise (BEC) pattern: a vague urgent task or payment-style request meant to pressure you into acting without normal verification.";
  }
  if (attackType === "Credential Theft") {
    return `This email is asking you to ${buildSensitiveRequestPhrase(intent)}. This is a credential theft attempt.`;
  }
  if (attackType === "Financial Scam") {
    return "This email uses a financial reward or prize to bait you into providing personal information or making a payment.";
  }
  if (attackType === "Brand Impersonation") {
    return "Someone is pretending to be a trusted organization and creating urgency to trick you into acting quickly.";
  }
  if (attackType === "Link Phishing") {
    return "This email contains links that lead to fake or dangerous websites designed to harvest your credentials.";
  }
  return "This email uses social manipulation techniques to trick you into taking a harmful action.";
}

function generateWhyRisky(
  classification: Classification,
  intent: IntentResult,
  trust: TrustResult,
  domainIntel: DomainIntelResult,
  behavior: BehaviorResult,
): string {
  if (classification === "safe")
    return "No risk indicators detected. The email is informational and does not request any sensitive actions.";

  const riskFactors: string[] = [];
  if (intent.isSensitiveRequest)
    riskFactors.push("it asks for sensitive credentials");
  if (trust.hasHeaderSpoof) riskFactors.push("the sender identity is forged");
  if (trust.senderHasRiskyTLD)
    riskFactors.push("the sender uses a disposable domain");
  if (domainIntel.hasSuspiciousLink)
    riskFactors.push("it contains suspicious links");
  if (behavior.hasUrgency && intent.isUserAskedToAct)
    riskFactors.push("it uses urgency to pressure you");
  if (behavior.hasExecutiveFraud)
    riskFactors.push("it matches a possible business email compromise (BEC) pattern");
  if (behavior.hasJobScamPattern)
    riskFactors.push("it follows a fake-job and deposit scam pattern");
  if (behavior.hasOffPlatformRedirect)
    riskFactors.push("it tries to move the conversation off-platform");
  if (behavior.hasCallbackScam)
    riskFactors.push("it tries to redirect you to a phone number to continue the scam verbally");
  if (behavior.hasOAuthConsentLure)
    riskFactors.push("it asks you to approve app permissions or mailbox access through an OAuth-style consent flow");
  if (behavior.hasSubscriptionTrap)
    riskFactors.push("it uses a subscription cancellation or renewal pretext with an untrusted link");
  if (behavior.hasLoanOrCreditBait)
    riskFactors.push("it uses a pre-approved credit or loan lure");
  if (behavior.hasKycOrUpiScam)
    riskFactors.push("it matches a common KYC or UPI scam pattern");
  if (behavior.hasFinancialLure) riskFactors.push("it uses financial bait");

  if (riskFactors.length === 0)
    return "The message contains suspicious action or account-related language that should be verified independently.";
  return `This is risky because ${riskFactors.join(", ")}.`;
}

function generateAttackerGoal(
  classification: Classification,
  attackType: AttackType,
  intent: IntentResult,
  behavior: BehaviorResult,
): string {
  if (classification === "safe")
    return "No attacker detected. This appears to be a legitimate sender.";
  if (attackType === "Credential Theft")
    return `The attacker wants your ${intent.sensitiveTerms.join(", ")} to gain unauthorized access to your accounts.`;
  if (behavior.hasJobScamPattern)
    return "The attacker wants you to leave trusted channels, pay a fake onboarding or setup fee, and continue the scam privately.";
  if (behavior.hasCallbackScam)
    return "The attacker wants you to call a fake support number, lower your guard in a live conversation, and then steal money or remote access.";
  if (behavior.hasOAuthConsentLure)
    return "The attacker wants you to grant a malicious app access to your mailbox, files, or account without stealing your password directly.";
  if (behavior.hasSubscriptionTrap)
    return "The attacker wants you to click into a fake subscription-management flow and hand over payment or account details.";
  if (behavior.hasLoanOrCreditBait)
    return "The attacker wants you to trust a fake credit or loan offer and enter information into a risky application flow.";
  if (attackType === "Financial Scam")
    return "The attacker wants to trick you into paying a fake fee, clicking into a risky billing flow, or revealing financial details.";
  if (attackType === "Brand Impersonation")
    return "The attacker wants to exploit your trust in a well-known brand to extract personal information.";
  if (attackType === "Link Phishing")
    return "The attacker wants you to visit a fake website where your login credentials will be captured.";
  return "The attacker is using psychological manipulation to trick you into a harmful action.";
}

function generateUserAdvice(
  classification: Classification,
  attackType: AttackType,
  behavior: BehaviorResult,
): string {
  if (classification === "safe")
    return "No special action needed. This email appears safe.";
  if (classification === "uncertain")
    return "Exercise caution. Verify the sender through a separate channel before taking any action.";

  if (behavior.hasCallbackScam)
    return "Do NOT call the number in the email. Open the vendor's official website or app yourself and verify the charge there instead.";
  if (behavior.hasOAuthConsentLure)
    return "Do NOT approve the app request from the email. Review connected apps only from your official Google or Microsoft account settings.";
  if (attackType === "Credential Theft")
    return "Do NOT send any credentials. Contact the organization directly through their official website or helpline.";
  if (attackType === "Financial Scam")
    return "Ignore the financial claim. No legitimate organization gives prizes via email without prior context.";
  if (attackType === "Link Phishing")
    return "Do NOT click any links. If concerned, go to the service directly by typing their URL in your browser.";
  return "Do not reply or click any links. Report this email as phishing.";
}

function predictImpact(
  classification: Classification,
  attackType: AttackType,
  intent: IntentResult,
): ImpactPrediction {
  if (classification === "safe") {
    return {
      accountTakeover: false,
      financialLoss: false,
      identityTheft: false,
      summary: "No harmful impact expected. This email is safe.",
    };
  }

  const accountTakeover =
    attackType === "Credential Theft" || attackType === "Link Phishing";
  const financialLoss =
    attackType === "Financial Scam" ||
    intent.sensitiveTerms.some((t) =>
      ["CVV", "card number", "bank details", "PIN"].includes(t),
    );
  const identityTheft = intent.sensitiveTerms.some((t) =>
    ["Aadhaar", "PAN", "SSN"].includes(t),
  );

  const impacts: string[] = [];
  if (accountTakeover) impacts.push("account takeover");
  if (financialLoss) impacts.push("financial loss");
  if (identityTheft) impacts.push("identity theft");

  return {
    accountTakeover,
    financialLoss,
    identityTheft,
    summary:
      impacts.length > 0
        ? `If you respond to this email, you risk: ${impacts.join(", ")}.`
        : "Potential social engineering impact — proceed with caution.",
  };
}
