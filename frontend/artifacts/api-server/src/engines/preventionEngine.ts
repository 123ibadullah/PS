import type { AttachmentIntelResult } from "./attachmentEngine";
import type { ThreatIntelResult } from "./threatIntelEngine";

export interface PreventionPlan {
  recommendedDisposition: "allow" | "review" | "block";
  autoBlockRecommended: boolean;
  preventionActions: string[];
}

function dedupe(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

export function buildPreventionPlan(input: {
  classification: "safe" | "uncertain" | "phishing";
  attackType: string;
  suspiciousUrlCount: number;
  attachmentIntel: AttachmentIntelResult;
  threatIntel: ThreatIntelResult;
}): PreventionPlan {
  const { classification, attackType, suspiciousUrlCount, attachmentIntel, threatIntel } = input;

  const recommendedDisposition: PreventionPlan["recommendedDisposition"] =
    classification === "phishing" || threatIntel.recommendedAction === "block" || attachmentIntel.hasHighRiskAttachment
      ? "block"
      : classification === "uncertain" || threatIntel.recommendedAction === "review" || attachmentIntel.suspiciousAttachmentCount > 0
        ? "review"
        : "allow";

  const contextualActions = /Business Email Compromise/i.test(attackType)
    ? [
        "Call the sender directly on a known phone number before any transfer.",
        "Alert the finance team and pause all payment processing for this request.",
      ]
    : /OTP Scam/i.test(attackType)
      ? [
          "Never share your OTP, PIN, or passcode with anyone over email or chat.",
          "Report the message to your bank using its official helpline or app.",
        ]
      : /Reward Scam|Lottery|KBC/i.test(attackType)
        ? [
            "Report this phishing attempt to the national cybercrime portal at cybercrime.gov.in.",
            "Do not pay fees or share personal details to claim a prize.",
          ]
        : /Delivery Fee Scam/i.test(attackType)
          ? [
              "Check the official courier website or app manually before paying any fee.",
              "Ignore delivery-fee demands inside the email until the shipment is verified independently.",
            ]
          : /Newsletter \/ Digest/i.test(attackType)
            ? [
                "Add the sender to Safe Senders if you recognize it as a trusted digest.",
                "Mark the message as safe so future phishing training improves.",
              ]
            : [
                suspiciousUrlCount > 0
                  ? "Do not click links directly from the message; open the official site manually instead."
                  : "Use only official websites or apps if you need to verify the notification.",
                attachmentIntel.suspiciousAttachmentCount > 0
                  ? "Do not open attached files or scan QR codes until the sender and file are verified."
                  : "Avoid sharing passwords, OTPs, or approval codes by email.",
              ];

  const preventionActions = dedupe([
    recommendedDisposition === "block"
      ? "Quarantine or block this message before the user can act on it."
      : recommendedDisposition === "review"
        ? "Hold this message for manual review before allowing any action."
        : "No automatic blocking is needed, but keep standard sender verification in place.",
    ...contextualActions,
    /Credential|OTP|Bank|Reward|Social|Business Email Compromise/i.test(attackType)
      ? "If you already interacted with the email, rotate credentials and review account activity immediately."
      : "Report suspicious messages to the security team so similar attacks can be blocked faster.",
  ]).slice(0, 5);

  return {
    recommendedDisposition,
    autoBlockRecommended: recommendedDisposition === "block",
    preventionActions,
  };
}
