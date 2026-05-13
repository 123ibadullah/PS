export type ContextCategory =
  | "newsletter"
  | "collaboration"
  | "shipping"
  | "security_notice"
  | "invoice_or_payment"
  | "business_request"
  | "unknown";

export interface ContextAnalysisResult {
  category: ContextCategory;
  isRoutineOperationalMessage: boolean;
  hasWorkflowMismatch: boolean;
  hasThreadHijackStyleShift: boolean;
  hasUrgentWorkflowPressure: boolean;
  contextRiskScore: number;
  safeMarkers: string[];
  riskMarkers: string[];
}

function dedupe(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

export function analyzeContext(emailText: string): ContextAnalysisResult {
  const textLower = emailText.toLowerCase().replace(/\s+/g, " ").trim();
  const safeMarkers: string[] = [];
  const riskMarkers: string[] = [];

  const isNewsletterContext =
    /(newsletter|read online|unsubscribe|update your email preferences|privacy statement|release notes|official blog|product update)/i.test(
      textLower,
    );
  const isCollaborationContext =
    /(onedrive|sharepoint|microsoft teams|google docs|google drive|google workspace|gmail|drive permissions|app permissions|dropbox|docusign|shared a file with you|commented on|join the meeting|zoom meeting)/i.test(
      textLower,
    );
  const isShippingContext =
    /(dhl|fedex|ups|usps|courier|parcel|shipment|package|delivery|tracking number|customs)/i.test(
      textLower,
    );
  const isSecurityNotice =
    /(new sign(?:-|\s)?in|password changed|verification code|security alert|login alert)/i.test(
      textLower,
    );
  const isInvoiceOrPaymentContext =
    /(invoice|remittance|purchase order|vendor payment|beneficiary|payment request|wire transfer)/i.test(
      textLower,
    );
  const isReplyThread =
    /subject:\s*re:/i.test(emailText) ||
    /\b(as discussed|following up|per my last email|as requested)\b/i.test(textLower);

  const hasUrgentWorkflowPressure =
    /(?:in|within) (?:the )?(?:next )?\d+\s*(?:hours?|hr)|today|tonight|immediate(?:ly)?|urgent(?:ly)?|asap|before (?:close of business|end of day|noon)|avoid return to sender|maintain access|restore access|continue (?:using|to use)|keep using/i.test(
      textLower,
    );

  const hasShippingPaymentPivot =
    isShippingContext &&
    /(release fee|customs fee|delivery fee|reschedule fee|pay(?:ment)? .*?(?:fee|duty|release)|held at customs|return to sender|import duty)/i.test(
      textLower,
    );

  const hasCollaborationCredentialPivot =
    isCollaborationContext &&
    /(approve sign(?:-|\s)?in|grant consent|authorize app|review (?:requested )?(?:app )?permissions|allow (?:the )?app|requested access to (?:your )?(?:gmail|drive|mailbox|calendar)|keep access|continue using your (?:workspace|google|microsoft 365) account|mailbox (?:will be )?restricted|verify your account|secure document review pending|review document now)/i.test(
      textLower,
    );

  const hasThreadHijackFinancialPivot =
    isReplyThread &&
    /(change(?:d)? the beneficiary|new beneficiary|update bank details|wire transfer|process the transfer|send confirmation once done|can't talk right now|cannot talk right now|i(?:'m| am) in a meeting)/i.test(
      textLower,
    );

  const hasRoutineCollaborationMarkers =
    isCollaborationContext &&
    /(you(?:'re| are) receiving this email because|manage notification settings|privacy statement|microsoft corporation|google llc|join zoom meeting|meeting id|passcode|open in onedrive|open in dropbox|view in google docs|shared a (?:file|folder) with you|view event in google calendar)/i.test(
      textLower,
    ) &&
    !hasCollaborationCredentialPivot &&
    !hasUrgentWorkflowPressure;

  const hasRoutineSecurityMarkers =
    isSecurityNotice &&
    /(no action required|ignore if not you|can safely ignore|do not share|will never ask)/i.test(
      textLower,
    );

  const hasRoutineShippingMarkers =
    isShippingContext &&
    /(track package|delivery scheduled|out for delivery|package delivered)/i.test(textLower) &&
    !hasShippingPaymentPivot;

  if (isNewsletterContext) {
    safeMarkers.push("newsletter or editorial footer context detected");
  }

  if (hasRoutineCollaborationMarkers) {
    safeMarkers.push("routine collaboration or meeting notice from an official platform");
  }

  if (hasRoutineSecurityMarkers) {
    safeMarkers.push("passive security notification with a safe fallback path");
  }

  if (hasRoutineShippingMarkers) {
    safeMarkers.push("routine delivery update with no unexpected payment request");
  }

  let contextRiskScore = 0;

  if (hasShippingPaymentPivot) {
    contextRiskScore += hasUrgentWorkflowPressure ? 48 : 38;
    riskMarkers.push("shipping or customs notice unexpectedly demands payment");
  }

  if (hasCollaborationCredentialPivot) {
    contextRiskScore += hasUrgentWorkflowPressure ? 52 : 42;
    riskMarkers.push("shared-document notice pivots into sign-in approval or OAuth consent");
  }

  if (hasThreadHijackFinancialPivot) {
    contextRiskScore += 46;
    riskMarkers.push("reply thread shifts into a payment or beneficiary-change request");
  }

  if (
    hasUrgentWorkflowPressure &&
    /(reply once payment is complete|send confirmation once done|keep access|maintain access|avoid return to sender)/i.test(
      textLower,
    )
  ) {
    contextRiskScore += 18;
    riskMarkers.push("operational workflow is paired with deadline pressure and confirmation demand");
  }

  if (safeMarkers.length > 0 && riskMarkers.length === 0) {
    contextRiskScore = Math.max(0, contextRiskScore - 18);
  }

  let category: ContextCategory = "unknown";
  if (isCollaborationContext) category = "collaboration";
  else if (isShippingContext) category = "shipping";
  else if (isSecurityNotice) category = "security_notice";
  else if (isInvoiceOrPaymentContext) category = "invoice_or_payment";
  else if (isNewsletterContext) category = "newsletter";
  else if (isReplyThread) category = "business_request";

  const hasWorkflowMismatch = hasShippingPaymentPivot || hasCollaborationCredentialPivot;
  const hasThreadHijackStyleShift = hasThreadHijackFinancialPivot;
  const isRoutineOperationalMessage = safeMarkers.length > 0 && riskMarkers.length === 0;

  return {
    category,
    isRoutineOperationalMessage,
    hasWorkflowMismatch,
    hasThreadHijackStyleShift,
    hasUrgentWorkflowPressure,
    contextRiskScore: Math.max(0, Math.min(100, contextRiskScore)),
    safeMarkers: dedupe(safeMarkers).slice(0, 4),
    riskMarkers: dedupe(riskMarkers).slice(0, 4),
  };
}
