export interface AttachmentContext {
  filename?: string;
  contentType?: string;
  size?: number;
  isPasswordProtected?: boolean;
  hasQrCode?: boolean;
  extractedText?: string;
}

export interface AttachmentFinding {
  filename: string;
  contentType?: string;
  risk: "low" | "medium" | "high";
  score: number;
  reasons: string[];
}

export interface AttachmentIntelResult {
  totalAttachments: number;
  suspiciousAttachmentCount: number;
  hasHighRiskAttachment: boolean;
  score: number;
  findings: AttachmentFinding[];
  summarySignals: string[];
  recommendedActions: string[];
}

const EXECUTABLE_EXTENSIONS = new Set([
  ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".bat", ".cmd", ".ps1", ".msi", ".jar", ".apk", ".iso", ".img", ".lnk", ".hta",
]);
const MACRO_EXTENSIONS = new Set([".docm", ".xlsm", ".pptm", ".xlam", ".dotm"]);
const ARCHIVE_EXTENSIONS = new Set([".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img"]);
const CONTAINER_EXTENSIONS = new Set([".eml", ".msg"]);
const SHORTCUT_EXTENSIONS = new Set([".url", ".website", ".webloc", ".scf", ".search-ms", ".library-ms", ".appref-ms"]);
const NOTEBOOK_EXTENSIONS = new Set([".one"]);
const WEB_EXTENSIONS = new Set([".html", ".htm", ".shtml", ".mht"]);
const BENIGN_EXTENSIONS = new Set([".pdf", ".png", ".jpg", ".jpeg", ".gif", ".txt", ".csv", ".ics", ".vcf"]);
const DECEPTIVE_DOUBLE_EXTENSION = /\.(?:pdf|docx?|xlsx?|pptx?|txt|jpg|jpeg|png|mp3|wav)\.(?:html?|js|jse|vbs|scr|exe|bat|cmd|zip|iso|img|lnk|url|one|svg)$/i;

function getExtension(filename: string): string {
  const match = filename.toLowerCase().match(/\.[a-z0-9]+$/i);
  return match ? match[0] : "";
}

function dedupe(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

export function analyzeAttachments(
  attachments: AttachmentContext[] = [],
  emailText: string = "",
  isTrustedSender: boolean = false,
): AttachmentIntelResult {
  if (!attachments.length) {
    return {
      totalAttachments: 0,
      suspiciousAttachmentCount: 0,
      hasHighRiskAttachment: false,
      score: 0,
      findings: [],
      summarySignals: [],
      recommendedActions: [],
    };
  }

  const loweredEmail = emailText.toLowerCase();
  const findings: AttachmentFinding[] = [];

  for (const attachment of attachments) {
    const filename = String(attachment.filename || "attachment").trim() || "attachment";
    const contentType = attachment.contentType?.trim() || undefined;
    const ext = getExtension(filename);
    const normalizedName = filename.toLowerCase();
    const extractedText = String(attachment.extractedText || "").toLowerCase();
    const combinedText = `${loweredEmail}\n${extractedText}`;
    const hasDoubleExtensionLure = DECEPTIVE_DOUBLE_EXTENSION.test(normalizedName);
    const hasMimeMismatch =
      /\.(?:pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|txt)$/i.test(normalizedName) &&
      /text\/html|application\/x-msdownload|application\/javascript|application\/hta|image\/svg\+xml|application\/internet-shortcut|text\/uri-list/i.test(contentType || "");
    const hasSociallyEngineeredName =
      /voice.?mail|voice note|fax|payment copy|payment advice|remittance|bank form|delivery label|shipping document|secure message|secure fax|browser update|account statement|shared document|review copy|review document|invoice|statement|purchase order|missed call/i.test(
        normalizedName,
      );
    const hasDangerousShortcut =
      SHORTCUT_EXTENSIONS.has(ext) || /application\/internet-shortcut|text\/uri-list/i.test(contentType || "");
    const hasNotebookLure = NOTEBOOK_EXTENSIONS.has(ext) || /application\/onenote/i.test(contentType || "");
    const hasSvgAttachment = ext === ".svg" || /image\/svg\+xml/i.test(contentType || "");
    const hasBenignArchiveContext =
      ARCHIVE_EXTENSIONS.has(ext) &&
      !attachment.isPasswordProtected &&
      !attachment.hasQrCode &&
      !hasDangerousShortcut &&
      !hasNotebookLure &&
      !hasSvgAttachment &&
      !hasSociallyEngineeredName &&
      /(source|src|build|artifact|logs?|backup|export|dataset|bundle|release|package)/i.test(normalizedName) &&
      /(internal testing|internal use|approved source archive|approved source bundle|source archive|source bundle|build artifact|diagnostic bundle|debug logs?|dataset export|backup copy|reference only|for your records|no action required)/i.test(
        combinedText,
      ) &&
      !/(login|sign-?in|credential|password|otp|invoice|payment|review the document|review the secure|secure message|voice(?:mail)?|recording|authorize app|grant consent|urgent|immediately|keep access|maintain access)/i.test(
        combinedText,
      );
    const reasons: string[] = [];
    let score = 0;

    if (EXECUTABLE_EXTENSIONS.has(ext)) {
      score += 85;
      reasons.push("Executable or script attachment type detected");
    }

    if (hasDangerousShortcut) {
      score += 82;
      reasons.push("Shortcut attachment can silently open an external site or script when clicked");
    }

    if (hasNotebookLure) {
      score += 78;
      reasons.push("OneNote attachment type is commonly abused to deliver embedded phishing or malware lures");
    }

    if (MACRO_EXTENSIONS.has(ext)) {
      score += 75;
      reasons.push("Macro-enabled Office document detected");
    }

    if (WEB_EXTENSIONS.has(ext) || /text\/html|message\/rfc822/i.test(contentType || "")) {
      score += 65;
      reasons.push("HTML or web-style attachment could be used for HTML smuggling or fake login pages");
    }

    if (hasSvgAttachment) {
      score += hasSociallyEngineeredName || /sign-?in|login|credential|password|invoice|statement|voice(?:mail)?|recording|review|secure/i.test(`${combinedText}\n${normalizedName}`) ? 74 : 42;
      reasons.push("SVG attachment can render active web content or a fake login page when opened");
    }

    if (CONTAINER_EXTENSIONS.has(ext)) {
      score += 18;
      reasons.push("Attached email/container file can hide a second-stage phishing lure or nested malicious content");
    }

    if (ARCHIVE_EXTENSIONS.has(ext)) {
      score += 35;
      reasons.push("Archive attachment requires extra caution");
    }

    if (hasDoubleExtensionLure) {
      score += 45;
      reasons.push("Attachment uses a deceptive double extension to look harmless while delivering active content");
    }

    if (hasMimeMismatch) {
      score += 35;
      reasons.push("Attachment filename and MIME type do not match, which is common in disguised malware delivery");
    }

    if (attachment.isPasswordProtected) {
      score += 22;
      reasons.push("Password-protected attachment can hide malware from normal scanners");
    }

    if (attachment.hasQrCode || /\bqr\b|scan the qr|scan qr|qr code/i.test(combinedText)) {
      score += 28;
      reasons.push("QR-based access or login lure detected");
    }

    if (/microsoft 365|onedrive|sharepoint|docusign|dropbox|authorize app|grant consent|verify your account|re-?enter|login|sign-?in|credential|password|otp|beneficiary|wallet|seed phrase/i.test(combinedText)) {
      score += 24;
      reasons.push("Attachment context contains credential, access, or payment pressure language");
    }

    if (/invoice|payment|remittance|salary|payroll|beneficiary|voicemail|voice.?mail|document|statement|secure|review|customs|delivery|fax|shared|shortcut|recording/i.test(normalizedName)) {
      score += 8;
      reasons.push("Attachment name uses a common phishing lure theme");
    }

    if (hasSociallyEngineeredName) {
      score += 12;
      reasons.push("Attachment filename is written like a social-engineering lure (voicemail, payment copy, delivery label, or secure document)");
    }

    if (hasBenignArchiveContext) {
      score = Math.max(0, score - 32);
      reasons.push("Archive context looks like an internal source, logs, or export bundle rather than an action-driven lure");
    }

    if (!isTrustedSender && BENIGN_EXTENSIONS.has(ext) && /review|urgent|confirm|beneficiary|salary|payroll|wire|bank/i.test(combinedText)) {
      score += 10;
    }

    if (isTrustedSender && (BENIGN_EXTENSIONS.has(ext) || hasBenignArchiveContext) && !attachment.isPasswordProtected && !attachment.hasQrCode && !/credential|password|otp|seed phrase|wallet|authorize app/i.test(combinedText)) {
      score = Math.max(0, score - 18);
    }

    score = Math.max(0, Math.min(100, score));
    const risk: AttachmentFinding["risk"] = score >= 70 ? "high" : score >= 30 ? "medium" : "low";

    findings.push({
      filename,
      contentType,
      risk,
      score,
      reasons: dedupe(reasons).slice(0, 4),
    });
  }

  const suspiciousAttachmentCount = findings.filter((finding) => finding.risk !== "low").length;
  const hasHighRiskAttachment = findings.some((finding) => finding.risk === "high");
  const score = Math.max(0, Math.min(100, Math.max(0, ...findings.map((finding) => finding.score))));
  const summarySignals = dedupe(findings.flatMap((finding) => finding.reasons)).slice(0, 6);

  const recommendedActions = dedupe([
    hasHighRiskAttachment ? "Do not open or download the attachment until it is verified." : "Preview the attachment in a safe viewer before opening it.",
    suspiciousAttachmentCount > 0 ? "Verify the sender through an official channel before interacting with attached files." : "No risky attachment behavior detected.",
    findings.some((finding) => /qr|credential|authorize/i.test(finding.reasons.join(" ").toLowerCase()))
      ? "Do not scan attached QR codes or approve sign-in requests from email attachments."
      : "Use the official app or website instead of any attachment-based prompts.",
  ]).filter((value) => !/No risky attachment behavior detected\./.test(value) || suspiciousAttachmentCount === 0);

  return {
    totalAttachments: attachments.length,
    suspiciousAttachmentCount,
    hasHighRiskAttachment,
    score,
    findings,
    summarySignals,
    recommendedActions,
  };
}
