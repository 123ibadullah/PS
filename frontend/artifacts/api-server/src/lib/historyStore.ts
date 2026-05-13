import type { DetectionReason, ScanHistoryItem } from "@workspace/api-zod";
import { createHash, randomUUID } from "crypto";
import { client, db, scanHistoryTable, feedbackTable } from "@workspace/db";
import { count, desc, eq } from "drizzle-orm";
import {
  recordFeedbackLearningEvent,
  type CorrectedClassification,
  type FeedbackSource,
} from "./selfLearning.js";

const MAX_HISTORY = 50;
const MAX_EMAIL_LENGTH = 50_000;
const MAX_EXPORT_ROWS = 5_000;
const MAX_FEEDBACK_NOTE_LENGTH = 280;
const MAX_REASON_TEXT_LENGTH = 240;
const MAX_ATTACK_TYPE_LENGTH = 120;

type UserFeedback = "correct" | "incorrect";

export type FeedbackDisposition =
  | "confirmed-correct"
  | "false-negative"
  | "false-positive"
  | "needs-review";

export type FeedbackExportItem = {
  scanId: string;
  timestamp: string;
  emailText: string;
  emailPreview: string;
  predictedClassification: "safe" | "uncertain" | "phishing";
  correctedClassification: "safe" | "uncertain" | "phishing";
  riskScore: number;
  confidence: number;
  attackType: string;
  reasons: string[];
  reasonCount: number;
  userFeedback: UserFeedback;
  feedbackSource: FeedbackSource;
  feedbackNotes?: string;
  isMisclassified: boolean;
  feedbackDisposition: FeedbackDisposition;
  suggestedLabel: "safe" | "uncertain" | "phishing";
};

const MIGRATION_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS scan_history (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    email_preview TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    classification TEXT NOT NULL,
    detected_language TEXT NOT NULL,
    url_count INTEGER NOT NULL,
    reason_count INTEGER NOT NULL
  )`,
  `ALTER TABLE scan_history ADD COLUMN email_text TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE scan_history ADD COLUMN confidence INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE scan_history ADD COLUMN attack_type TEXT NOT NULL DEFAULT 'Unknown'`,
  `ALTER TABLE scan_history ADD COLUMN reasons_json TEXT NOT NULL DEFAULT '[]'`,
  `ALTER TABLE scan_history ADD COLUMN user_feedback TEXT`,
  `ALTER TABLE scan_history ADD COLUMN corrected_classification TEXT`,
  `ALTER TABLE scan_history ADD COLUMN feedback_updated_at TEXT`,
  `CREATE INDEX IF NOT EXISTS scan_history_timestamp_idx ON scan_history(timestamp)`,
  `CREATE INDEX IF NOT EXISTS scan_history_classification_idx ON scan_history(classification)`,
  `CREATE INDEX IF NOT EXISTS scan_history_feedback_idx ON scan_history(user_feedback)`,
  `CREATE TABLE IF NOT EXISTS feedback (
    id TEXT PRIMARY KEY,
    email_id TEXT NOT NULL,
    email_preview TEXT NOT NULL DEFAULT '',
    email_text TEXT NOT NULL DEFAULT '',
    predicted_classification TEXT NOT NULL DEFAULT 'uncertain',
    risk_score INTEGER NOT NULL DEFAULT 0,
    confidence INTEGER NOT NULL DEFAULT 0,
    attack_type TEXT NOT NULL DEFAULT 'Unknown',
    reasons_json TEXT NOT NULL DEFAULT '[]',
    user_feedback TEXT NOT NULL,
    is_accurate INTEGER NOT NULL,
    created_at TEXT NOT NULL
  )`,
  `ALTER TABLE feedback ADD COLUMN email_preview TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE feedback ADD COLUMN email_text TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE feedback ADD COLUMN predicted_classification TEXT NOT NULL DEFAULT 'uncertain'`,
  `ALTER TABLE feedback ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE feedback ADD COLUMN confidence INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE feedback ADD COLUMN attack_type TEXT NOT NULL DEFAULT 'Unknown'`,
  `ALTER TABLE feedback ADD COLUMN reasons_json TEXT NOT NULL DEFAULT '[]'`,
  `ALTER TABLE feedback ADD COLUMN user_feedback TEXT`,
  `ALTER TABLE feedback ADD COLUMN corrected_classification TEXT`,
  `ALTER TABLE feedback ADD COLUMN feedback_source TEXT NOT NULL DEFAULT 'user'`,
  `ALTER TABLE feedback ADD COLUMN feedback_notes TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE feedback ADD COLUMN feedback_disposition TEXT NOT NULL DEFAULT 'needs-review'`,
  `UPDATE feedback
   SET user_feedback = CASE WHEN is_accurate = 1 THEN 'correct' ELSE 'incorrect' END
   WHERE user_feedback IS NULL`,
  `CREATE INDEX IF NOT EXISTS feedback_email_id_idx ON feedback(email_id)`,
  `CREATE INDEX IF NOT EXISTS feedback_created_at_idx ON feedback(created_at)`,
  `CREATE INDEX IF NOT EXISTS feedback_user_feedback_idx ON feedback(user_feedback)`,
] as const;

let storageReadyPromise: Promise<void> | null = null;

async function ensureFeedbackStorage(): Promise<void> {
  if (!storageReadyPromise) {
    storageReadyPromise = (async () => {
      for (const statement of MIGRATION_STATEMENTS) {
        try {
          await client.execute(statement);
        } catch (error) {
          const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
          if (message.includes("duplicate column name") || message.includes("already exists")) {
            continue;
          }
          throw error;
        }
      }
    })();
  }

  await storageReadyPromise;
}

function normalizeClassification(value: string): "safe" | "uncertain" | "phishing" {
  if (value === "safe" || value === "phishing" || value === "uncertain") {
    return value;
  }
  return "uncertain";
}

function parseReasonDescriptions(raw: string | null | undefined): string[] {
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw) as Array<{ description?: string }>;
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed
      .map((item) => (typeof item?.description === "string" ? item.description.trim() : ""))
      .filter(Boolean);
  } catch {
    return [];
  }
}

function sanitizeMultilineStorageText(value: string | null | undefined, maxLength: number): string {
  return (value ?? "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, " ")
    .replace(/\r/g, "")
    .trim()
    .slice(0, maxLength);
}

function sanitizeSingleLineText(value: string | null | undefined, maxLength: number): string {
  return sanitizeMultilineStorageText(value, maxLength * 2)
    .replace(/<[^>]*>/g, " ")
    .replace(/[<>]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function normalizeHistoryFingerprint(raw: string | null | undefined): string {
  return (raw ?? "")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 2_000);
}

function hashHistoryFingerprint(raw: string | null | undefined): string {
  const normalized = normalizeHistoryFingerprint(raw);
  if (!normalized) {
    return "";
  }
  return createHash("sha256").update(normalized).digest("hex");
}

function deriveFeedbackDisposition(
  predictedClassification: "safe" | "uncertain" | "phishing",
  userFeedback: UserFeedback,
  correctedClassification?: CorrectedClassification,
): {
  isMisclassified: boolean;
  feedbackDisposition: FeedbackDisposition;
  suggestedLabel: "safe" | "uncertain" | "phishing";
} {
  const suggestedLabel = correctedClassification
    ? normalizeClassification(correctedClassification)
    : userFeedback === "correct"
      ? predictedClassification
      : predictedClassification === "safe"
        ? "phishing"
        : predictedClassification === "phishing"
          ? "safe"
          : "uncertain";

  if (userFeedback === "correct" || suggestedLabel === predictedClassification) {
    return {
      isMisclassified: false,
      feedbackDisposition: "confirmed-correct",
      suggestedLabel: predictedClassification,
    };
  }

  if (predictedClassification === "safe" && suggestedLabel !== "safe") {
    return {
      isMisclassified: true,
      feedbackDisposition: "false-negative",
      suggestedLabel,
    };
  }

  if (predictedClassification === "phishing" && suggestedLabel === "safe") {
    return {
      isMisclassified: true,
      feedbackDisposition: "false-positive",
      suggestedLabel,
    };
  }

  return {
    isMisclassified: true,
    feedbackDisposition: "needs-review",
    suggestedLabel,
  };
}

export async function addToHistory(params: {
  emailText: string;
  id?: string;
  riskScore: number;
  classification: "safe" | "uncertain" | "phishing";
  confidence?: number;
  attackType?: string;
  reasons?: DetectionReason[];
  detectedLanguage: string;
  urlCount: number;
  reasonCount: number;
}): Promise<void> {
  await ensureFeedbackStorage();

  const normalizedEmailText = sanitizeMultilineStorageText(params.emailText, MAX_EMAIL_LENGTH);
  const sanitizedReasons = (params.reasons ?? []).slice(0, 20).map((reason) => ({
    ...reason,
    description: sanitizeSingleLineText(reason.description, MAX_REASON_TEXT_LENGTH),
    matchedTerms: (reason.matchedTerms ?? [])
      .map((term) => sanitizeSingleLineText(term, 60))
      .filter(Boolean)
      .slice(0, 10),
  }));
  const item = {
    id: params.id || randomUUID(),
    timestamp: new Date().toISOString(),
    emailPreview: sanitizeSingleLineText(normalizedEmailText.slice(0, 80).replace(/\n/g, " "), 160),
    emailText: normalizedEmailText,
    riskScore: params.riskScore,
    classification: params.classification,
    confidence: Math.round((params.confidence ?? 0) * 100),
    attackType: sanitizeSingleLineText(params.attackType ?? "Unknown", MAX_ATTACK_TYPE_LENGTH) || "Unknown",
    detectedLanguage: params.detectedLanguage,
    urlCount: params.urlCount,
    reasonCount: params.reasonCount,
    reasonsJson: JSON.stringify(sanitizedReasons),
    userFeedback: null,
    correctedClassification: null,
    feedbackUpdatedAt: null,
  };

  const fingerprint = hashHistoryFingerprint(item.emailText);
  const existingRecentItems = await db
    .select()
    .from(scanHistoryTable)
    .orderBy(desc(scanHistoryTable.timestamp))
    .limit(MAX_HISTORY * 4);

  const duplicateItem = existingRecentItems.find((historyItem) => {
    const existingFingerprint = hashHistoryFingerprint(historyItem.emailText || historyItem.emailPreview);
    return fingerprint.length > 0 && existingFingerprint === fingerprint;
  });

  if (duplicateItem) {
    await db
      .update(scanHistoryTable)
      .set({
        timestamp: item.timestamp,
        emailPreview: item.emailPreview,
        emailText: item.emailText,
        riskScore: item.riskScore,
        classification: item.classification,
        confidence: item.confidence,
        attackType: item.attackType,
        detectedLanguage: item.detectedLanguage,
        urlCount: item.urlCount,
        reasonCount: item.reasonCount,
        reasonsJson: item.reasonsJson,
      })
      .where(eq(scanHistoryTable.id, duplicateItem.id));
    return;
  }

  await db.insert(scanHistoryTable).values(item);
}

export async function getHistory(): Promise<ScanHistoryItem[]> {
  await ensureFeedbackStorage();

  const items = await db
    .select()
    .from(scanHistoryTable)
    .orderBy(desc(scanHistoryTable.timestamp))
    .limit(MAX_HISTORY * 4);

  const seenFingerprints = new Set<string>();
  const uniqueItems = items
    .filter((item) => {
      const fingerprint = hashHistoryFingerprint(item.emailText || item.emailPreview);
      if (!fingerprint || seenFingerprints.has(fingerprint)) {
        return false;
      }
      seenFingerprints.add(fingerprint);
      return true;
    })
    .slice(0, MAX_HISTORY);

  return uniqueItems.map((item) => ({
    id: item.id,
    timestamp: item.timestamp,
    emailPreview: item.emailPreview,
    riskScore: item.riskScore,
    classification: normalizeClassification(item.classification),
    detectedLanguage: item.detectedLanguage,
    urlCount: item.urlCount,
    reasonCount: item.reasonCount,
    userFeedback:
      item.userFeedback === "correct" || item.userFeedback === "incorrect"
        ? item.userFeedback
        : undefined,
  }));
}

export async function clearHistory(): Promise<void> {
  await ensureFeedbackStorage();
  await db.delete(scanHistoryTable);
}

export async function addFeedback(data: {
  emailId: string;
  userFeedback?: UserFeedback;
  correctedClassification?: CorrectedClassification;
  feedbackSource?: FeedbackSource;
  notes?: string;
  emailText?: string;
  emailPreview?: string;
  predictedClassification?: "safe" | "uncertain" | "phishing";
  riskScore?: number;
  confidence?: number;
  attackType?: string;
  reasons?: string[];
}): Promise<void> {
  await ensureFeedbackStorage();

  const createdAt = new Date().toISOString();
  const scanRows = await db
    .select()
    .from(scanHistoryTable)
    .where(eq(scanHistoryTable.id, data.emailId))
    .limit(1);

  const scan = scanRows[0];
  const sanitizedNotes = sanitizeSingleLineText(data.notes, MAX_FEEDBACK_NOTE_LENGTH);
  const fallbackEmailText = sanitizeMultilineStorageText(data.emailText, MAX_EMAIL_LENGTH);
  const fallbackEmailPreview =
    sanitizeSingleLineText(data.emailPreview, 160) || sanitizeSingleLineText(fallbackEmailText.slice(0, 80).replace(/\n/g, " "), 160);
  const predictedClassification = normalizeClassification(
    scan?.classification ?? data.predictedClassification ?? "uncertain",
  );
  const normalizedCorrection = data.correctedClassification
    ? normalizeClassification(data.correctedClassification)
    : undefined;
  const normalizedFeedback: UserFeedback = data.userFeedback
    ? data.userFeedback
    : normalizedCorrection && normalizedCorrection === predictedClassification
      ? "correct"
      : "incorrect";
  const disposition = deriveFeedbackDisposition(
    predictedClassification,
    normalizedFeedback,
    normalizedCorrection,
  );
  const correctedClassification = normalizedCorrection ?? disposition.suggestedLabel;
  const fallbackReasonsJson = JSON.stringify(
    (data.reasons ?? [])
      .slice(0, 20)
      .map((description) => ({ description: sanitizeSingleLineText(description, MAX_REASON_TEXT_LENGTH) })),
  );
  const emailPreview = sanitizeSingleLineText(scan?.emailPreview ?? fallbackEmailPreview, 160);
  const emailText = sanitizeMultilineStorageText(scan?.emailText ?? fallbackEmailText, MAX_EMAIL_LENGTH);
  const riskScore = scan?.riskScore ?? Math.max(0, Math.round(data.riskScore ?? 0));
  const confidence = scan?.confidence ?? Math.max(0, Math.round((data.confidence ?? 0) * 100));
  const attackType = sanitizeSingleLineText(scan?.attackType ?? data.attackType ?? "Unknown", MAX_ATTACK_TYPE_LENGTH) || "Unknown";
  const reasonsJson = scan?.reasonsJson ?? fallbackReasonsJson;

  try {
    await db.insert(feedbackTable).values({
      id: randomUUID(),
      emailId: data.emailId,
      emailPreview,
      emailText,
      predictedClassification,
      correctedClassification,
      feedbackSource: data.feedbackSource ?? "user",
      feedbackNotes: sanitizedNotes,
      feedbackDisposition: disposition.feedbackDisposition,
      riskScore,
      confidence,
      attackType,
      reasonsJson,
      userFeedback: normalizedFeedback,
      isAccurate: normalizedFeedback === "correct",
      createdAt,
    });

    await db
      .update(scanHistoryTable)
      .set({
        userFeedback: normalizedFeedback,
        correctedClassification,
        feedbackUpdatedAt: createdAt,
      })
      .where(eq(scanHistoryTable.id, data.emailId));

    await recordFeedbackLearningEvent({
      scanId: data.emailId,
      timestamp: createdAt,
      emailText,
      emailPreview,
      predictedClassification,
      correctedClassification,
      userFeedback: normalizedFeedback,
      isMisclassified: disposition.isMisclassified,
      feedbackDisposition: disposition.feedbackDisposition,
      riskScore,
      confidence: Number(confidence ?? 0) / 100,
      attackType,
      reasons: parseReasonDescriptions(reasonsJson),
      feedbackSource: data.feedbackSource ?? "user",
      notes: sanitizedNotes || undefined,
    });
  } catch (err) {
    console.error("[addFeedback] DB insert failed:", err);
    throw err;
  }
}

export async function exportFeedbackData(options?: {
  onlyIncorrect?: boolean;
}): Promise<FeedbackExportItem[]> {
  await ensureFeedbackStorage();

  const rows = await db
    .select()
    .from(feedbackTable)
    .orderBy(desc(feedbackTable.createdAt))
    .limit(MAX_EXPORT_ROWS);

  return rows
    .map((row) => {
      const reasons = parseReasonDescriptions(row.reasonsJson);
      const predictedClassification = normalizeClassification(row.predictedClassification);
      const userFeedback: UserFeedback = row.userFeedback === "incorrect" ? "incorrect" : "correct";
      const correctedClassification = normalizeClassification(
        row.correctedClassification ?? predictedClassification,
      );
      const disposition = deriveFeedbackDisposition(
        predictedClassification,
        userFeedback,
        correctedClassification,
      );
      const feedbackSource: FeedbackSource =
        row.feedbackSource === "qa"
          ? "qa"
          : row.feedbackSource === "imported"
            ? "imported"
            : "user";

      return {
        scanId: row.emailId,
        timestamp: row.createdAt,
        emailText: row.emailText,
        emailPreview: row.emailPreview,
        predictedClassification,
        correctedClassification,
        riskScore: row.riskScore,
        confidence: Number(row.confidence ?? 0) / 100,
        attackType: row.attackType,
        reasons,
        reasonCount: reasons.length,
        userFeedback,
        feedbackSource,
        feedbackNotes: row.feedbackNotes || undefined,
        feedbackDisposition:
          row.feedbackDisposition === "confirmed-correct" ||
          row.feedbackDisposition === "false-negative" ||
          row.feedbackDisposition === "false-positive" ||
          row.feedbackDisposition === "needs-review"
            ? row.feedbackDisposition
            : disposition.feedbackDisposition,
        isMisclassified: disposition.isMisclassified,
        suggestedLabel: disposition.suggestedLabel,
      };
    })
    .filter((item) => (options?.onlyIncorrect ? item.isMisclassified : true));
}

export async function getSessionCounts(): Promise<{
  totalScans: number;
  phishingDetected: number;
  suspiciousDetected: number;
  safeDetected: number;
}> {
  await ensureFeedbackStorage();

  const groups = await db
    .select({
      classification: scanHistoryTable.classification,
      count: count(scanHistoryTable.id),
    })
    .from(scanHistoryTable)
    .groupBy(scanHistoryTable.classification);

  let totalScans = 0;
  let phishingDetected = 0;
  let suspiciousDetected = 0;
  let safeDetected = 0;

  for (const group of groups) {
    const c = Number(group.count);
    totalScans += c;
    if (group.classification === "phishing") phishingDetected += c;
    else if (group.classification === "suspicious" || group.classification === "uncertain") suspiciousDetected += c;
    else if (group.classification === "safe") safeDetected += c;
  }

  return { totalScans, phishingDetected, suspiciousDetected, safeDetected };
}
