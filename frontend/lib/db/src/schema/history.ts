import { sqliteTable, text, integer, index } from "drizzle-orm/sqlite-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";

export const scanHistoryTable = sqliteTable(
  "scan_history",
  {
    id: text("id").primaryKey(),
    timestamp: text("timestamp").notNull(),
    emailPreview: text("email_preview").notNull(),
    emailText: text("email_text").notNull().default(""),
    riskScore: integer("risk_score").notNull(),
    classification: text("classification").notNull(),
    confidence: integer("confidence").notNull().default(0),
    attackType: text("attack_type").notNull().default("Unknown"),
    detectedLanguage: text("detected_language").notNull(),
    urlCount: integer("url_count").notNull(),
    reasonCount: integer("reason_count").notNull(),
    reasonsJson: text("reasons_json").notNull().default("[]"),
    userFeedback: text("user_feedback"),
    correctedClassification: text("corrected_classification"),
    feedbackUpdatedAt: text("feedback_updated_at"),
  },
  (table) => ({
    timestampIdx: index("scan_history_timestamp_idx").on(table.timestamp),
    classificationIdx: index("scan_history_classification_idx").on(table.classification),
    feedbackIdx: index("scan_history_feedback_idx").on(table.userFeedback),
  }),
);

export const insertScanHistorySchema = createInsertSchema(scanHistoryTable);
export const selectScanHistorySchema = createSelectSchema(scanHistoryTable);

export const feedbackTable = sqliteTable(
  "feedback",
  {
    id: text("id").primaryKey(),
    emailId: text("email_id").notNull(),
    emailPreview: text("email_preview").notNull().default(""),
    emailText: text("email_text").notNull().default(""),
    predictedClassification: text("predicted_classification").notNull().default("uncertain"),
    riskScore: integer("risk_score").notNull().default(0),
    confidence: integer("confidence").notNull().default(0),
    attackType: text("attack_type").notNull().default("Unknown"),
    reasonsJson: text("reasons_json").notNull().default("[]"),
    userFeedback: text("user_feedback").notNull(),
    correctedClassification: text("corrected_classification"),
    feedbackSource: text("feedback_source").notNull().default("user"),
    feedbackNotes: text("feedback_notes").notNull().default(""),
    feedbackDisposition: text("feedback_disposition").notNull().default("needs-review"),
    isAccurate: integer("is_accurate", { mode: "boolean" }).notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    emailIdIdx: index("feedback_email_id_idx").on(table.emailId),
    createdAtIdx: index("feedback_created_at_idx").on(table.createdAt),
    userFeedbackIdx: index("feedback_user_feedback_idx").on(table.userFeedback),
  }),
);

export const insertFeedbackSchema = createInsertSchema(feedbackTable);
export const selectFeedbackSchema = createSelectSchema(feedbackTable);
