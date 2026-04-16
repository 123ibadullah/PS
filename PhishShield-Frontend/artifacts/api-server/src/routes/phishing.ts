import {
  Router,
  type IRouter,
  type Request,
  type Response,
  type NextFunction,
} from "express";
import {
  AnalyzeEmailBody,
  SubmitFeedbackBody,
  GenerateReportBody,
  type AnalyzeResult,
} from "@workspace/api-zod";
import { analyzeEmail } from "../lib/phishingDetector.js";
import { cleanEmail } from "../lib/emailPreprocessor.js";
import { addToHistory, addFeedback, exportFeedbackData } from "../lib/historyStore.js";
import { randomUUID } from "crypto";
import rateLimit from "express-rate-limit";
import {
  asyncHandler,
  ValidationError,
  AuthenticationError,
  InternalServerError
} from "../middlewares/errorHandler.js";
import { logger, phishingLogger } from "../lib/logger.js";

const router: IRouter = Router();

const MAX_EMAIL_LENGTH = 50_000;

// Rate limiter: Max 30 requests per minute
const analyzeLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // Limit each IP/API key to 30 requests per minute
  message: {
    error: "rate_limited",
    message: "Too many analysis requests, please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Authentication Middleware
const requireApiKey = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  const expectedKey = process.env.API_KEY || "dev-sandbox-key";

  if (
    !authHeader ||
    !authHeader.startsWith("Bearer ") ||
    authHeader.split(" ")[1] !== expectedKey
  ) {
    throw new AuthenticationError("Invalid or missing API key.");
  }

  next();
};

router.post("/analyze", analyzeLimiter, requireApiKey, asyncHandler(async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;

  // Validate request body
  const parsed = AnalyzeEmailBody.safeParse(req.body);
  if (!parsed.success) {
    throw new ValidationError("Invalid request body. Please provide emailText as a string.");
  }

  let { emailText, headers, attachments } = parsed.data;

  // Reject extremely massive inputs outright before regex mapping
  if (emailText && emailText.length > 500_000) {
    throw new ValidationError("Email length exceeds maximum safe hardware bounds (500k).");
  }

  // 1. Safe Processing pipeline
  const cleanOutput = cleanEmail(emailText);
  const safeText = cleanOutput.bodyText;
  const safeHeaders = headers || cleanOutput.rawHeaders || "";

  if (!safeText || safeText.trim().length === 0) {
    // Return a safe neutral fallback rather than crashing
    const scanId = randomUUID();
    phishingLogger.info("Empty email text after cleaning, returning safe fallback", { scanId }, correlationId);

    res.json({
      id: scanId,
      riskScore: 0,
      risk_score: 0,
      classification: "safe",
      confidence: 0,
      confidenceLevel: "LOW",
      confidenceLabel: "Low",
      confidence_level: "Low",
      displayLabel: "🟢 0% · Safe with low-risk indicators",
      display_label: "🟢 0% · Safe with low-risk indicators",
      explanation:
        "No readable email text was found, so there are no phishing signs to evaluate.",
      detectedSignals: ["No readable email content to analyze"],
      detected_signals: ["No readable email content to analyze"],
      signals: ["No readable email content to analyze"],
      detectedLanguage: "en",
      reasons: [],
      suspiciousSpans: [],
      urlAnalyses: [],
      safetyTips: [
        "Message was blank or consisted entirely of removed base64 attachments.",
      ],
      warnings: [],
      recommendedDisposition: "allow",
      autoBlockRecommended: false,
      preventionActions: [
        "No action is needed because the message had no readable content.",
      ],
      attachmentFindings: [],
      threatIntel: {
        reputationScore: 0,
        hasKnownBadInfrastructure: false,
        maliciousDomains: [],
        matchedIndicators: [],
        recommendedAction: "allow",
      },
      mlScore: 0,
      ruleScore: 0,
      urlScore: 0,
      headerScore: 0,
      featureImportance: [],
      attackType: "Safe / Informational",
      scamStory:
        "No readable email text was found, so there are no phishing signs to evaluate.",
    });
    return;
  }

  const scanId = randomUUID();
  phishingLogger.info("Starting email analysis", { scanId, textLength: safeText.length }, correlationId);

  let result: AnalyzeResult;
  try {
    result = await analyzeEmail(safeText, safeHeaders, scanId, attachments ?? []);

    // Guardrail from earlier parser edge cases: once in a while an empty or malformed
    // payload can still leave us with a bad score, and we would rather normalize it here.
    if (isNaN(result.riskScore)) result.riskScore = 0;
    if (!result.classification) result.classification = "safe";

    phishingLogger.info("Email analysis completed", {
      scanId,
      riskScore: result.riskScore,
      classification: result.classification,
      urlCount: result.urlAnalyses.length
    }, correlationId);
  } catch (engineError) {
    phishingLogger.error("analyzeEmail engine crashed", engineError as Error, { scanId }, correlationId);

    // Keep the API response usable even if the deeper analysis path blows up.
    result = {
      id: scanId,
      riskScore: 30, // Defaulting to slight risk since it broke the parser
      risk_score: 30,
      classification: "uncertain",
      confidence: 0,
      confidenceLevel: "MEDIUM",
      confidenceLabel: "Medium",
      confidence_level: "Medium",
      displayLabel: "🟠 30% · Suspicious with moderate confidence",
      display_label: "🟠 30% · Suspicious with moderate confidence",
      explanation:
        "This email could not be fully analyzed because the content was heavily malformed, so it has been placed in the suspicious range as a precaution.",
      detectedSignals: ["Malformed or highly unusual email structure"],
      detected_signals: ["Malformed or highly unusual email structure"],
      signals: ["Malformed or highly unusual email structure"],
      detectedLanguage: "en",
      reasons: [
        {
          category: "ml_score",
          description:
            "Email contains extremely complex or malformed structures that triggered analysis fallbacks.",
          severity: "low",
          matchedTerms: [],
        },
      ],
      suspiciousSpans: [],
      urlAnalyses: [],
      safetyTips: [
        "Always exercise caution with dynamically complex emails that are heavily encoded.",
      ],
      warnings: ["System Analysis Fallback triggered"],
      recommendedDisposition: "review",
      autoBlockRecommended: false,
      preventionActions: [
        "Hold the message for manual review because the deeper analysis path failed.",
        "Avoid clicking links or opening attachments until the message is verified.",
      ],
      attachmentFindings: [],
      threatIntel: {
        reputationScore: 30,
        hasKnownBadInfrastructure: false,
        maliciousDomains: [],
        matchedIndicators: [],
        recommendedAction: "review",
      },
      mlScore: 30,
      ruleScore: 0,
      urlScore: 0,
      headerScore: 0,
      featureImportance: [],
      attackType: "Social Engineering",
      scamStory:
        "This email could not be fully analyzed because the content was heavily malformed, so it has been placed in the suspicious range as a precaution.",
    } as AnalyzeResult;
  }

  // Send the response back immediately (Non-blocking performance)
  res.json(result);

  // Fire and forget: Persist to database async without making the user wait
  addToHistory({
    emailText: safeText,
    id: scanId,
    riskScore: result.riskScore,
    classification: result.classification,
    confidence: result.confidence,
    attackType: result.attackType,
    reasons: result.reasons,
    detectedLanguage: result.detectedLanguage,
    urlCount: result.urlAnalyses.length,
    reasonCount: result.reasons.length,
  }).catch((err) => {
    phishingLogger.error("History logging failed", err, { scanId }, correlationId);
  });
}));

router.post("/feedback", requireApiKey, asyncHandler(async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;

  const parsed = SubmitFeedbackBody.safeParse(req.body);
  if (!parsed.success) {
    throw new ValidationError(
      "Invalid feedback payload. Expected { emailId, userFeedback } or { emailId, correctedClassification }.",
    );
  }

  const {
    emailId,
    userFeedback,
    isAccurate,
    correctedClassification,
    feedbackSource,
    notes,
    emailText,
    emailPreview,
    predictedClassification,
    riskScore,
    confidence,
    attackType,
    reasons,
  } = parsed.data;
  const normalizedFeedback =
    userFeedback === "correct" || userFeedback === "incorrect"
      ? userFeedback
      : typeof isAccurate === "boolean"
        ? (isAccurate ? "correct" : "incorrect")
        : correctedClassification
          ? "incorrect"
          : null;

  if (!normalizedFeedback) {
    throw new ValidationError("Feedback must include userFeedback as 'correct' or 'incorrect', or provide a correctedClassification.");
  }

  logger.info(
    "Processing feedback",
    { emailId, userFeedback: normalizedFeedback, correctedClassification, feedbackSource },
    correlationId,
  );

  await addFeedback({
    emailId,
    userFeedback: normalizedFeedback,
    correctedClassification,
    feedbackSource,
    notes,
    emailText,
    emailPreview,
    predictedClassification,
    riskScore,
    confidence,
    attackType,
    reasons,
  });

  res.json({ status: "ok" });
}));

router.get("/feedback/export", requireApiKey, asyncHandler(async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;
  const format = typeof req.query.format === "string" && req.query.format.toLowerCase() === "jsonl"
    ? "jsonl"
    : "json";
  const onlyIncorrect =
    typeof req.query.onlyIncorrect === "string" &&
    ["1", "true", "yes", "incorrect"].includes(req.query.onlyIncorrect.toLowerCase());

  const rows = await exportFeedbackData({ onlyIncorrect });

  logger.info("Exporting feedback dataset", { count: rows.length, format, onlyIncorrect }, correlationId);

  if (format === "jsonl") {
    res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="phishshield-feedback-export.jsonl"');
    res.send(rows.map((row) => JSON.stringify(row)).join("\n"));
    return;
  }

  res.json(rows);
}));

router.post("/report", requireApiKey, asyncHandler(async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;

  const parsed = GenerateReportBody.safeParse(req.body);
  if (!parsed.success) {
    throw new ValidationError("Invalid report payload");
  }

  const result: any = parsed.data;

  logger.info("Generating report", {
    classification: result.classification,
    riskScore: result.riskScore
  }, correlationId);

  let reportText = `=== PHISHSHIELD AI DETAILED REPORT ===\n`;
  reportText += `Generated on: ${new Date().toISOString()}\n\n`;
  reportText += `VERDICT: ${result.classification.toUpperCase()}\n`;
  reportText += `RISK SCORE: ${result.riskScore}/100\n`;
  reportText += `CONFIDENCE: ${(result.confidence * 100).toFixed(1)}%\n\n`;

  if (result.reasons && result.reasons.length > 0) {
    reportText += `--- REASONS ---\n`;
    result.reasons.forEach((r: any) => {
      reportText += `[${r.severity.toUpperCase()}] ${r.category}: ${r.description}\n`;
      if (r.matchedTerms.length > 0)
        reportText += `Matches: ${r.matchedTerms.join(", ")}\n`;
    });
    reportText += "\n";
  }

  if (result.urlAnalyses && result.urlAnalyses.length > 0) {
    reportText += `--- LINKS DETECTED ---\n`;
    result.urlAnalyses.forEach((u: any) => {
      reportText += `URL: ${u.url}\n`;
      reportText += `Risk: ${u.isSuspicious ? "Suspicious" : "Safe"}\n`;
    });
    reportText += "\n";
  }

  res.setHeader(
    "Content-Disposition",
    "attachment; filename=phishshield-report.txt",
  );
  res.setHeader("Content-Type", "text/plain");
  res.send(reportText);
}));

export default router;
