import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export type CorrectedClassification = "safe" | "uncertain" | "phishing";
export type FeedbackDisposition =
  | "confirmed-correct"
  | "false-negative"
  | "false-positive"
  | "needs-review";
export type FeedbackSource = "user" | "qa" | "imported";
export type DriftLevel = "low" | "medium" | "high";

export type LearningFeedbackEvent = {
  scanId: string;
  timestamp: string;
  emailText: string;
  emailPreview: string;
  predictedClassification: CorrectedClassification;
  correctedClassification: CorrectedClassification;
  userFeedback: "correct" | "incorrect";
  isMisclassified: boolean;
  feedbackDisposition: FeedbackDisposition;
  riskScore: number;
  confidence: number;
  attackType: string;
  reasons: string[];
  feedbackSource: FeedbackSource;
  notes?: string;
};

export type SelfLearningMetrics = {
  feedbackSamples: number;
  confirmedCorrect: number;
  falsePositiveCount: number;
  falseNegativeCount: number;
  needsReviewCount: number;
  correctedSafeCount: number;
  correctedPhishingCount: number;
  feedbackAgreementRate: number;
  driftScore: number;
  driftLevel: DriftLevel;
  retrainingRecommended: boolean;
  samplesSinceLastRetrain: number;
  samplesNeededForRetrain: number;
  currentModelVersion: string;
  topThreatThemes: string[];
  retrainingFocusArea?: string;
  lastModelTrainingAt?: string;
  lastModelAccuracy?: number;
};

type RegistryEntry = {
  version: string;
  createdAt: string;
  datasetSize: number;
  metrics?: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1Score?: number;
    falseNegativeRate?: number;
  };
  status?: "candidate" | "deployed" | "rejected" | "rolled_back" | "archived";
  artifactPath?: string;
  notes?: string;
};

type ModelRegistry = {
  deployedVersion: string;
  lastTrainedAt?: string;
  versions: RegistryEntry[];
};

function resolveExistingPath(candidates: string[], fallback: string): string {
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  return fallback;
}

const ML_ENGINE_ROOT = resolveExistingPath(
  [
    path.resolve(process.cwd(), "../ml-engine"),
    path.resolve(process.cwd(), "artifacts/ml-engine"),
    path.resolve(process.cwd(), "ml-engine"),
  ],
  path.resolve(process.cwd(), "artifacts/ml-engine"),
);
const FEEDBACK_DIR = path.join(ML_ENGINE_ROOT, "data", "feedback");
const STATE_DIR = path.join(ML_ENGINE_ROOT, "state");
const REGISTRY_DIR = path.join(ML_ENGINE_ROOT, "models", "registry");
const FEEDBACK_LOG_PATH = path.join(FEEDBACK_DIR, "user-feedback.jsonl");
const MISCLASSIFIED_LOG_PATH = path.join(FEEDBACK_DIR, "misclassified-samples.jsonl");
const LEARNING_STATUS_PATH = path.join(STATE_DIR, "learning-status.json");
const REGISTRY_PATH = path.join(REGISTRY_DIR, "model-registry.json");
const CURRENT_MODEL_PATH = path.join(ML_ENGINE_ROOT, "models", "current-model.json");

const RETRAIN_SAMPLE_THRESHOLD = Number(process.env.PHISHSHIELD_RETRAIN_SAMPLE_THRESHOLD ?? 25);
const RETRAIN_DAY_THRESHOLD = Number(process.env.PHISHSHIELD_RETRAIN_DAY_THRESHOLD ?? 7);

const DEFAULT_REGISTRY: ModelRegistry = {
  deployedVersion: "top-end-phishing-v2",
  lastTrainedAt: "2026-04-03T00:00:00.000Z",
  versions: [
    {
      version: "top-end-phishing-v2",
      createdAt: "2026-04-03T00:00:00.000Z",
      datasetSize: 0,
      metrics: {
        accuracy: 0.8571,
        precision: 0.8571,
        recall: 0.8421,
        f1Score: 0.8421,
        falseNegativeRate: 0.1,
      },
      status: "deployed",
      artifactPath: "artifacts/ml-engine/models/top-end-phishing-v2",
      notes: "Current deployed local phishing model. The deterministic hybrid rule engine remains the product safety backstop.",
    },
  ],
};

async function ensureLearningArtifacts(): Promise<void> {
  await mkdir(FEEDBACK_DIR, { recursive: true });
  await mkdir(STATE_DIR, { recursive: true });
  await mkdir(REGISTRY_DIR, { recursive: true });

  try {
    await readFile(REGISTRY_PATH, "utf-8");
  } catch {
    await writeFile(REGISTRY_PATH, JSON.stringify(DEFAULT_REGISTRY, null, 2), "utf-8");
  }

  try {
    await readFile(CURRENT_MODEL_PATH, "utf-8");
  } catch {
    await writeFile(
      CURRENT_MODEL_PATH,
      JSON.stringify(
        {
          version: DEFAULT_REGISTRY.deployedVersion,
          artifactPath: "models/top-end-phishing-v2",
          promotedAt: DEFAULT_REGISTRY.lastTrainedAt,
          notes: "Auto-generated default active model pointer for the local PhishShield service.",
        },
        null,
        2,
      ),
      "utf-8",
    );
  }
}

async function readJsonFile<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const raw = await readFile(filePath, "utf-8");
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

async function loadRegistry(): Promise<ModelRegistry> {
  await ensureLearningArtifacts();
  return readJsonFile<ModelRegistry>(REGISTRY_PATH, DEFAULT_REGISTRY);
}

async function loadFeedbackEvents(): Promise<LearningFeedbackEvent[]> {
  await ensureLearningArtifacts();

  try {
    const raw = await readFile(FEEDBACK_LOG_PATH, "utf-8");
    return raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line) as LearningFeedbackEvent)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  } catch {
    return [];
  }
}

function tokenizeForDrift(text: string): string[] {
  return (text.toLowerCase().match(/[a-z\u0900-\u097F\u0C00-\u0C7F]{3,}/g) || [])
    .filter((token) => !new Set(["this", "that", "with", "your", "from", "have", "will", "please", "account"]).has(token));
}

const THREAT_THEME_PATTERNS = [
  { theme: "credential-theft", pattern: /otp|password|pin\b|passcode|credentials?|mailbox|sign(?:-|\s)?in|approve sign(?:-|\s)?in/i },
  { theme: "financial-scam", pattern: /payment|invoice|beneficiary|wire transfer|refund|fee|wallet|crypto|bank details|customs|delivery fee/i },
  { theme: "bec-tasking", pattern: /i(?:'m| am) in a meeting|can't talk|cannot talk|send confirmation once done|process the transfer|gift cards?/i },
  { theme: "cloud-share-oauth", pattern: /sharepoint|onedrive|google docs|grant consent|authorize app|shared document|browser extension/i },
  { theme: "newsletter-promo", pattern: /newsletter|unsubscribe|product update|release notes|read online/i },
  { theme: "security-notice", pattern: /new sign(?:-|\s)?in|security alert|verification code|password changed/i },
] as const;

function detectThreatThemes(text: string): string[] {
  const lowered = text.toLowerCase();
  return THREAT_THEME_PATTERNS.filter((entry) => entry.pattern.test(lowered)).map((entry) => entry.theme);
}

function summarizeThreatThemes(events: Array<Pick<LearningFeedbackEvent, "emailText" | "isMisclassified">>): {
  topThreatThemes: string[];
  retrainingFocusArea?: string;
} {
  const counts = new Map<string, number>();

  for (const event of events) {
    const themes = detectThreatThemes(event.emailText);
    const weightedThemes = themes.length > 0 ? themes : ["general-phishing"];

    for (const theme of weightedThemes) {
      const current = counts.get(theme) ?? 0;
      counts.set(theme, current + (event.isMisclassified ? 2 : 1));
    }
  }

  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  return {
    topThreatThemes: ranked.slice(0, 3).map(([theme]) => theme),
    retrainingFocusArea: ranked[0]?.[0],
  };
}

function computeDriftLevel(events: Array<Pick<LearningFeedbackEvent, "emailText" | "isMisclassified">>): {
  driftScore: number;
  driftLevel: DriftLevel;
} {
  if (events.length === 0) {
    return { driftScore: 0, driftLevel: "low" };
  }

  const recent = events.slice(0, 50);
  const uniqueTokens = new Set<string>();
  let totalTokens = 0;

  for (const event of recent) {
    const tokens = tokenizeForDrift(event.emailText);
    totalTokens += tokens.length;
    for (const token of tokens) {
      uniqueTokens.add(token);
    }
  }

  const lexicalNovelty = totalTokens > 0 ? uniqueTokens.size / totalTokens : 0;
  const misclassifiedRatio = recent.filter((item) => item.isMisclassified).length / recent.length;
  const driftScore = Number(Math.min(1, misclassifiedRatio * 0.75 + lexicalNovelty * 0.45).toFixed(2));

  if (driftScore >= 0.45) {
    return { driftScore, driftLevel: "high" };
  }
  if (driftScore >= 0.25) {
    return { driftScore, driftLevel: "medium" };
  }
  return { driftScore, driftLevel: "low" };
}

export async function summarizeSelfLearning(
  feedbackItems: Array<{
    timestamp: string;
    emailText: string;
    predictedClassification: CorrectedClassification;
    correctedClassification?: CorrectedClassification;
    suggestedLabel?: CorrectedClassification;
    isMisclassified: boolean;
    feedbackDisposition: FeedbackDisposition;
  }>,
): Promise<SelfLearningMetrics> {
  const registry = await loadRegistry();
  const currentVersion =
    registry.deployedVersion || registry.versions.find((entry) => entry.status === "deployed")?.version || "unversioned";
  const currentEntry = registry.versions.find((entry) => entry.version === currentVersion);
  const lastTrainedAt = registry.lastTrainedAt || currentEntry?.createdAt;

  const feedbackSamples = feedbackItems.length;
  const confirmedCorrect = feedbackItems.filter((item) => item.feedbackDisposition === "confirmed-correct").length;
  const falsePositiveCount = feedbackItems.filter((item) => item.feedbackDisposition === "false-positive").length;
  const falseNegativeCount = feedbackItems.filter((item) => item.feedbackDisposition === "false-negative").length;
  const needsReviewCount = feedbackItems.filter((item) => item.feedbackDisposition === "needs-review").length;
  const correctedSafeCount = feedbackItems.filter(
    (item) => (item.correctedClassification ?? item.suggestedLabel) === "safe",
  ).length;
  const correctedPhishingCount = feedbackItems.filter(
    (item) => (item.correctedClassification ?? item.suggestedLabel) === "phishing",
  ).length;
  const feedbackAgreementRate = feedbackSamples > 0 ? confirmedCorrect / feedbackSamples : 1;
  const { driftScore, driftLevel } = computeDriftLevel(feedbackItems);
  const { topThreatThemes, retrainingFocusArea } = summarizeThreatThemes(feedbackItems);

  const samplesSinceLastRetrain = lastTrainedAt
    ? feedbackItems.filter((item) => item.timestamp > lastTrainedAt).length
    : feedbackSamples;

  let daysSinceLastRetrain = RETRAIN_DAY_THRESHOLD;
  if (lastTrainedAt) {
    const last = new Date(lastTrainedAt).getTime();
    const now = Date.now();
    if (!Number.isNaN(last)) {
      daysSinceLastRetrain = Math.max(0, Math.floor((now - last) / (24 * 60 * 60 * 1000)));
    }
  }

  const retrainingRecommended =
    samplesSinceLastRetrain >= RETRAIN_SAMPLE_THRESHOLD ||
    daysSinceLastRetrain >= RETRAIN_DAY_THRESHOLD ||
    driftLevel === "high";

  return {
    feedbackSamples,
    confirmedCorrect,
    falsePositiveCount,
    falseNegativeCount,
    needsReviewCount,
    correctedSafeCount,
    correctedPhishingCount,
    feedbackAgreementRate: Number(feedbackAgreementRate.toFixed(3)),
    driftScore,
    driftLevel,
    retrainingRecommended,
    samplesSinceLastRetrain,
    samplesNeededForRetrain: Math.max(0, RETRAIN_SAMPLE_THRESHOLD - samplesSinceLastRetrain),
    currentModelVersion: currentVersion,
    topThreatThemes,
    retrainingFocusArea,
    lastModelTrainingAt: lastTrainedAt,
    lastModelAccuracy: currentEntry?.metrics?.accuracy,
  };
}

export async function recordFeedbackLearningEvent(event: LearningFeedbackEvent): Promise<void> {
  await ensureLearningArtifacts();

  const normalized = {
    ...event,
    emailText: event.emailText.slice(0, 50_000),
    emailPreview: event.emailPreview.slice(0, 160),
    reasons: event.reasons.slice(0, 20),
  };

  await appendFile(FEEDBACK_LOG_PATH, `${JSON.stringify(normalized)}\n`, "utf-8");

  if (normalized.isMisclassified) {
    await appendFile(MISCLASSIFIED_LOG_PATH, `${JSON.stringify(normalized)}\n`, "utf-8");
  }

  const allEvents = await loadFeedbackEvents();
  const summary = await summarizeSelfLearning(allEvents);
  await writeFile(LEARNING_STATUS_PATH, JSON.stringify(summary, null, 2), "utf-8");
}

export async function getLatestLearningStatus(): Promise<SelfLearningMetrics> {
  await ensureLearningArtifacts();

  const persisted = await readJsonFile<SelfLearningMetrics | null>(LEARNING_STATUS_PATH, null);
  if (persisted) {
    return persisted;
  }

  const events = await loadFeedbackEvents();
  return summarizeSelfLearning(events);
}
