import type { AttachmentContext } from "../engines/attachmentEngine";

export type Verdict = "safe" | "uncertain" | "phishing";
export type ConfidenceLevel = "LOW" | "MEDIUM" | "HIGH";

export type VerificationSuiteName =
  | "basic"
  | "phishing-detection"
  | "safe-email"
  | "edge-cases"
  | "multilingual"
  | "url-analysis"
  | "header-spoofing"
  | "transformer-only"
  | "llm-fallback"
  | "integration"
  | "failure-handling"
  | "consistency"
  | "performance";

export interface VerificationExpectation {
  expectedClassification: Verdict;
  acceptableLabels?: Verdict[];
  expectedConfidenceLevel?: ConfidenceLevel | ConfidenceLevel[];
  minScore?: number;
  maxScore?: number;
  expectedLanguage?: string | string[];
  requiresUrlAnalysis?: boolean;
  requiresHeaderAnalysis?: boolean;
  requiresHighlights?: boolean;
  requiresExplanation?: boolean;
  requiresLLMUsage?: boolean;
}

export interface VerificationCase {
  id: string;
  suite: VerificationSuiteName;
  name: string;
  emailText: string;
  headersText?: string;
  attachments?: AttachmentContext[];
  tags?: string[];
  notes?: string;
  expected: VerificationExpectation;
}

export interface TestExecutionResult {
  caseId: string;
  suite: VerificationSuiteName;
  name: string;
  passed: boolean;
  latencyMs: number;
  expectedClassification: Verdict;
  actualClassification?: Verdict;
  riskScore?: number;
  confidence?: number;
  confidenceLevel?: ConfidenceLevel;
  llmUsed?: boolean;
  issues: string[];
  error?: string;
}

export interface SuiteSummary {
  suite: VerificationSuiteName;
  total: number;
  passed: number;
  failed: number;
  avgLatencyMs: number;
}

export interface MetricsSummary {
  totalCases: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface PerformanceSummary {
  batchSize: number;
  averageLatencyMs: number;
  p95LatencyMs: number;
  maxLatencyMs: number;
  throughputPerSecond: number;
  memoryDeltaMb: number;
  passed: boolean;
}

export interface ThresholdConfig {
  accuracy: number;
  phishingRecall: number;
  precision: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  averageLatencyMs: number;
  p95LatencyMs: number;
}

export interface VerificationReport {
  generatedAt: string;
  seed: number;
  summary: {
    total: number;
    passed: number;
    failed: number;
  };
  suites: SuiteSummary[];
  metrics: MetricsSummary;
  performance: PerformanceSummary;
  thresholds: ThresholdConfig;
  thresholdFailures: string[];
  failures: TestExecutionResult[];
  results: TestExecutionResult[];
  artifacts: {
    jsonReportPath: string;
    htmlReportPath: string;
  };
}
