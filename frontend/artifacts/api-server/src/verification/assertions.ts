import type { AnalyzeResult } from "@workspace/api-zod";
import type { ConfidenceLevel, TestExecutionResult, VerificationCase, Verdict } from "./types.js";

export function normalizeClassification(value?: string): Verdict {
  if (value === "safe" || value === "phishing" || value === "uncertain") {
    return value;
  }
  return "uncertain";
}

export function normalizeConfidenceLevel(value?: string, riskScore?: number): ConfidenceLevel {
  if (value === "LOW" || value === "MEDIUM" || value === "HIGH") {
    return value;
  }

  if (typeof riskScore === "number") {
    if (riskScore <= 25) return "HIGH";
    if (riskScore <= 60) return "MEDIUM";
    return "HIGH";
  }

  return "MEDIUM";
}

export function detectLlmUsage(result: AnalyzeResult): boolean {
  return Boolean(
    result.featureImportance?.some((feature) => /llm fallback/i.test(feature.feature)) ||
      result.reasons?.some((reason) => /llm fallback/i.test(reason.description)),
  );
}

function hasHighlights(result: AnalyzeResult): boolean {
  if (result.suspiciousSpans.length > 0) {
    return true;
  }

  return result.reasons.some((reason) => reason.matchedTerms.length > 0);
}

function validateUrlAnalysis(result: AnalyzeResult, issues: string[]) {
  if (!Array.isArray(result.urlAnalyses) || result.urlAnalyses.length === 0) {
    issues.push("URL analysis output is missing.");
    return;
  }

  for (const url of result.urlAnalyses) {
    if (!url.url || !url.domain) {
      issues.push("URL analysis entry is incomplete.");
      break;
    }
    if (!Number.isFinite(url.riskScore) || url.riskScore < 0 || url.riskScore > 100) {
      issues.push("URL analysis risk score is out of range.");
      break;
    }
  }
}

export function validateAnalyzeResult(testCase: VerificationCase, result: AnalyzeResult): string[] {
  const issues: string[] = [];
  const actual = normalizeClassification(result.classification);
  const allowedLabels = testCase.expected.acceptableLabels ?? [testCase.expected.expectedClassification];

  if (!allowedLabels.includes(actual)) {
    issues.push(
      `Classification mismatch. Expected ${allowedLabels.join("/")}, received ${actual}.`,
    );
  }

  if (!Number.isFinite(result.riskScore) || result.riskScore < 0 || result.riskScore > 100) {
    issues.push("Risk score must be a number between 0 and 100.");
  }

  if (!Number.isFinite(result.confidence) || result.confidence < 0 || result.confidence > 1) {
    issues.push("Confidence must be a number between 0 and 1.");
  }

  const actualConfidenceLevel = normalizeConfidenceLevel(
    (result as AnalyzeResult & { confidenceLevel?: string }).confidenceLevel,
    result.riskScore,
  );
  const expectedConfidenceLevels = (
    testCase.expected.expectedConfidenceLevel
      ? Array.isArray(testCase.expected.expectedConfidenceLevel)
        ? testCase.expected.expectedConfidenceLevel
        : [testCase.expected.expectedConfidenceLevel]
      : [...new Set(allowedLabels.map((label) => (label === "uncertain" ? "MEDIUM" : "HIGH")))]
  ) as ConfidenceLevel[];

  if (!expectedConfidenceLevels.includes(actualConfidenceLevel)) {
    issues.push(
      `Confidence level mismatch. Expected ${expectedConfidenceLevels.join("/")}, received ${actualConfidenceLevel}.`,
    );
  }

  const minScore =
    testCase.expected.minScore ??
    (testCase.expected.expectedClassification === "safe"
      ? 0
      : testCase.expected.expectedClassification === "uncertain"
        ? 30
        : 71);
  const maxScore =
    testCase.expected.maxScore ??
    (testCase.expected.expectedClassification === "safe"
      ? 29
      : testCase.expected.expectedClassification === "uncertain"
        ? 70
        : 100);

  if (result.riskScore < minScore || result.riskScore > maxScore) {
    issues.push(`Risk score ${result.riskScore} is outside the expected range ${minScore}-${maxScore}.`);
  }

  const uxResult = result as AnalyzeResult & {
    risk_score?: number;
    confidence_level?: string;
    displayLabel?: string;
    display_label?: string;
    explanation?: string;
    detectedSignals?: string[];
    detected_signals?: string[];
    signals?: string[];
  };

  if ((testCase.expected.requiresExplanation ?? true) && !result.scamStory?.trim()) {
    issues.push("Missing human-readable explanation (`scamStory`).");
  }
  if ((testCase.expected.requiresExplanation ?? true) && !uxResult.explanation?.trim()) {
    issues.push("Missing plain-language explanation (`explanation`).");
  }

  const normalizedExplanation = (uxResult.explanation ?? "").toLowerCase();
  if (
    actual === "phishing" &&
    normalizedExplanation &&
    !/(phishing|scam|risky|danger|high risk|suspicious|do not trust|verify the sender)/i.test(normalizedExplanation)
  ) {
    issues.push("High-risk classification returned an explanation that does not clearly describe danger.");
  }

  if (
    actual === "safe" &&
    /(phishing|scam|danger|high risk)/i.test(normalizedExplanation) &&
    !/(does not show|no strong phishing signs|looks routine)/i.test(normalizedExplanation)
  ) {
    issues.push("Safe classification returned an explanation that sounds threatening.");
  }

  if (uxResult.risk_score !== result.riskScore) {
    issues.push("Missing or inconsistent snake_case `risk_score` alias.");
  }

  const expectedHumanConfidence =
    actualConfidenceLevel === "HIGH" ? "High" : actualConfidenceLevel === "LOW" ? "Low" : "Medium";
  if (uxResult.confidence_level !== expectedHumanConfidence) {
    issues.push(
      `Human confidence label mismatch. Expected ${expectedHumanConfidence}, received ${uxResult.confidence_level ?? "missing"}.`,
    );
  }

  const displayLabel = uxResult.display_label ?? uxResult.displayLabel;
  if (!displayLabel?.trim()) {
    issues.push("Missing UI-ready `display_label`.");
  } else {
    const expectedBand = result.riskScore <= 25 ? "Safe" : result.riskScore <= 60 ? "Suspicious" : "High Risk";
    if (!displayLabel.includes(expectedBand)) {
      issues.push(`Display label mismatch. Expected it to include '${expectedBand}', received '${displayLabel}'.`);
    }
  }

  const signalList = uxResult.signals ?? uxResult.detectedSignals ?? uxResult.detected_signals;
  if (!Array.isArray(signalList) || signalList.length === 0) {
    issues.push("Missing human-readable detected signals list.");
  }

  if (!result.attackType?.trim()) {
    issues.push("Missing attack type.");
  }

  if (!Array.isArray(result.reasons)) {
    issues.push("Reasons array is missing.");
  } else if (actual !== "safe" && result.reasons.length === 0) {
    issues.push("Risky verdict returned without any reasons.");
  }

  if (testCase.expected.requiresHighlights && !hasHighlights(result)) {
    issues.push("Expected suspicious terms or highlights were not returned.");
  }

  if (testCase.expected.requiresUrlAnalysis) {
    validateUrlAnalysis(result, issues);
  }

  if (testCase.expected.requiresHeaderAnalysis) {
    if (!result.headerAnalysis?.hasHeaders) {
      issues.push("Expected header analysis details were not returned.");
    }
  }

  if (testCase.expected.requiresLLMUsage && !detectLlmUsage(result)) {
    issues.push("LLM fallback should have been used but was not detected in the result output.");
  }

  if (testCase.expected.expectedLanguage) {
    const expectedLanguages = Array.isArray(testCase.expected.expectedLanguage)
      ? testCase.expected.expectedLanguage
      : [testCase.expected.expectedLanguage];

    if (!expectedLanguages.includes(result.detectedLanguage)) {
      issues.push(
        `Detected language mismatch. Expected ${expectedLanguages.join("/")}, received ${result.detectedLanguage}.`,
      );
    }
  }

  return issues;
}

export function summarizeForConsole(result: TestExecutionResult): string {
  const status = result.passed ? "PASS" : "FAIL";
  const score = typeof result.riskScore === "number" ? ` score=${result.riskScore}` : "";
  const latency = ` ${result.latencyMs.toFixed(1)}ms`;
  const classification = result.actualClassification ? ` ${result.actualClassification}` : "";
  return `[${status}] ${result.suite} :: ${result.name}${classification}${score}${latency}`;
}
