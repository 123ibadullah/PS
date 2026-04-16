// PhishShield Guardian — Enterprise popup script

let currentRender = {
  result: null,
  tabUrl: '',
  classification: 'safe',
  feedbackStatus: null,
};

function show(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.display = id === 'state-loading' ? 'flex' : 'block';
}

function hide(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = 'none';
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function toVisualClassification(classification) {
  return classification === 'uncertain' ? 'suspicious' : (classification || 'safe');
}

function isMailContext(source, tabUrl = '', domain = '') {
  const blob = `${source || ''} ${tabUrl || ''} ${domain || ''}`.toLowerCase();
  return /gmail-email|mail\.google\.com/.test(blob);
}

function getContextNoun(source, tabUrl = '', domain = '') {
  return isMailContext(source, tabUrl, domain) ? 'Message' : 'Destination';
}

function getLanguageLabel(code) {
  switch (String(code || 'EN').toUpperCase()) {
    case 'HI': return 'Hindi';
    case 'TE': return 'Telugu';
    case 'MX': return 'Mixed';
    default: return 'English';
  }
}

function getExplanationText(text) {
  if (!text) return '';
  const normalized = typeof text === 'string'
    ? text
    : typeof text === 'number' || typeof text === 'boolean'
      ? String(text)
      : typeof text === 'object'
        ? String(
            text.why_risky
            || text.scamStory
            || text.summary
            || text.reason
            || text.message
            || text.description
            || text.text
            || ''
          ).trim()
        : '';

  if (/^top words driving this verdict$/i.test(normalized) || /^ai analysis completed$/i.test(normalized)) {
    return '';
  }

  return normalized;
}

function canonicalizeInsight(item) {
  const raw = String(item || '').trim();
  const lower = raw.toLowerCase();

  if (/known sender|trusted sender|verified .*domain/.test(lower)) return 'Trusted sender';
  if (/routine|newsletter|product-update|informational|welcome/.test(lower)) return 'Routine communication';
  if (/no credential|no password|no otp|no payment/.test(lower)) return 'No sensitive request';
  if (/no urgency|fear pressure/.test(lower)) return 'No urgency pressure';
  if (/no suspicious|no spoofed|verified destination/.test(lower)) return 'No spoofing detected';
  if (/credential request/.test(lower)) return 'Credential request';
  if (/suspicious link/.test(lower)) return 'Suspicious link';
  if (/urgency/.test(lower)) return 'Urgency pressure';
  if (/impersonation/.test(lower)) return 'Impersonation risk';
  return raw;
}

function getCategoryLabel(result, classification) {
  const raw = String(result?.category || result?.attackType || '').trim();
  if (raw && !/^safe email$/i.test(raw)) return raw;

  const blob = [raw, result?.intent, result?.explanation, ...(result?.reasons || [])].join(' ').toLowerCase();
  if (/welcome/.test(blob)) return 'Welcome email';
  if (/terms|policy/.test(blob)) return 'Terms update';
  if (/password reset|account recovery/.test(blob)) return 'Password reset flow';
  if (/otp|verification|security alert|account activity|sign-?in/.test(blob)) return 'Account activity notification';
  if (/newsletter|digest|product update/.test(blob)) return 'Routine notification';
  if (classification === 'phishing') return 'Phishing threat';
  if (classification === 'suspicious') return 'Needs review';
  return 'Low-risk communication';
}

function getIntentLabel(result, classification) {
  const raw = String(result?.intent || '').trim();
  if (raw) return raw;

  const blob = [result?.category, result?.attackType, result?.explanation, ...(result?.reasons || [])].join(' ').toLowerCase();
  if (/password reset|account recovery/.test(blob)) return 'Password reset flow';
  if (/otp|verification code|login alert|security alert|account activity/.test(blob)) return 'OTP / account verification';
  if (/payment|refund|invoice|billing|bank transfer|upi/.test(blob)) return 'Payment or banking request';
  if (/terms|policy/.test(blob)) return 'Terms update message';
  if (/newsletter|digest|product update|welcome/.test(blob)) return 'Routine notification';
  if (classification === 'phishing') return 'Credential or payment theft attempt';
  if (classification === 'suspicious') return 'Needs independent verification';
  return 'Routine communication';
}

function formatBrandLabel(value) {
  const raw = String(value || '').trim();
  const normalized = raw.toLowerCase().replace(/^www\./, '');
  if (!normalized) return 'sender';

  if (/google/.test(normalized)) return 'Google';
  if (/amazon/.test(normalized)) return 'Amazon';
  if (/microsoft|outlook|office|live/.test(normalized)) return 'Microsoft';
  if (/github/.test(normalized)) return 'GitHub';
  if (/overleaf/.test(normalized)) return 'Overleaf';
  if (/openai|chatgpt/.test(normalized)) return 'OpenAI';
  if (/linkedin|lnkd/.test(normalized)) return 'LinkedIn';

  const token = normalized.split(/[.\s-]/)[0] || normalized;
  return token.charAt(0).toUpperCase() + token.slice(1);
}

function getDomainTrustText(result) {
  const trust = result?.domainTrust || {};
  if (trust?.label) return trust.label;

  const trustState = String(trust?.trust || trust?.domainTrust || trust?.status || '').toLowerCase();
  if (/suspicious/.test(trustState)) return 'Domain mismatch or spoofing detected';

  if (/trusted|verified/.test(trustState)) {
    const brand = formatBrandLabel(trust?.brand || trust?.domain || result?.headerAnalysis?.senderDomain || result?.domain || 'sender');
    return `Verified ${brand} domain`;
  }

  return 'This domain is not widely recognized — verify if unsure.';
}

function getLinkAnalysisText(result, classification) {
  if (Array.isArray(result?.urlAnalyses) && result.urlAnalyses.length) {
    const suspiciousCount = result.urlAnalyses.filter((item) => item?.isSuspicious).length;
    if (suspiciousCount > 0) return `${suspiciousCount} risky link${suspiciousCount > 1 ? 's' : ''} detected`;
    return 'Links align with the sender context';
  }

  if (result?.linkAnalysis?.label) return result.linkAnalysis.label;
  if (classification === 'phishing') return 'Suspicious link pattern detected';
  if (classification === 'suspicious') return 'Link should be verified first';
  return 'No risky link behavior detected';
}

function getHeaderAuthText(result) {
  const headerAnalysis = result?.headerAnalysis;
  if (!headerAnalysis) return 'Authentication checks require full email headers.';
  if (headerAnalysis?.spoofingRisk && headerAnalysis.spoofingRisk !== 'none') {
    return `Authentication checks suggest ${headerAnalysis.spoofingRisk} spoofing risk.`;
  }
  if (headerAnalysis?.hasHeaders) return 'Authentication checks look consistent.';
  return 'Email authentication headers are not available in this view.';
}

function getConfidenceLabel(result, riskScore) {
  const classification = toVisualClassification(result?.visualClassification || result?.classification);
  const raw = Number(result?.confidence ?? result?.confidenceLevel ?? riskScore ?? 0);
  const percent = raw <= 1 ? raw * 100 : raw;
  const trustText = getDomainTrustText(result).toLowerCase();
  const contentBlob = [result?.category, result?.attackType, result?.intent, result?.explanation, ...(result?.reasons || [])].join(' ').toLowerCase();
  const looksLikeTrustedOtp = classification === 'safe'
    && /verified .* domain/.test(trustText)
    && /otp|verification code|security alert|account activity|sign-?in/.test(contentBlob)
    && Number(riskScore) <= 30;

  if (classification === 'safe') {
    if (looksLikeTrustedOtp) return 'Protected';
    if (Number(riskScore) <= 18 || percent >= 70) return 'High confidence safe';
    return 'Medium confidence safe';
  }

  if (classification === 'phishing') {
    return percent >= 70 ? 'High confidence threat' : 'Likely phishing';
  }

  return percent >= 55 ? 'Medium confidence review' : 'Needs review';
}

function getHeadline(classification, source = 'page-content', tabUrl = '', domain = '', result = null) {
  const noun = getContextNoun(source, tabUrl, domain);
  const category = getCategoryLabel(result, classification);
  if (classification === 'phishing') return category === 'Phishing threat' ? `High-Risk ${noun}` : category;
  if (classification === 'suspicious') return category === 'Needs review' ? `${noun} Needs Review` : category;
  if (/welcome|terms|notification|password reset|account activity/i.test(category)) return category;
  return `Protected ${noun}`;
}

function getStatusLabel(classification, source = 'page-content', tabUrl = '', domain = '') {
  const noun = isMailContext(source, tabUrl, domain) ? 'communication' : 'destination';
  if (classification === 'phishing') return `High risk · ${noun} blocked`;
  if (classification === 'suspicious') return 'Review recommended · verify independently';
  return `Protected · trusted ${noun}`;
}

function buildHumanSummary(result, classification) {
  const raw = String(getExplanationText(result?.explanation || result?.scamStory) || '').trim();
  const category = getCategoryLabel(result, classification);
  const intent = getIntentLabel(result, classification);
  const blob = [raw, category, intent, ...(result?.reasons || []), ...(result?.keySignals || []), ...(result?.flags || [])].join(' ').toLowerCase();

  if (raw && !/no sign of spoofing|no risky behavior detected|trusted sender with no strong phishing signals detected|top words driving this verdict|ai analysis completed/i.test(raw)) {
    return raw.replace(/\s+/g, ' ').trim();
  }

  if (classification === 'safe') {
    if (/welcome/.test(blob)) return 'Welcome email detected from a known sender. This is a trusted message.';
    if (/terms|policy/.test(blob)) return 'This looks like a normal terms or policy update from a trusted sender.';
    if (/otp|verification|security alert|account activity|sign-?in/.test(blob)) {
      return 'This is a legitimate account verification message. Only use the OTP on the official website.';
    }
    if (/newsletter|digest|product update|routine/.test(blob)) {
      return 'This looks like a normal product update or newsletter from a trusted source.';
    }
    return 'No risky behavior detected. This is a trusted message.';
  }

  if (classification === 'phishing') {
    if (/credential|password|otp|pin/.test(blob)) {
      return 'This message tries to collect sensitive information or approval codes, which is a strong phishing signal.';
    }
    if (/link|domain|spoof|lookalike/.test(blob)) {
      return 'The links or sender details look deceptive and could redirect you to a fake sign-in or payment page.';
    }
    return 'This content shows strong phishing indicators and should not be trusted.';
  }

  if (/password reset/.test(blob)) {
    return 'This looks like a password reset flow. Open the official site directly if you initiated it.';
  }

  return 'This content has mixed signals. Verify it through the official site or support channel before acting.';
}

function getSignalPool(result, classification) {
  const pool = [
    ...(result?.keySignals || []),
    ...(result?.flags || []),
    getCategoryLabel(result, classification),
    getIntentLabel(result, classification),
    classification === 'safe' ? getDomainTrustText(result) : '',
  ]
    .map((item) => canonicalizeInsight(item))
    .filter(Boolean);

  const deduped = [...new Set(pool)].slice(0, classification === 'safe' ? 3 : 4);
  if (deduped.length) return deduped;

  if (classification === 'phishing') return ['Credential request', 'Suspicious link', 'Urgency pressure'];
  if (classification === 'suspicious') return ['Needs verification', 'Manual review'];
  return ['Trusted sender', 'No sensitive request'];
}

function getReasonPool(result, classification) {
  const reasons = Array.isArray(result?.reasons)
    ? [...new Set(result.reasons
        .map((item) => (typeof item === 'string'
          ? item
          : item?.description || item?.label || item?.category || ''))
        .map((item) => canonicalizeInsight(item))
        .filter(Boolean))]
        .slice(0, 4)
    : [];

  if (reasons.length) return reasons;

  if (classification === 'phishing') {
    return ['Credential harvesting, urgency, or a deceptive link pattern was detected.'];
  }
  if (classification === 'suspicious') {
    return ['This page or email should be verified independently before you sign in, pay, or reply.'];
  }
  return ['No risky behavior detected. This is a trusted message.'];
}

function getComparisonCopy(result, classification) {
  const trustText = getDomainTrustText(result).toLowerCase();
  if (classification === 'phishing') {
    return 'If this request were genuine, it would stay on the real brand domain and would not ask for OTPs, passwords, or payment details through an unverified flow.';
  }
  if (classification === 'suspicious') {
    return 'If this is legitimate, you should be able to find the same request inside the official app or website without urgency or mismatched links.';
  }
  if (/verified/.test(trustText)) {
    return 'This looks consistent with a verified sender and normal account-security messaging.';
  }
  return 'This looks safe because no risky behavior was detected and the sender context appears trustworthy.';
}

function deriveScoreBreakdown(result, classification) {
  const rawItems = Array.isArray(result?.scoreBreakdown) ? result.scoreBreakdown : [];
  const normalized = rawItems
    .map((item) => ({
      label: String(item?.label || item?.reason || item?.title || '').trim(),
      impact: Number(item?.impact ?? item?.delta ?? 0),
      detail: String(item?.detail || '').trim(),
    }))
    .filter((item) => item.label);

  if (normalized.length) return normalized.slice(0, 4);

  const fallback = [];
  if (/verified/i.test(getDomainTrustText(result))) {
    fallback.push({ label: 'Trusted domain verification', impact: -45, detail: getDomainTrustText(result) });
  }
  if (getSignalPool(result, classification).some((item) => /Credential request/i.test(item))) {
    fallback.push({ label: 'Sensitive request detected', impact: 30, detail: 'OTP, password, or credential prompt' });
  }
  if (getSignalPool(result, classification).some((item) => /Suspicious link/i.test(item))) {
    fallback.push({ label: 'Suspicious link pattern', impact: 25, detail: 'Domain mismatch or deceptive URL' });
  }
  if (getSignalPool(result, classification).some((item) => /Urgency/i.test(item))) {
    fallback.push({ label: 'Urgency pressure', impact: 18, detail: 'Pressure to act quickly' });
  }
  if (!fallback.length && classification === 'safe') {
    fallback.push({ label: 'No risky behavior detected', impact: -12, detail: 'Latest scan looked routine and low-risk' });
  }
  return fallback.slice(0, 4);
}

function deriveAnalysisRows(result, classification, tabUrl = '', domain = '') {
  return [
    { label: 'Category', value: getCategoryLabel(result, classification) },
    { label: 'Intent', value: getIntentLabel(result, classification) },
    { label: 'Domain trust', value: getDomainTrustText(result) },
    { label: 'Link analysis', value: getLinkAnalysisText(result, classification) },
    { label: 'Authentication checks', value: getHeaderAuthText(result) },
    { label: 'Language', value: getLanguageLabel(result?.detectedLanguage || result?.language || 'EN') },
    { label: 'Source', value: isMailContext(result?.source, tabUrl, domain) ? 'Mail + backend AI' : 'Page + URL intelligence' },
  ].slice(0, 6);
}

function getNextStepAdvice(classification, source = 'page-content') {
  if (classification === 'phishing') {
    return {
      meterLabel: 'Escalate now',
      meterValue: 100,
      title: 'Recommended action',
      text: 'Do not authenticate, reply, or submit payment details. Verify through the trusted site or your security workflow only.',
    };
  }

  if (classification === 'suspicious') {
    return {
      meterLabel: 'Verify first',
      meterValue: 62,
      title: 'Recommended action',
      text: 'Pause before clicking or entering anything, then confirm the request through the official website or a trusted business channel.',
    };
  }

  return {
    meterLabel: 'Protected',
    meterValue: 18,
    title: 'Recommended action',
    text: source === 'gmail-email'
      ? 'This looks like a normal account or business message. Continue normally, but still use the trusted site for sign-ins or billing changes.'
      : 'This destination appears low risk. Continue normally, but keep sensitive actions on the trusted site only.',
  };
}

function setGuidanceState(prefix, classification, source = 'page-content') {
  const advice = getNextStepAdvice(classification, source);
  setText(`${prefix}meter-label`, advice.meterLabel);
  setText(`${prefix}next-step-title`, advice.title);
  setText(`${prefix}next-step-text`, advice.text);

  const fill = document.getElementById(`${prefix}risk-fill`);
  if (fill) {
    fill.style.width = `${advice.meterValue}%`;
  }
}

function setChipMarkup(id, items) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = items
    .map((item) => `<span class="chip">${escapeHtml(item)}</span>`)
    .join('');
}

function setDetailMarkup(id, items) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = items
    .map((item) => `<div class="detail-row"><span class="detail-dot">•</span><span>${escapeHtml(item)}</span></div>`)
    .join('');
}

function setBreakdownMarkup(id, items) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = items
    .map((item) => {
      const impact = Number(item?.impact || 0);
      const impactClass = impact >= 0 ? 'positive' : 'negative';
      const detail = item?.detail ? ` · ${escapeHtml(item.detail)}` : '';
      return `<div class="breakdown-row"><span class="breakdown-text">${escapeHtml(item.label)}${detail}</span><span class="breakdown-impact ${impactClass}">${impact >= 0 ? '+' : ''}${impact}</span></div>`;
    })
    .join('');
}

function setAnalysisMarkup(id, items) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = items
    .map((item) => `<div class="analysis-row"><strong>${escapeHtml(item.label)}</strong><span>${escapeHtml(item.value)}</span></div>`)
    .join('');
}

function setFeedbackNote(id, feedbackStatus) {
  const el = document.getElementById(id);
  if (!el) return;

  if (feedbackStatus) {
    const improving = feedbackStatus.model_improving ? 'improving' : 'stable';
    el.innerHTML = `<strong>Your feedback improves detection.</strong> ${feedbackStatus.total_feedback} feedback item(s) logged · ${feedbackStatus.needed_for_retrain} until the next learning checkpoint · Status: ${improving}.`;
    return;
  }

  el.innerHTML = '<strong>Your feedback improves detection.</strong> Feedback system is available when backend is connected.';
}

function flashButton(id, text) {
  const button = document.getElementById(id);
  if (!button) return;
  const original = button.dataset.originalLabel || button.textContent || '';
  button.dataset.originalLabel = original;
  button.textContent = text;
  window.setTimeout(() => {
    button.textContent = original;
  }, 1400);
}

function getOfficialSiteUrl(result, tabUrl, classification) {
  const haystack = `${result?.domain || ''} ${tabUrl || ''}`.toLowerCase();
  const knownSites = [
    { match: /(google|gmail)/, url: 'https://accounts.google.com/' },
    { match: /amazon/, url: 'https://www.amazon.com/' },
    { match: /netflix/, url: 'https://www.netflix.com/' },
    { match: /microsoft|outlook|office/, url: 'https://www.microsoft.com/' },
    { match: /apple|icloud/, url: 'https://www.apple.com/' },
    { match: /paypal/, url: 'https://www.paypal.com/' },
    { match: /github/, url: 'https://github.com/' },
    { match: /linkedin/, url: 'https://www.linkedin.com/' },
    { match: /openai|chatgpt/, url: 'https://chatgpt.com/' },
    { match: /cursor/, url: 'https://www.cursor.com/' },
    { match: /sbi/, url: 'https://retail.onlinesbi.sbi/' },
    { match: /hdfc/, url: 'https://www.hdfcbank.com/' },
    { match: /icici/, url: 'https://www.icicibank.com/' },
    { match: /axis/, url: 'https://www.axisbank.com/' },
    { match: /paytm/, url: 'https://paytm.com/' },
    { match: /phonepe/, url: 'https://www.phonepe.com/' },
    { match: /bhim|upi/, url: 'https://www.bhimupi.org.in/' },
    { match: /irctc/, url: 'https://www.irctc.co.in/' },
    { match: /aadhaar|uidai/, url: 'https://uidai.gov.in/' },
    { match: /gst|incometax/, url: 'https://www.incometax.gov.in/' },
  ];

  const matched = knownSites.find((site) => site.match.test(haystack));
  if (matched) return matched.url;

  if (classification === 'safe') {
    try {
      return new URL(tabUrl).origin;
    } catch {
      return tabUrl || 'https://cybercrime.gov.in/';
    }
  }

  return 'https://cybercrime.gov.in/';
}

function renderFeedbackNotes() {
  setFeedbackNote('result-feedback-note', currentRender.feedbackStatus);
  setFeedbackNote('safe-feedback-note', currentRender.feedbackStatus);
}

function renderIntelligenceSections(result, classification, tabUrl, domain, prefix) {
  setBreakdownMarkup(`${prefix}breakdown-list`, deriveScoreBreakdown(result, classification));
  setAnalysisMarkup(`${prefix}analysis-list`, deriveAnalysisRows(result, classification, tabUrl, domain));
  setText(`${prefix}comparison-title`, classification === 'safe' ? 'Why this looks safe' : 'What could have gone wrong?');
  setText(`${prefix}comparison-copy`, getComparisonCopy(result, classification));
}

async function copyCurrentSummary() {
  if (!currentRender.result) return;

  const riskScore = Math.max(0, Math.min(100, Number(currentRender.result?.riskScore || currentRender.result?.risk_score || 0)));
  const explanation = buildHumanSummary(currentRender.result, currentRender.classification);
  const signals = getSignalPool(currentRender.result, currentRender.classification);
  const actions = getNextStepAdvice(currentRender.classification, currentRender.result?.source);
  const summary = [
    `PhishShield verdict: ${getHeadline(currentRender.classification, currentRender.result?.source, currentRender.tabUrl, currentRender.result?.domain, currentRender.result)}`,
    `Risk score: ${riskScore}/100`,
    `Confidence: ${getConfidenceLabel(currentRender.result, riskScore)}`,
    `Category: ${getCategoryLabel(currentRender.result, currentRender.classification)}`,
    `Intent: ${getIntentLabel(currentRender.result, currentRender.classification)}`,
    `Domain trust: ${getDomainTrustText(currentRender.result)}`,
    `Target: ${currentRender.result?.domain || currentRender.tabUrl || 'Current page'}`,
    `Signals: ${signals.join(', ')}`,
    `Summary: ${explanation}`,
    `Recommended action: ${actions.text}`,
  ].join('\n');

  try {
    await navigator.clipboard.writeText(summary);
    ['btn-copy', 'btn-copy-safe'].forEach((id) => flashButton(id, 'Copied'));
  } catch {
    ['btn-copy', 'btn-copy-safe'].forEach((id) => flashButton(id, 'Unavailable'));
  }
}

function openOfficialSite() {
  const url = getOfficialSiteUrl(currentRender.result, currentRender.tabUrl, currentRender.classification);
  chrome.tabs.create({ url });
}

function openReportSupport() {
  chrome.tabs.create({ url: 'https://www.cybercrime.gov.in/Webform/Crime_AuthoLogin.aspx?rnt=5' });
  ['btn-report', 'btn-report-safe'].forEach((id) => flashButton(id, 'Opened'));
}

function renderResult(result, tabUrl) {
  hide('state-loading');

  const classification = toVisualClassification(result?.visualClassification || result?.classification);
  const riskScore = Math.max(0, Math.min(100, Number(result?.riskScore || result?.risk_score || 0)));

  currentRender = {
    ...currentRender,
    result: result || null,
    tabUrl: tabUrl || '',
    classification,
  };

  let domain = result?.domain || 'This page';
  try {
    domain = result?.domain || new URL(tabUrl || '').hostname;
  } catch {
    // ignore parse errors
  }

  const explanation = buildHumanSummary(result || {}, classification);

  if (!result || classification === 'safe') {
    hide('state-result');
    show('state-safe');
    const safeScore = Math.max(0, Math.min(100, riskScore || 12));
    const safeLabel = isMailContext(result?.source, tabUrl, domain)
      ? 'Protected · trusted communication'
      : 'Protected · trusted destination';
    document.getElementById('safe-panel')?.setAttribute('data-state', 'safe');
    setText('safe-headline', getHeadline('safe', result?.source, tabUrl, domain, result));
    setText('safe-score-label', safeLabel);
    setText('safe-score', String(safeScore));
    setText('safe-domain-text', domain);
    setText('safe-summary', explanation);
    setText('safe-confidence', getConfidenceLabel(result, safeScore));
    setGuidanceState('safe-', 'safe', result?.source || 'page-content');
    setChipMarkup('safe-flags-wrap', getSignalPool(result, 'safe'));
    setDetailMarkup('safe-details-list', getReasonPool(result, 'safe'));
    renderIntelligenceSections(result || {}, 'safe', tabUrl, domain, 'safe-');
    renderFeedbackNotes();
    return;
  }

  hide('state-safe');
  show('state-result');
  document.getElementById('result-panel')?.setAttribute('data-state', classification);
  setText('score-num', String(riskScore));
  setText('result-headline', getHeadline(classification, result?.source, tabUrl, domain, result));
  setText('score-label', getStatusLabel(classification, result?.source, tabUrl, domain));
  setText('result-confidence', getConfidenceLabel(result, riskScore));
  setText('domain-text', domain);
  setText('result-explanation', explanation);
  setGuidanceState('result-', classification, result?.source || 'page-content');
  setChipMarkup('flags-wrap', getSignalPool(result, classification));
  setDetailMarkup('result-details-list', getReasonPool(result, classification));
  renderIntelligenceSections(result || {}, classification, tabUrl, domain, 'result-');
  renderFeedbackNotes();
}

async function rescan(tab) {
  show('state-loading');
  ['state-result', 'state-safe'].forEach(hide);
  await chrome.runtime.sendMessage({ type: 'RECHECK_TAB', tabId: tab.id, url: tab.url });
  const result = await chrome.runtime.sendMessage({ type: 'GET_TAB_RESULT', tabId: tab.id });
  renderResult(result, tab.url);
}

async function fetchFeedbackStatus() {
  const endpoints = ['http://127.0.0.1:8000/feedback/stats', 'http://localhost:8000/feedback/stats'];
  for (const endpoint of endpoints) {
    try {
      const response = await fetch(endpoint);
      if (!response.ok) continue;
      currentRender.feedbackStatus = await response.json();
      renderFeedbackNotes();
      return;
    } catch {
      // ignore connectivity failures
    }
  }

  currentRender.feedbackStatus = null;
  renderFeedbackNotes();
}

async function init() {
  show('state-loading');
  ['state-result', 'state-safe'].forEach(hide);

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    hide('state-loading');
    return;
  }

  const result = await chrome.runtime.sendMessage({ type: 'GET_TAB_RESULT', tabId: tab.id });
  renderResult(result, tab.url);
  void fetchFeedbackStatus();

  const dismiss = () => window.close();
  document.getElementById('btn-recheck')?.addEventListener('click', () => rescan(tab));
  document.getElementById('btn-recheck-safe')?.addEventListener('click', () => rescan(tab));
  document.getElementById('btn-copy')?.addEventListener('click', copyCurrentSummary);
  document.getElementById('btn-copy-safe')?.addEventListener('click', copyCurrentSummary);
  document.getElementById('btn-official')?.addEventListener('click', openOfficialSite);
  document.getElementById('btn-official-safe')?.addEventListener('click', openOfficialSite);
  document.getElementById('btn-report')?.addEventListener('click', openReportSupport);
  document.getElementById('btn-report-safe')?.addEventListener('click', openReportSupport);
  document.getElementById('btn-dismiss')?.addEventListener('click', dismiss);
  document.getElementById('btn-dismiss-safe')?.addEventListener('click', dismiss);
}

init();
