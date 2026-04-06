// PhishShield Guardian — Premium popup script

let currentRender = {
  result: null,
  tabUrl: '',
  classification: 'safe',
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

function getConfidenceLabel(result, riskScore) {
  const raw = Number(result?.confidence ?? result?.confidenceLevel ?? riskScore ?? 0);
  const percent = raw <= 1 ? raw * 100 : raw;
  if (percent >= 75) return 'High confidence';
  if (percent >= 45) return 'Medium confidence';
  return 'Low confidence';
}

function getHeadline(classification) {
  if (classification === 'phishing') return '⚠️ High Risk Email';
  if (classification === 'suspicious') return '⚠️ Suspicious Email';
  return '✅ Safe Email';
}

function getSignalPool(result, classification) {
  const pool = [...(result?.keySignals || []), ...(result?.flags || [])]
    .map((item) => String(item || '').trim())
    .filter(Boolean);

  const deduped = [...new Set(pool)].slice(0, 3);
  if (deduped.length) return deduped;

  if (classification === 'phishing') return ['Credential Request', 'Suspicious Link', 'Urgency'];
  if (classification === 'suspicious') return ['Needs Verification', 'Review Carefully'];
  return ['No Strong Signals'];
}

function getReasonPool(result, classification) {
  const reasons = Array.isArray(result?.reasons)
    ? result.reasons
        .map((item) => (typeof item === 'string'
          ? item
          : item?.description || item?.label || item?.category || ''))
        .filter(Boolean)
        .slice(0, 3)
    : [];

  if (reasons.length) return reasons;

  if (classification === 'phishing') {
    return ['Credential harvesting, urgency, or a deceptive link pattern was detected.'];
  }
  if (classification === 'suspicious') {
    return ['This page should be verified independently before you sign in, pay, or reply.'];
  }
  return ['No strong phishing signals were detected during this scan.'];
}

function compactExplanation(text, classification) {
  const fallback = classification === 'safe'
    ? 'No strong phishing signals were detected.'
    : classification === 'phishing'
      ? 'This content shows strong phishing indicators and should not be trusted.'
      : 'This content should be verified before you act on it.';

  const source = String(text || fallback).replace(/\s+/g, ' ').trim();
  return source.split(/(?<=[.!?])\s+/).slice(0, 2).join(' ');
}

function getNextStepAdvice(classification) {
  if (classification === 'phishing') {
    return {
      meterLabel: 'Escalate now',
      meterValue: 100,
      title: 'Recommended response',
      text: 'Leave this page, do not reply or sign in, and verify from the official site only.',
    };
  }

  if (classification === 'suspicious') {
    return {
      meterLabel: 'Verify first',
      meterValue: 62,
      title: 'Recommended response',
      text: 'Pause before clicking or entering anything, then verify using the official app or website.',
    };
  }

  return {
    meterLabel: 'Monitor',
    meterValue: 22,
    title: 'Recommended response',
    text: 'This looks low risk, but continue using the official site for payments, sign-ins, or password changes.',
  };
}

function setGuidanceState(prefix, classification) {
  const advice = getNextStepAdvice(classification);
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

async function copyCurrentSummary() {
  if (!currentRender.result) return;

  const riskScore = Math.max(0, Math.min(100, Number(currentRender.result?.riskScore || currentRender.result?.risk_score || 0)));
  const explanation = compactExplanation(currentRender.result?.explanation || currentRender.result?.scamStory, currentRender.classification);
  const summary = [
    `PhishShield verdict: ${getHeadline(currentRender.classification)}`,
    `Risk score: ${riskScore}/100`,
    `Confidence: ${getConfidenceLabel(currentRender.result, riskScore)}`,
    `Domain: ${currentRender.result?.domain || currentRender.tabUrl || 'Current page'}`,
    `Summary: ${explanation}`,
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

function renderResult(result, tabUrl) {
  hide('state-loading');

  const classification = toVisualClassification(result?.visualClassification || result?.classification);
  const riskScore = Math.max(0, Math.min(100, Number(result?.riskScore || result?.risk_score || 0)));
  const explanation = compactExplanation(result?.explanation || result?.scamStory, classification);

  currentRender = {
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

  if (!result || classification === 'safe') {
    hide('state-result');
    show('state-safe');
    const safeScore = Math.max(0, Math.min(100, riskScore || 12));
    document.getElementById('safe-panel')?.setAttribute('data-state', 'safe');
    setText('safe-score', String(safeScore));
    setText('safe-domain-text', domain);
    setText('safe-summary', explanation);
    setText('safe-confidence', getConfidenceLabel(result, safeScore));
    setGuidanceState('safe-', 'safe');
    setChipMarkup('safe-flags-wrap', getSignalPool(result, 'safe'));
    setDetailMarkup('safe-details-list', getReasonPool(result, 'safe'));
    return;
  }

  hide('state-safe');
  show('state-result');
  document.getElementById('result-panel')?.setAttribute('data-state', classification);
  setText('score-num', String(riskScore));
  setText('result-headline', getHeadline(classification));
  setText('score-label', `${classification === 'phishing' ? 'High risk' : 'Suspicious'} · ${riskScore}/100`);
  setText('result-confidence', getConfidenceLabel(result, riskScore));
  setText('domain-text', domain);
  setText('result-explanation', explanation);
  setGuidanceState('result-', classification);
  setChipMarkup('flags-wrap', getSignalPool(result, classification));
  setDetailMarkup('result-details-list', getReasonPool(result, classification));
}

async function rescan(tab) {
  show('state-loading');
  ['state-result', 'state-safe'].forEach(hide);
  await chrome.runtime.sendMessage({ type: 'RECHECK_TAB', tabId: tab.id, url: tab.url });
  const result = await chrome.runtime.sendMessage({ type: 'GET_TAB_RESULT', tabId: tab.id });
  renderResult(result, tab.url);
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

  const dismiss = () => window.close();
  document.getElementById('btn-recheck')?.addEventListener('click', () => rescan(tab));
  document.getElementById('btn-recheck-safe')?.addEventListener('click', () => rescan(tab));
  document.getElementById('btn-copy')?.addEventListener('click', copyCurrentSummary);
  document.getElementById('btn-copy-safe')?.addEventListener('click', copyCurrentSummary);
  document.getElementById('btn-official')?.addEventListener('click', openOfficialSite);
  document.getElementById('btn-official-safe')?.addEventListener('click', openOfficialSite);
  document.getElementById('btn-dismiss')?.addEventListener('click', dismiss);
  document.getElementById('btn-dismiss-safe')?.addEventListener('click', dismiss);
}

init();
