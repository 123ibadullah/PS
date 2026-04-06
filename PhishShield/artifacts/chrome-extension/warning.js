var params = new URLSearchParams(location.search);
var url = params.get('url') || '';
var score = parseInt(params.get('score') || '0', 10);
var level = params.get('level') || 'phishing';
var reasons = JSON.parse(params.get('reasons') || '[]');
var india = params.get('india') === '1';
var dest = params.get('dest') || '';

var isSuspicious = level === 'suspicious';
document.body.setAttribute('data-state', isSuspicious ? 'suspicious' : 'phishing');

function deriveSignals(reasonsText, indiaFlag, suspicious) {
  var pool = [];
  var text = (reasonsText || []).join(' ').toLowerCase();

  if (/otp|password|credential|pin|sign in/.test(text)) pool.push('Credential Request');
  if (/url|domain|link|lookalike|spoof|shortener/.test(text)) pool.push('Suspicious Link');
  if (/urgent|immediately|deadline|suspend|blocked/.test(text)) pool.push('Urgency');
  if (/bank|brand|impersonat|upi|payment/.test(text)) pool.push('Impersonation');
  if (indiaFlag) pool.push('Banking Alert');

  if (!pool.length) {
    pool = suspicious
      ? ['Needs Verification', 'Review Carefully']
      : ['Credential Request', 'Suspicious Link', 'Urgency'];
  }

  return pool.slice(0, 3);
}

function buildSummary(scoreValue, suspicious, indiaFlag, reasonsText) {
  var text = (reasonsText || []).join(' ').toLowerCase();

  if (/otp|password|credential|pin/.test(text)) {
    return 'This page appears to be asking for sensitive information, which is a strong phishing signal.';
  }
  if (/lookalike|spoof|domain|link/.test(text)) {
    return 'This link pattern looks deceptive and could send you to a fake sign-in or payment page.';
  }
  if (indiaFlag) {
    return 'This page appears to imitate a banking or payment brand, so do not enter codes, PINs, or personal details.';
  }
  if (suspicious || scoreValue < 75) {
    return 'This site shows suspicious behavior and should be verified independently before you continue.';
  }
  return 'This site shows strong phishing indicators and was blocked to protect your account and data.';
}

function confidenceLabel(scoreValue) {
  if (scoreValue >= 75) return 'High confidence';
  if (scoreValue >= 45) return 'Medium confidence';
  return 'Low confidence';
}

function setText(id, value) {
  var el = document.getElementById(id);
  if (el) el.textContent = value;
}

setText('page-title', isSuspicious ? '⚠️ Suspicious Site' : '🚫 High-Risk Site Blocked');
setText(
  'page-subtitle',
  isSuspicious
    ? 'Proceed only if you can verify this destination through an official source.'
    : 'This destination shows strong phishing indicators and was stopped for your protection.',
);
setText('shield-icon', isSuspicious ? '⚠️' : '🛡');
setText('confidence-pill', confidenceLabel(score));
setText('score-value', String(score));
setText('score-label', isSuspicious ? 'Suspicious behavior detected' : 'Phishing threat detected');
setText(
  'score-desc',
  isSuspicious
    ? 'Do not sign in or share codes until you verify the destination.'
    : 'Do not enter passwords, codes, or payment details on this page.',
);
setText('summary-copy', buildSummary(score, isSuspicious, india, reasons));
setText('url-text', url || 'Unknown destination');

if (india) {
  document.getElementById('india-alert').style.display = 'block';
}

var chipWrap = document.getElementById('signal-chips');
deriveSignals(reasons, india, isSuspicious).forEach(function(signal) {
  var chip = document.createElement('span');
  chip.className = 'chip';
  chip.textContent = signal;
  chipWrap.appendChild(chip);
});

var list = document.getElementById('reasons-list');
var items = reasons.length ? reasons.slice(0, 3) : ['This site matched multiple phishing indicators.'];
items.forEach(function(reason) {
  var li = document.createElement('li');
  li.className = 'reason-item';
  li.textContent = reason;
  list.appendChild(li);
});

document.getElementById('btn-back').addEventListener('click', function() {
  chrome.tabs.getCurrent(function(tab) {
    if (tab) {
      chrome.tabs.update(tab.id, { url: 'https://www.google.com' });
    } else if (history.length > 1) {
      history.back();
    } else {
      window.close();
    }
  });
});

document.getElementById('btn-proceed').addEventListener('click', function() {
  if (!dest) return;
  chrome.runtime.sendMessage({ type: 'ALLOW_URL', url: dest }, function() {
    location.href = dest;
  });
});
