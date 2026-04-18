from __future__ import annotations

import re
from typing import Any, Callable

import numpy as np

try:
    import shap
except Exception:  # pragma: no cover - optional dependency at runtime
    shap = None

try:
    from lime.lime_text import LimeTextExplainer
except Exception:  # pragma: no cover - optional dependency at runtime
    LimeTextExplainer = None

STOPWORDS = {
    'the', 'and', 'for', 'with', 'your', 'this', 'that', 'from', 'have', 'please', 'dear', 'team', 'regards',
    'will', 'been', 'just', 'into', 'here', 'there', 'http', 'https', 'com', 'www', 'you', 'are', 'our', 'has',
    'be', 'at', 'hi', 'find', 'john', 'customer', 'account', 'net', 'org', 'in', 'hello', 'thanks', 'thank',
    'successfully', 'review', 'update', 'notice', 'kindly', 'today', 'subject', 'page', 'display', 'help',
    'official', 'reply', 'fast', 'html', 'amazon', 'google', 'linkedin', 'github', 'paytm', 'microsoft',
}
KEYWORD_HINTS = {
    'otp': 0.34,
    'urgent': 0.28,
    'immediately': 0.28,
    'suspended': 0.24,
    'suspend': 0.24,
    'verify': 0.24,
    'kyc': 0.22,
    'upi': 0.2,
    'password': 0.24,
    'pin': 0.22,
    'bank': 0.18,
    'payment': 0.24,
    'transfer': 0.26,
    'beneficiary': 0.24,
    'confidential': 0.24,
    'sbi': 0.2,
    'hdfc': 0.2,
    'icici': 0.2,
    'तुरंत': 0.28,
    'अभी': 0.22,
    'बंद': 0.2,
    'వెంటనే': 0.28,
    'నిలిపివేయబడుతుంది': 0.24,
    'ఓటిపి': 0.3,
}


def clean_text(text: str) -> str:
    text = str(text).lower()
    text = re.sub(r"[^\w\s@.-]", " ", text, flags=re.UNICODE)
    return re.sub(r"\s+", " ", text).strip()


def _normalize_items(items: list[tuple[str, float]], limit: int = 5) -> list[dict[str, float | str]]:
    filtered: list[tuple[str, float]] = []
    seen: set[str] = set()
    for word, score in items:
        token = str(word).strip()
        if not token or token.lower() in STOPWORDS:
            continue
        if len(token) < 3 and token.upper() not in {'OTP', 'UPI', 'SBI', 'GST'}:
            continue
        lowered = token.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        filtered.append((token, abs(float(score))))

    if not filtered:
        return []

    filtered = sorted(filtered, key=lambda item: item[1], reverse=True)[:limit]
    total = sum(score for _, score in filtered) or 1.0
    return [
        {"word": word, "contribution": round(score / total, 2)}
        for word, score in filtered
    ]


def _heuristic_explanation(email_text: str) -> list[dict[str, float | str]]:
    tokens = re.findall(r"[\w.@-]+", email_text, flags=re.UNICODE)
    weighted = [(token, KEYWORD_HINTS.get(token.lower(), 0.08)) for token in tokens if token.lower() in KEYWORD_HINTS]

    url_match = re.search(r"https?://([^\s/]+)[^\s]*", email_text, flags=re.IGNORECASE)
    if url_match:
        weighted.append((url_match.group(1), 0.22))

    if not weighted:
        weighted = [(token, 0.05) for token in tokens[:5]]

    return _normalize_items(weighted)


def _combine_explanations(primary: list[dict[str, float | str]], secondary: list[dict[str, float | str]]) -> list[dict[str, float | str]]:
    merged: dict[str, float] = {}
    for source in (primary, secondary):
        for item in source:
            word = str(item.get('word', '')).strip()
            contribution = float(item.get('contribution', 0.0) or 0.0)
            if not word:
                continue
            merged[word] = max(merged.get(word, 0.0), contribution)

    return _normalize_items(list(merged.items()))


def _tfidf_linear_contributions(email_text: str, model: Any, vectorizer: Any) -> list[dict[str, float | str]]:
    if model is None or vectorizer is None or not hasattr(model, 'coef_'):
        return []

    cleaned = clean_text(email_text)
    if not cleaned:
        return []

    vector = vectorizer.transform([cleaned])
    coefficients = model.coef_[0]
    contribution_matrix = vector.multiply(coefficients)
    coo = contribution_matrix.tocoo()
    feature_names = vectorizer.get_feature_names_out()
    items = [(feature_names[index], float(value)) for _, index, value in zip(coo.row, coo.col, coo.data)]
    return _normalize_items(items)


def _shap_tfidf_explanation(email_text: str, model: Any, vectorizer: Any) -> list[dict[str, float | str]]:
    if shap is None or model is None or vectorizer is None:
        return []

    try:
        predictor = lambda texts: model.predict_proba(vectorizer.transform([clean_text(text) for text in texts]))[:, 1]
        masker = shap.maskers.Text(r"\W+")
        explainer = shap.Explainer(predictor, masker)
        shap_values = explainer([email_text], max_evals=128)
        tokens = list(shap_values.data[0])
        values = list(shap_values.values[0])
        items = [(token, float(value)) for token, value in zip(tokens, values) if str(token).strip()]
        return _normalize_items(items)
    except Exception:
        return []


def _lime_text_explanation(email_text: str, predictor: Callable[[list[str]], np.ndarray] | None) -> list[dict[str, float | str]]:
    if LimeTextExplainer is None or predictor is None:
        return []

    try:
        explainer = LimeTextExplainer(class_names=['safe', 'phishing'])
        explanation = explainer.explain_instance(
            email_text,
            classifier_fn=predictor,
            num_features=5,
            num_samples=64,
        )
        return _normalize_items([(word, score) for word, score in explanation.as_list()])
    except Exception:
        return []


def explain_prediction(
    email_text: str,
    *,
    risk_score: int,
    signal_count: int,
    model: Any | None = None,
    vectorizer: Any | None = None,
    predictor: Callable[[list[str]], np.ndarray] | None = None,
) -> dict[str, Any]:
    top_words = _shap_tfidf_explanation(email_text, model, vectorizer)
    method = 'shap'

    if not top_words:
        top_words = _tfidf_linear_contributions(email_text, model, vectorizer)
        method = 'linear-weights'

    if not top_words:
        top_words = _lime_text_explanation(email_text, predictor)
        method = 'lime'

    heuristic_words = _heuristic_explanation(email_text)
    if top_words:
        top_words = _combine_explanations(top_words, heuristic_words)
    else:
        top_words = heuristic_words
        method = 'heuristic'

    confidence_margin = max(3, min(12, 12 - min(signal_count, 4)))
    return {
        'top_words': top_words[:5],
        'why_risky': 'Top words driving this verdict',
        'confidence_interval': f'{int(round(risk_score))}% ± {confidence_margin}%',
        'method': method,
    }
