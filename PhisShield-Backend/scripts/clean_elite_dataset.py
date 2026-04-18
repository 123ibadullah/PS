from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Literal


Label = Literal["safe", "phishing"]


_URL_RE = re.compile(r"\bhttps?://[^\s<>()]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.IGNORECASE)


def _norm_text(s: str) -> str:
    s = s.replace("\u200b", "").replace("\ufeff", "")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def _canonical_key(s: str) -> str:
    s2 = _norm_text(s).lower()
    s2 = re.sub(r"\s+", " ", s2).strip()
    return hashlib.sha256(s2.encode("utf-8", errors="ignore")).hexdigest()


def _looks_like_sms_or_chat(s: str) -> bool:
    t = s.lower()
    lines = [ln.strip() for ln in _norm_text(s).split("\n") if ln.strip()]
    if len(lines) <= 2 and len(t) < 120:
        return True
    sms_markers = [
        "txt",
        "text me",
        "u r",
        " ur ",
        " pls ",
        "stop to",
        "reply stop",
        "2optout",
        "optout",
        "msg",
        "mins",
        "mths",
        "wkly",
        " r ",
    ]
    if any(m in t for m in sms_markers) and len(lines) <= 4:
        return True
    if re.search(r"\b\d{5,}\b", t) and ("call" in t or "reply" in t) and len(lines) <= 4:
        return True
    return False


def _looks_email_like(s: str) -> bool:
    t = s.lower()
    s = _norm_text(s)
    lines = [ln for ln in s.split("\n") if ln.strip()]
    if len(lines) >= 5:
        return True
    # Single-line "unsubscribe"/marketing snippets are common in SMS spam; don't treat as email.
    if len(lines) <= 2:
        return False
    header_markers = ("from:", "to:", "subject:", "date:", "mailed-by:", "reply-to:")
    if any(m in t for m in header_markers):
        return True
    if _EMAIL_RE.search(s) and len(s) >= 120:
        return True
    greetings = ("dear ", "hi ", "hello", "good morning", "good afternoon", "good evening")
    closings = ("regards", "sincerely", "best,", "thanks,", "thank you", "kind regards")
    if any(g in t for g in greetings) and any(c in t for c in closings) and len(s) >= 140:
        return True
    return False


def _high_conf_phishing(s: str) -> bool:
    t = s.lower()
    if _URL_RE.search(s):
        if any(k in t for k in ("login", "verify", "password", "account", "wallet", "reset", "confirm", "suspend")):
            return True
        return True
    if any(k in t for k in ("verify your account", "reset your password", "confirm your identity")):
        return True
    return False


def _high_conf_safe(s: str) -> bool:
    t = s.lower()
    if _URL_RE.search(s):
        return False
    if any(k in t for k in ("verify", "password", "login", "suspend", "urgent", "immediately", "confirm your")):
        return False
    return _looks_email_like(s) and len(_norm_text(s)) >= 80


def _derive_label(s: str) -> Label | None:
    if _high_conf_phishing(s):
        return "phishing"
    if _high_conf_safe(s):
        return "safe"
    return None


@dataclass(frozen=True)
class CleanStats:
    input_count: int
    kept_count: int
    removed_sms_chat: int
    removed_not_email_like: int
    removed_uncertain_label: int
    deduped_out: int
    safe_count: int
    phishing_count: int


def clean_items(items: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], CleanStats]:
    input_items = list(items)

    removed_sms_chat = 0
    removed_not_email_like = 0
    removed_uncertain_label = 0

    deduped_out = 0
    seen: set[str] = set()
    kept: list[dict[str, Any]] = []

    for obj in input_items:
        text = _norm_text(str(obj.get("text", "")))
        if not text:
            removed_not_email_like += 1
            continue

        if _looks_like_sms_or_chat(text):
            removed_sms_chat += 1
            continue

        if not _looks_email_like(text):
            removed_not_email_like += 1
            continue

        label = _derive_label(text)
        if label is None:
            removed_uncertain_label += 1
            continue

        key = _canonical_key(text)
        if key in seen:
            deduped_out += 1
            continue
        seen.add(key)

        kept.append({"text": text, "label": label})

    safe = [x for x in kept if x["label"] == "safe"]
    phish = [x for x in kept if x["label"] == "phishing"]

    # Deterministic balancing by stable hash ordering on text.
    def _order_key(x: dict[str, Any]) -> str:
        return hashlib.sha256(x["text"].encode("utf-8", errors="ignore")).hexdigest()

    safe_sorted = sorted(safe, key=_order_key)
    phish_sorted = sorted(phish, key=_order_key)
    n = min(len(safe_sorted), len(phish_sorted))
    safe_bal = safe_sorted[:n]
    phish_bal = phish_sorted[:n]
    balanced = safe_bal + phish_bal
    balanced_sorted = sorted(balanced, key=_order_key)

    stats = CleanStats(
        input_count=len(input_items),
        kept_count=len(balanced_sorted),
        removed_sms_chat=removed_sms_chat,
        removed_not_email_like=removed_not_email_like,
        removed_uncertain_label=removed_uncertain_label,
        deduped_out=deduped_out,
        safe_count=sum(1 for x in balanced_sorted if x["label"] == "safe"),
        phishing_count=sum(1 for x in balanced_sorted if x["label"] == "phishing"),
    )
    return balanced_sorted, stats


def main() -> int:
    ap = argparse.ArgumentParser(description="Clean FINAL_ELITE_DATASET.json into email-only, deduped, relabeled set.")
    ap.add_argument("--input", required=True, type=Path, help="Path to FINAL_ELITE_DATASET.json")
    ap.add_argument("--output", required=True, type=Path, help="Path to write cleaned JSON")
    ap.add_argument("--backup", type=Path, default=None, help="Optional backup path for original input")
    args = ap.parse_args()

    raw = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise SystemExit("Expected a JSON array of objects with {text,label}.")

    cleaned, stats = clean_items(raw)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = args.output.with_suffix(args.output.suffix + ".tmp")
    tmp_path.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.backup is not None and args.backup.resolve() != args.input.resolve():
        args.backup.parent.mkdir(parents=True, exist_ok=True)
        if not args.backup.exists():
            args.backup.write_text(args.input.read_text(encoding="utf-8"), encoding="utf-8")

    # Atomic-ish replace on Windows.
    os.replace(tmp_path, args.output)

    print(json.dumps(stats.__dict__, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
