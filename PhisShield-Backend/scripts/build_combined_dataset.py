from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable


GMAIL_SPLIT_RE = re.compile(
    r"\n\s*Skip to content\s*\nUsing Gmail with screen readers\s*\n\d+\s+of\s+\d+\s*\n",
    re.IGNORECASE,
)


def _norm(s: str) -> str:
    s = s.replace("\u200b", "").replace("\ufeff", "")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def _dedupe(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for it in items:
        text = _norm(str(it.get("text", "")))
        if not text:
            continue
        key = hashlib.sha256(re.sub(r"\s+", " ", text.lower()).encode("utf-8", errors="ignore")).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        out.append({"text": text, "label": str(it.get("label", "")).strip().lower()})
    return out


def parse_real_gmail(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    raw = raw.lstrip("\n\r\t ")
    # Split on Gmail screen-reader envelope markers.
    chunks = [c for c in GMAIL_SPLIT_RE.split(raw) if _norm(c)]
    emails: list[dict[str, Any]] = []
    for c in chunks:
        text = _norm(c)
        # Drop the "Skip to content" lines inside each chunk if they occur.
        text = re.sub(r"(?im)^\s*Skip to content\s*$", "", text)
        text = re.sub(r"(?im)^\s*Using Gmail with screen readers\s*$", "", text)
        text = _norm(text)
        if len(text) < 80:
            continue
        emails.append({"text": text, "label": "safe", "source": "real_gmail"})
    return emails


def parse_phishtank(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise SystemExit("phishtank_dataset.json must be a JSON array.")
    out: list[dict[str, Any]] = []
    for obj in raw:
        text = _norm(str(obj.get("text", "")))
        if not text:
            continue
        out.append({"text": text, "label": "phishing", "source": "phishtank"})
    return out


def parse_elite_cleaned(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise SystemExit("FINAL_ELITE_DATASET.json must be a JSON array.")
    out: list[dict[str, Any]] = []
    for obj in raw:
        text = _norm(str(obj.get("text", "")))
        label = str(obj.get("label", "")).strip().lower()
        if not text:
            continue
        if label not in ("safe", "phishing"):
            continue
        out.append({"text": text, "label": label, "source": "elite_cleaned"})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Build combined evaluation dataset (jsonl).")
    ap.add_argument("--real_gmail", required=True, type=Path)
    ap.add_argument("--phishtank", required=True, type=Path)
    ap.add_argument("--elite", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path, help="Output JSONL path")
    ap.add_argument(
        "--out_balanced",
        default=None,
        type=Path,
        help="Optional output JSONL path for class-balanced slice",
    )
    args = ap.parse_args()

    items = []
    items.extend(parse_real_gmail(args.real_gmail))
    items.extend(parse_phishtank(args.phishtank))
    items.extend(parse_elite_cleaned(args.elite))

    # Cross-source dedupe by normalized text.
    items = _dedupe(items)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.out.with_suffix(args.out.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
    os.replace(tmp, args.out)

    safe = sum(1 for x in items if x["label"] == "safe")
    phish = sum(1 for x in items if x["label"] == "phishing")
    summary: dict[str, Any] = {"total": len(items), "safe": safe, "phishing": phish}

    if args.out_balanced:
        safe_items = [x for x in items if x["label"] == "safe"]
        phish_items = [x for x in items if x["label"] == "phishing"]

        def _order_key(x: dict[str, Any]) -> str:
            return hashlib.sha256(x["text"].encode("utf-8", errors="ignore")).hexdigest()

        safe_sorted = sorted(safe_items, key=_order_key)
        phish_sorted = sorted(phish_items, key=_order_key)
        n = min(len(safe_sorted), len(phish_sorted))
        balanced = sorted((safe_sorted[:n] + phish_sorted[:n]), key=_order_key)

        args.out_balanced.parent.mkdir(parents=True, exist_ok=True)
        tmp2 = args.out_balanced.with_suffix(args.out_balanced.suffix + ".tmp")
        with tmp2.open("w", encoding="utf-8") as f:
            for it in balanced:
                f.write(json.dumps(it, ensure_ascii=False) + "\n")
        os.replace(tmp2, args.out_balanced)
        summary["balanced_total"] = len(balanced)
        summary["balanced_safe"] = sum(1 for x in balanced if x["label"] == "safe")
        summary["balanced_phishing"] = sum(1 for x in balanced if x["label"] == "phishing")

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

