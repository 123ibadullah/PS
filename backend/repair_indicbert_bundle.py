"""Repair incomplete backend/indicbert_model exports (config + tokenizer_config)."""
from __future__ import annotations

from main import ensure_indicbert_bundle, has_complete_indicbert_assets, INDICBERT_MODEL_DIR


def main() -> None:
    ensure_indicbert_bundle()
    if has_complete_indicbert_assets():
        print(f"IndicBERT bundle ready: {INDICBERT_MODEL_DIR}")
    else:
        print(f"IndicBERT bundle still incomplete: {INDICBERT_MODEL_DIR}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
