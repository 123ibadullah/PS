"""Upload local SecureBERT/MuRIL checkpoints to Hugging Face Model repos."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from huggingface_hub import HfApi


def upload_folder(api: HfApi, local_dir: Path, repo_id: str) -> None:
    if not local_dir.is_dir():
        raise FileNotFoundError(local_dir)
    print(f"Uploading {local_dir} -> {repo_id} (repo_type=model)...", flush=True)
    api.upload_folder(
        folder_path=str(local_dir),
        repo_id=repo_id,
        repo_type="model",
        commit_message="Add PhishShield fine-tuned classifier weights",
    )
    print(f"Done: {repo_id}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secure-repo", default="Mohd1314234123/phishshield-securebert")
    parser.add_argument("--muril-repo", default="Mohd1314234123/phishshield-muril")
    parser.add_argument("--secure-only", action="store_true")
    parser.add_argument("--muril-only", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    load_dotenv(root / ".env")
    load_dotenv(root / "backend" / ".env", override=True)

    token = (os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACE_HUB_TOKEN") or "").strip()
    if not token:
        print("HF_TOKEN missing — create a Write token at https://huggingface.co/settings/tokens", file=sys.stderr)
        print("Then: .venv\\Scripts\\huggingface-cli.exe login", file=sys.stderr)
        return 1

    api = HfApi(token=token)
    try:
        who = api.whoami()
        print(f"HF user: {who.get('name', who)}", flush=True)
    except Exception as exc:
        print(f"HF auth failed: {exc}", file=sys.stderr)
        return 1
    backend = root / "backend"

    if not args.muril_only:
        upload_folder(api, backend / "models" / "securebert_model", args.secure_repo)
    if not args.secure_only:
        upload_folder(api, backend / "models" / "muril_model", args.muril_repo)

    print("\nNext: add Space Secrets PHISHSHIELD_SECUREBERT_HF_REPO and PHISHSHIELD_MURIL_HF_REPO, then Restart Space.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
