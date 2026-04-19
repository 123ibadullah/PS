"""
Legacy shim: full Phase-1 pipeline lives in repo-root certify_dataset.py
(near-duplicate removal, label fixes, diversity synth, Phishing_Email_cleaned.csv).

Run from workspace root:
  python certify_dataset.py
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
script = ROOT / "certify_dataset.py"
if script.exists():
    subprocess.check_call([sys.executable, str(script)], cwd=str(ROOT))
else:
    print("certify_dataset.py not found at", script, file=sys.stderr)
    sys.exit(1)
