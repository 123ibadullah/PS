from __future__ import annotations

import importlib
import sys
from collections import OrderedDict
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"

# Manual integration scripts that hit a live HTTP server or run certification on import.
collect_ignore = [
    "test_advanced_detection.py",
    "test_harness.py",
    "test_e2e.py",
    "test_script.py",
    "test_scan_simple.py",
    "test_wsbroadcast.py",
    "test_e2e_websocket.py",
    "test_10_cases.py",
    "test_phishshield_cases.py",
    # Legacy offline suite — thresholds/fields drifted from current strict pipeline.
    "test_regression.py",
]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

backend_main = importlib.import_module("main")
app = backend_main.app


@pytest.fixture(scope="session", autouse=True)
def _load_model_artifacts_once() -> None:
    """Load TF-IDF artifacts before API tests (CI runs backend/train_model.py first)."""
    backend_main.load_artifacts()


@pytest.fixture(autouse=True)
def _reset_scan_cache_for_tests(tmp_path, monkeypatch) -> None:
    """Avoid cross-test pollution from scan_cache / explanations (stable scores)."""
    app.state.scan_cache = OrderedDict()
    app.state.scan_explanations = OrderedDict()
    app.state.scan_rate_limits = {}
    monkeypatch.setattr(backend_main, "SCANS_DB_PATH", tmp_path / "scans.test.db")
    yield


@pytest.fixture
def sample_emails():
    return {
        "safe_project": "Subject: Project Update\nTeam meeting scheduled tomorrow.",
        "safe_report": "Monthly report attached. No action required.",
        "linkedin": "Your LinkedIn weekly digest is ready.",
        "otp_awareness": "We never ask for OTP or passwords.",
        "otp_scam": "Send OTP immediately to avoid account block.",
        "phishing_link": "Verify now: http://secure-login.xyz",
        "bec": "Process urgent wire transfer confidentially.",
        "delivery": "Pay INR 50 delivery fee: http://pay-delivery.xyz",
        "verify": "Account notice: http://verify-now.xyz",
        "tax": "Claim refund: http://refund-portal.xyz",
    }


@pytest_asyncio.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as async_client:
        yield async_client
