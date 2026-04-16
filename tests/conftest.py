from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "PhisShield-Backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

backend_main = importlib.import_module("main")
app = backend_main.app


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
