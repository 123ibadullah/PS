from __future__ import annotations

import importlib
import sys
from collections import OrderedDict
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

backend_main = importlib.import_module("main")
app = backend_main.app


@pytest.fixture(autouse=True)
def _reset_scan_cache_for_tests() -> None:
    app.state.scan_cache = OrderedDict()
    app.state.scan_explanations = OrderedDict()
    app.state.scan_rate_limits = {}
    yield
    app.state.scan_cache = OrderedDict()
    app.state.scan_explanations = OrderedDict()
    app.state.scan_rate_limits = {}


@pytest_asyncio.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as async_client:
        yield async_client
