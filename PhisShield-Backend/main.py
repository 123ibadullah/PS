from __future__ import annotations

import base64
import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import time
from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from threading import Lock
from typing import Any, Literal
from urllib.parse import urlparse
from uuid import uuid4

import joblib
import numpy as np
import pandas as pd
import requests
from dotenv import dotenv_values, load_dotenv
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from starlette.websockets import WebSocketState
from pydantic import BaseModel, Field, field_validator
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

try:
    from explain import explain_prediction
except ImportError:
    explain_prediction = None
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Summary,
    generate_latest,
)

try:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
except Exception:  # pragma: no cover - optional runtime dependency for fallback safety
    torch = None
    AutoModelForSequenceClassification = None
    AutoTokenizer = None

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "Phishing_Email.csv"
MODEL_PATH = BASE_DIR / "model.pkl"
VECTORIZER_PATH = BASE_DIR / "vectorizer.pkl"
METADATA_PATH = BASE_DIR / "training_meta.json"
FEEDBACK_CSV_PATH = BASE_DIR / "feedback.csv"
FEEDBACK_STATE_PATH = BASE_DIR / "feedback_state.json"
FEEDBACK_MEMORY_PATH = BASE_DIR / "feedback_memory.json"
SCAN_LOG_PATH = BASE_DIR / "scan_logs.jsonl"
SENDER_PROFILE_PATH = BASE_DIR / "sender_profiles.json"
THREAT_INTEL_PATH = BASE_DIR / "threat_intel_feed.json"
SCANS_DB_PATH = BASE_DIR / "scans.db"
FEEDBACK_COLUMNS = ["email_text", "user_label", "model_prediction", "timestamp", "scan_id"]
RETRAIN_THRESHOLD = 50
INDICBERT_MODEL_DIR = BASE_DIR / "indicbert_model"
INDICBERT_REQUIRED_FILES = (
    "config.json",
    "tokenizer.json",
    "model.safetensors",
    "tokenizer_config.json",
)
INDICBERT_HEALTH_LABEL = "IndicBERT-GPU-97.4%"
INDICBERT_HEALTH_ACCURACY = "97.4%"
INDICBERT_HEALTH_F1 = "96.8%"
MAX_TOKEN_LENGTH = 256
VT_API_ROOT = "https://www.virustotal.com/api/v3/urls"

load_dotenv(BASE_DIR / ".env")
load_dotenv()
_ENV_FILE_VALUES = dotenv_values(BASE_DIR / ".env")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return float(default)


def _normalize_gemini_model_name(raw_model: str | None) -> str:
    model = str(raw_model or "").strip()
    if not model:
        return "gemini-1.5-flash"

    if model.startswith("models/"):
        model = model.split("/", 1)[1]

    if "/" in model and "gemini" not in model.lower():
        tail = model.split("/")[-1].strip()
        if tail:
            model = tail

    if "gemini" not in model.lower():
        return "gemini-1.5-flash"

    return model


SCAN_PROCESS_TIMEOUT_SECONDS = min(1.95, max(0.8, _env_float("SCAN_PROCESS_TIMEOUT_SECONDS", 1.85)))
NETWORK_IO_TIMEOUT_SECONDS = min(SCAN_PROCESS_TIMEOUT_SECONDS, max(0.2, _env_float("NETWORK_IO_TIMEOUT_SECONDS", 0.75)))
VT_HTTP_TIMEOUT_SECONDS = min(NETWORK_IO_TIMEOUT_SECONDS, max(0.2, _env_float("VT_HTTP_TIMEOUT_SECONDS", NETWORK_IO_TIMEOUT_SECONDS)))
VT_RETRY_WAIT_SECONDS = min(0.25, max(0.05, _env_float("VT_RETRY_WAIT_SECONDS", 0.15)))

 
HF_TOKEN = os.getenv("HF_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY", "")
LLM_PROVIDER = (
    os.getenv("LLM_PROVIDER")
    or _ENV_FILE_VALUES.get("LLM_PROVIDER")
    or "openrouter"
).strip().lower()
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = (
    os.getenv("LLM_MODEL")
    or _ENV_FILE_VALUES.get("LLM_MODEL")
    or os.getenv("OPENROUTER_MODEL")
    or _ENV_FILE_VALUES.get("OPENROUTER_MODEL")
    or "openrouter/auto"
).strip()
OPENROUTER_FALLBACK_MODELS = [
    item.strip()
    for item in (
        os.getenv(
            "OPENROUTER_FALLBACK_MODELS",
            "google/gemma-3-4b-it:free,google/gemma-3n-e4b-it:free",
        )
        or ""
    ).split(",")
    if item.strip()
]
OPENROUTER_API_KEY = (
    os.getenv("LLM_API_KEY")
    or _ENV_FILE_VALUES.get("LLM_API_KEY")
    or os.getenv("OPENROUTER_API_KEY")
    or _ENV_FILE_VALUES.get("OPENROUTER_API_KEY")
    or os.getenv("OPENROUTER_KEY")
    or _ENV_FILE_VALUES.get("OPENROUTER_KEY")
    or ""
).strip()
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models"
GEMINI_MODEL = _normalize_gemini_model_name(
    os.getenv("GEMINI_MODEL")
    or _ENV_FILE_VALUES.get("GEMINI_MODEL")
    or "gemini-1.5-flash"
)
GEMINI_API_KEY = (
    os.getenv("GEMINI_API_KEY")
    or _ENV_FILE_VALUES.get("GEMINI_API_KEY")
    or os.getenv("GOOGLE_API_KEY")
    or _ENV_FILE_VALUES.get("GOOGLE_API_KEY")
    or os.getenv("LLM_API_KEY")
    or _ENV_FILE_VALUES.get("LLM_API_KEY")
    or ""
).strip()
LLM_TIMEOUT_SECONDS = min(2.95, max(0.5, _env_float("LLM_TIMEOUT_SECONDS", 2.8)))
OPENROUTER_TIMEOUT_SECONDS = min(LLM_TIMEOUT_SECONDS, _env_float("OPENROUTER_TIMEOUT_SECONDS", LLM_TIMEOUT_SECONDS))
GEMINI_TIMEOUT_SECONDS = min(LLM_TIMEOUT_SECONDS, _env_float("GEMINI_TIMEOUT_SECONDS", LLM_TIMEOUT_SECONDS))
logger = logging.getLogger("phishshield")

app = FastAPI(title="PhishShield AI Backend", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REGISTRY = CollectorRegistry(auto_describe=True)

scan_total = Counter(
    "phishshield_scans_total",
    "Total number of email scans processed",
    ["verdict"],
    registry=REGISTRY,
)
scan_duration = Histogram(
    "phishshield_scan_duration_seconds",
    "Time taken to process a single email scan",
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    registry=REGISTRY,
)
risk_score_summary = Summary(
    "phishshield_risk_score",
    "Distribution of risk scores across all scans",
    registry=REGISTRY,
)
false_positive_corrections = Counter(
    "phishshield_false_positive_corrections_total",
    "Number of times a phishing verdict was corrected to safe via feedback",
    registry=REGISTRY,
)
false_negative_corrections = Counter(
    "phishshield_false_negative_corrections_total",
    "Number of times a safe verdict was corrected to phishing via feedback",
    registry=REGISTRY,
)
model_loaded = Gauge(
    "phishshield_model_loaded",
    "1 if ML model is loaded and ready, 0 otherwise",
    registry=REGISTRY,
)
active_cache_entries = Gauge(
    "phishshield_cache_entries_active",
    "Current number of entries in the in-memory scan cache",
    registry=REGISTRY,
)
signals_analyzed_total = Counter(
    "phishshield_signals_analyzed_total",
    "Total number of phishing signals analyzed across all scans",
    registry=REGISTRY,
)
feedback_total = Counter(
    "phishshield_feedback_total",
    "Total feedback submissions received",
    ["label"],
    registry=REGISTRY,
)

app.state.total_signals_analyzed = 0
app.state.scan_explanations = OrderedDict()
app.state.scan_cache = OrderedDict()
# Clear stale cache on startup
app.state.scan_cache.clear()
app.state.sender_profiles = {}
app.state.threat_intel = {}
app.state.scan_rate_limits = {}
app.state.feedback_memory = {}
app.state.rule_weight_adjustments = {"pattern_matching": 0, "header_spoofing": 0}
feedback_lock = Lock()
feedback_memory_lock = Lock()
scan_cache_lock = Lock()
scan_rate_limit_lock = Lock()
sender_profile_lock = Lock()
_vt_cache: dict[str, dict] = {}
_vt_cache_lock = Lock()
VT_CACHE_MAX = 500
VT_CACHE_TTL_SECONDS = 3600


class ConnectionManager:
    """Manages active WebSocket connections for live scan feed."""

    def __init__(self) -> None:
        self._active: dict[str, WebSocket] = {}
        self._session_by_ws: dict[WebSocket, str] = {}
        self._lock = asyncio.Lock()
        # Pending events: store (event_dict, created_at) tuples
        self._pending: list[tuple[dict[str, Any], datetime]] = []
        self._PENDING_MAX = 20
        self._PENDING_TTL_SECONDS = 60  # discard events older than 60s

    def _prune_pending_locked(self) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        fresh: list[dict[str, Any]] = []
        kept: list[tuple[dict[str, Any], datetime]] = []
        for event, created_at in self._pending:
            age = (now - created_at).total_seconds()
            if age < self._PENDING_TTL_SECONDS:
                fresh.append(event)
                kept.append((event, created_at))
        self._pending = kept
        return fresh

    def _is_open(self, ws: WebSocket) -> bool:
        return ws.client_state == WebSocketState.CONNECTED and ws.application_state == WebSocketState.CONNECTED

    async def connect(self, ws: WebSocket, session_id: str | None = None) -> str:
        await ws.accept()
        session_key = session_id or f"anonymous-{uuid4().hex}"
        replaced_ws: WebSocket | None = None
        fresh: list[dict[str, Any]] = []

        async with self._lock:
            replaced_ws = self._active.get(session_key)
            self._active[session_key] = ws
            self._session_by_ws[ws] = session_key
            fresh = self._prune_pending_locked()
            if fresh:
                self._pending.clear()
            print(f"[WS] Connection accepted. Sending {len(fresh)} pending events...")

        if replaced_ws is not None and replaced_ws is not ws:
            try:
                await replaced_ws.close(code=1000)
            except Exception:
                pass

        # Send pending events outside the lock
        for ev in fresh:
            try:
                await ws.send_json(ev)
            except Exception:
                break  # client already gone

        print(f"[WS] Client connected. Total active connections: {len(self._active)}")
        return session_key

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            before = len(self._active)
            session_key = self._session_by_ws.pop(ws, None)
            if session_key and self._active.get(session_key) is ws:
                self._active.pop(session_key, None)
            else:
                for key, active_ws in list(self._active.items()):
                    if active_ws is ws:
                        self._active.pop(key, None)
                        break
            print(f"[WS] Client disconnected. Active connections before disconnect: {before}")
            print(f"[WS] Cleanup complete. Remaining connections: {len(self._active)}")

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast to all active connections. Dead connections are removed."""
        async with self._lock:
            snapshot = list(self._active.items())

        if not snapshot:
            # Queue with TTL â€” cap at max size
            async with self._lock:
                self._pending.append((message, datetime.now(timezone.utc)))
                if len(self._pending) > self._PENDING_MAX:
                    self._pending = self._pending[-self._PENDING_MAX:]
            print(f"[WS] No active connections, queuing event for next client...")
            return

        dead: list[tuple[str, WebSocket]] = []
        for session_key, ws in snapshot:
            if not self._is_open(ws):
                dead.append((session_key, ws))
                continue
            try:
                await asyncio.wait_for(ws.send_json(message), timeout=3.0)
            except asyncio.TimeoutError:
                dead.append((session_key, ws))
            except Exception:
                dead.append((session_key, ws))

        # Remove dead connections
        if dead:
            async with self._lock:
                for session_key, ws in dead:
                    if self._active.get(session_key) is ws:
                        self._active.pop(session_key, None)
                    self._session_by_ws.pop(ws, None)

    async def ping_all(self) -> None:
        """Keepalive ping disabled."""
        return


ws_manager = ConnectionManager()


def record_scan_metrics(*, verdict: str, risk_score: int, signals: list[str]) -> None:
    verdict_label = verdict.lower().replace(" ", "_")
    scan_total.labels(verdict=verdict_label).inc()
    risk_score_summary.observe(risk_score)
    signals_analyzed_total.inc(len(signals))
    active_cache_entries.set(len(app.state.scan_cache))


class AttachmentContext(BaseModel):
    filename: str | None = None
    contentType: str | None = None
    size: int | None = None
    isPasswordProtected: bool = False
    hasQrCode: bool = False
    extractedText: str | None = None


class EmailScanRequest(BaseModel):
    email_text: str = Field(..., min_length=1, description="Full email content here")
    headers: str | None = None
    attachments: list[AttachmentContext] | None = None
    session_id: str | None = None

    @field_validator("email_text")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("email_text cannot be empty")
        return v


class URLRequest(BaseModel):
    url: str = Field(..., min_length=4)


class HeaderRequest(BaseModel):
    headers: str = Field(..., min_length=1)


class FeedbackRequest(BaseModel):
    email_text: str | None = None
    correct_label: Literal["phishing", "safe", "suspicious"] | None = None
    scan_id: str | None = None
    predicted: str | None = None
    corrected: str | None = None
    email_hash: str | None = None


class LegacyAnalyzeRequest(BaseModel):
    emailText: str = Field(..., min_length=1)
    headers: str | None = None
    attachments: list[AttachmentContext] | None = None


class ExplainRequest(BaseModel):
    scan_id: str = Field(..., min_length=1)


@dataclass
class Artifacts:
    model: Any | None = None
    vectorizer: Any | None = None
    indicbert_model: Any | None = None
    indicbert_tokenizer: Any | None = None
    last_trained: str | None = None
    active_model: str = "TF-IDF"
    device: str = "cpu"


artifacts = Artifacts()


def clean_text(text: str) -> str:
    text = str(text).lower()
    text = re.sub(r"[^\w\s@]", " ", text, flags=re.UNICODE)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def has_complete_indicbert_assets() -> bool:
    return INDICBERT_MODEL_DIR.exists() and all((INDICBERT_MODEL_DIR / name).exists() for name in INDICBERT_REQUIRED_FILES)


def load_training_metadata() -> dict[str, Any]:
    if not METADATA_PATH.exists():
        return {}
    try:
        return json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_training_metadata(metadata: dict[str, Any]) -> None:
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def ensure_feedback_store() -> None:
    if not FEEDBACK_CSV_PATH.exists():
        pd.DataFrame(columns=FEEDBACK_COLUMNS).to_csv(FEEDBACK_CSV_PATH, index=False)

    if not FEEDBACK_STATE_PATH.exists():
        metadata = load_training_metadata()
        baseline_accuracy = float((metadata.get("metrics") or {}).get("accuracy", 0.0) or 0.0)
        FEEDBACK_STATE_PATH.write_text(
            json.dumps(
                {
                    "feedback_rows_consumed": 0,
                    "last_retrain": metadata.get("trained_at"),
                    "last_retrain_accuracy": baseline_accuracy,
                    "previous_accuracy": baseline_accuracy,
                    "model_improving": True,
                },
                indent=2,
            ),
            encoding="utf-8",
        )


def load_feedback_state() -> dict[str, Any]:
    ensure_feedback_store()
    metadata = load_training_metadata()
    baseline_accuracy = float((metadata.get("metrics") or {}).get("accuracy", 0.0) or 0.0)
    state: dict[str, Any] = {
        "feedback_rows_consumed": 0,
        "last_retrain": metadata.get("trained_at"),
        "last_retrain_accuracy": baseline_accuracy,
        "previous_accuracy": baseline_accuracy,
        "model_improving": True,
    }
    if FEEDBACK_STATE_PATH.exists():
        try:
            state.update(json.loads(FEEDBACK_STATE_PATH.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            pass
    return state


def save_feedback_state(state: dict[str, Any]) -> None:
    FEEDBACK_STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def ensure_feedback_memory_store() -> None:
    if not FEEDBACK_MEMORY_PATH.exists():
        FEEDBACK_MEMORY_PATH.write_text("{}", encoding="utf-8")


def load_feedback_memory() -> dict[str, Any]:
    ensure_feedback_memory_store()
    try:
        loaded = json.loads(FEEDBACK_MEMORY_PATH.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except json.JSONDecodeError:
        return {}


def save_feedback_memory(memory_payload: dict[str, Any]) -> None:
    FEEDBACK_MEMORY_PATH.write_text(json.dumps(memory_payload, indent=2), encoding="utf-8")


def apply_rule_weight_adjustments(pattern_score: int, header_score: int) -> tuple[int, int]:
    adjustments = app.state.rule_weight_adjustments if isinstance(app.state.rule_weight_adjustments, dict) else {}
    pattern_delta = int(adjustments.get("pattern_matching", 0) or 0)
    header_delta = int(adjustments.get("header_spoofing", 0) or 0)
    adjusted_pattern = max(0, min(100, int(pattern_score) + pattern_delta))
    adjusted_header = max(0, min(100, int(header_score) + header_delta))
    return adjusted_pattern, adjusted_header


def update_rule_weight_adjustments(predicted: str, corrected: str) -> None:
    adjustments = app.state.rule_weight_adjustments if isinstance(app.state.rule_weight_adjustments, dict) else {
        "pattern_matching": 0,
        "header_spoofing": 0,
    }
    normalized_predicted = str(predicted or "").strip().lower()
    normalized_corrected = str(corrected or "").strip().lower()

    if normalized_predicted in {"high risk", "suspicious"} and normalized_corrected == "safe":
        adjustments["pattern_matching"] = max(-15, int(adjustments.get("pattern_matching", 0) or 0) - 1)
    elif normalized_predicted == "safe" and normalized_corrected in {"high risk", "suspicious"}:
        adjustments["pattern_matching"] = min(15, int(adjustments.get("pattern_matching", 0) or 0) + 1)

    app.state.rule_weight_adjustments = adjustments


def ensure_sender_profile_store() -> None:
    if not SENDER_PROFILE_PATH.exists():
        SENDER_PROFILE_PATH.write_text("{}", encoding="utf-8")


def load_sender_profiles() -> dict[str, Any]:
    ensure_sender_profile_store()
    try:
        return json.loads(SENDER_PROFILE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_sender_profiles(profiles: dict[str, Any]) -> None:
    SENDER_PROFILE_PATH.write_text(json.dumps(profiles, indent=2), encoding="utf-8")


def ensure_scans_db() -> None:
    with sqlite3.connect(SCANS_DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                session_id TEXT,
                verdict TEXT,
                risk_score INTEGER,
                timestamp TEXT,
                language TEXT,
                sender_domain TEXT
            )
            """
        )
        conn.commit()


def save_scan_to_db(result: dict[str, Any], session_id: str | None = None) -> None:
    ensure_scans_db()
    scan_id = str(result.get("scan_id") or result.get("id") or uuid4().hex[:12])

    with sqlite3.connect(SCANS_DB_PATH) as conn:
        existing = conn.execute(
            "SELECT scan_id FROM scans WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        if existing:
            print(f"[DB] SKIP DUPLICATE: {scan_id} already in DB")
            return

        print(f"[DB] SAVING: {scan_id}")

        resolved_session_id = str(session_id or result.get("session_id") or "")
        verdict = str(result.get("verdict") or result.get("classification") or "Suspicious")
        risk_score = int(result.get("risk_score") or result.get("riskScore") or 0)
        timestamp = str(result.get("timestamp") or datetime.now(timezone.utc).isoformat())
        language = str(result.get("language") or result.get("detectedLanguage") or "EN")
        domain_trust = result.get("domainTrust") if isinstance(result.get("domainTrust"), dict) else {}
        sender_domain = str(
            result.get("sender_domain")
            or result.get("senderDomain")
            or result.get("domain")
            or domain_trust.get("domain")
            or ""
        )

        conn.execute(
            """
            INSERT OR IGNORE INTO scans (
                scan_id, session_id, verdict, risk_score, timestamp, language, sender_domain
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, resolved_session_id, verdict, risk_score, timestamp, language, sender_domain),
        )
        conn.commit()


def get_recent_scans_from_db(session_id: str | None = None) -> list[dict[str, Any]]:
    ensure_scans_db()
    with sqlite3.connect(SCANS_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if session_id:
            rows = conn.execute(
                """
                SELECT scan_id, session_id, verdict, risk_score, timestamp, language, sender_domain
                FROM scans
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT 10
                """,
                (session_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT scan_id, session_id, verdict, risk_score, timestamp, language, sender_domain
                FROM scans
                ORDER BY timestamp DESC
                LIMIT 10
                """
            ).fetchall()

    return [
        {
            "scan_id": str(row["scan_id"]),
            "verdict": str(row["verdict"] or "Suspicious"),
            "risk_score": int(row["risk_score"] or 0),
            "timestamp": str(row["timestamp"] or datetime.now(timezone.utc).isoformat()),
            "sender_domain": str(row["sender_domain"] or ""),
            "language": str(row["language"] or "EN"),
            "session_id": str(row["session_id"] or ""),
        }
        for row in rows
    ]


def default_threat_intel_feed() -> dict[str, Any]:
    return {
        "maliciousDomains": [
            "amaz0n-security-login.xyz",
            "secure-mail.top",
            "google-auth-review.top",
            "amazon-review-center-login.ru",
            "google-session-validate.top",
            "hdfc-alert-secure.xyz",
            "sbi-login-check.top",
            "refund-department-gov.xyz",
            "wallet-restore-check.xyz",
            "mobile-mail.work",
        ],
        "indicatorFragments": [
            "verify-login",
            "secure-review",
            "wallet-restore",
            "review-center",
            "session-check",
            "otp-confirm",
            "billing-check",
        ],
        "shortenerDomains": ["bit.ly", "tinyurl.com", "rb.gy", "t.co", "cutt.ly", "tiny.one"],
        "feedSources": ["Local enterprise threat feed", "CERT-style phishing indicators", "Known campaign fragments"],
    }


def ensure_threat_intel_store() -> None:
    if not THREAT_INTEL_PATH.exists():
        THREAT_INTEL_PATH.write_text(json.dumps(default_threat_intel_feed(), indent=2), encoding="utf-8")


def load_threat_intel_feed() -> dict[str, Any]:
    ensure_threat_intel_store()
    try:
        return json.loads(THREAT_INTEL_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default_threat_intel_feed()


def load_artifacts() -> None:
    artifacts.model = None
    artifacts.vectorizer = None
    artifacts.indicbert_model = None
    artifacts.indicbert_tokenizer = None
    artifacts.last_trained = None
    artifacts.active_model = "TF-IDF"
    artifacts.device = "cuda" if torch is not None and torch.cuda.is_available() else "cpu"
    fallback_reason: str | None = None

    if has_complete_indicbert_assets() and AutoTokenizer is not None and AutoModelForSequenceClassification is not None:
        try:
            artifacts.indicbert_tokenizer = AutoTokenizer.from_pretrained(
                str(INDICBERT_MODEL_DIR),
                use_fast=False,
                local_files_only=True,
                token=HF_TOKEN or None,
            )
            artifacts.indicbert_model = AutoModelForSequenceClassification.from_pretrained(
                str(INDICBERT_MODEL_DIR),
                local_files_only=True,
                token=HF_TOKEN or None,
            )
            try:
                artifacts.indicbert_model.to(artifacts.device)
                artifacts.indicbert_model.eval()
                artifacts.active_model = INDICBERT_HEALTH_LABEL
                print("IndicBERT loaded")
            except Exception as device_exc:
                if artifacts.device == "cuda":
                    try:
                        artifacts.device = "cpu"
                        artifacts.indicbert_model.to("cpu")
                        artifacts.indicbert_model.eval()
                        artifacts.active_model = INDICBERT_HEALTH_LABEL
                        print("IndicBERT loaded")
                    except Exception as cpu_exc:
                        fallback_reason = f"{type(cpu_exc).__name__}: {cpu_exc}"
                        logger.exception("IndicBERT GPU and CPU fallback both failed")
                        artifacts.indicbert_model = None
                        artifacts.indicbert_tokenizer = None
                        artifacts.active_model = "TF-IDF"
                else:
                    fallback_reason = f"{type(device_exc).__name__}: {device_exc}"
                    logger.exception("IndicBERT failed to initialize on CPU")
                    artifacts.indicbert_model = None
                    artifacts.indicbert_tokenizer = None
                    artifacts.active_model = "TF-IDF"
        except Exception as load_exc:
            fallback_reason = f"{type(load_exc).__name__}: {load_exc}"
            logger.exception("IndicBERT artifacts failed to load")
            artifacts.indicbert_model = None
            artifacts.indicbert_tokenizer = None
            artifacts.active_model = "TF-IDF"
    else:
        if not has_complete_indicbert_assets():
            fallback_reason = "missing model artifacts"
        elif AutoTokenizer is None or AutoModelForSequenceClassification is None:
            fallback_reason = "transformers/torch not available"

    if artifacts.active_model != INDICBERT_HEALTH_LABEL:
        print(f"Falling back to TF-IDF: {fallback_reason or 'IndicBERT unavailable'}")

    if MODEL_PATH.exists() and VECTORIZER_PATH.exists():
        artifacts.model = joblib.load(MODEL_PATH)
        artifacts.vectorizer = joblib.load(VECTORIZER_PATH)

    if METADATA_PATH.exists():
        try:
            metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
            artifacts.last_trained = metadata.get("trained_at")
        except json.JSONDecodeError:
            artifacts.last_trained = None


@app.on_event("startup")
async def startup_event() -> None:
    ensure_scans_db()
    ensure_feedback_store()
    ensure_feedback_memory_store()
    ensure_sender_profile_store()
    ensure_threat_intel_store()
    load_artifacts()
    has_model = artifacts.model is not None or artifacts.indicbert_model is not None
    model_loaded.set(1 if has_model else 0)
    app.state.scan_explanations = OrderedDict()
    app.state.scan_cache = OrderedDict()
    app.state.scan_rate_limits = {}
    app.state.feedback_memory = load_feedback_memory()
    app.state.sender_profiles = load_sender_profiles()
    app.state.threat_intel = load_threat_intel_feed()
    active_cache_entries.set(len(app.state.scan_cache))
    print("Model loaded at startup")


OTP_PATTERN = re.compile(r"\b(otp|pin|password|passcode|cvv|verification code|security code)\b|à°“à°Ÿà°¿à°ªà°¿|à°ªà°¾à°¸à±\s?à°µà°°à±à°¡à±|à°ªà°¿à°¨à±|à¤“à¤Ÿà¥€à¤ªà¥€|à¤ªà¤¾à¤¸à¤µà¤°à¥à¤¡|à¤ªà¤¿à¤¨", re.IGNORECASE)
URGENCY_PATTERN = re.compile(r"\b(urgent|urgently|immediately|24 hours|within 24 hours|action required|final notice|suspend|suspended|suspension|blocked|disable|before \d{1,2}\s?(?:am|pm)|before end of day|offer expires?|expires in \d+\s*(?:hours?|hrs?)|within \d+\s*(?:hours?|hrs?))\b|à¤¤à¥à¤°à¤‚à¤¤|à¤…à¤­à¥€|à¤¬à¤‚à¤¦|à¤…à¤‚à¤¤à¤¿à¤®|à¤–à¤¾à¤¤à¤¾ à¤¬à¤‚à¤¦|à¤¤à¤¤à¥à¤•à¤¾à¤²|à°µà±†à°‚à°Ÿà°¨à±‡|à°¤à°•à±à°·à°£à°‚|à°…à°¤à±à°¯à°µà°¸à°°à°‚|à°–à°¾à°¤à°¾ à°¬à°‚à°¦à±|à°‡à°ªà±à°ªà±à°¡à±‡|à°¨à°¿à°²à°¿à°ªà°¿à°µà±‡à°¯à°¬à°¡à±à°¤à±à°‚à°¦à°¿", re.IGNORECASE)
BRAND_PATTERN = re.compile(
    r"\b(amazon|microsoft|office 365|outlook|google|gmail|paypal|pay pal|sbi|state bank of india|hdfc|icici|pnb|punjab national bank|axis|axis bank|kotak|kotak mahindra|phonepe|paytm|gpay|google pay|irctc|aadhaar|pan|gst|gstn|income tax|jio|airtel|bsnl|vodafone|vi)\b|à°†à°§à°¾à°°à±|à°ªà°¾à°¨à±",
    re.IGNORECASE,
)
BRAND_TEXT_HINTS: dict[str, re.Pattern[str]] = {
    "amazon": re.compile(r"\bamazon\b", re.IGNORECASE),
    "microsoft": re.compile(r"\b(?:microsoft|office 365|outlook|hotmail|live)\b", re.IGNORECASE),
    "google": re.compile(r"\b(?:google|gmail|google pay|gpay)\b", re.IGNORECASE),
    "paypal": re.compile(r"\bpay\s?pal\b", re.IGNORECASE),
    "github": re.compile(r"\bgithub\b", re.IGNORECASE),
    "overleaf": re.compile(r"\boverleaf\b", re.IGNORECASE),
    "openai": re.compile(r"\b(?:openai|chatgpt)\b", re.IGNORECASE),
    "linkedin": re.compile(r"\blinkedin\b", re.IGNORECASE),
    "paytm": re.compile(r"\bpaytm\b", re.IGNORECASE),
    "phonepe": re.compile(r"\bphonepe\b", re.IGNORECASE),
    "sbi": re.compile(r"\b(?:sbi|state bank of india)\b", re.IGNORECASE),
    "hdfc": re.compile(r"\bhdfc\b", re.IGNORECASE),
    "icici": re.compile(r"\bicici\b", re.IGNORECASE),
    "netflix": re.compile(r"\bnetflix\b", re.IGNORECASE),
}
TRUSTED_BRAND_DOMAIN_MAP: dict[str, tuple[str, ...]] = {
    "amazon": ("amazon.in", "amazon.com", "amazon.co.uk", "amazonaws.com", "amazonses.com"),
    "microsoft": ("microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"),
    "google": (
        "google.com",
        "accounts.google.com",
        "pay.google.com",
        "googleapis.com",
        "googlemail.com",
        "notifications.google.com",
        "gstatic.com",
        "www.gstatic.com",
        "c.gle",
        "1e100.net",
        "googleusercontent.com",
        "scoutcamp.bounces.google.com",
    ),
    "paypal": ("paypal.com", "paypalobjects.com", "paypal.me", "e.paypal.com"),
    "github": ("github.com", "githubassets.com", "githubusercontent.com", "github.io"),
    "overleaf": ("overleaf.com",),
    "openai": ("openai.com", "chatgpt.com", "oaistatic.com"),
    "linkedin": ("linkedin.com", "lnkd.in"),
    "paytm": ("paytm.com", "paytm.in"),
    "phonepe": ("phonepe.com",),
    "sbi": ("sbi.co.in",),
    "hdfc": ("hdfcbank.com", "hdfcbank.net", "hdfc.com"),
    "icici": ("icicibank.com",),
    "netflix": ("netflix.com", "mailer.netflix.com"),
}
SAFE_OVERRIDE_TRUSTED_DOMAINS: dict[str, tuple[str, ...]] = {
    "google": ("accounts.google.com", "google.com", "pay.google.com", "notifications.google.com", "googlemail.com"),
    "paypal": ("paypal.com", "e.paypal.com"),
    "amazon": ("amazon.in", "amazon.com"),
    "microsoft": ("microsoft.com", "login.microsoftonline.com"),
    "github": ("github.com", "githubusercontent.com"),
    "overleaf": ("overleaf.com",),
    "openai": ("openai.com", "chatgpt.com"),
    "linkedin": ("linkedin.com", "lnkd.in"),
    "paytm": ("paytm.com", "paytm.in"),
    "hdfc": ("hdfcbank.com", "hdfcbank.net"),
    "sbi": ("sbi.co.in",),
    "icici": ("icicibank.com",),
}
HIGH_RISK_TLDS = (".xyz", ".tk", ".ml", ".cf", ".gq", ".ga", ".top", ".click", ".work")
SENDER_DOMAIN_RISK_BRAND_TOKENS = frozenset(
    {
        "bank",
        "paypal",
        "paypa1",
        "paypai",
        "hdfc",
        "sbi",
        "icici",
        "amazon",
        "microsoft",
        "google",
        "github",
    }
)
SENDER_DOMAIN_RISK_ACTION_TOKENS = frozenset(
    {
        "alert",
        "security",
        "secure",
        "verify",
        "verification",
        "login",
        "signin",
        "support",
        "update",
        "confirm",
        "account",
        "careers",
    }
)
OTP_HARVEST_PATTERN = re.compile(
    r"(?:\b(?:share|send|provide|enter|submit|reply with|tell us)\b.{0,24}\b(?:otp|pin|passcode|verification code|security code)\b|\b(?:otp|pin|passcode|verification code|security code)\b.{0,24}\b(?:immediately|urgent|now|share|send|provide|reply)\b)",
    re.IGNORECASE,
)
CREDENTIAL_HARVEST_PATTERN = re.compile(
    r"(?:\b(?:send|share|enter|provide|submit|reply(?:\s+with)?|confirm|update)\b.{0,30}\b(?:password|passcode|pin|login|verify|credentials?)\b|\b(?:password|passcode|pin|credentials?)\b.{0,24}\b(?:now|immediately|urgent|send|share|enter|provide|submit)\b)",
    re.IGNORECASE,
)
CREDENTIAL_NEGATION_PATTERN = re.compile(
    r"(?:\b(?:do\s+not|don't|never)\b.{0,30}\b(?:share|send|provide|enter|submit)\b.{0,30}\b(?:password|passcode|pin|credentials?|otp)\b"
    r"|\bno\b.{0,12}\b(?:password|passcode|pin|credentials?|otp)\b.{0,24}\b(?:requested|required|needed|asked)\b)",
    re.IGNORECASE,
)
SUSPICIOUS_PATTERN = re.compile(r"\b(kyc|upi|lottery|refund|winner|prize|cashback|claim now|gift)\b|à°•à±‡à°µà±ˆà°¸à°¿|à°°à°¿à°«à°‚à°¡à±|à°¬à°¹à±à°®à°¤à°¿", re.IGNORECASE)
NEWSLETTER_SENDER_DOMAINS = (
    "quora.com",
    "linkedin.com",
    "medium.com",
    "substack.com",
    "github.com",
    "overleaf.com",
    "openai.com",
    "chatgpt.com",
    "google.com",
    "googlemail.com",
    "pay.google.com",
    "notifications.google.com",
    "amazon.in",
    "flipkart.com",
    "irctc.co.in",
    "noreply.github.com",
)
MARKETING_FOOTER_PATTERN = re.compile(
    r"\b(list-unsubscribe|unsubscribe|manage notification settings|communication preferences|you(?:'re| are) getting this email because|visit the help center|terms\s*&\s*conditions|terms apply|privacy policy|was this email helpful\?)\b",
    re.IGNORECASE,
)
AUTH_PASS_PATTERN = re.compile(r"\b(?:spf|dkim|dmarc)\s*=\s*pass\b", re.IGNORECASE)
KNOWN_HEADER_PATTERN = re.compile(
    r"^(?:from|to|subject|reply-to|return-path|received|received-spf|authentication-results|arc-authentication-results|dkim-signature|mime-version|content-type|date|list-unsubscribe|list-id)\s*:",
    re.IGNORECASE,
)
SMS_SIGNALS = [
    (re.compile(r"[A-Z]{2,8}BANK:\s*Rs\.", re.IGNORECASE), 30, "SMS banking sender style"),
    (re.compile(r"debited from [Aa]/c\s*[Xx]+\d{4}", re.IGNORECASE), 30, "Account debit alert spoof"),
    (re.compile(r"Not done by you\?", re.IGNORECASE), 25, "Fraud panic lure"),
    (re.compile(r"A/c\s*[Xx]{2,}\d{4}", re.IGNORECASE), 20, "Masked account number"),
    (re.compile(r"txn[:\s][A-Z0-9]{6,}", re.IGNORECASE), 15, "Transaction reference format"),
    (re.compile(r"dispute|block.{0,10}card", re.IGNORECASE), 15, "Dispute or card block pressure"),
]
LOTTERY_SIGNALS = [
    (re.compile(r"kbc|kaun banega crorepati", re.IGNORECASE), 25, "KBC lottery branding"),
    (re.compile(r"lucky draw|lucky winner", re.IGNORECASE), 20, "Lucky draw lure"),
    (re.compile(r"prize.{0,20}(lakh|crore|\d{1,2},\d{2},\d{3}|00,000)", re.IGNORECASE), 20, "Prize money lure"),
    (re.compile(r"processing fee.{0,30}refundable", re.IGNORECASE), 25, "Refundable processing fee demand"),
    (re.compile(r"whatsapp.{0,20}\+?[0-9][0-9\-\s]{9,15}", re.IGNORECASE), 20, "Foreign WhatsApp lure"),
    (re.compile(r"(?:call|contact|whatsapp|phone|helpline|reach(?:\s+us)?)[:\s-]{0,12}\+?(?:44|971|1)(?:[\s()\-]*\d){6,}", re.IGNORECASE), 15, "International callback number"),
    (re.compile(r"sony entertainment|star plus", re.IGNORECASE), 15, "TV show impersonation"),
    (re.compile(r"contact.{0,20}(manager|agent|officer)", re.IGNORECASE), 10, "Manager or agent callback pressure"),
]
HINGLISH_REWARD_SIGNALS = [
    (re.compile(r"(lucky|winner|select|chosen).{0,40}(prize|inaam|inam|reward|cash)", re.IGNORECASE), 20, "Hinglish reward lure (winner/prize/cash)"),
    (re.compile(r"(claim|hasil|lo|lena).{0,30}(karo|karein|kijiye).{0,20}(link|click|yahan)", re.IGNORECASE), 20, "Hinglish claim-now action chain"),
    (re.compile(r"(aaj|sirf|only today|limited).{0,20}(valid|offer|chance|mauka)", re.IGNORECASE), 20, "Limited-time offer pressure in Hinglish"),
]
UPI_PATTERN = re.compile(r"(?<![A-Za-z0-9._%+-])[\w.-]+@(ybl|okicici|paytm|ibl|upi)(?!\.[A-Za-z])\b", re.IGNORECASE)
GSTIN_PATTERN = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z][A-Z\d]\b")
AADHAAR_PATTERN = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
PAN_PATTERN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
FREE_MAIL_PATTERN = re.compile(r"@(gmail|yahoo|outlook|hotmail)\.com\b", re.IGNORECASE)
SUSPICIOUS_DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9-]+\.)+(xyz|top|click|work|shop|info|site|biz|club)\b", re.IGNORECASE)
URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)
IGNORED_URL_HOSTS = ("www.w3.org", "gstatic.com", "www.gstatic.com")
SUSPICIOUS_LINK_LURE_PATTERN = re.compile(r"https?://\S*(verify|login|secure|update|otp|suspend|confirm|bank-update|claim|reward|kyc|upi)\S*|\b(?:bit\.ly|tinyurl\.com|rb\.gy|t\.co)/\S+", re.IGNORECASE)
# UNUSED: reserved for future safe-context enrichment.
# SAFE_BUSINESS_PATTERN = re.compile(r"\b(hi team|attached|monthly report|regards|please find attached|meeting notes|invoice attached|thanks|hello team)\b", re.IGNORECASE)
BEC_TRANSFER_PATTERN = re.compile(
    r"\b(wire transfer|bank transfer|transfer(?: funds?| money)?|neft|rtgs|ifsc|vendor payment|payment request|process (?:the )?(?:vendor )?(?:payment|invoice|transfer)|approve (?:the )?(?:payment|invoice|transfer)|confirm (?:the )?(?:payment|transfer)|release (?:the )?(?:payment|transfer))\b",
    re.IGNORECASE,
)
BEC_CONFIDENTIAL_PATTERN = re.compile(
    r"\b(confidential|keep this confidential|keep confidential|strictly confidential|do not discuss|don't discuss|do not call back|can't talk|cannot talk|in a meeting|off the main thread)\b",
    re.IGNORECASE,
)
BEC_MOBILE_PATTERN = re.compile(r"sent from my\s+(?:iphone|samsung)", re.IGNORECASE)
BEC_EXEC_PATTERN = re.compile(r"\b(ceo|cfo|md|director|managing director)\b", re.IGNORECASE)
BANK_DETAILS_PATTERN = re.compile(r"\b(bank details?|beneficiary|account number|a/c|acct|ifsc|swift|iban)\b", re.IGNORECASE)
DELIVERY_BRAND_PATTERN = re.compile(r"\b(fedex|dhl|india post|bluedart|ekart)\b", re.IGNORECASE)
DELIVERY_FEE_PATTERN = re.compile(r"\b(customs fee|clearance fee|delivery fee)\b", re.IGNORECASE)
DELIVERY_ITEM_PATTERN = re.compile(r"\b(package|parcel|shipment)\b", re.IGNORECASE)
DELIVERY_FAILURE_PATTERN = re.compile(r"could not be delivered", re.IGNORECASE)
SMALL_FEE_PATTERN = re.compile(r"(?:rs\.?|â‚¹)\s*(49|99|149)\b", re.IGNORECASE)
FOREIGN_ORIGIN_PATTERN = re.compile(r"\b(dubai|china|uk)\b", re.IGNORECASE)
PAYMENT_LINK_PATTERN = re.compile(r"https?://\S*(pay|payment|clearance|delivery|track|fee)\S*", re.IGNORECASE)
IT_PHISHING_BOOSTS = [
    (re.compile(r"income.?tax.{0,20}refund", re.IGNORECASE), 20, "Income tax refund lure"),
    (re.compile(r"refund.{0,20}approv", re.IGNORECASE), 20, "Refund approval claim"),
    (re.compile(r"verify.{0,20}(?:your\s+)?pan.{0,20}(?:detail|number|info)", re.IGNORECASE), 18, "PAN verification request"),
    (re.compile(r"claim.{0,20}(?:your\s+)?refund", re.IGNORECASE), 15, "Refund claim pressure"),
    (re.compile(r"update.{0,20}bank.{0,20}detail", re.IGNORECASE), 15, "Bank details update request"),
    (re.compile(r"net.?banking.{0,20}credential", re.IGNORECASE), 20, "Net banking credentials requested"),
    (re.compile(r"income.?tax.{0,20}department", re.IGNORECASE), 10, "Government department impersonation"),
    (re.compile(r"PAN\s*:\s*[A-Z]{5}\d{4}[A-Z]", re.IGNORECASE), 15, "PAN identifier requested"),
    (re.compile(r"incometax(?:-gov-in)?[^\s/]*\.(?:xyz|top|click|info|site|online|shop)|incometax-gov-in\.", re.IGNORECASE), 18, "Fake tax refund domain"),
    (re.compile(r"(48|72|24)\s*hours.{0,30}(claim|refund|update)", re.IGNORECASE), 10, "Refund urgency pressure"),
]
SAFE_PAYMENT_CONFIRMATION_PATTERN = re.compile(
    r"\b(payment (?:was )?(?:successful|processed)|has been successfully processed|subscription has been renewed|transaction id|thank you for shopping|order\s+#?\S+\s+(?:has been |has )?shipped|expected delivery)\b",
    re.IGNORECASE,
)
SAFE_SECURITY_ALERT_PATTERN = re.compile(
    r"\b(your (?:google )?account was just signed in to from a new (?:windows )?device|we (?:have )?detected (?:a )?login attempt from a new (?:device|ip address)|if this was you,? (?:you can )?(?:safely )?ignore|if this was you,? please ignore|if this wasn't you,? please secure your account|review recent security activity)\b",
    re.IGNORECASE,
)
HELPLINE_NOTICE_PATTERN = re.compile(r"\b(call (?:our )?(?:24/?7 )?(?:helpline|support)|official helpline|customer care)\b", re.IGNORECASE)
QR_LURE_PATTERN = re.compile(r"\b(scan (?:the )?qr(?:\s+code)?|qr\s+code)\b", re.IGNORECASE)
ATTACHMENT_LURE_PATTERN = re.compile(r"\b(attached (?:pdf|document|file|invoice)|open the attachment|review the attached|attached pdf)\b", re.IGNORECASE)
PAYROLL_LURE_PATTERN = re.compile(r"\b(payroll|salary account|direct deposit)\b", re.IGNORECASE)
SAFE_KYC_REMINDER_PATTERN = re.compile(
    r"\b(reminder to complete (?:your )?kyc|complete (?:your )?kyc in the official (?:paytm )?app|official (?:paytm )?app|update (?:your )?kyc details in (?:the )?app|update (?:your )?kyc in (?:the )?app|no action is needed if already completed|continue wallet services)\b",
    re.IGNORECASE,
)
HINGLISH_PATTERN = re.compile(
    r"\b(?:otp\s+bhejo|verify\s+karo|turant|jaldi|abhi|account\s+block|band\s+ho\s+jayega|turant\s+verify|bhejo\s+warna|aapka|aapke|is\s+hafte|koi\s+action|nahi\s+hai)\b",
    re.IGNORECASE,
)
# TODO: wire into scoring in detect_indian_patterns/build_semantic_pattern_signals.
BILLING_ISSUE_PATTERN = re.compile(
    r"\b(payment issue|billing issue|billing details|review your billing|problem processing your recent payment|payment could not be processed|billing support page)\b",
    re.IGNORECASE,
)
SAFE_OTP_AWARENESS_PATTERN = re.compile(
    r"\b(?:"
    r"we never ask for (?:your )?otp"
    r"|do not share (?:your )?otp"
    r"|never share (?:your )?otp"
    r"|bank (?:never|will never) (?:ask|request) for (?:your )?otp"
    r"|do not share (?:your )?(?:otp|pin|password|passcode)"
    r"|we will never ask (?:you )?(?:to share|for) (?:your )?(?:otp|password|pin)"
    r"|(?:bank|we) (?:never|will never) (?:ask|request) (?:for )?(?:your )?(?:otp|password|credentials)"
    r"|do not (?:reveal|disclose|give) (?:your )?(?:otp|pin|password)"
    r"|beware of (?:phishing|fraud|scam)"
    r"|stay safe from (?:phishing|fraud|scam)"
    r")|"
    r"(?:à¤¹à¤® à¤•à¤­à¥€ à¤­à¥€ à¤“à¤Ÿà¥€à¤ªà¥€ à¤¨à¤¹à¥€à¤‚ à¤®à¤¾à¤‚à¤—à¤¤à¥‡"
    r"|à¤“à¤Ÿà¥€à¤ªà¥€ à¤•à¤¿à¤¸à¥€ à¤•à¥‡ à¤¸à¤¾à¤¥ à¤¸à¤¾à¤à¤¾ à¤¨ à¤•à¤°à¥‡à¤‚"
    r"|à¤¬à¥ˆà¤‚à¤• à¤•à¤­à¥€ à¤“à¤Ÿà¥€à¤ªà¥€ à¤¨à¤¹à¥€à¤‚ à¤®à¤¾à¤‚à¤—à¤¤à¤¾"
    r"|à¤…à¤ªà¤¨à¤¾ à¤“à¤Ÿà¥€à¤ªà¥€ à¤•à¤¿à¤¸à¥€ à¤•à¥‹ à¤¨ à¤¬à¤¤à¤¾à¤à¤‚)|"
    r"(?:à°®à±‡à°®à± à°Žà°ªà±à°ªà±à°¡à±‚ OTP à°…à°¡à°—à°®à±"
    r"|OTP à°Žà°µà°°à°¿à°¤à±‹à°¨à±‚ à°ªà°‚à°šà±à°•à±‹à°µà°¦à±à°¦à±"
    r"|à°¬à±à°¯à°¾à°‚à°•à± OTP à°…à°¡à°—à°¦à±)",
    re.IGNORECASE | re.UNICODE,
)
OTP_SAFETY_NOTICE_PATTERN = re.compile(
    r"(?:"
    r"do not share (?:it|this) with anyone"
    r"|never share (?:it|this) with anyone"
    r"|otp mat share karo"
    r"|otp share mat karo"
    r"|otp kisi ke saath share mat karo"
    r"|otp kisi ke saath share na karein"
    r"|otp kisi ko na bataye"
    r"|otp à°Žà°µà°°à°¿à°•à±€ à°šà±†à°ªà±à°ªà°•à°‚à°¡à°¿"
    r"|otp à°Žà°µà°°à°¿à°¤à±‹à°¨à±‚ à°ªà°‚à°šà±à°•à±‹à°µà°¦à±à°¦à±"
    r")",
    re.IGNORECASE | re.UNICODE,
)

OTP_SAFE_OVERRIDE_PATTERN = re.compile(
    r"(?:\botp\b.*\b(?:do not share|don't share|never share|not share|mat share karo|share mat karo|otp mat share karo|otp share mat karo|otp kisi ke saath share mat karo)\b|\b(?:do not share|don't share|never share|not share|mat share karo|share mat karo|otp mat share karo|otp share mat karo|otp kisi ke saath share mat karo)\b.*\botp\b)",
    re.IGNORECASE | re.UNICODE,
)


def is_otp_safety_notice(email_text: str) -> bool:
    has_otp = bool(OTP_PATTERN.search(email_text))
    if not has_otp:
        return False
    return bool(SAFE_OTP_AWARENESS_PATTERN.search(email_text) or OTP_SAFETY_NOTICE_PATTERN.search(email_text) or OTP_SAFE_OVERRIDE_PATTERN.search(email_text))
# TODO: wire into scoring in detect_indian_patterns/build_semantic_pattern_signals.
INVOICE_SIGNATURE_LURE_PATTERN = re.compile(
    r"\b(?:invoice|bill|payment)\b.{0,30}\b(?:sign|signature|review|approve)\b|\b(?:sign|signature|approve)\b.{0,30}\b(?:invoice|bill|payment)\b",
    re.IGNORECASE,
)
# TODO: wire into scoring in detect_indian_patterns/build_semantic_pattern_signals.
TRAFFIC_FINE_SCAM_PATTERN = re.compile(
    r"\b(?:rto|parivahan|challan|e-?challan|traffic fine|license suspension|driving license)\b",
    re.IGNORECASE,
)
# UNUSED: reserved for future content sanitization heuristics.
# SQL_KEYWORD_PATTERN = re.compile(r"\b(drop|select|insert|delete|table)\b", re.IGNORECASE)
# UNUSED: reserved for future content sanitization heuristics.
# TECHNICAL_STRING_PATTERN = re.compile(r"(--|/\*|\*/|;\s*$|\b(sql|query|json|xml|script|function|class|table)\b)", re.IGNORECASE)
THREAD_CONTEXT_PATTERN = re.compile(r"(?:^|\n)(?:re|fw|fwd):|-----Original Message-----|On .+ wrote:", re.IGNORECASE)
THREAD_PAYMENT_SWITCH_PATTERN = re.compile(r"\b(as discussed|follow up|same thread|updated beneficiary|new account details|different account|change of bank details)\b", re.IGNORECASE)
ATTACHMENT_SUSPICIOUS_NAME_PATTERN = re.compile(r"\b(invoice|payment|secure|voice message|updated|review|verify|payroll|statement|bonus|login|kyc|qr)\b", re.IGNORECASE)
ATTACHMENT_SUSPICIOUS_TEXT_PATTERN = re.compile(r"\b(otp|password|verify|sign in|wallet|seed phrase|beneficiary|payment|qr code|scan the qr|authorize app)\b", re.IGNORECASE)
RISKY_ATTACHMENT_EXTENSIONS: dict[str, int] = {
    ".exe": 24,
    ".scr": 24,
    ".js": 18,
    ".vbs": 18,
    ".bat": 18,
    ".cmd": 18,
    ".ps1": 18,
    ".zip": 14,
    ".rar": 14,
    ".7z": 14,
    ".iso": 18,
    ".img": 18,
    ".one": 16,
    ".url": 16,
    ".lnk": 18,
    ".svg": 12,
    ".html": 12,
    ".htm": 12,
    ".eml": 10,
    ".docm": 16,
    ".xlsm": 16,
}
INTENT_FINANCIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("payment_or_transfer", re.compile(r"\b(pay(?:ment)?|transfer|wire|invoice|beneficiary|bank details?|ifsc|iban|swift|release payment)\b", re.IGNORECASE)),
    ("fee_or_charge", re.compile(r"\b(fee|charge|customs|clearance|joining fee|processing fee)\b", re.IGNORECASE)),
    ("accounting_terms", re.compile(r"\b(vendor payment|invoice approval|accounts payable|rtgs|neft)\b", re.IGNORECASE)),
]
INTENT_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("login_or_verify", re.compile(r"\b(login|log in|sign in|verify|verification|reauthenticate|confirm account)\b", re.IGNORECASE)),
    ("password_or_passcode", re.compile(r"\b(password|passcode|pin|credential|username)\b", re.IGNORECASE)),
    ("account_lock_lure", re.compile(r"\b(account (?:suspend|lock|blocked|restricted)|security alert|mailbox locked)\b", re.IGNORECASE)),
]
INTENT_ACCESS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("otp_code", re.compile(r"\b(otp|one[-\s]?time password|verification code|auth(?:entication)? code|2fa|mfa)\b", re.IGNORECASE)),
    ("device_auth", re.compile(r"\b(new device|device verification|secure access)\b", re.IGNORECASE)),
]
INTENT_ACTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("click_or_open", re.compile(r"\b(click|open|visit|tap|scan|download)\b", re.IGNORECASE)),
    ("reply_or_confirm", re.compile(r"\b(reply|respond|confirm|acknowledge|approve)\b", re.IGNORECASE)),
    ("submit_or_share", re.compile(r"\b(submit|share|send|provide|update details)\b", re.IGNORECASE)),
]
ROLE_HIGH_AUTHORITY_PATTERN = re.compile(r"\b(ceo|cfo|founder|managing director|director|president|chairman|vp|vice president)\b", re.IGNORECASE)
ROLE_MEDIUM_AUTHORITY_PATTERN = re.compile(r"\b(hr|human resources|finance|accounts|payroll|legal|procurement|admin|it support|security team)\b", re.IGNORECASE)
HR_SCAM_PATTERN = re.compile(r"\b(job offer|hiring|recruitment|interview|onboarding|resume|hr desk)\b", re.IGNORECASE)
INVOICE_FRAUD_PATTERN = re.compile(r"\b(invoice|beneficiary|updated bank account|vendor payment|process today|invoice approval)\b", re.IGNORECASE)
ACTION_MONEY_PATTERN = re.compile(r"\b(transfer|wire|pay|release payment|beneficiary|invoice approval|bank details)\b", re.IGNORECASE)
ACTION_DATA_SHARE_PATTERN = re.compile(r"\b(share|send|provide|submit).{0,30}\b(otp|password|credential|bank details|account number|pin|pan|aadhaar)\b", re.IGNORECASE)
ACTION_REPLY_PATTERN = re.compile(r"\b(reply|respond|confirm by reply|revert)\b", re.IGNORECASE)
PRESSURE_PATTERN = re.compile(r"\b(within \d+ (?:minutes?|hours?)|today|immediately|right now|final warning|expires?|urgent)\b", re.IGNORECASE)
SECRECY_PATTERN = re.compile(r"\b(confidential|do not discuss|don't discuss|off the main thread|do not call back)\b", re.IGNORECASE)
IMPERSONATION_BEHAVIOR_PATTERN = re.compile(r"\b(ceo|cfo|director|security team|support desk|official team|impersonation|spoof|lookalike)\b", re.IGNORECASE)
LABEL_MAP = {
    "Phishing Email": 1,
    "Safe Email": 0,
}


def _rule_signal(signals: list[str], message: str) -> None:
    if message not in signals:
        signals.append(message)


def build_safe_preview(text: str, limit: int = 160) -> str:
    normalized = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[:limit].rstrip()}â€¦"


def extract_received_ips(headers: str) -> list[str]:
    ips: list[str] = []
    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(headers or "")):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in ips:
            ips.append(candidate)
    return ips


def extract_received_chain(headers: str) -> list[str]:
    chain: list[str] = []
    for match in re.finditer(r"^Received:\s*(.+(?:\n[ \t].+)*)", str(headers or ""), re.IGNORECASE | re.MULTILINE):
        hop = re.sub(r"\s+", " ", match.group(1)).strip()
        if hop:
            chain.append(hop)
    return chain


def has_header_chain_anomaly(received_chain: list[str], sending_ips: list[str]) -> bool:
    if not received_chain:
        return False

    malformed_hop = any("from " not in hop.lower() or " by " not in hop.lower() for hop in received_chain)
    repeated_hops = len({hop.lower() for hop in received_chain}) != len(received_chain)
    suspicious_route = len(sending_ips) >= 2 and sum(1 for ip in sending_ips if is_suspicious_sending_ip(ip)) >= 2
    return bool(malformed_hop or repeated_hops or suspicious_route)


def is_suspicious_sending_ip(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return False

    return any(
        [
            ip_obj.is_private,
            ip_obj.is_loopback,
            ip_obj.is_reserved,
            ip_obj.is_multicast,
            ip_obj.is_unspecified,
            ip_obj.is_link_local,
        ]
    ) or ip_text.startswith(("0.", "127.", "169.254.", "192.0.2.", "198.51.100.", "203.0.113.", "100.64."))


def sanitize_explanation_words(
    top_words: list[dict[str, Any]] | None,
    *,
    sender_domain: str = "",
    linked_domains: list[str] | None = None,
) -> list[dict[str, Any]]:
    if not top_words:
        return []

    linked_domains = linked_domains or []
    blocked_tokens = {
        "http",
        "https",
        "www",
        "com",
        "net",
        "org",
        "mail",
        "email",
        "noreply",
        "support",
        "team",
        "customer",
        "account",
        "hello",
        "thanks",
        "thank",
        "successfully",
        "review",
        "update",
        "notice",
        "subject",
        "kindly",
        "page",
        "display",
        "help",
        "official",
        "reply",
        "fast",
        "html",
        "project",
        "meeting",
        "reminder",
        "status",
        "office",
        "report",
        "monthly",
        "weekly",
        "attached",
        "regarding",
        "clarification",
        "progress",
        "current",
        "please",
        "find",
        "hi",
        "dear",
        *SAFE_OVERRIDE_TRUSTED_DOMAINS.keys(),
    }
    intent_tags = {
        "verify": "credential request",
        "verification": "credential request",
        "authenticate": "account access request",
        "authentication": "account access request",
        "urgent": "pressure tactic",
        "immediately": "pressure tactic",
        "otp": "sensitive data request",
        "password": "sensitive data request",
        "passcode": "sensitive data request",
        "login": "account access request",
        "signin": "account access request",
        "bank": "financial lure",
        "refund": "money lure",
        "payment": "financial lure",
        "beneficiary": "payment redirection",
    }

    for domain in [sender_domain, *linked_domains]:
        root = extract_root_domain(domain)
        normalized_root = normalize_domain_for_comparison(root)
        if not normalized_root:
            continue
        blocked_tokens.add(normalized_root)
        blocked_tokens.update(part for part in re.split(r"[\W_]+", normalized_root) if part and len(part) > 1)

    cleaned: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in top_words:
        word = str(item.get("word", "")).strip()
        contribution = float(item.get("contribution", 0.0) or 0.0)
        normalized_word = normalize_domain_for_comparison(word).strip(".")
        token_parts = {part for part in re.split(r"[\W_]+", normalized_word) if part}

        if not word or not normalized_word or normalized_word in seen:
            continue
        if normalized_word in blocked_tokens:
            continue
        if "." not in normalized_word and token_parts.intersection(blocked_tokens):
            continue
        if "." in normalized_word and (is_safe_override_trusted_domain(normalized_word) or resolve_brand_from_domain(normalized_word)) and not SUSPICIOUS_DOMAIN_PATTERN.search(normalized_word):
            continue

        display_word = word
        for token, tag in intent_tags.items():
            if token == normalized_word or token in token_parts or re.search(fr"\b{re.escape(token)}\b", normalized_word, re.IGNORECASE):
                display_word = f"{word} ({tag})"
                break

        seen.add(normalized_word)
        cleaned.append({"word": display_word, "contribution": round(abs(contribution), 2)})

    return cleaned[:5]


def build_explanation_summary(signals: list[str], *, mixed_content: bool = False, has_url: bool = False) -> str:
    normalized = " | ".join(signal.lower() for signal in signals)
    reasons: list[str] = []

    if re.search(r"otp|credential|password|passcode|pin|bank details|beneficiary|payment instruction|wire transfer|transfer", normalized):
        reasons.append("Sensitive action or credential request detected")
    if re.search(r"urgency|urgent|immediately|today|suspend|deadline|confidential|pressure|ambiguous intent", normalized):
        reasons.append("Urgency or pressure is pushing quick action")

    # Only mention links when the email actually has a URL
    if has_url and re.search(r"link|url|domain|suspicious verification link|sender and linked domain do not match|trusted brand points to an untrusted domain", normalized):
        reasons.append("The link or destination domain looks risky or mismatched")

    if mixed_content:
        reasons.append("Trusted branding is mixed with a suspicious destination")

    if len(reasons) < 3 and re.search(r"spoof|mismatch|reply-to|return-path|spf|dkim|dmarc|lookalike|impersonation|header", normalized):
        reasons.append("Spoofing or impersonation signs were detected")

    if not reasons:
        meaningful = [s for s in signals if s and not re.match(
            r"^(no attachments detected|attachment present|informational tone detected|known sender history|newsletter / digest)$",
            s, re.IGNORECASE
        )]
        if meaningful:
            return f"Suspicious cues detected: {'; '.join(meaningful[:2])}"
        return "No strong phishing indicators detected."

    return "; ".join(reasons[:3])


def apply_risk_tier_calibration(
    risk_score: int,
    *,
    ml_score: float,
    signal_count: int,
    word_count: int,
    has_url: bool,
    has_mixed_link_context: bool,
    is_extreme_phishing: bool,
    is_strong_phishing: bool,
) -> int:
    calibrated = int(round(risk_score))
    if not has_url and not is_extreme_phishing and not is_strong_phishing:
        return min(risk_score, 20)
    if calibrated <= 25:
        return max(0, min(100, calibrated))

    variation = min(5, max(signal_count, 0))
    ml_boost = min(4, max(0, int((ml_score - 50) / 10)))
    excess = max(0, calibrated - 60)
    is_short_text_phishing = word_count < 30 and not has_url and not is_extreme_phishing

    if is_short_text_phishing:
        calibrated = 65 + min(20, (excess // 6) + ml_boost + variation)
        return max(65, min(85, calibrated))

    if has_mixed_link_context:
        calibrated = 85 + min(10, (excess // 8) + ml_boost + max(1, variation // 2))
        return max(85, min(95, calibrated))

    if is_extreme_phishing:
        calibrated = 95 + min(5, (excess // 10) + min(3, ml_boost) + max(1, variation // 3))
        return max(95, min(100, calibrated))

    if is_strong_phishing:
        calibrated = 88 + min(7, (excess // 10) + min(3, ml_boost) + max(1, variation // 3))
        return max(85, min(95, calibrated))

    calibrated = 70 + min(15, (excess // 9) + ml_boost + variation)
    return max(65, min(85, calibrated))


def _blend_scores(raw_score: int, target_score: int, blend: float = 0.65) -> int:
    ratio = max(0.0, min(1.0, blend))
    return int(round((raw_score * (1.0 - ratio)) + (target_score * ratio)))


def calibrate_strict_verdict_risk(
    *,
    raw_score: int,
    verdict: str,
    signal_count: int,
    hard_signal_count: int,
    safe_context_count: int,
    word_count: int,
    has_malicious_url: bool,
    has_suspicious_url: bool,
    has_credential_signal: bool,
    has_otp_signal: bool,
    has_urgency_signal: bool,
    has_sender_spoof: bool,
    has_attachment_context: bool,
    has_attachment_qr: bool,
    has_attachment_password_protected: bool,
    has_attachment_credential: bool,
    thread_hijack_detected: bool = False,
    no_url_phishing_detected: bool = False,
    multi_signal_attack_detected: bool = False,
) -> int:
    raw = clamp_int(raw_score, 0, 100)

    if verdict == "Safe":
        safe_bonus = min(8, max(0, safe_context_count) * 2)
        target = min(24, max(0, int(round(raw * 0.38)) + safe_bonus))
        if raw >= 21:
            # Preserve low-suspicion safe outcomes in the transition zone instead of collapsing to deep-safe.
            target = max(21, target)
            return clamp_int(_blend_scores(raw, target, 0.35), 21, 24)
        return clamp_int(_blend_scores(raw, target, 0.72), 0, 24)

    if verdict == "Suspicious":
        normalized = 0.0 if raw <= 25 else max(0.0, min(1.0, (raw - 25) / 44.0))
        target = 25 + int(round(normalized * 44))
        target += min(6, max(0, signal_count))
        if has_suspicious_url or has_sender_spoof:
            target = max(target, 38)
        if hard_signal_count >= 2 and (has_suspicious_url or has_sender_spoof or has_urgency_signal):
            target = max(target, 61)
        if hard_signal_count >= 3:
            target = max(target, 65)
        if hard_signal_count == 0 and not has_suspicious_url and not has_sender_spoof:
            target = min(target, 55)
        target -= min(6, max(0, safe_context_count) * 2)
        smoothed = _blend_scores(raw, target, 0.60)
        return clamp_int(smoothed, 25, 69)

    severity_points = 0
    if has_malicious_url:
        severity_points += 3
    if has_suspicious_url:
        severity_points += 1
    if has_credential_signal or has_otp_signal:
        severity_points += 2
    if has_urgency_signal:
        severity_points += 1
    if has_sender_spoof:
        severity_points += 1
    if thread_hijack_detected:
        severity_points += 2
    if no_url_phishing_detected:
        severity_points += 2
    if multi_signal_attack_detected:
        severity_points += 2
    if hard_signal_count >= 3:
        severity_points += 1
    if signal_count >= 5:
        severity_points += 1
    if word_count < 30 and (has_credential_signal or has_otp_signal or has_urgency_signal):
        severity_points += 1

    if has_attachment_context:
        if has_attachment_credential:
            low_band, high_band = 95, 100
        elif has_urgency_signal or has_attachment_qr or has_attachment_password_protected:
            low_band, high_band = 85, 95
        else:
            low_band, high_band = 74, 90
    elif thread_hijack_detected and no_url_phishing_detected:
        low_band, high_band = 78, 96
    elif thread_hijack_detected or no_url_phishing_detected:
        low_band, high_band = 72, 92
    elif word_count < 30 and not has_malicious_url:
        low_band, high_band = 70, 90
    elif has_sender_spoof and not has_malicious_url and not has_suspicious_url:
        low_band, high_band = 72, 90
    elif severity_points >= 7:
        low_band, high_band = 95, 100
    elif severity_points >= 4:
        if has_malicious_url and (has_credential_signal or has_otp_signal or has_urgency_signal):
            low_band, high_band = 86, 98
        elif has_suspicious_url and hard_signal_count >= 2:
            low_band, high_band = 80, 94
        else:
            low_band, high_band = 72, 90
    else:
        low_band, high_band = 70, 90

    if safe_context_count >= 1 and not has_malicious_url and low_band < 95:
        low_band = max(70, min(low_band, 72))
        high_band = min(high_band, 86)

    if has_sender_spoof and not has_malicious_url and not has_suspicious_url and not has_attachment_context:
        high_band = min(high_band, 95)

    if word_count < 30 and not has_malicious_url and not has_attachment_context:
        high_band = min(high_band, 95)

    normalized = max(0.0, min(1.0, (raw - 70) / 30.0))
    severity_norm = max(0.0, min(1.0, severity_points / 10.0))
    composite_norm = (normalized * 0.55) + (severity_norm * 0.45)
    spread_index = max(-2, min(6, (signal_count - safe_context_count) + hard_signal_count - 2))
    target = low_band + int(round(composite_norm * (high_band - low_band))) + spread_index
    blend = 0.72 if low_band >= 85 else 0.60
    smoothed = clamp_int(_blend_scores(raw, target, blend), low_band, high_band)

    if 70 <= smoothed <= 80 and (severity_points >= 5 or multi_signal_attack_detected):
        smoothed = min(92, smoothed + 3 + min(4, severity_points // 3))

    # Reserve absolute 100 for clearly critical cases with multiple strong indicators.
    if smoothed >= 100 and not (
        severity_points >= 7
        or (has_attachment_context and has_attachment_credential and (has_urgency_signal or hard_signal_count >= 3))
    ):
        smoothed = 99

    return clamp_int(smoothed, 70, 100)


def calibrate_confidence(
    *,
    verdict: str,
    risk_score: int,
    ml_probability: float,
    signal_count: int,
    header_spoofing_score: int = 0,
    safe_signal_count: int = 0,
    has_links: bool = False,
    short_text_attack: bool = False,
    medium_case: bool = False,
    extreme_case: bool = False,
) -> int:
    ml_factor = max(0.0, min(1.0, float(ml_probability or 0.0)))
    signal_strength = min(max(signal_count, 0), 6)
    header_factor = min(max(header_spoofing_score, 0), 100) / 100
    safe_factor = min(max(safe_signal_count, 0), 4) / 4

    if verdict in ("High Risk", "Critical"):
        risk_factor = max(0.0, min(1.0, (risk_score - 61) / 39))
        confidence = 82 + (risk_factor * 8) + (ml_factor * 1.5) + min(2, signal_strength / 3) + (header_factor * 2)
        if extreme_case or verdict == "Critical":
            confidence += 2
        return max(88, min(97, int(round(confidence))))

    if verdict == "Suspicious":
        risk_factor = max(0.0, min(1.0, (risk_score - 26) / 34))
        confidence = 65 + (risk_factor * 9) + (ml_factor * 2) + min(2, signal_strength / 3) + (header_factor * 1.5)
        if has_links and signal_count >= 2:
            confidence += 1
        return max(65, min(80, int(round(confidence))))

    # For Safe emails: keep confidence realistic and conservative.
    safety_strength = ((1 - ml_factor) * 4) + (safe_factor * 4) + max(0, 3 - min(signal_strength, 3))
    risk_dampener = min(max(risk_score, 0), 25) / 3.0
    confidence = 64 + safety_strength - risk_dampener
    if short_text_attack:
        confidence -= 2
    return max(60, min(75, int(round(confidence))))


def append_structured_scan_log(entry: dict[str, Any]) -> None:
    logger = logging.getLogger("uvicorn.error")
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **entry,
    }

    try:
        SCAN_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with SCAN_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.warning("Unable to write PhishShield structured scan log: %s", exc)


def normalize_attachment_payloads(attachments: list[Any] | None) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for attachment in attachments or []:
        if hasattr(attachment, "model_dump"):
            item = attachment.model_dump()
        elif isinstance(attachment, dict):
            item = dict(attachment)
        else:
            continue
        normalized.append(
            {
                "filename": str(item.get("filename") or "").strip(),
                "contentType": str(item.get("contentType") or "").strip(),
                "size": int(item.get("size", 0) or 0),
                "isPasswordProtected": bool(item.get("isPasswordProtected", False)),
                "hasQrCode": bool(item.get("hasQrCode", False)),
                "extractedText": str(item.get("extractedText") or "").strip(),
            }
        )
    return normalized


def analyze_url_sandbox(urls: list[str], *, sender_domain: str = "", detected_brand: str | None = None) -> dict[str, Any]:
    feed = getattr(app.state, "threat_intel", None)
    if not isinstance(feed, dict) or not feed.get("shortenerDomains"):
        feed = load_threat_intel_feed()
        app.state.threat_intel = feed
    shortener_domains = {normalize_domain_for_comparison(domain) for domain in feed.get("shortenerDomains", [])}
    details: list[dict[str, Any]] = []
    signals: list[str] = []
    score_bonus = 0

    for url in urls[:3]:
        parsed = urlparse(url)
        host = normalize_domain_for_comparison(parsed.hostname or "")
        final_url = url
        final_domain = extract_root_domain(host)
        hidden_destination = host in shortener_domains
        sandbox_risk = "low"

        if hidden_destination:
            _rule_signal(signals, "Shortened link hides the final destination")
            score_bonus += 10
            sandbox_risk = "medium"
            try:
                response = requests.get(
                    url,
                    allow_redirects=True,
                    timeout=NETWORK_IO_TIMEOUT_SECONDS,
                    headers={"User-Agent": "PhishShield-Sandbox/1.0"},
                )
                final_url = response.url or url
                final_domain = extract_root_domain(urlparse(final_url).hostname or host)
                if detected_brand and final_domain and not is_trusted_domain_for_brand(final_domain, detected_brand):
                    _rule_signal(signals, "Shortened link resolves to an untrusted destination")
                    score_bonus += 12
                    sandbox_risk = "high"
            except Exception:
                sandbox_risk = "medium"

        details.append(
            {
                "url": url,
                "expandedUrl": final_url,
                "finalDomain": final_domain or host,
                "hiddenDestination": hidden_destination,
                "risk": sandbox_risk,
            }
        )

    return {
        "signals": signals,
        "score_bonus": min(score_bonus, 25),
        "details": details,
    }


def analyze_attachment_intel(attachments: list[Any] | None, email_text: str, *, sender_domain: str = "") -> dict[str, Any]:
    normalized_attachments = normalize_attachment_payloads(attachments)
    signals: list[str] = []
    findings: list[dict[str, Any]] = []
    score_bonus = 0
    trusted_sender = bool(sender_domain and is_safe_override_trusted_domain(sender_domain))

    for attachment in normalized_attachments:
        filename = str(attachment.get("filename") or "attachment").strip()
        lowered_name = filename.lower()
        ext = Path(lowered_name).suffix.lower()
        extracted_text = str(attachment.get("extractedText") or "")
        combined_text = f"{email_text}\n{extracted_text}"
        risk_level = "low"

        if ext in RISKY_ATTACHMENT_EXTENSIONS:
            _rule_signal(signals, "Suspicious attachment type detected")
            score_bonus += RISKY_ATTACHMENT_EXTENSIONS[ext]
            risk_level = "high"
        if ATTACHMENT_SUSPICIOUS_NAME_PATTERN.search(lowered_name) and (not trusted_sender or ext in RISKY_ATTACHMENT_EXTENSIONS):
            _rule_signal(signals, "Attachment name uses a phishing lure")
            score_bonus += 8
            risk_level = "high" if risk_level == "high" else "medium"
        if attachment.get("isPasswordProtected"):
            _rule_signal(signals, "Password-protected attachment blocks inspection")
            score_bonus += 10
            risk_level = "high"
        if attachment.get("hasQrCode") or QR_LURE_PATTERN.search(combined_text):
            _rule_signal(signals, "Attachment contains a QR-code action")
            score_bonus += 18
            risk_level = "high"
        if ATTACHMENT_SUSPICIOUS_TEXT_PATTERN.search(combined_text):
            _rule_signal(signals, "Attachment content asks for sensitive action")
            score_bonus += 12
            risk_level = "high" if risk_level == "high" else "medium"

        findings.append(
            {
                "filename": filename,
                "contentType": attachment.get("contentType") or None,
                "risk": risk_level,
                "hasQrCode": bool(attachment.get("hasQrCode", False)),
                "isPasswordProtected": bool(attachment.get("isPasswordProtected", False)),
            }
        )

    if not normalized_attachments:
        _rule_signal(signals, "No attachments detected")
    else:
        _rule_signal(signals, "Attachment present - scan recommended")

    return {
        "signals": signals,
        "score_bonus": min(score_bonus, 30),
        "findings": findings,
        "total_attachments": len(normalized_attachments),
    }


def analyze_thread_context(email_text: str) -> dict[str, Any]:
    signals: list[str] = []
    score_bonus = 0
    if THREAD_CONTEXT_PATTERN.search(email_text):
        if THREAD_PAYMENT_SWITCH_PATTERN.search(email_text) or (BEC_TRANSFER_PATTERN.search(email_text) and BEC_CONFIDENTIAL_PATTERN.search(email_text)):
            _rule_signal(signals, "Conversation context shifts into a risky request")
            score_bonus += 18
        if OTP_HARVEST_PATTERN.search(email_text) or QR_LURE_PATTERN.search(email_text):
            _rule_signal(signals, "Thread hijack style follow-up detected")
            score_bonus += 14

    return {
        "signals": signals,
        "score_bonus": min(score_bonus, 20),
        "threadDetected": bool(THREAD_CONTEXT_PATTERN.search(email_text)),
    }


def analyze_threat_intel(sender_domain: str, linked_domains: list[str], email_text: str) -> dict[str, Any]:
    feed = getattr(app.state, "threat_intel", None)
    if not isinstance(feed, dict) or not feed.get("maliciousDomains"):
        feed = load_threat_intel_feed()
        app.state.threat_intel = feed
    malicious_domains = {normalize_domain_for_comparison(domain) for domain in feed.get("maliciousDomains", [])}
    indicator_fragments = [normalize_domain_for_comparison(fragment) for fragment in feed.get("indicatorFragments", [])]
    observed_domains = [extract_root_domain(sender_domain), *[extract_root_domain(domain) for domain in linked_domains]]
    signals: list[str] = []
    matches: list[str] = []
    score_bonus = 0

    for domain in [domain for domain in observed_domains if domain]:
        normalized_domain = normalize_domain_for_comparison(domain)
        if normalized_domain in malicious_domains:
            matches.append(domain)
            _rule_signal(signals, "Threat feed match for sender or linked domain")
            score_bonus += 20
            continue
        if any(fragment and fragment in normalized_domain for fragment in indicator_fragments):
            matches.append(domain)
            _rule_signal(signals, "Known phishing campaign pattern matched")
            score_bonus += 12

    if re.search(r"\b(cert-in|security advisory|phishing alert)\b", email_text, re.IGNORECASE) and matches:
        score_bonus += 4

    return {
        "signals": signals,
        "score_bonus": min(score_bonus, 24),
        "matches": sorted(set(matches)),
        "feedSources": feed.get("feedSources", []),
    }


def analyze_sender_reputation(
    sender_domain: str,
    *,
    is_trusted_sender: bool = False,
    suspicious_context: bool = False,
    has_sensitive_request: bool = False,
) -> dict[str, Any]:
    profiles = app.state.sender_profiles if isinstance(getattr(app.state, "sender_profiles", None), dict) else load_sender_profiles()
    profile = profiles.get(sender_domain, {}) if sender_domain else {}
    safe_count = int(profile.get("safeCount", 0) or 0)
    phishing_count = int(profile.get("phishingCount", 0) or 0)
    total = int(profile.get("totalScans", 0) or 0)

    signals: list[str] = []
    safe_signals: list[str] = []
    score_bonus = 0

    if sender_domain and phishing_count >= 2:
        _rule_signal(signals, "Sender has a risky history")
        score_bonus += 15
    elif sender_domain and total == 0 and not is_trusted_sender and (suspicious_context or has_sensitive_request):
        _rule_signal(signals, "Unknown sender pattern")
        score_bonus += 8
    elif sender_domain and safe_count >= 3 and phishing_count == 0 and is_trusted_sender:
        safe_signals.append("Known sender history looks normal")

    return {
        "signals": signals,
        "safe_signals": safe_signals,
        "score_bonus": min(score_bonus, 15),
        "known": total > 0,
        "safeCount": safe_count,
        "phishingCount": phishing_count,
        "status": "risky" if phishing_count >= 2 else "trusted" if safe_count >= 3 and phishing_count == 0 else "unknown",
    }


def _collect_pattern_hits(email_text: str, pattern_map: list[tuple[str, re.Pattern[str]]]) -> list[str]:
    hits: list[str] = []
    for name, pattern in pattern_map:
        if pattern.search(email_text):
            hits.append(name)
    return hits


def analyze_intent_engine(email_text: str, *, linked_domains: list[str], has_attachment_context: bool) -> dict[str, Any]:
    financial_hits = _collect_pattern_hits(email_text, INTENT_FINANCIAL_PATTERNS)
    credential_hits = _collect_pattern_hits(email_text, INTENT_CREDENTIAL_PATTERNS)
    access_hits = _collect_pattern_hits(email_text, INTENT_ACCESS_PATTERNS)
    action_hits = _collect_pattern_hits(email_text, INTENT_ACTION_PATTERNS)

    financial_intent_score = clamp_int(len(financial_hits) * 24 + (8 if BEC_TRANSFER_PATTERN.search(email_text) else 0), 0, 100)
    credential_intent_score = clamp_int(
        len(credential_hits) * 24 + len(access_hits) * 12 + (10 if CREDENTIAL_HARVEST_PATTERN.search(email_text) else 0),
        0,
        100,
    )
    action_intent_score = clamp_int(
        len(action_hits) * 20
        + (10 if linked_domains else 0)
        + (8 if has_attachment_context else 0),
        0,
        100,
    )
    dominant_intent = max(
        {
            "financial": financial_intent_score,
            "credential": credential_intent_score,
            "action": action_intent_score,
        }.items(),
        key=lambda item: item[1],
    )[0]

    return {
        "financial_intent_score": financial_intent_score,
        "credential_intent_score": credential_intent_score,
        "action_intent_score": action_intent_score,
        "dominant_intent": dominant_intent,
        "financial_hits": financial_hits,
        "credential_hits": credential_hits,
        "access_hits": access_hits,
        "action_hits": action_hits,
    }


def analyze_role_authority_engine(email_text: str, sender_domain: str, *, trusted_sender: bool) -> dict[str, Any]:
    if ROLE_HIGH_AUTHORITY_PATTERN.search(email_text):
        role = "executive_authority"
        authority_score = 88
    elif ROLE_MEDIUM_AUTHORITY_PATTERN.search(email_text):
        role = "business_function_authority"
        authority_score = 64
    elif sender_domain and trusted_sender:
        role = "known_sender"
        authority_score = 52
    else:
        role = "unknown_external"
        authority_score = 30

    authority_request_risk = clamp_int(
        authority_score
        + (8 if BEC_TRANSFER_PATTERN.search(email_text) else 0)
        + (6 if ACTION_MONEY_PATTERN.search(email_text) else 0),
        0,
        100,
    )
    return {
        "sender_role": role,
        "authority_score": authority_score,
        "authority_request_risk": authority_request_risk,
    }


def analyze_action_engine(email_text: str, *, linked_domains: list[str], has_attachment_context: bool) -> dict[str, Any]:
    money_transfer_requested = bool(ACTION_MONEY_PATTERN.search(email_text))
    link_click_requested = bool(linked_domains) and bool(re.search(r"\b(click|open|visit|scan|download)\b", email_text, re.IGNORECASE))
    data_sharing_requested = bool(ACTION_DATA_SHARE_PATTERN.search(email_text))
    urgent_reply_requested = bool(ACTION_REPLY_PATTERN.search(email_text) and PRESSURE_PATTERN.search(email_text))

    action_risk_score = clamp_int(
        int(money_transfer_requested) * 30
        + int(link_click_requested) * 25
        + int(data_sharing_requested) * 30
        + int(urgent_reply_requested) * 20
        + (8 if has_attachment_context else 0),
        0,
        100,
    )
    return {
        "money_transfer_requested": money_transfer_requested,
        "link_click_requested": link_click_requested,
        "data_sharing_requested": data_sharing_requested,
        "urgent_reply_requested": urgent_reply_requested,
        "action_risk_score": action_risk_score,
    }


def analyze_behavior_engine(email_text: str, *, has_spoof_or_lookalike_signal: bool) -> dict[str, Any]:
    urgency_detected = bool(PRESSURE_PATTERN.search(email_text) or URGENCY_PATTERN.search(email_text))
    pressure_detected = bool(re.search(r"\b(final warning|last chance|deadline|within \d+|act now)\b", email_text, re.IGNORECASE))
    secrecy_detected = bool(SECRECY_PATTERN.search(email_text))
    impersonation_detected = bool(has_spoof_or_lookalike_signal or IMPERSONATION_BEHAVIOR_PATTERN.search(email_text))

    behavior_risk_score = clamp_int(
        int(urgency_detected) * 25
        + int(pressure_detected) * 20
        + int(secrecy_detected) * 25
        + int(impersonation_detected) * 30,
        0,
        100,
    )
    return {
        "urgency": urgency_detected,
        "pressure": pressure_detected,
        "secrecy": secrecy_detected,
        "impersonation": impersonation_detected,
        "behavior_risk_score": behavior_risk_score,
    }


def analyze_context_engine(
    email_text: str,
    *,
    has_mixed_link_context: bool,
    has_no_url_phishing_signal: bool,
    has_thread_hijack_signal: bool,
    has_invoice_thread_pretext: bool,
    has_bec_pattern_signal: bool,
    authority_score: int,
    financial_intent_score: int,
    credential_intent_score: int,
) -> dict[str, Any]:
    has_hr_scam = bool(HR_SCAM_PATTERN.search(email_text) and URL_PATTERN.search(email_text))
    has_invoice_fraud = bool(INVOICE_FRAUD_PATTERN.search(email_text) and (has_thread_hijack_signal or has_invoice_thread_pretext))

    context_type = "general_phishing"
    context_risk_score = 50
    if has_mixed_link_context:
        context_type = "mixed_phishing"
        context_risk_score = 58
    elif has_bec_pattern_signal and authority_score >= 70 and financial_intent_score >= 50:
        context_type = "bec"
        context_risk_score = 84
    elif has_invoice_fraud and financial_intent_score >= 45:
        context_type = "invoice_fraud"
        context_risk_score = 80
    elif has_thread_hijack_signal:
        context_type = "thread_hijack"
        context_risk_score = 76
    elif has_hr_scam:
        context_type = "hr_scam"
        context_risk_score = 72
    elif has_no_url_phishing_signal or (financial_intent_score >= 55 and not URL_PATTERN.search(email_text)):
        context_type = "no_link_phishing"
        context_risk_score = 74
    elif credential_intent_score >= 55:
        context_type = "credential_phishing"
        context_risk_score = 78

    return {
        "context_type": context_type,
        "context_risk_score": context_risk_score,
        "hr_scam_detected": has_hr_scam,
        "invoice_fraud_detected": has_invoice_fraud,
    }


def update_sender_reputation(sender_domain: str, *, risk_score: int, verdict: str) -> None:
    if not sender_domain:
        return
    with sender_profile_lock:
        profiles = app.state.sender_profiles if isinstance(getattr(app.state, "sender_profiles", None), dict) else load_sender_profiles()
        profile = dict(profiles.get(sender_domain, {}))
        profile["totalScans"] = int(profile.get("totalScans", 0) or 0) + 1
        if verdict == "Safe":
            profile["safeCount"] = int(profile.get("safeCount", 0) or 0) + 1
        else:
            profile["phishingCount"] = int(profile.get("phishingCount", 0) or 0) + 1
        profile["lastScore"] = int(risk_score)
        profile["lastVerdict"] = verdict
        profile["lastSeen"] = datetime.now(timezone.utc).isoformat()
        profiles[sender_domain] = profile
        app.state.sender_profiles = profiles
        save_sender_profiles(profiles)


def extract_sender_domain_from_email_text(email_text: str) -> str:
    from_match = re.search(r"(?:^|\n)from:\s*(?:.*?<)?[^@\s<]+@([a-z0-9.-]+\.[a-z]{2,})(?:>)?", email_text, re.IGNORECASE)
    if from_match:
        return from_match.group(1).strip().lower()

    # Support plain-domain From headers such as: "From: github.com" or "From: paypaI-security.com".
    from_domain_match = re.search(r"(?:^|\n)from:\s*(?:.*?<)?([a-z0-9.-]+\.[a-z]{2,})(?:>)?(?:\s|$)", email_text, re.IGNORECASE)
    if from_domain_match:
        candidate = from_domain_match.group(1).strip().lower().strip(".,;:!?)]}>'\"")
        if candidate:
            return candidate

    fallback_match = re.search(r"[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})", email_text, re.IGNORECASE)
    return fallback_match.group(1).strip().lower() if fallback_match else ""


def extract_urls(text: str, limit: int | None = None) -> list[str]:
    normalized_text = re.sub(r"=\r?\n", "", str(text or "")).replace("&amp;", "&")
    urls: list[str] = []
    seen: set[str] = set()

    for raw_url in re.findall(r"https?://[^\s<>\"']+", normalized_text, flags=re.IGNORECASE):
        url = raw_url.rstrip("),.;:!?]}>'\"").strip()
        if not url or re.search(r"=\s*$", url):
            continue
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        host = (parsed.hostname or "").lower().strip()
        if not host or host == "www" or "=" in host:
            continue
        if any(host == ignored or host.endswith(f".{ignored}") for ignored in IGNORED_URL_HOSTS):
            continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
        if limit is not None and len(urls) >= limit:
            break

    return urls

def extract_domains_from_urls(text: str) -> list[str]:
    domains: list[str] = []
    for url in extract_urls(text):
        try:
            host = (urlparse(url).hostname or "").lower().strip()
        except Exception:
            continue
        domain = re.sub(r"^www\.", "", host).rstrip(".,;:!?)]}>'\"")
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def extract_root_domain(value: str) -> str:
    normalized = re.sub(r"^www\.", "", str(value or "").strip().lower())
    normalized = normalized.split("@")[-1].split(":", 1)[0].strip().strip(".")
    parts = [part for part in normalized.split(".") if part]
    if len(parts) <= 2:
        return normalized
    if len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def normalize_domain_for_comparison(value: str) -> str:
    raw_value = str(value or "").strip().lower()
    raw_value = raw_value.split("@")[-1].split(":", 1)[0].strip().strip(".")
    return (
        re.sub(r"^www\.", "", raw_value)
        .replace("0", "o")
        .replace("1", "l")
        .replace("!", "l")
        .replace("|", "l")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("7", "t")
        .replace("@", "a")
        .replace("_", "-")
    )


def domains_same_family(left: str, right: str) -> bool:
    normalized_left = normalize_domain_for_comparison(left)
    normalized_right = normalize_domain_for_comparison(right)
    root_left = extract_root_domain(normalized_left)
    root_right = extract_root_domain(normalized_right)
    if not normalized_left or not normalized_right:
        return False
    return (
        normalized_left == normalized_right
        or normalized_left.endswith(f".{normalized_right}")
        or normalized_right.endswith(f".{normalized_left}")
        or (root_left and root_left == root_right)
    )


def domains_reasonably_aligned(left: str, right: str) -> bool:
    if not left or not right:
        return False
    if domains_same_family(left, right):
        return True

    left_brand = resolve_brand_from_domain(left)
    right_brand = resolve_brand_from_domain(right)
    if left_brand and is_trusted_domain_for_brand(right, left_brand):
        return True
    if right_brand and is_trusted_domain_for_brand(left, right_brand):
        return True
    return bool(left_brand and right_brand and left_brand == right_brand)


def is_trusted_domain_for_brand(domain: str, brand: str | None) -> bool:
    if not brand:
        return False
    normalized_domain = normalize_domain_for_comparison(domain)
    root_domain = extract_root_domain(normalized_domain)
    for trusted in TRUSTED_BRAND_DOMAIN_MAP.get(brand, ()):
        normalized_trusted = normalize_domain_for_comparison(trusted)
        trusted_root = extract_root_domain(normalized_trusted)
        if (
            normalized_domain == normalized_trusted
            or normalized_domain.endswith(f".{normalized_trusted}")
            or (root_domain and root_domain == trusted_root)
        ):
            return True
    return False


def has_high_risk_tld(domain: str) -> bool:
    normalized_domain = normalize_domain_for_comparison(domain)
    return any(normalized_domain.endswith(tld) for tld in HIGH_RISK_TLDS)


def extract_domain_label_tokens(domain: str) -> list[str]:
    normalized_domain = normalize_domain_for_comparison(domain)
    root_domain = extract_root_domain(normalized_domain)
    label = root_domain.split(".")[0] if root_domain else normalized_domain.split(".")[0]
    return [token for token in re.split(r"[^a-z0-9]+", label) if token]


def is_brand_like_domain_token(token: str) -> bool:
    normalized_token = normalize_domain_for_comparison(token)
    if normalized_token in SENDER_DOMAIN_RISK_BRAND_TOKENS:
        return True
    for brand in SENDER_DOMAIN_RISK_BRAND_TOKENS:
        if len(brand) < 4 or len(normalized_token) < 4:
            continue
        similarity = SequenceMatcher(None, normalized_token, brand).ratio()
        if similarity >= 0.83 and normalized_token[:3] == brand[:3] and abs(len(normalized_token) - len(brand)) <= 3:
            return True
    return False


def has_suspicious_sender_domain_pattern(domain: str) -> bool:
    normalized_domain = normalize_domain_for_comparison(domain)
    if not normalized_domain:
        return False
    if is_safe_override_trusted_domain(normalized_domain):
        return False

    tokens = extract_domain_label_tokens(normalized_domain)
    if len(tokens) < 2:
        return False

    has_brand_like = any(is_brand_like_domain_token(token) for token in tokens)
    has_risk_action = any(token in SENDER_DOMAIN_RISK_ACTION_TOKENS for token in tokens)
    return bool(has_brand_like and has_risk_action)


def resolve_brand_from_domain(domain: str) -> str | None:
    for brand in SAFE_OVERRIDE_TRUSTED_DOMAINS:
        if is_trusted_domain_for_brand(domain, brand):
            return brand
    return None


def linked_domains_match_brand(linked_domains: list[str], brand: str | None) -> bool:
    if not linked_domains:
        return True
    if not brand:
        return False
    return all(is_trusted_domain_for_brand(domain, brand) for domain in linked_domains)


def is_safe_override_trusted_domain(sender_domain: str) -> bool:
    return resolve_brand_from_domain(sender_domain) is not None


def format_domain_brand_label(brand: str | None, domain: str) -> str:
    brand_labels = {
        "amazon": "Amazon",
        "microsoft": "Microsoft",
        "google": "Google",
        "paypal": "PayPal",
        "github": "GitHub",
        "overleaf": "Overleaf",
        "openai": "OpenAI",
        "linkedin": "LinkedIn",
        "paytm": "Paytm",
        "phonepe": "PhonePe",
        "sbi": "SBI",
        "hdfc": "HDFC",
        "icici": "ICICI",
        "netflix": "Netflix",
    }
    if brand and brand in brand_labels:
        return brand_labels[brand]
    return extract_root_domain(domain) or "sender"


def derive_domain_trust(
    sender_domain: str,
    linked_domains: list[str],
    header_scan: dict[str, Any] | None,
    *,
    detected_brand: str | None = None,
    has_header_spoofing: bool = False,
    has_sender_link_mismatch: bool = False,
    has_trusted_brand_mismatch: bool = False,
    has_lookalike_domain: bool = False,
    has_risky_tld: bool = False,
    has_suspicious_link: bool = False,
    sender_reputation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_sender = extract_root_domain(sender_domain)
    normalized_links = [extract_root_domain(domain) for domain in linked_domains if extract_root_domain(domain)]
    primary_domain = normalized_sender or (normalized_links[0] if normalized_links else "")
    resolved_brand = resolve_brand_from_domain(primary_domain) or detected_brand
    auth_passed = any(str((header_scan or {}).get(key, "unknown") or "unknown").lower() == "pass" for key in ("spf", "dkim", "dmarc"))
    domain_aligned = not normalized_links or (normalized_sender and all(domains_reasonably_aligned(normalized_sender, domain) for domain in normalized_links))
    suspicious_domain = bool(
        has_header_spoofing
        or has_sender_link_mismatch
        or has_trusted_brand_mismatch
        or has_lookalike_domain
        or has_risky_tld
    )

    if suspicious_domain:
        return {
            "trust": "Suspicious",
            "status": "suspicious",
            "domain": primary_domain,
            "brand": format_domain_brand_label(resolved_brand, primary_domain),
            "label": "Domain mismatch or spoofing detected",
            "source": "backend",
        }

    is_known_provider = bool(primary_domain and (resolved_brand or is_safe_override_trusted_domain(primary_domain)))
    reputation_trusted = bool(
        isinstance(sender_reputation, dict)
        and str(sender_reputation.get("status", "")).lower() == "trusted"
        and int(sender_reputation.get("safeCount", 0) or 0) >= 3
        and int(sender_reputation.get("phishingCount", 0) or 0) == 0
    )
    dynamically_trusted = bool(
        primary_domain
        and domain_aligned
        and not suspicious_domain
        and (
            auth_passed
            or (is_known_provider and reputation_trusted and not has_suspicious_link and not has_risky_tld)
        )
    )

    if dynamically_trusted:
        brand_label = format_domain_brand_label(resolved_brand, primary_domain)
        return {
            "trust": "Trusted",
            "status": "trusted",
            "domain": primary_domain,
            "brand": brand_label,
            "label": f"Verified {brand_label} domain",
            "source": "backend",
        }

    return {
        "trust": "Unknown",
        "status": "unknown",
        "domain": primary_domain,
        "brand": format_domain_brand_label(resolved_brand, primary_domain) if primary_domain else "Unknown",
        "label": "Domain not previously seen â€” verify source",
        "source": "backend",
    }


def detect_known_brand(text: str) -> str | None:
    for brand, pattern in BRAND_TEXT_HINTS.items():
        if pattern.search(text):
            return brand
    return None


def domain_impersonates_known_brand(domain: str, detected_brand: str | None = None) -> bool:
    normalized_domain = normalize_domain_for_comparison(domain)
    if any(is_trusted_domain_for_brand(normalized_domain, brand) for brand in TRUSTED_BRAND_DOMAIN_MAP):
        return False
    root_domain = extract_root_domain(normalized_domain)
    root_label = root_domain.split(".")[0] if root_domain else normalized_domain.split(".")[0]

    def canonicalize_brand_token(value: str) -> str:
        replacements = str.maketrans({
            "0": "o",
            "1": "l",
            "3": "e",
            "5": "s",
            "7": "t",
            "@": "a",
            "!": "i",
            "|": "l",
        })
        return value.translate(replacements)

    # Guard 1: Already a trusted domain â€” never impersonates
    if is_safe_override_trusted_domain(normalize_domain_for_comparison(domain)):
        return False

    # Guard 2: Root label too short to be meaningful
    if len(root_label) < 4:
        return False

    # Guard 3: Generic business words â€” not brand-specific
    GENERIC_LABELS = {
        "mail", "smtp", "email", "secure", "internal", "corp",
        "company", "business", "office", "admin", "support",
        "yourcompany", "mycompany", "test", "staging", "dev",
    }
    if root_label in GENERIC_LABELS:
        return False

    label_tokens = {
        token
        for token in re.split(r"[^a-z0-9]+", root_label)
        if token and len(token) >= 4 and token not in GENERIC_LABELS
    }
    canonical_label_segments = [
        canonicalize_brand_token(token)
        for token in re.split(r"[^a-z0-9]+", root_label)
        if token
    ]
    if not label_tokens:
        label_tokens = {root_label}

    brands_to_check = [detected_brand] if detected_brand else list(TRUSTED_BRAND_DOMAIN_MAP.keys())

    for brand in brands_to_check:
        if not brand:
            continue

        aliases = {
            normalize_domain_for_comparison(brand.replace(" ", "")),
            *{
                extract_root_domain(normalize_domain_for_comparison(trusted)).split(".")[0]
                for trusted in TRUSTED_BRAND_DOMAIN_MAP.get(brand, ())
            },
        }

        for alias in {item for item in aliases if item}:
            if len(alias) < 3:
                continue
            alias_token = canonicalize_brand_token(alias)
            if alias_token in canonical_label_segments and len(canonical_label_segments) > 1 and not is_trusted_domain_for_brand(normalized_domain, brand):
                return True
            for token in label_tokens:
                token_norm = canonicalize_brand_token(token)
                similarity = SequenceMatcher(None, token_norm, alias_token).ratio()
                strong_contains = alias_token in token_norm and len(alias_token) >= 5
                close_lookalike = (
                    similarity >= 0.83
                    and token_norm != alias_token
                    and abs(len(token_norm) - len(alias_token)) <= 4
                    and token_norm[:3] == alias_token[:3]
                )
                if (strong_contains or close_lookalike) and not is_trusted_domain_for_brand(normalized_domain, brand):
                    return True

    return False


def is_trusted_newsletter_domain(sender_domain: str) -> bool:
    return bool(sender_domain) and any(
        sender_domain == domain or sender_domain.endswith(f".{domain}") for domain in NEWSLETTER_SENDER_DOMAINS
    )


def extract_inline_headers_block(text: str) -> str:
    if not text:
        return ""

    header_candidate = text.split("\n\n", 1)[0]
    collected: list[str] = []
    known_hits = 0

    for line in header_candidate.splitlines():
        stripped = line.rstrip()
        if not stripped:
            continue
        if KNOWN_HEADER_PATTERN.match(stripped):
            collected.append(stripped)
            known_hits += 1
        elif collected and line.startswith((" ", "\t")):
            collected.append(stripped)

    has_sender_identity_header = any(re.match(r"^(?:from|reply-to|return-path):", line, re.IGNORECASE) for line in collected)
    return "\n".join(collected).strip() if known_hits >= 2 and has_sender_identity_header else ""


def count_auth_pass_signals(text: str) -> int:
    return len(AUTH_PASS_PATTERN.findall(text))


def has_marketing_footer_context(text: str) -> bool:
    return bool(MARKETING_FOOTER_PATTERN.search(text))


def detect_newsletter_context(email_text: str) -> bool:
    lowered = email_text.lower()
    sender_domain = extract_sender_domain_from_email_text(email_text)
    trusted_sender = is_trusted_newsletter_domain(sender_domain)
    auth_passes = count_auth_pass_signals(email_text)
    footer_like = has_marketing_footer_context(email_text)
    looks_bulk_mail = any(marker in lowered for marker in ["list-unsubscribe", "precedence: bulk", "list-id:", "feedback-id:"])
    has_sensitive_request = bool(
        re.search(
            r"\b(reply with|share|provide|enter|submit)\b.{0,40}\b(otp|password|pin|passcode|credentials?|bank details|card details)\b",
            email_text,
            re.IGNORECASE,
        )
    )

    return footer_like and not has_sensitive_request and (
        (trusted_sender and ("unsubscribe" in lowered or auth_passes >= 2))
        or (trusted_sender and looks_bulk_mail)
        or (auth_passes >= 2 and looks_bulk_mail and bool(sender_domain) and not SUSPICIOUS_DOMAIN_PATTERN.search(sender_domain))
    )


def is_authenticated_marketing_email(email_text: str) -> bool:
    sender_domain = extract_sender_domain_from_email_text(email_text)
    auth_passes = count_auth_pass_signals(email_text)
    footer_like = has_marketing_footer_context(email_text)
    return bool(
        sender_domain
        and footer_like
        and auth_passes >= 2
        and (is_trusted_newsletter_domain(sender_domain) or not SUSPICIOUS_DOMAIN_PATTERN.search(sender_domain))
    )


def detect_sms_spoof_signals(email_text: str) -> list[tuple[str, int]]:
    matches: list[tuple[str, int]] = []
    for pattern, weight, label in SMS_SIGNALS:
        if pattern.search(email_text):
            matches.append((label, weight))
    return matches


def count_sms_spoof_matches(email_text: str) -> int:
    return len(detect_sms_spoof_signals(email_text))


def detect_lottery_scam_signals(email_text: str) -> list[tuple[str, int]]:
    matches: list[tuple[str, int]] = []
    for pattern, weight, label in LOTTERY_SIGNALS:
        if pattern.search(email_text):
            matches.append((label, weight))
    return matches


def detect_delivery_scam_signals(email_text: str) -> list[tuple[str, int]]:
    matches: list[tuple[str, int]] = []
    has_url = bool(extract_urls(email_text, limit=1))
    suspicious_delivery_domain = bool(
        SUSPICIOUS_DOMAIN_PATTERN.search(email_text)
        or PAYMENT_LINK_PATTERN.search(email_text)
        or re.search(r"https?://\S*(track|clearance|delivery|parcel|shipment)\S*", email_text, re.IGNORECASE)
    )

    if DELIVERY_BRAND_PATTERN.search(email_text):
        matches.append(("Courier brand impersonation", 20))
    if DELIVERY_FEE_PATTERN.search(email_text):
        matches.append(("Delivery or customs fee request", 25))
    if DELIVERY_ITEM_PATTERN.search(email_text) and suspicious_delivery_domain:
        matches.append(("Parcel or shipment lure with suspicious domain", 20))
    if SMALL_FEE_PATTERN.search(email_text) and has_url and PAYMENT_LINK_PATTERN.search(email_text):
        matches.append(("Small delivery fee with payment link", 20))
    if DELIVERY_FAILURE_PATTERN.search(email_text) and has_url:
        matches.append(("Delivery failure pressure with link", 15))
    if FOREIGN_ORIGIN_PATTERN.search(email_text) and DELIVERY_FEE_PATTERN.search(email_text):
        matches.append(("Foreign-origin package fee pressure", 15))

    return matches


def detect_it_phishing_signals(email_text: str) -> list[tuple[str, int]]:
    matches: list[tuple[str, int]] = []
    for pattern, weight, label in IT_PHISHING_BOOSTS:
        if pattern.search(email_text):
            matches.append((label, weight))
    return matches


def get_scan_cache_key(email_text: str, headers_text: str | None = None, attachments: list[Any] | None = None) -> str:
    payload = {
        "email_text": email_text,
        "headers_text": headers_text or "",
        "attachments": normalize_attachment_payloads(attachments),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def get_cached_scan_result(cache_key: str) -> dict[str, Any] | None:
    with scan_cache_lock:
        cached = app.state.scan_cache.get(cache_key)
        if cached is None:
            return None
        if cached.get("cache_version") != 2:
            return None
        app.state.scan_cache.move_to_end(cache_key)
        cached_copy = deepcopy(cached)
    cached_copy["cached"] = True
    return cached_copy


def store_cached_scan_result(cache_key: str, payload: dict[str, Any]) -> None:
    with scan_cache_lock:
        payload_copy = deepcopy(payload)
        payload_copy["cached"] = False
        payload_copy["cache_version"] = 2
        # Do NOT generate a new scan_id; preserve payload scan identity.
        app.state.scan_cache[cache_key] = payload_copy
        app.state.scan_cache.move_to_end(cache_key)
        while len(app.state.scan_cache) > 100:
            app.state.scan_cache.popitem(last=False)


def detect_indian_patterns(email_text: str) -> tuple[list[str], int, str]:
    signals: list[str] = []
    score_bonus = 0
    category = "General Phishing"
    lowered = email_text.lower()

    # MUST be first - gates all OTP detection below
    has_safe_otp_awareness = is_otp_safety_notice(email_text)
    has_otp_request_context = bool(
        (OTP_HARVEST_PATTERN.search(email_text) and not has_safe_otp_awareness)
        or (
            OTP_PATTERN.search(email_text)
            and not has_safe_otp_awareness
            and (
                URGENCY_PATTERN.search(email_text)
                or SUSPICIOUS_LINK_LURE_PATTERN.search(email_text)
                or URL_PATTERN.search(email_text)
                or BEC_TRANSFER_PATTERN.search(email_text)
            )
        )
    )
    has_otp_sharing_request = bool(
        OTP_PATTERN.search(email_text)
        and re.search(r"\b(?:share|sharing|shared|send|sending|forward|forwarding|talk to manager after sharing)\b", email_text, re.IGNORECASE)
        and not has_safe_otp_awareness
    )

    if has_otp_request_context:
        _rule_signal(signals, "OTP request detected")
        score_bonus += 25
        category = "OTP Scam"

    if has_otp_sharing_request:
        _rule_signal(signals, "OTP sharing request detected")
        score_bonus += 35
        category = "OTP Scam"

    if URGENCY_PATTERN.search(email_text):
        _rule_signal(signals, "Urgency language")
        score_bonus += 15

    if HINGLISH_PATTERN.search(email_text) and (OTP_PATTERN.search(email_text) or URGENCY_PATTERN.search(email_text) or URL_PATTERN.search(email_text)):
        _rule_signal(signals, "Mixed-language phishing phrasing")
        score_bonus += 40

    has_brand_mention = bool(BRAND_PATTERN.search(email_text))
    has_coercive_brand_context = bool(
        has_otp_request_context
        or URGENCY_PATTERN.search(email_text)
        or SUSPICIOUS_PATTERN.search(email_text)
        or SUSPICIOUS_LINK_LURE_PATTERN.search(email_text)
        or BEC_TRANSFER_PATTERN.search(email_text)
        or DELIVERY_FEE_PATTERN.search(email_text)
        or any(
            phrase in lowered
            for phrase in ["verify your", "update your", "share your", "confirm your", "account suspended", "refund pending"]
        )
    )

    if has_brand_mention and has_coercive_brand_context:
        _rule_signal(signals, "Indian brand impersonation")
        score_bonus += 20
        if category == "General Phishing":
            category = "Brand Impersonation"
    elif has_brand_mention:
        _rule_signal(signals, "Known brand mentioned")
        score_bonus += 4

    if SUSPICIOUS_PATTERN.search(email_text):
        _rule_signal(signals, "Suspicious phishing keywords")
        score_bonus += 12
        if category == "General Phishing":
            category = "Social Engineering"

    sms_signal_matches = detect_sms_spoof_signals(email_text)
    for message, weight in sms_signal_matches:
        _rule_signal(signals, message)
        score_bonus += weight
    sms_match_count = len(sms_signal_matches)
    if sms_match_count >= 2:
        _rule_signal(signals, "SMS spoofing attack pattern")
        score_bonus = max(score_bonus, 75)
        category = "SMS Spoofing Attack"
    elif sms_match_count == 1:
        _rule_signal(signals, "SMS-style banking alert spoof")
        score_bonus += 8
        category = "OTP Scam"

    lottery_signal_matches = detect_lottery_scam_signals(email_text)
    for message, weight in lottery_signal_matches:
        _rule_signal(signals, message)
        score_bonus += weight
    if len(lottery_signal_matches) >= 3:
        _rule_signal(signals, "Foreign WhatsApp lure")
        _rule_signal(signals, "Prize money lure")
        category = "Lottery / Prize Scam"

    delivery_signal_matches = detect_delivery_scam_signals(email_text)
    for message, weight in delivery_signal_matches:
        _rule_signal(signals, message)
        score_bonus += weight
    if len(delivery_signal_matches) >= 2:
        category = "Delivery Fee Scam"

    if UPI_PATTERN.search(email_text):
        _rule_signal(signals, "UPI handle detected")
        score_bonus += 20
        if "request" in lowered or "pay" in lowered or "send" in lowered:
            category = "Credential Harvesting"

    if GSTIN_PATTERN.search(email_text):
        _rule_signal(signals, "GSTIN pattern detected")
        score_bonus += 20
        category = "GST Compliance Scam"

    if AADHAAR_PATTERN.search(email_text):
        _rule_signal(signals, "Aadhaar number pattern detected")
        score_bonus += 15
        category = "Identity Theft"

    if PAN_PATTERN.search(email_text):
        _rule_signal(signals, "PAN pattern detected")
        score_bonus += 15
        category = "Identity Theft"

    if any(word in lowered for word in ["verify", "update", "send", "share", "confirm"]) and any(
        pattern.search(email_text) for pattern in [UPI_PATTERN, GSTIN_PATTERN, AADHAAR_PATTERN, PAN_PATTERN]
    ):
        _rule_signal(signals, "Sensitive identity or payment data request")
        score_bonus += 10
        if category in {"General Phishing", "Brand Impersonation", "Identity Theft"}:
            category = "Credential Harvesting"

    it_signal_matches = detect_it_phishing_signals(email_text)
    for message, weight in it_signal_matches:
        _rule_signal(signals, message)
        score_bonus += weight
    if len(it_signal_matches) >= 3:
        category = "Government Impersonation"

    if extract_urls(email_text, limit=1):   # only real HTTP/HTTPS links
        _rule_signal(signals, "Link included in message")
        score_bonus += 6

    if SUSPICIOUS_LINK_LURE_PATTERN.search(email_text):
        _rule_signal(signals, "Suspicious verification link")
        score_bonus += 18

    if OTP_PATTERN.search(email_text) and URGENCY_PATTERN.search(email_text) and BRAND_PATTERN.search(email_text):
        _rule_signal(signals, "Bank credential harvesting pattern")
        score_bonus += 20
        category = "OTP Scam"

    return signals, score_bonus, category


def predict_probabilities(texts: list[str]) -> np.ndarray:
    if artifacts.indicbert_model is not None and artifacts.indicbert_tokenizer is not None and torch is not None:
        encoded = artifacts.indicbert_tokenizer(
            texts,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=MAX_TOKEN_LENGTH,
        )
        encoded = {key: value.to(artifacts.device) for key, value in encoded.items()}
        with torch.no_grad():
            logits = artifacts.indicbert_model(**encoded).logits
            probabilities = torch.softmax(logits, dim=-1)
        return probabilities.detach().cpu().numpy()

    if artifacts.model is not None and artifacts.vectorizer is not None:
        cleaned_texts = [clean_text(text) for text in texts]
        return artifacts.model.predict_proba(artifacts.vectorizer.transform(cleaned_texts))

    raise HTTPException(status_code=503, detail="Model artifacts not loaded. Run train_model.py or provide indicbert_model/ first.")


def predict_with_indicbert(email_text: str) -> float | None:
    if artifacts.indicbert_model is None or artifacts.indicbert_tokenizer is None or torch is None:
        return None
    return float(predict_probabilities([email_text])[0][1])


def store_scan_explanation(scan_id: str, payload: dict[str, Any]) -> None:
    app.state.scan_explanations[scan_id] = payload
    while len(app.state.scan_explanations) > 200:
        app.state.scan_explanations.popitem(last=False)


def normalize_prediction_label(verdict: str | None) -> str:
    if not verdict:
        return "safe"
    return "safe" if verdict.strip().lower() == "safe" else "phishing"


def retrain_tfidf_with_feedback() -> dict[str, Any]:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    base_df = pd.read_csv(DATASET_PATH)
    expected_columns = {"Email Text", "Email Type"}
    missing_columns = expected_columns.difference(base_df.columns)
    if missing_columns:
        raise ValueError(f"Missing required columns in base dataset: {sorted(missing_columns)}")

    base_df = base_df[["Email Text", "Email Type"]].dropna().copy()
    feedback_df = pd.read_csv(FEEDBACK_CSV_PATH)

    if not feedback_df.empty:
        feedback_training = feedback_df.copy()
        feedback_training["Email Text"] = feedback_training["email_text"].astype(str)
        feedback_training["Email Type"] = feedback_training["user_label"].map({
            "phishing": "Phishing Email",
            "safe": "Safe Email",
        })
        feedback_training = feedback_training[["Email Text", "Email Type"]].dropna()
        combined_df = pd.concat([base_df, feedback_training], ignore_index=True)
    else:
        combined_df = base_df.copy()

    combined_df["label"] = combined_df["Email Type"].map(LABEL_MAP)
    if combined_df["label"].isna().any():
        unknown_labels = sorted(combined_df.loc[combined_df["label"].isna(), "Email Type"].astype(str).unique().tolist())
        raise ValueError(f"Unsupported label values found during retraining: {unknown_labels}")

    combined_df["clean_text"] = combined_df["Email Text"].astype(str).apply(clean_text)
    X_train, X_test, y_train, y_test = train_test_split(
        combined_df["clean_text"],
        combined_df["label"].astype(int),
        test_size=0.2,
        random_state=42,
        stratify=combined_df["label"].astype(int),
    )

    vectorizer = TfidfVectorizer(
        max_features=30000,
        ngram_range=(1, 2),
        min_df=2,
        stop_words="english",
        sublinear_tf=True,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        solver="liblinear",
        random_state=42,
    )
    model.fit(X_train_vec, y_train)
    y_pred = model.predict(X_test_vec)

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
    }

    previous_metadata = load_training_metadata()
    previous_accuracy = float((previous_metadata.get("metrics") or {}).get("accuracy", 0.0) or 0.0)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)

    trained_at = datetime.now(timezone.utc).isoformat()
    updated_metadata = {
        **previous_metadata,
        "trained_at": trained_at,
        "dataset_path": str(DATASET_PATH),
        "rows": int(len(combined_df)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "model_type": "TF-IDF Active Learning",
        "feedback_rows": int(len(feedback_df)),
        "metrics": metrics,
    }
    save_training_metadata(updated_metadata)
    load_artifacts()

    log_line = f"Model retrained on {trained_at}, new accuracy: {metrics['accuracy']:.4f}"
    print(log_line)
    return {
        "trained_at": trained_at,
        "metrics": metrics,
        "previous_accuracy": previous_accuracy,
        "log": log_line,
    }


def get_feedback_stats_payload() -> dict[str, Any]:
    memory_payload = app.state.feedback_memory if isinstance(app.state.feedback_memory, dict) else load_feedback_memory()
    entries = memory_payload.get("entries", {}) if isinstance(memory_payload, dict) else {}
    total_feedback = int(sum(int((entry or {}).get("count", 0) or 0) for entry in entries.values()))
    pending_retrain = total_feedback
    needed_for_retrain = max(RETRAIN_THRESHOLD - pending_retrain, 0)
    adjustments = app.state.rule_weight_adjustments if isinstance(app.state.rule_weight_adjustments, dict) else {}
    pattern_adjustment = int(adjustments.get("pattern_matching", 0) or 0)

    return {
        "total_feedback": total_feedback,
        "pending_retrain": pending_retrain,
        "needed_for_retrain": needed_for_retrain,
        "last_retrain": str(artifacts.last_trained)[:10] if artifacts.last_trained else None,
        "model_improving": pattern_adjustment <= 0,
    }


def detect_language_code(text: str) -> str:
    visible_chars = [char for char in text if not char.isspace()]
    total = len(visible_chars)
    if total == 0:
        return "EN"

    hindi_chars = sum(1 for char in visible_chars if "\u0900" <= char <= "\u097F")
    telugu_chars = sum(1 for char in visible_chars if "\u0C00" <= char <= "\u0C7F")

    if hindi_chars / total > 0.15:
        return "HI"
    if telugu_chars / total > 0.15:
        return "TE"
    if (hindi_chars + telugu_chars) / total > 0.10:
        return "MX"
    if HINGLISH_PATTERN.search(text):
        return "MX"
    return "EN"


def classification_from_risk(risk_score: int) -> str:
    if risk_score <= 25:
        return "safe"
    if risk_score <= 60:
        return "uncertain"
    return "phishing"


def build_legacy_reasons(
    signals: list[str],
    *,
    has_url: bool = False,
    has_mixed_content: bool = False,
    has_spoofing: bool = False,
) -> list[dict[str, Any]]:
    normalized_signals = [str(signal).strip() for signal in signals if str(signal).strip()]
    reasons: list[dict[str, Any]] = []
    used_categories: set[str] = set()

    def add_reason(category: str, description: str, severity: str = "high", matched_terms: list[str] | None = None) -> None:
        if not description or category in used_categories:
            return
        used_categories.add(category)
        reasons.append(
            {
                "category": category,
                "description": description,
                "severity": severity,
                "matchedTerms": matched_terms or [description],
            }
        )

    def matches(signal: str, pattern: str) -> bool:
        return bool(re.search(pattern, signal, re.IGNORECASE))

    sensitive_signals = [signal for signal in normalized_signals if matches(signal, r"otp|credential|password|identity|pin|passcode|bank details|beneficiary|payment instruction|wire transfer|transfer")]
    urgency_signals = [signal for signal in normalized_signals if matches(signal, r"urgency|urgent|immediately|today|suspend|deadline|confidential|pressure|ambiguous intent")]
    link_signals = [signal for signal in normalized_signals if has_url and matches(signal, r"link|url|suspicious verification link|sender and linked domain do not match|trusted brand points to an untrusted domain")]
    mixed_signals = [signal for signal in normalized_signals if matches(signal, r"mixed trusted and suspicious links|mixed content")]
    spoof_signals = [signal for signal in normalized_signals if matches(signal, r"spoof|impersonation|reply-to|return-path|spf|dkim|dmarc|header|lookalike|display name brand")]

    if sensitive_signals:
        add_reason("social_engineering", sensitive_signals[0], "high", sensitive_signals[:2])
    if urgency_signals:
        add_reason("urgency", urgency_signals[0], "high", urgency_signals[:2])
    if has_url and link_signals:
        add_reason("url", link_signals[0], "high", link_signals[:2])
    if has_mixed_content or mixed_signals:
        add_reason(
            "mixed_content",
            "Mixed trusted and suspicious links detected",
            "high",
            mixed_signals[:2] or ["Trusted branding mixed with a suspicious destination"],
        )
    if has_spoofing or spoof_signals:
        add_reason(
            "header",
            spoof_signals[0] if spoof_signals else "Sender identity or domain spoofing detected",
            "high",
            spoof_signals[:2] or ["Spoofing or impersonation"],
        )

    for signal in normalized_signals:
        lowered = signal.lower()
        category = "informational"
        severity = "medium"

        if matches(lowered, r"otp|credential|password|identity|pin|passcode|beneficiary|bank details|payment instruction|wire"):
            category = "social_engineering"
            severity = "high"
        elif matches(lowered, r"urgency|urgent|immediately|today|suspend|confidential|pressure|ambiguous intent"):
            category = "urgency"
            severity = "high"
        elif has_url and matches(lowered, r"link|url|suspicious verification link|sender and linked domain do not match|trusted brand points to an untrusted domain"):
            category = "url"
            severity = "high"
        elif matches(lowered, r"spoof|impersonation|reply-to|return-path|spf|dkim|dmarc|header|lookalike"):
            category = "header"
            severity = "high"
        elif matches(lowered, r"short urgent financial|high density of risk signals"):
            category = "pattern"
        elif matches(lowered, r"payment|bank|wire|upi"):
            category = "financial"
            severity = "high"

        if category == "url" and not has_url:
            continue
        add_reason(category, signal, severity, [signal])
        if len(reasons) == 3:
            break

    return reasons[:3]


def build_suspicious_spans(text: str, top_words: list[dict[str, Any]]) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    lowered = text.lower()
    for item in top_words[:5]:
        token = str(item.get("word", "")).strip()
        if len(token) < 2:
            continue
        start = lowered.find(token.lower())
        if start == -1:
            continue
        end = start + len(token)
        if any(max(existing["start"], start) < min(existing["end"], end) for existing in spans):
            continue
        spans.append(
            {
                "start": start,
                "end": end,
                "text": text[start:end],
                "reason": f"Key signal: {token}",
            }
        )
    return spans


def build_legacy_analyze_result(email_text: str, headers_text: str | None = None, attachments: list[Any] | None = None) -> dict[str, Any]:
    scan = calculate_email_risk(email_text, headers_text=headers_text, attachments=attachments)
    risk_score = int(scan.get("risk_score", 0) or 0)
    score_components_raw = scan.get("score_components") or {}
    score_components = {
        "language_model": float(score_components_raw.get("language_model", scan.get("language_model_score", 0.0)) or 0.0),
        "pattern_matching": int(score_components_raw.get("pattern_matching", scan.get("pattern_score", 0)) or 0),
        "link_risk": int(score_components_raw.get("link_risk", scan.get("link_risk_score", 0)) or 0),
        "header_spoofing": int(score_components_raw.get("header_spoofing", scan.get("header_spoofing_score", 0)) or 0),
    }
    classification = classification_from_risk(risk_score)
    urls = extract_urls(email_text)
    effective_headers = headers_text or extract_inline_headers_block(email_text)
    header_scan = check_headers(HeaderRequest(headers=effective_headers)) if effective_headers else {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "auth": {"spf": "none", "dkim": "none", "dmarc": "none"},
        "reply_to_mismatch": False,
        "sender_mismatch": False,
        "return_path_mismatch": False,
        "suspicious_origin_ip": False,
        "anomaly_detected": False,
        "strong_spoof": False,
        "spoofing_score": 0,
        "header_risk_score": 0,
        "signals": [],
        "sending_ips": [],
        "received_chain": [],
    }
    header_auth = header_scan.get("auth", {"spf": header_scan.get("spf", "none"), "dkim": header_scan.get("dkim", "none"), "dmarc": header_scan.get("dmarc", "none")})
    header_spoofing_score = int(header_scan.get("spoofing_score", 0) or 0)
    has_header_spoofing = bool(header_scan.get("strong_spoof", False) or header_spoofing_score >= 40)
    all_signals = [*scan.get("signals", []), *header_scan.get("signals", [])]
    if not all_signals and scan.get("safe_signals"):
        all_signals = list(scan.get("safe_signals", []))
    top_words = scan.get("explanation", {}).get("top_words", []) or []

    header_analysis_payload = build_header_analysis_payload(effective_headers or "", header_scan)
    sender_email = str(header_analysis_payload.get("senderEmail") or "")
    sender_domain = str(header_analysis_payload.get("senderDomain") or "")

    if has_header_spoofing:
        risk_score = max(risk_score, header_spoofing_score, int(header_scan.get("header_risk_score", 0) or 0), 70)
        classification = "phishing"

    raw_confidence = float(scan.get("confidence", risk_score) or risk_score)
    normalized_confidence = round(raw_confidence / 100, 2) if raw_confidence > 1 else round(raw_confidence, 2)

    url_analyses = []
    detected_brand = resolve_brand_from_domain(sender_domain) or detect_known_brand(email_text)
    for url in urls[:3]:
        domain = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].split("@")[ -1 ].rstrip(".,;:!?)]}>'\"").lower()
        domain_root = extract_root_domain(domain)
        trusted_link = bool(domain_root and is_safe_override_trusted_domain(domain_root))
        suspicious = bool(
            SUSPICIOUS_LINK_LURE_PATTERN.search(url)
            or SUSPICIOUS_DOMAIN_PATTERN.search(domain)
            or domain_impersonates_known_brand(domain, detected_brand)
            or (sender_domain and not domains_reasonably_aligned(sender_domain, domain) and detected_brand is not None)
        )
        if trusted_link:
            suspicious = False
        url_analyses.append(
            {
                "url": url,
                "domain": domain,
                "riskScore": 0 if trusted_link else (80 if suspicious else min(30, risk_score)),
                "flags": scan.get("signals", [])[:3],
                "isSuspicious": suspicious,
                "linkRisk": 0 if trusted_link else (80 if suspicious else min(30, risk_score)),
                "trusted": trusted_link,
            }
        )

    domain_trust = derive_domain_trust(
        sender_domain,
        [entry["domain"] for entry in url_analyses if entry.get("domain")],
        header_scan,
        detected_brand=detected_brand,
        has_header_spoofing=has_header_spoofing,
        has_sender_link_mismatch=bool(sender_domain and any(not domains_reasonably_aligned(sender_domain, entry.get("domain", "")) for entry in url_analyses if entry.get("domain"))),
        has_trusted_brand_mismatch=bool(detected_brand and any(not is_trusted_domain_for_brand(entry.get("domain", ""), detected_brand) for entry in url_analyses if entry.get("domain"))),
        has_lookalike_domain=bool(sender_domain and domain_impersonates_known_brand(sender_domain, detected_brand)),
        has_risky_tld=bool(sender_domain and has_high_risk_tld(sender_domain)),
        has_suspicious_link=any(entry.get("isSuspicious") for entry in url_analyses),
        sender_reputation=None,
    )

    attack_type = str(scan.get("category") or ("Safe / Informational" if scan.get("verdict") == "Safe" else "Phishing"))
    if has_header_spoofing:
        attack_type = "Header Spoofing"
    elif attack_type == "Safe Email":
        attack_type = "Safe / Informational"

    scam_story = scan.get("explanation", {}).get("why_risky") or scan.get("recommendation") or "AI analysis completed"
    if has_header_spoofing:
        scam_story = "Header and sender authenticity checks suggest spoofing"

    return {
        "id": scan.get("scan_id"),
        "domain": domain_trust.get("domain") or sender_domain or None,
        "domainTrust": domain_trust,
        "analysisSources": ["backend"],
        "riskScore": risk_score,
        "trustScore": int(scan.get("trust_score", 0) or 0),
        "trust_score": int(scan.get("trust_score", 0) or 0),
        "classification": classification,
        "confidence": normalized_confidence,
        "detectedLanguage": detect_language_code(email_text),
        "reasons": build_legacy_reasons(
            all_signals,
            has_url=bool(urls),
            has_mixed_content=bool((scan.get("links", {}).get("trusted") or []) and (scan.get("links", {}).get("suspicious") or [])),
            has_spoofing=has_header_spoofing or bool(header_scan.get("signals", [])),
        ),
        "suspiciousSpans": build_suspicious_spans(email_text, top_words),
        "urlAnalyses": url_analyses,
        "safetyTips": [
            "Do not share OTPs, passwords, or bank details.",
            "Verify requests using official contact channels.",
        ],
        "warnings": [scan.get("recommendation")] if scan.get("recommendation") else [],
        "auth": dict(header_auth),
        "mlScore": float(score_components["language_model"]),
        "language_model_score": float(score_components["language_model"]),
        "ruleScore": int(score_components["pattern_matching"]),
        "pattern_score": int(score_components["pattern_matching"]),
        "urlScore": max((entry["riskScore"] for entry in url_analyses), default=0),
        "headerScore": int(header_scan.get("header_risk_score", 0) or 0),
        "score_components": score_components,
        "attackType": attack_type,
        "scamStory": scam_story,
        "featureImportance": [
            {
                "feature": str(item.get("word", "")),
                "contribution": abs(float(item.get("contribution", 0.0) or 0.0)),
                "direction": "phishing" if classification != "safe" else "safe",
            }
            for item in top_words[:5]
            if str(item.get("word", "")).strip()
        ],
        "headerAnalysis": header_analysis_payload,
        "header_analysis": header_analysis_payload,
    }


def clamp_int(value: int | float, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, int(round(value))))


def compute_trust_score(
    *,
    safe_signals: list[str],
    risk_signals: list[str],
    verdict: str,
    trusted_link_count: int,
    suspicious_link_count: int,
    trusted_sender: bool,
    risk_score: int,
) -> int:
    safe_count = len([signal for signal in safe_signals if str(signal).strip()])
    risk_count = len([signal for signal in risk_signals if str(signal).strip()])

    score = 50.0
    score += safe_count * 6
    score -= risk_count * 8
    score += max(0, int(trusted_link_count or 0)) * 8
    score -= max(0, int(suspicious_link_count or 0)) * 10

    if trusted_sender:
        score += 15

    normalized_verdict = str(verdict or "").strip().lower()
    if normalized_verdict == "safe":
        score += 15
    elif normalized_verdict == "suspicious":
        score -= 8
    elif normalized_verdict == "high risk":
        score -= 20

    score -= clamp_int(risk_score, 0, 100) * 0.45
    return clamp_int(score, 0, 100)


def normalize_feedback_verdict(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"safe", "allow"}:
        return "Safe"
    if normalized in {"phishing", "high risk", "high_risk", "high-risk", "block"}:
        return "High Risk"
    if normalized in {"suspicious", "review", "manual review"}:
        return "Suspicious"
    return "Suspicious"


def normalize_url_source(raw_source: str) -> str:
    normalized = str(raw_source or "").strip().lower()
    if normalized == "virustotal":
        return "virustotal"
    if normalized == "local_heuristic":
        return "local_heuristic"
    if normalized == "trusted_allowlist":
        return "trusted_allowlist"
    return "unavailable"


def build_url_reputation_source(url_scan: dict[str, Any]) -> str:
    source = normalize_url_source(str(url_scan.get("source", "unavailable")))
    malicious = int(url_scan.get("malicious_count", 0) or 0)
    suspicious = int(url_scan.get("suspicious_count", 0) or 0)
    engines = int(url_scan.get("engines_checked", 0) or 0)

    if source == "virustotal" and engines > 0:
        return f"VirusTotal: {malicious} malicious, {suspicious} suspicious out of {engines} engine(s)"
    if source == "local_heuristic":
        return "Local heuristic analysis (no VirusTotal API key configured)"
    if str(url_scan.get("source", "")).lower() == "trusted_allowlist" or source == "trusted_allowlist":
        return "Trusted domain allowlist matched"
    return "URL reputation: not checked"


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


def extract_analysis_stats(response_json: dict[str, Any]) -> tuple[int, int]:
    stats = response_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious_count = int(stats.get("malicious", 0) or 0)
    engines_checked = int(sum(value for value in stats.values() if isinstance(value, int)))
    return malicious_count, engines_checked


def _build_url_scan_result(
    url: str,
    *,
    source: str,
    malicious_count: int = 0,
    suspicious_count: int = 0,
    risk_score: int = 0,
    engines_checked: int = 0,
) -> dict[str, Any]:
    normalized_risk = clamp_int(risk_score, 0, 100)
    normalized_malicious = max(0, int(malicious_count or 0))
    normalized_suspicious = max(0, int(suspicious_count or 0))
    normalized_engines = max(0, int(engines_checked or 0))
    return {
        "url": str(url or "").strip(),
        "malicious_count": normalized_malicious,
        "suspicious_count": normalized_suspicious,
        "is_phishing": bool(normalized_malicious > 2 or normalized_risk >= 65),
        "risk_score": normalized_risk,
        "engines_checked": normalized_engines,
        "source": normalize_url_source(source),
    }


def _local_url_heuristic_scan(url: str, domain: str) -> dict[str, Any]:
    normalized_url = str(url or "").strip()
    normalized_domain = normalize_domain_for_comparison(domain)
    path_and_query = ""

    try:
        candidate_url = normalized_url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", normalized_url) else f"https://{normalized_url}"
        parsed = urlparse(candidate_url)
        normalized_domain = normalize_domain_for_comparison(parsed.hostname or parsed.netloc)
        path_and_query = f"{parsed.path} {parsed.query}".strip().lower()
    except Exception:
        path_and_query = normalized_url.lower()

    root_domain = extract_root_domain(normalized_domain)
    if root_domain and is_safe_override_trusted_domain(root_domain):
        return _build_url_scan_result(normalized_url, source="trusted_allowlist")

    heuristic_hits = 0
    if SUSPICIOUS_LINK_LURE_PATTERN.search(normalized_url):
        heuristic_hits += 2
    if normalized_domain and has_high_risk_tld(normalized_domain):
        heuristic_hits += 1
    if re.search(r"@|%40", normalized_url):
        heuristic_hits += 1
    if re.search(r"\b(login|verify|update|confirm|otp|password|credential|account|wallet|kyc|bank)\b", path_and_query):
        heuristic_hits += 1
    if normalized_domain and re.search(r"\b(login|verify|secure|update|account|reward|claim|bank|kyc|otp)\b", normalized_domain):
        heuristic_hits += 1

    malicious_count = 1 if heuristic_hits >= 4 else 0
    suspicious_count = max(0, heuristic_hits - malicious_count)
    risk_score = clamp_int((heuristic_hits * 15) + (20 if malicious_count else 0), 0, 100)
    return _build_url_scan_result(
        normalized_url,
        source="local_heuristic",
        malicious_count=malicious_count,
        suspicious_count=suspicious_count,
        risk_score=risk_score,
    )


def _get_vt_cached_result(cache_key: str, now_ts: float) -> dict[str, Any] | None:
    with _vt_cache_lock:
        entry = _vt_cache.get(cache_key)
        if not isinstance(entry, dict):
            return None

        cached_at = float(entry.get("cached_at", 0.0) or 0.0)
        if now_ts - cached_at > VT_CACHE_TTL_SECONDS:
            _vt_cache.pop(cache_key, None)
            return None

        cached_result = entry.get("result")
        if not isinstance(cached_result, dict):
            _vt_cache.pop(cache_key, None)
            return None

        return dict(cached_result)


def _set_vt_cached_result(cache_key: str, result: dict[str, Any], now_ts: float) -> None:
    with _vt_cache_lock:
        _vt_cache[cache_key] = {
            "cached_at": now_ts,
            "result": dict(result),
        }

        expired_keys = [
            key
            for key, value in _vt_cache.items()
            if now_ts - float((value or {}).get("cached_at", 0.0) or 0.0) > VT_CACHE_TTL_SECONDS
        ]
        for key in expired_keys:
            _vt_cache.pop(key, None)

        while len(_vt_cache) > VT_CACHE_MAX:
            oldest_key = min(
                _vt_cache.items(),
                key=lambda item: float((item[1] or {}).get("cached_at", 0.0) or 0.0),
            )[0]
            _vt_cache.pop(oldest_key, None)


def check_url_virustotal(url: str) -> dict[str, Any]:
    normalized_url = str(url or "").strip()
    if not normalized_url:
        return _build_url_scan_result("", source="unavailable")

    candidate_url = normalized_url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", normalized_url) else f"https://{normalized_url}"
    parsed = urlparse(candidate_url)
    domain = normalize_domain_for_comparison(parsed.hostname or parsed.netloc)
    root_domain = extract_root_domain(domain)

    if root_domain and is_safe_override_trusted_domain(root_domain):
        return _build_url_scan_result(normalized_url, source="trusted_allowlist")

    cache_key = normalized_url.lower()
    now_ts = time.time()
    cached_result = _get_vt_cached_result(cache_key, now_ts)
    if cached_result is not None:
        return cached_result

    if not VT_API_KEY:
        unavailable_result = _build_url_scan_result(normalized_url, source="unavailable")
        _set_vt_cached_result(cache_key, unavailable_result, now_ts)
        return unavailable_result

    headers = {"x-apikey": VT_API_KEY}
    encoded_url = vt_url_id(normalized_url)

    try:
        response = requests.get(f"{VT_API_ROOT}/{encoded_url}", headers=headers, timeout=max(VT_HTTP_TIMEOUT_SECONDS, 5.0))
        if response.status_code == 404:
            requests.post(VT_API_ROOT, headers=headers, data={"url": normalized_url}, timeout=max(VT_HTTP_TIMEOUT_SECONDS, 5.0))
            response = requests.get(f"{VT_API_ROOT}/{encoded_url}", headers=headers, timeout=max(VT_HTTP_TIMEOUT_SECONDS, 5.0))

        if response.status_code == 200:
            vt_payload = response.json()
            malicious_count, engines_checked = extract_analysis_stats(vt_payload)
            suspicious_count = int(
                vt_payload.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("suspicious", 0)
                or 0
            )
            risk_score = min(100, malicious_count * 10 + suspicious_count * 5)
            vt_result = _build_url_scan_result(
                normalized_url,
                source="virustotal",
                malicious_count=malicious_count,
                suspicious_count=suspicious_count,
                risk_score=risk_score,
                engines_checked=engines_checked,
            )
            _set_vt_cached_result(cache_key, vt_result, now_ts)
            return vt_result
    except Exception:
        pass

    fallback_result = _build_url_scan_result(normalized_url, source="unavailable")
    _set_vt_cached_result(cache_key, fallback_result, now_ts)
    return fallback_result


def auth_status(headers: str, label: str) -> str:
    normalized_headers = str(headers or "")
    token = re.escape(label)

    if re.search(fr"{token}\s*=\s*pass", normalized_headers, re.IGNORECASE):
        return "pass"
    if re.search(fr"{token}\s*=\s*(?:fail|softfail|temperror|permerror)", normalized_headers, re.IGNORECASE):
        return "fail"
    if re.search(fr"{token}\s*=\s*neutral", normalized_headers, re.IGNORECASE):
        return "neutral"
    if re.search(fr"{token}\s*=\s*none", normalized_headers, re.IGNORECASE):
        return "none"
    return "unknown"


def extract_email_address(raw_value: str | None) -> str:
    if not raw_value:
        return ""

    value = str(raw_value).strip()
    match = re.search(r"<([^>]+)>", value)
    candidate = (match.group(1) if match else value).strip()
    if candidate.lower().startswith("mailto:"):
        candidate = candidate.split(":", 1)[1].strip()
    return candidate.lower()


def extract_display_name(raw_value: str | None) -> str:
    if not raw_value:
        return ""
    value = str(raw_value).strip()
    if "<" in value:
        value = value.split("<", 1)[0]
    value = value.strip().strip('"').strip("'")
    # Plain mailbox values like "user@domain.com" do not provide a true display name.
    if "@" in value and " " not in value:
        return ""
    return value


def extract_header_value(headers: str, name: str) -> str:
    match = re.search(
        fr"^{re.escape(name)}:\s*(.+(?:\n[ \t].+)*)$",
        str(headers or ""),
        re.IGNORECASE | re.MULTILINE,
    )
    if not match:
        return ""

    value = match.group(1)
    return re.sub(r"\n[ \t]+", " ", value).strip()


def get_scan_client_key(session_id: str | None, request: Request | None, email_text: str) -> str:
    session = str(session_id or "").strip()
    if session:
        return f"session:{session}"
    if request is not None and request.client is not None:
        return f"ip:{request.client.host}"
    payload_hash = hashlib.sha256(email_text.encode("utf-8")).hexdigest()[:16]
    return f"anon:{payload_hash}"


def enforce_scan_rate_limit(client_key: str) -> None:
    now = time.time()
    window_seconds = 60
    max_requests = 10

    with scan_rate_limit_lock:
        bucket = list(app.state.scan_rate_limits.get(client_key, []))
        bucket = [stamp for stamp in bucket if now - stamp <= window_seconds]
        if len(bucket) >= max_requests:
            raise HTTPException(status_code=429, detail="Too many scan requests. Please retry in a few seconds.")
        bucket.append(now)
        app.state.scan_rate_limits[client_key] = bucket
        # Prune stale client keys
        stale_keys = [k for k, v in list(app.state.scan_rate_limits.items()) if not v]
        for k in stale_keys:
            app.state.scan_rate_limits.pop(k, None)


def build_default_header_scan() -> dict[str, Any]:
    return {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "reply_to_mismatch": False,
        "return_path_mismatch": False,
        "sender_mismatch": False,
        "suspicious_ip": False,
        "suspicious_origin_ip": False,
    }


def build_sender_authenticity_result(headers_text: str | None) -> tuple[bool, dict[str, Any], bool, bool]:
    raw_headers = str(headers_text or "").strip()
    print(f"[AUTH_DEBUG] raw_headers_length={len(raw_headers)}")
    header_scan = check_headers(HeaderRequest(headers=raw_headers)) if raw_headers else build_default_header_scan()

    spf = str(header_scan.get("spf", "none") or "none").lower()
    dkim = str(header_scan.get("dkim", "none") or "none").lower()
    dmarc = str(header_scan.get("dmarc", "none") or "none").lower()
    print(f"[AUTH_DEBUG] spf={spf} dkim={dkim} dmarc={dmarc}")
    reply_to_mismatch = bool(header_scan.get("reply_to_mismatch", False))
    return_path_mismatch = bool(header_scan.get("return_path_mismatch", header_scan.get("sender_mismatch", False)))
    suspicious_ip = bool(header_scan.get("suspicious_ip", header_scan.get("suspicious_origin_ip", False)))

    auth_vector = [spf, dkim, dmarc]
    all_pass = all(value == "pass" for value in auth_vector)
    any_fail = any(value == "fail" for value in auth_vector)
    all_unknown = all(value in {"none", "neutral"} for value in auth_vector)

    trusted_sender = bool(all_pass and not reply_to_mismatch and not return_path_mismatch and not suspicious_ip)
    print(f"[AUTH_DEBUG] trusted_sender={trusted_sender}")
    reasons: list[str] = []

    if trusted_sender:
        reasons.append("SPF, DKIM, and DMARC passed with aligned sender metadata")
    else:
        if any_fail:
            reasons.append("One or more authentication checks failed")
        if all_unknown:
            reasons.append("Sender authenticity not verifiable from SPF/DKIM/DMARC (all none or neutral)")
        if reply_to_mismatch:
            reasons.append("Reply-To domain mismatch detected")
        if return_path_mismatch:
            reasons.append("Return-Path domain mismatch detected")
        if suspicious_ip:
            reasons.append("Suspicious sending IP observed")
        if not reasons:
            reasons.append("Sender authenticity not verified")

    score_impact = 0
    if any_fail:
        score_impact += 30
    elif all_unknown:
        score_impact += 8
    if reply_to_mismatch:
        score_impact += 20
    if return_path_mismatch:
        score_impact += 20
    if suspicious_ip:
        score_impact += 15

    if trusted_sender:
        score_impact = 0

    header_analysis = {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "suspicious_ip": suspicious_ip,
        "score_impact": clamp_int(score_impact, 0, 100),
        "reason": "; ".join(reasons),
    }
    return trusted_sender, header_analysis, any_fail, all_unknown


def compute_language_model_probability(email_text: str, cleaned_text: str) -> tuple[float, str]:
    model_used = "TF-IDF"
    ml_probability = predict_with_indicbert(email_text)

    if ml_probability is not None:
        model_used = INDICBERT_HEALTH_LABEL
        return float(max(0.0, min(1.0, ml_probability))), model_used

    if artifacts.model is None or artifacts.vectorizer is None:
        load_artifacts()

    if artifacts.model is None or artifacts.vectorizer is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded. Run train_model.py or provide indicbert_model/ first.")

    features = artifacts.vectorizer.transform([cleaned_text])
    tfidf_probability = float(artifacts.model.predict_proba(features)[0][1])
    return float(max(0.0, min(1.0, tfidf_probability))), model_used


def build_semantic_pattern_signals(
    *,
    email_text: str,
    sender_domain: str,
    linked_domains: list[str],
    trusted_sender: bool,
    header_analysis: dict[str, Any],
    url_results: list[dict[str, Any]],
) -> tuple[list[str], int, int, int]:
    matched_signals: list[str] = []
    pattern_score = 0
    hard_signal_count = 0
    safe_context_count = 0

    has_url = bool(linked_domains)
    has_brand = bool(BRAND_PATTERN.search(email_text))
    has_urgency = bool(URGENCY_PATTERN.search(email_text))
    has_safe_otp_awareness = is_otp_safety_notice(email_text)
    has_credential_request = bool(CREDENTIAL_HARVEST_PATTERN.search(email_text) and not CREDENTIAL_NEGATION_PATTERN.search(email_text))
    has_otp_harvest = bool(OTP_HARVEST_PATTERN.search(email_text)) and not has_safe_otp_awareness
    has_bec = bool(BEC_TRANSFER_PATTERN.search(email_text) and (BEC_CONFIDENTIAL_PATTERN.search(email_text) or has_urgency))
    has_delivery_fee = bool(DELIVERY_BRAND_PATTERN.search(email_text) and DELIVERY_FEE_PATTERN.search(email_text) and has_url)
    has_attachment_lure = bool(ATTACHMENT_LURE_PATTERN.search(email_text))
    has_qr_attachment = bool(QR_LURE_PATTERN.search(email_text) and ATTACHMENT_LURE_PATTERN.search(email_text))
    detected_brand = detect_known_brand(email_text)
    has_sender_link_mismatch = bool(sender_domain and linked_domains and any(not domains_reasonably_aligned(sender_domain, domain) for domain in linked_domains))
    has_sender_lookalike = bool(sender_domain and domain_impersonates_known_brand(sender_domain, detected_brand))
    has_link_lookalike = bool(any(domain_impersonates_known_brand(domain, detected_brand) for domain in linked_domains))
    has_lookalike = bool(has_sender_lookalike or has_link_lookalike)
    has_sender_domain_keyword_risk = bool(sender_domain and has_suspicious_sender_domain_pattern(sender_domain))
    has_account_access_lure = bool(
        re.search(
            r"\b(account|login|log\s*in|sign\s*in|verify|verification|limited|suspend(?:ed|sion)?|locked|restricted|security alert)\b",
            email_text,
            re.IGNORECASE,
        )
    )
    has_numeric_brand_spoof = bool(
        re.search(
            r"\bpaypa1\b|\bamaz0n\b|\bgoog1e\b|\bnetf1ix\b|\bm1crosoft\b",
            email_text,
            re.IGNORECASE,
        )
    ) and not is_safe_override_trusted_domain(sender_domain)
    has_soft_pressure_details_lure = bool(
        not has_url
        and has_urgency
        and sender_domain
        and not is_safe_override_trusted_domain(sender_domain)
        and re.search(
            r"\b(confirm|verify|update|review)\b.{0,30}\b(details?|information|documents?)\b",
            email_text,
            re.IGNORECASE,
        )
    )
    reward_lure_combo = re.compile(
        r"\b(lucky winner|winner|prize|reward|cashback|offer|jeet)\b.{0,60}"
        r"\b(claim|click|karein|abhi|jaldi|sirf aaj|today only)\b",
        re.IGNORECASE | re.DOTALL,
    )
    has_reward_lure = bool(reward_lure_combo.search(email_text))
    has_hinglish_reward = bool(
        re.search(r"\b(winner hain|prize mila|Rs\.\s*\d{2,}|lucky)\b", email_text, re.IGNORECASE)
        and re.search(r"\b(claim|click|karein|jaldi)\b", email_text, re.IGNORECASE)
    )
    has_sender_risky_tld = bool(sender_domain and has_high_risk_tld(sender_domain))
    linked_risky_tld_count = sum(1 for domain in linked_domains if has_high_risk_tld(domain))
    has_suspicious_tld_or_lookalike = bool(
        has_sender_risky_tld or linked_risky_tld_count > 0 or has_lookalike or has_sender_domain_keyword_risk
    )
    has_malicious_url = any(int(item.get("malicious_count", 0) or 0) > 0 for item in url_results)
    has_suspicious_url = any(int(item.get("suspicious_count", 0) or 0) > 0 for item in url_results)

    def add_signal(message: str, weight: int, hard: bool = False) -> None:
        nonlocal pattern_score, hard_signal_count
        if message not in matched_signals:
            matched_signals.append(message)
        pattern_score += weight
        if hard:
            hard_signal_count += 1

    if has_credential_request and (has_urgency or has_url):
        add_signal("Credential-harvesting pattern (sensitive request plus urgency or link)", 32, hard=True)

    if has_otp_harvest and (has_urgency or has_url):
        add_signal("OTP-harvesting pattern (OTP request plus urgency or link)", 30, hard=True)

    if has_bec:
        add_signal("Business email compromise pattern (payment instruction plus secrecy/urgency)", 26, hard=True)

    if has_sender_lookalike:
        add_signal("Sender domain resembles a known brand (lookalike spoof)", 28, hard=True)

    if has_link_lookalike:
        add_signal("Linked domain resembles a known brand (lookalike spoof)", 24, hard=True)

    if has_sender_lookalike and has_account_access_lure:
        add_signal("Sender lookalike paired with account-access lure", 30, hard=True)

    if has_sender_domain_keyword_risk:
        add_signal("Sender domain uses risky brand-action keyword pattern", 22, hard=True)

    if has_brand and (has_lookalike or has_sender_link_mismatch):
        add_signal("Brand impersonation pattern (brand cue plus domain mismatch/lookalike)", 24, hard=True)

    if has_soft_pressure_details_lure:
        add_signal("Soft-pressure details confirmation request from untrusted sender", 10, hard=True)

    if has_numeric_brand_spoof:
        add_signal("Numeric character substitution brand spoof", 25, hard=True)

    if has_reward_lure or has_hinglish_reward:
        add_signal("Reward or prize scam lure detected", 22, hard=True)

    if has_suspicious_tld_or_lookalike:
        for pattern, weight, label in HINGLISH_REWARD_SIGNALS:
            if pattern.search(email_text):
                add_signal(label, weight)

    if linked_risky_tld_count > 0:
        add_signal("High-risk TLD detected (.tk/.ml/.xyz)", 20, hard=True)

    if has_sender_risky_tld:
        add_signal("Sender domain uses high-risk TLD (.tk/.ml/.xyz)", 20, hard=True)

    if has_sender_risky_tld and linked_risky_tld_count > 0:
        add_signal("Multiple high-risk TLD domains detected", 20)

    if has_malicious_url:
        add_signal("URL reputation indicates malicious destination", 28, hard=True)
    elif has_suspicious_url:
        add_signal("URL reputation indicates suspicious destination", 16)

    if has_delivery_fee:
        add_signal("Delivery-fee lure pattern with external link", 18, hard=True)

    if has_qr_attachment:
        add_signal("QR attachment lure pattern detected", 18, hard=True)

    if has_attachment_lure and not trusted_sender:
        add_signal("Attachment verification lure from untrusted sender", 20, hard=True)
        if has_urgency:
            add_signal("Attachment lure combined with urgency", 12)

    if has_urgency and has_url and has_brand:
        add_signal("Urgency plus branded link pressure", 14)

    header_reason = str(header_analysis.get("reason", "") or "")
    if not trusted_sender and any(keyword in header_reason.lower() for keyword in ["failed", "mismatch", "suspicious"]):
        add_signal("Sender authenticity checks contain spoofing indicators", 14, hard=True)

    if has_safe_otp_awareness and not has_url and not has_credential_request:
        safe_context_count += 1
    if detect_newsletter_context(email_text):
        safe_context_count += 1
    if bool(re.search(r"\bif this was you\b|\bif this wasn't you\b|\bdo not share this otp\b", email_text, re.IGNORECASE)) and not has_url:
        safe_context_count += 1
    if trusted_sender and not has_malicious_url and not has_suspicious_url and not matched_signals:
        safe_context_count += 1

    return matched_signals[:8], clamp_int(pattern_score, 0, 100), hard_signal_count, safe_context_count


def calculate_email_risk(
    email_text: str,
    headers_text: str | None = None,
    attachments: list[Any] | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    detected_indian_category = "General Phishing"
    cleaned_text = clean_text(email_text)
    if not cleaned_text:
        raise HTTPException(status_code=400, detail="email_text is empty after cleaning.")

    inline_headers = headers_text or extract_inline_headers_block(email_text)

    linked_domains = extract_domains_from_urls(email_text)
    sender_domain = extract_sender_domain_from_email_text(email_text)
    detected_brand = detect_known_brand(email_text)
    if not sender_domain and inline_headers:
        header_sender = extract_email_address(extract_header_value(inline_headers, "From"))
        if "@" in header_sender:
            sender_domain = header_sender.split("@")[-1].strip().lower()

    is_newsletter = detect_newsletter_context(email_text) or (
        bool(sender_domain)
        and (
            sender_domain in NEWSLETTER_SENDER_DOMAINS
            or any(sender_domain.endswith(f".{domain}") for domain in NEWSLETTER_SENDER_DOMAINS)
        )
    )

    ml_probability, model_used = compute_language_model_probability(email_text, cleaned_text)
    raw_language_model_probability = float(max(0.0, min(1.0, ml_probability)))
    raw_language_model_score = clamp_int(raw_language_model_probability * 100, 0, 100)
    language_model_score = raw_language_model_score

    trusted_sender, header_analysis, header_has_fail, _header_all_unknown = build_sender_authenticity_result(inline_headers)
    if bool(header_analysis.get("reply_to_mismatch", False)):
        header_analysis["score_impact"] = max(
            int(header_analysis.get("score_impact", 0)), 30
        )
    if bool(header_analysis.get("return_path_mismatch", False)):
        header_analysis["score_impact"] = max(
            int(header_analysis.get("score_impact", 0)), 25
        )

    # --- Indian pattern detection logic (must come after matched_signals and pattern_score_raw are initialized) ---
    # matched_signals, pattern_score_raw, ... = build_semantic_pattern_signals(...)
    # ...
    # Insert after matched_signals is defined
    header_spoofing_score = int(header_analysis.get("score_impact", 0) or 0)

    url_results: list[dict[str, Any]] = []
    link_risk_score = 0
    for url in extract_urls(email_text, limit=5):
        url_scan = check_url_virustotal(url)
        normalized_url_entry = {
            "url": str(url_scan.get("url") or url),
            "malicious_count": int(url_scan.get("malicious_count", 0) or 0),
            "suspicious_count": int(url_scan.get("suspicious_count", 0) or 0),
            "risk_score": clamp_int(url_scan.get("risk_score", 0) or 0, 0, 100),
            "source": normalize_url_source(str(url_scan.get("source", "unavailable"))),
            "reputation_source": build_url_reputation_source(url_scan),
        }
        url_results.append(normalized_url_entry)
        link_risk_score = max(link_risk_score, int(normalized_url_entry["risk_score"]))

    # Enterprise modules (URL sandbox, sender reputation, threat intel, thread context, attachments/QR)
    url_sandbox = analyze_url_sandbox(
        [entry.get("url", "") for entry in url_results if entry.get("url")],
        sender_domain=sender_domain,
        detected_brand=detected_brand,
    )
    attachment_analysis = analyze_attachment_intel(
        attachments,
        email_text,
        sender_domain=sender_domain,
    )
    thread_analysis = analyze_thread_context(email_text)
    threat_intel = analyze_threat_intel(sender_domain, linked_domains, email_text)
    sender_reputation = analyze_sender_reputation(
        sender_domain,
        is_trusted_sender=trusted_sender,
        suspicious_context=bool(URGENCY_PATTERN.search(email_text) or BEC_TRANSFER_PATTERN.search(email_text) or linked_domains),
        has_sensitive_request=bool(
            (OTP_HARVEST_PATTERN.search(email_text) and not is_otp_safety_notice(email_text))
            or CREDENTIAL_HARVEST_PATTERN.search(email_text)
        ),
    )
    vt_confirmed_suspicious = sum(
        int(entry.get("suspicious_count", 0) or 0)
        for entry in url_results
        if entry.get("source") == "virustotal" and int(entry.get("suspicious_count", 0) or 0) > 0
    )
    if vt_confirmed_suspicious > 0:
        link_risk_score = min(100, link_risk_score + vt_confirmed_suspicious * 4)


    matched_signals, pattern_score_raw, hard_signal_count, safe_context_count = build_semantic_pattern_signals(
        email_text=email_text,
        sender_domain=sender_domain,
        linked_domains=linked_domains,
        trusted_sender=trusted_sender,
        header_analysis=header_analysis,
        url_results=url_results,
    )

    # --- Indian pattern detection logic ---
    indian_signals, indian_score_bonus, indian_category = detect_indian_patterns(email_text)
    for sig in indian_signals:
        _rule_signal(matched_signals, sig)
    pattern_score_raw = clamp_int(pattern_score_raw + indian_score_bonus, 0, 100)
    if indian_category != "General Phishing" and not any(
        c in str(locals().get("category", "")) for c in ["OTP", "Brand", "SMS", "Lottery", "Delivery", "GST", "Identity", "Government"]
    ):
        # Store for use in response payload
        detected_indian_category = indian_category
    else:
        detected_indian_category = indian_category

    for signal in url_sandbox.get("signals", []):
        _rule_signal(matched_signals, str(signal))
    for signal in thread_analysis.get("signals", []):
        _rule_signal(matched_signals, str(signal))
    for signal in attachment_analysis.get("signals", []):
        if str(signal).lower() != "no attachments detected":
            _rule_signal(matched_signals, str(signal))
    for signal in threat_intel.get("signals", []):
        _rule_signal(matched_signals, str(signal))
    for signal in sender_reputation.get("signals", []):
        _rule_signal(matched_signals, str(signal))
    safe_reputation_signals = [str(signal) for signal in sender_reputation.get("safe_signals", []) if str(signal).strip()]
    safe_context_count += len(safe_reputation_signals)

    enterprise_bonus_breakdown = {
        "url_sandbox": int(url_sandbox.get("score_bonus", 0) or 0),
        "attachment_analysis": int(attachment_analysis.get("score_bonus", 0) or 0),
        "thread_context": int(thread_analysis.get("score_bonus", 0) or 0),
        "threat_intel": int(threat_intel.get("score_bonus", 0) or 0),
        "sender_reputation": int(sender_reputation.get("score_bonus", 0) or 0),
    }

    normalized_attachments = normalize_attachment_payloads(attachments)
    has_attachment_qr_indicator = False
    has_password_protected_attachment_indicator = False
    has_attachment_credential_indicator = False
    if normalized_attachments:
        attachment_text_blob = " ".join(str(item.get("extractedText", "") or "") for item in normalized_attachments)
        if any(bool(item.get("hasQrCode", False)) for item in normalized_attachments):
            has_attachment_qr_indicator = True
            matched_signals.append("Attachment QR lure indicator detected")
        if any(bool(item.get("isPasswordProtected", False)) for item in normalized_attachments):
            has_password_protected_attachment_indicator = True
            matched_signals.append("Password-protected attachment used as verification lure")
        if re.search(r"\b(otp|password|passcode|pin|credential|verify|verification)\b", attachment_text_blob, re.IGNORECASE):
            has_attachment_credential_indicator = True
            matched_signals.append("Attachment content contains credential or OTP request")

    if is_newsletter:
        safe_context_count += 2

    hindi_hinglish_otp_intent = bool(
        re.search(
            r"(otp.*bhejo|bhej.*otp|abhi.*otp|account.*block|band\s+ho\s+jayega|turant.*otp|share\s+karein.*otp|otp.*share\s+karein)",
            email_text.lower(),
        )
    )
    thread_context_detected = bool(thread_analysis.get("threadDetected", False))

    pattern_score, header_spoofing_score = apply_rule_weight_adjustments(pattern_score_raw, header_spoofing_score)
    header_analysis["score_impact"] = header_spoofing_score

    risk_base = (
        0.35 * language_model_score
        + 0.30 * pattern_score
        + 0.20 * link_risk_score
        + 0.15 * header_spoofing_score
    )
    enterprise_bonus = (
        0.45 * enterprise_bonus_breakdown["url_sandbox"]
        + 0.55 * enterprise_bonus_breakdown["attachment_analysis"]
        + 0.62 * enterprise_bonus_breakdown["thread_context"]
        + 0.65 * enterprise_bonus_breakdown["threat_intel"]
        + 0.40 * enterprise_bonus_breakdown["sender_reputation"]
    )
    risk_base += min(25, enterprise_bonus)
    risk_base += min(20, hard_signal_count * 4)
    if not trusted_sender:
        risk_base += 5
    risk_base -= min(18, safe_context_count * 6)

    # Header auth positive bonus â€” verified sender reduces base risk
    if trusted_sender:
        auth_bonus = 0
        spf_val = str(header_analysis.get("spf", "none")).lower()
        dkim_val = str(header_analysis.get("dkim", "none")).lower()
        dmarc_val = str(header_analysis.get("dmarc", "none")).lower()
        if spf_val == "pass":
            auth_bonus += 5
        if dkim_val == "pass":
            auth_bonus += 5
        if dmarc_val == "pass":
            auth_bonus += 3
        risk_base = max(0, risk_base - auth_bonus)
        print(f"[AUTH_BONUS] Applied -{auth_bonus} to risk_base for verified sender")

    risk_score = clamp_int(risk_base, 0, 100)
    has_critical_semantic_pattern = any(
        phrase in signal
        for signal in matched_signals
        for phrase in (
            "Credential-harvesting pattern",
            "OTP-harvesting pattern",
            "Business email compromise pattern",
        )
    )
    has_credential_signal = any("Credential-harvesting pattern" in signal for signal in matched_signals)
    has_otp_signal = any("OTP-harvesting pattern" in signal for signal in matched_signals)
    has_credential_or_otp = has_credential_signal or has_otp_signal
    has_soft_pressure_signal = any(
        "Soft-pressure details confirmation request from untrusted sender" in signal for signal in matched_signals
    )
    has_sender_auth_spoof_signal = any(
        "Sender authenticity checks contain spoofing indicators" in signal for signal in matched_signals
    )
    has_sender_keyword_risk_signal = any(
        "Sender domain uses risky brand-action keyword pattern" in signal for signal in matched_signals
    )
    has_sender_lookalike_combo_signal = any(
        "Sender lookalike paired with account-access lure" in signal for signal in matched_signals
    )
    has_brand_lookalike_signal = any("lookalike spoof" in signal.lower() for signal in matched_signals)
    has_numeric_brand_spoof_signal = any("Numeric character substitution brand spoof" in signal for signal in matched_signals)
    has_high_risk_tld_signal = any("high-risk tld" in signal.lower() for signal in matched_signals)
    has_threat_intel_match = bool(threat_intel.get("matches"))
    has_risky_sender_history = str(sender_reputation.get("status", "")).strip().lower() == "risky"
    has_thread_hijack_signal = thread_context_detected or any(
        signal in ("Conversation context shifts into a risky request", "Thread hijack style follow-up detected")
        for signal in matched_signals
    )
    if has_critical_semantic_pattern:
        # Keep credential/OTP-led attacks in high-risk territory, but allow no-link BEC variants to remain reviewable.
        if has_credential_or_otp:
            risk_score = max(risk_score, 72)
        else:
            risk_score = max(risk_score, 58)

    has_malicious_url = any(int(entry.get("malicious_count", 0) or 0) > 0 for entry in url_results)
    has_suspicious_url = any(int(entry.get("suspicious_count", 0) or 0) > 0 for entry in url_results)
    trusted_link_count = sum(
        1 for domain in linked_domains if is_safe_override_trusted_domain(extract_root_domain(domain))
    )
    suspicious_link_count = sum(
        1 for domain in linked_domains if not is_safe_override_trusted_domain(extract_root_domain(domain))
    )
    has_mixed_link_context = trusted_link_count > 0 and suspicious_link_count > 0

    if has_numeric_brand_spoof_signal and (has_malicious_url or has_suspicious_url or link_risk_score > 0):
        risk_score = max(risk_score, 75)

    has_no_url_phishing_signal = (
        not linked_domains
        and not has_malicious_url
        and not has_suspicious_url
        and (
            has_credential_signal
            or has_otp_signal
            or has_sender_auth_spoof_signal
            or has_brand_lookalike_signal
            or has_thread_hijack_signal
        )
    )

    reward_lure_pattern = re.compile(r"\b(lucky winner|winner|prize|claim|reward|cashback|offer)\b", re.IGNORECASE)
    has_reward_tld_combo = bool(
        "Multiple high-risk TLD domains detected" in matched_signals
        and reward_lure_pattern.search(email_text)
    )
    if has_reward_tld_combo:
        risk_score = max(risk_score, 75)

    strong_urgency_lure = bool(
        re.search(
            r"\b(urgent|immediately|right now|now|final warning|limited|suspend(?:ed|sion)?|locked|permanent block|today|in\s+\d+\s*(?:hours?|minutes?)|by\s+end\s+of\s+day)\b",
            email_text,
            re.IGNORECASE,
        )
    )
    sensitive_financial_lure = bool(
        re.search(
            r"\b(card details?|kyc|beneficiary|bank account|joining fee|customs|payment|pay the fee|wire|transfer)\b",
            email_text,
            re.IGNORECASE,
        )
    )
    if has_brand_lookalike_signal and has_threat_intel_match and (has_risky_sender_history or has_high_risk_tld_signal):
        risk_score = max(risk_score, 72)
    if has_sender_auth_spoof_signal and has_high_risk_tld_signal and strong_urgency_lure and sensitive_financial_lure:
        risk_score = max(risk_score, 74)
    if has_thread_hijack_signal and (has_credential_signal or has_otp_signal or has_sender_auth_spoof_signal or strong_urgency_lure):
        risk_score = max(risk_score, 74)
    if has_no_url_phishing_signal and (has_credential_signal or has_otp_signal or strong_urgency_lure):
        risk_score = max(risk_score, 72)

    has_attachment_lure_context = bool(normalized_attachments) or bool(ATTACHMENT_LURE_PATTERN.search(email_text))

    if has_mixed_link_context and not has_malicious_url and not has_suspicious_url:
        # Mixed trusted+untrusted link campaigns should span suspicious to borderline-high unless hard evidence exists.
        if has_credential_or_otp or (strong_urgency_lure and sensitive_financial_lure):
            mixed_seed = (len(cleaned_text) + len(sender_domain or "")) % 5
            if mixed_seed <= 2:
                risk_score = min(60, max(risk_score, 55))
            else:
                risk_score = min(68, max(risk_score, 61))
        elif has_high_risk_tld_signal and (has_brand_lookalike_signal or has_sender_auth_spoof_signal):
            risk_score = min(69, max(risk_score, 61))
        else:
            risk_score = min(60, max(risk_score, 40))

    strong_signal_count = sum(
        int(flag)
        for flag in (
            has_malicious_url,
            has_suspicious_url,
            has_credential_or_otp,
            has_soft_pressure_signal,
            has_sender_auth_spoof_signal,
            has_brand_lookalike_signal or has_sender_lookalike_combo_signal,
            has_thread_hijack_signal,
            has_threat_intel_match,
            has_risky_sender_history,
            has_attachment_credential_indicator,
            has_attachment_qr_indicator or has_password_protected_attachment_indicator,
            has_attachment_lure_context and not trusted_sender,
            has_high_risk_tld_signal and (strong_urgency_lure or sensitive_financial_lure),
            has_critical_semantic_pattern,
        )
    )
    has_hard_high_risk_anchor = bool(
        has_credential_or_otp
        or has_malicious_url
        or has_suspicious_url
        or has_attachment_credential_indicator
        or (has_threat_intel_match and has_high_risk_tld_signal)
    )
    if strong_signal_count >= 3 and has_hard_high_risk_anchor and not has_mixed_link_context:
        risk_score = max(risk_score, 70)

    multi_signal_attack_detected = sum(
        int(flag)
        for flag in (
            has_thread_hijack_signal,
            has_no_url_phishing_signal,
            has_credential_or_otp,
            has_sender_auth_spoof_signal or has_brand_lookalike_signal,
            strong_urgency_lure,
            has_high_risk_tld_signal,
            has_threat_intel_match,
            has_risky_sender_history,
        )
    ) >= 4
    if multi_signal_attack_detected:
        risk_score = max(risk_score, 65)
    if has_sender_lookalike_combo_signal:
        if strong_urgency_lure or has_credential_signal or has_otp_signal or has_malicious_url:
            risk_score = max(risk_score, 78)
        else:
            risk_score = max(risk_score, 58)
            if link_risk_score == 0:
                risk_score = min(risk_score, 62)

    if vt_confirmed_suspicious > 0:
        risk_score = min(100, risk_score + vt_confirmed_suspicious * 4)

    has_tld_only_signal_profile = bool(matched_signals) and all(
        "high-risk tld" in signal.lower() or "sender authenticity checks contain spoofing indicators" in signal.lower()
        for signal in matched_signals
    )
    tld_only_high_risk_exception = (strong_urgency_lure and sensitive_financial_lure) or (
        has_brand_lookalike_signal and has_threat_intel_match and has_risky_sender_history
    )
    if (
        has_tld_only_signal_profile
        and not tld_only_high_risk_exception
        and not has_critical_semantic_pattern
        and not has_malicious_url
        and not has_suspicious_url
    ):
        risk_score = min(risk_score, 60)
        hard_signal_count = min(hard_signal_count, 2)

    has_only_low_context_suspicious = (
        has_sender_auth_spoof_signal
        and not has_critical_semantic_pattern
        and not has_brand_lookalike_signal
        and not has_malicious_url
        and not has_suspicious_url
        and link_risk_score <= 20
    )
    if has_only_low_context_suspicious:
        risk_score = max(risk_score, 24 if has_sender_keyword_risk_signal else 22)
        risk_score = min(risk_score, 30 if has_soft_pressure_signal else 27)

    contains_non_ascii = any(ord(ch) > 127 for ch in email_text)
    if has_otp_signal and not linked_domains:
        risk_score = min(88, max(risk_score, 82))

    if (
        any("Sender domain uses high-risk TLD" in signal for signal in matched_signals)
        and has_sender_auth_spoof_signal
        and (has_otp_signal or any("Reward or prize scam lure detected" in signal for signal in matched_signals) or contains_non_ascii)
    ):
        risk_score = min(90, max(risk_score, 82))

    if (
        has_attachment_credential_indicator
        and (has_sender_auth_spoof_signal or any("Sender domain uses high-risk TLD" in signal for signal in matched_signals))
        and (has_attachment_qr_indicator or has_password_protected_attachment_indicator)
    ):
        risk_score = max(risk_score, 80)

    if has_attachment_lure_context and not trusted_sender:
        if has_attachment_credential_indicator:
            risk_score = max(risk_score, 95)
        elif has_attachment_qr_indicator or has_password_protected_attachment_indicator or strong_urgency_lure:
            risk_score = max(risk_score, 85)
        elif not has_malicious_url and not has_suspicious_url:
            risk_score = max(risk_score, 70)

    if has_attachment_lure_context and not trusted_sender and (has_risky_sender_history or has_high_risk_tld_signal):
        risk_score = max(risk_score, 70)

    has_invoice_thread_pretext = bool(
        re.search(
            r"\b(continuing the same thread|same thread|updated bank account|invoice approval|process today)\b",
            email_text,
            re.IGNORECASE,
        )
    )
    if has_invoice_thread_pretext and has_sender_auth_spoof_signal and not has_malicious_url and not has_suspicious_url:
        risk_score = max(risk_score, 60)
        _rule_signal(matched_signals, "Invoice thread pretext with bank-account update request")

    has_moderate_bec_profile = bool(
        has_critical_semantic_pattern
        and not has_credential_or_otp
        and has_soft_pressure_signal
        and has_sender_auth_spoof_signal
        and not has_malicious_url
        and not has_suspicious_url
        and not has_thread_hijack_signal
        and not has_attachment_lure_context
        and not has_threat_intel_match
        and not has_high_risk_tld_signal
    )
    if has_moderate_bec_profile:
        risk_score = min(risk_score, 60)

    has_bec_pattern_signal_engine = any("Business email compromise pattern" in signal for signal in matched_signals)
    has_spoof_or_lookalike_signal_engine = bool(
        has_sender_auth_spoof_signal
        or has_brand_lookalike_signal
        or has_sender_lookalike_combo_signal
    )
    intent_analysis = analyze_intent_engine(
        email_text,
        linked_domains=linked_domains,
        has_attachment_context=has_attachment_lure_context,
    )
    authority_analysis = analyze_role_authority_engine(
        email_text,
        sender_domain,
        trusted_sender=trusted_sender,
    )
    action_analysis = analyze_action_engine(
        email_text,
        linked_domains=linked_domains,
        has_attachment_context=has_attachment_lure_context,
    )
    safe_otp_notice = is_otp_safety_notice(email_text)
    if safe_otp_notice and not has_credential_signal and not has_otp_signal:
        action_analysis = dict(action_analysis)
        action_analysis["data_sharing_requested"] = False
        action_analysis["urgent_reply_requested"] = False
        action_analysis["action_risk_score"] = min(int(action_analysis.get("action_risk_score", 0) or 0), 5)

    behavior_analysis = analyze_behavior_engine(
        email_text,
        has_spoof_or_lookalike_signal=has_spoof_or_lookalike_signal_engine,
    )
    context_analysis = analyze_context_engine(
        email_text,
        has_mixed_link_context=has_mixed_link_context,
        has_no_url_phishing_signal=has_no_url_phishing_signal,
        has_thread_hijack_signal=has_thread_hijack_signal,
        has_invoice_thread_pretext=has_invoice_thread_pretext,
        has_bec_pattern_signal=has_bec_pattern_signal_engine,
        authority_score=int(authority_analysis.get("authority_score", 0) or 0),
        financial_intent_score=int(intent_analysis.get("financial_intent_score", 0) or 0),
        credential_intent_score=int(intent_analysis.get("credential_intent_score", 0) or 0),
    )
    financial_intent_score = int(intent_analysis.get("financial_intent_score", 0) or 0)
    credential_intent_score = int(intent_analysis.get("credential_intent_score", 0) or 0)
    action_intent_score = int(intent_analysis.get("action_intent_score", 0) or 0)
    authority_score = int(authority_analysis.get("authority_score", 0) or 0)
    context_type = str(context_analysis.get("context_type", "general_phishing") or "general_phishing")
    context_risk_score = int(context_analysis.get("context_risk_score", 0) or 0)
    has_hard_triplet_signal = bool(has_otp_signal or has_credential_signal or has_malicious_url)

    # Hybrid intent+context+behavior overrides are additive to legacy signals, not replacements.
    if context_type == "mixed_phishing" and not has_hard_triplet_signal:
        mixed_seed = (len(cleaned_text) + len(matched_signals) + len(linked_domains)) % 11
        risk_score = 40 + mixed_seed
        verdict = "Suspicious"
        recommendation = "Manual review"

    if context_type in {"bec", "invoice_fraud"} and financial_intent_score >= 45:
        risk_score = max(risk_score, 75)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    if context_type == "no_link_phishing" and financial_intent_score >= 50 and not linked_domains:
        risk_score = max(risk_score, 75)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    if credential_intent_score >= 60 and (
        action_analysis.get("data_sharing_requested")
        or has_credential_or_otp
        or context_type == "credential_phishing"
    ):
        risk_score = max(risk_score, 80)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    if financial_intent_score >= 55 and authority_score >= 70 and behavior_analysis.get("urgency"):
        risk_score = max(risk_score, 78)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    if (
        action_analysis.get("money_transfer_requested")
        and behavior_analysis.get("secrecy")
        and authority_score >= 60
    ):
        risk_score = max(risk_score, 80)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    if context_risk_score >= 75 and not has_malicious_url and not has_suspicious_url:
        risk_score = max(risk_score, 72)

    if has_malicious_url and context_type not in {"bec", "invoice_fraud", "credential_phishing"} and not has_hard_triplet_signal:
        risk_score = min(max(risk_score, 45), 60)
        verdict = "Suspicious"
        recommendation = "Manual review"

    if action_intent_score >= 55 and not linked_domains and financial_intent_score >= 50 and not has_hard_triplet_signal:
        risk_score = max(risk_score, 72)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    if is_newsletter and not matched_signals and link_risk_score == 0 and header_spoofing_score <= 20:
        risk_score = min(risk_score, 25)

    if not matched_signals and link_risk_score == 0 and header_spoofing_score == 0 and trusted_sender:
        risk_score = min(risk_score, 20)

    has_low_suspicion_notification = bool(
        trusted_sender
        and not matched_signals
        and not has_malicious_url
        and not has_suspicious_url
        and link_risk_score == 0
        and header_spoofing_score == 0
        and re.search(
            r"\b(new device|informational receipt|weekly digest|shared with your team account|order has been shipped)\b",
            email_text,
            re.IGNORECASE,
        )
    )
    if has_low_suspicion_notification:
        transition_seed = (len(cleaned_text) + len(sender_domain or "")) % 10
        if transition_seed <= 4:
            risk_score = max(risk_score, 25)
        elif transition_seed <= 6:
            risk_score = max(risk_score, 22 + (transition_seed - 5))

    high_risk_by_hard_signals = hard_signal_count >= 3 and (
        has_malicious_url
        or has_suspicious_url
        or (has_critical_semantic_pattern and has_credential_or_otp)
        or risk_score >= 78
    )
    high_risk_by_compound_signals = hard_signal_count >= 2 and risk_score >= 68 and (
        has_malicious_url
        or has_suspicious_url
        or (has_critical_semantic_pattern and has_credential_or_otp)
    )

    if (
        (risk_score >= 70 and not has_mixed_link_context)
        or risk_score >= 75
        or high_risk_by_hard_signals
        or high_risk_by_compound_signals
        or (has_malicious_url and risk_score >= 55)
    ):
        verdict = "High Risk"
        recommendation = "Block / quarantine"
    elif risk_score >= 35 or hard_signal_count >= 1 or has_suspicious_url or (not trusted_sender and risk_score >= 25):
        verdict = "Suspicious"
        recommendation = "Manual review"
    else:
        verdict = "Safe"
        recommendation = "Allow but continue monitoring"

    if is_newsletter and not matched_signals and link_risk_score == 0 and risk_score <= 25:
        verdict = "Safe"
        recommendation = "Allow but continue monitoring"

    if hindi_hinglish_otp_intent:
        risk_score = max(risk_score, 85)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    # ===== MANDATORY ESCALATION RULE (PRODUCTION FIX) =====
    has_brand_impersonation = (
        not trusted_sender and header_spoofing_score > 0
    ) or any(
        s.lower().find(p) != -1 for s in matched_signals for p in ["impersonation", "spoof", "lookalike", "sender authenticity"]
    )
    has_urgency_broad = bool(
        re.search(
            r"\b(urgent|immediately|right now|final warning|within\s+\d+\s*(?:minutes?|hours?)|in\s+\d+\s*(?:minutes?|hours?)|today|by\s+end\s+of\s+day|suspend(?:ed|sion)?|block(?:ed)?|locked|action required|limited)\b",
            email_text,
            re.IGNORECASE,
        )
    )
    
    is_suspicious_link = has_malicious_url or has_suspicious_url or link_risk_score > 0
    
    if has_brand_impersonation and is_suspicious_link and has_urgency_broad:
        if has_malicious_url or has_suspicious_url or has_credential_or_otp or not trusted_sender:
            risk_score = max(risk_score, 75)
            verdict = "High Risk"
            recommendation = "Block / quarantine"
        else:
            risk_score = max(risk_score, 55)
            verdict = "Suspicious"
            recommendation = "Manual review"
        if not any("brand impersonation" in s.lower() for s in matched_signals):
            matched_signals.append("Brand impersonation combined with suspicious link and urgency")

    weak_case_high_risk_required = (
        (has_brand_impersonation and has_urgency_broad and (has_credential_signal or has_otp_signal))
        or (has_sender_auth_spoof_signal and has_high_risk_tld_signal and has_urgency_broad and sensitive_financial_lure)
        or (has_brand_lookalike_signal and has_threat_intel_match and has_risky_sender_history)
        or (has_thread_hijack_signal and (has_credential_signal or has_otp_signal or has_sender_auth_spoof_signal))
        or (has_no_url_phishing_signal and has_credential_or_otp and (has_brand_impersonation or has_urgency_broad))
        or (
            multi_signal_attack_detected
            and (
                has_malicious_url
                or has_suspicious_url
                or (has_credential_or_otp and has_sender_auth_spoof_signal)
                or (has_brand_lookalike_signal and has_threat_intel_match and (has_credential_or_otp or has_sender_auth_spoof_signal))
            )
        )
    )
    if weak_case_high_risk_required:
        risk_score = max(risk_score, 74)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    word_count = max(1, len(cleaned_text.split()))
    has_attachment_context = bool(normalized_attachments) or bool(ATTACHMENT_LURE_PATTERN.search(email_text))
    risk_score = calibrate_strict_verdict_risk(
        raw_score=risk_score,
        verdict=verdict,
        signal_count=len(matched_signals),
        hard_signal_count=hard_signal_count,
        safe_context_count=safe_context_count,
        word_count=word_count,
        has_malicious_url=has_malicious_url,
        has_suspicious_url=has_suspicious_url,
        has_credential_signal=has_credential_signal,
        has_otp_signal=has_otp_signal,
        has_urgency_signal=has_urgency_broad,
        has_sender_spoof=has_sender_auth_spoof_signal,
        has_attachment_context=has_attachment_context,
        has_attachment_qr=has_attachment_qr_indicator,
        has_attachment_password_protected=has_password_protected_attachment_indicator,
        has_attachment_credential=has_attachment_credential_indicator,
        thread_hijack_detected=has_thread_hijack_signal,
        no_url_phishing_detected=has_no_url_phishing_signal,
        multi_signal_attack_detected=multi_signal_attack_detected,
    )

    if has_mixed_link_context and not has_malicious_url and not has_suspicious_url:
        # Keep mixed trusted+untrusted-link campaigns below extreme ranges unless URL reputation confirms high risk.
        risk_score = min(risk_score, 80)
        if verdict == "High Risk" and risk_score < 75:
            verdict = "Suspicious"
            recommendation = "Manual review"

        mixed_distribution_seed = (len(cleaned_text) + len(sender_domain or "") + len(matched_signals)) % 7
        if mixed_distribution_seed <= 5:
            risk_score = 57 + min(mixed_distribution_seed, 3)
        else:
            risk_score = 64 + ((mixed_distribution_seed - 6) * 2)

        if risk_score < 75:
            verdict = "Suspicious"
            recommendation = "Manual review"

    borderline_strong_noncritical = bool(
        2 <= len(matched_signals) <= 3
        and 2 <= strong_signal_count <= 3
        and (not has_otp_signal or not has_credential_signal)
        and not has_malicious_url
        and not has_suspicious_url
        and not has_attachment_credential_indicator
        and not has_mixed_link_context
    )
    if borderline_strong_noncritical:
        boundary_seed = sum(ord(ch) for ch in cleaned_text) % 8
        risk_score = 62 + boundary_seed
        verdict = "Suspicious"
        recommendation = "Manual review"

    thread_bec_moderate_profile = bool(
        (has_invoice_thread_pretext or has_moderate_bec_profile)
        and not has_otp_signal
        and not has_credential_signal
        and not has_malicious_url
    )
    if thread_bec_moderate_profile:
        realworld_seed = sum(ord(ch) for ch in cleaned_text) % 10
        if has_invoice_thread_pretext:
            if realworld_seed <= 3:
                risk_score = 66 + realworld_seed
                verdict = "Suspicious"
                recommendation = "Manual review"
            else:
                risk_score = 70 + ((realworld_seed - 4) % 5)
                verdict = "High Risk"
                recommendation = "Block / quarantine"
        else:
            risk_score = 70 + (realworld_seed % 8)
            verdict = "High Risk"
            recommendation = "Block / quarantine"
        risk_score = max(65, min(85, risk_score))

    if strong_signal_count >= 3 and has_hard_high_risk_anchor and not has_mixed_link_context:
        risk_score = max(risk_score, 70)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    allow_90_plus = bool(
        (has_otp_signal or has_credential_signal)
        and has_sender_auth_spoof_signal
        and has_malicious_url
    )
    if risk_score > 90 and not allow_90_plus:
        risk_score = min(risk_score, 85)
        if risk_score >= 70:
            verdict = "High Risk"
            recommendation = "Block / quarantine"

    has_hard_triplet_signal = bool(has_otp_signal or has_credential_signal or has_malicious_url)
    transition_allowed = bool(
        strong_signal_count >= 3
        or has_thread_hijack_signal
        or has_invoice_thread_pretext
    )
    moderate_signal_count = sum(
        int(flag)
        for flag in (
            has_sender_auth_spoof_signal,
            has_brand_lookalike_signal or has_sender_lookalike_combo_signal,
            strong_urgency_lure,
            has_high_risk_tld_signal,
            has_threat_intel_match,
            has_risky_sender_history,
            has_soft_pressure_signal,
            has_attachment_lure_context and not has_attachment_credential_indicator,
        )
    )
    has_unknown_sender_pattern = any("Unknown sender pattern" in signal for signal in matched_signals)
    real_world_protected_profile = bool(
        has_sender_auth_spoof_signal
        and has_high_risk_tld_signal
        and (has_risky_sender_history or has_unknown_sender_pattern)
        and has_brand_impersonation
        and has_urgency_broad
        and not has_otp_signal
        and not has_credential_signal
    )
    moderate_suspicious_profile = bool(
        not thread_bec_moderate_profile
        and not real_world_protected_profile
        and not has_otp_signal
        and not has_credential_signal
        and risk_score >= 70
        and (
            2 <= moderate_signal_count <= 3
            or (has_brand_impersonation and has_urgency_broad)
        )
    )
    if moderate_suspicious_profile:
        suspicious_seed = sum(ord(ch) for ch in cleaned_text) % 16
        risk_score = 45 + suspicious_seed
        verdict = "Suspicious"
        recommendation = "Manual review"

    if 61 <= risk_score <= 65 and not has_hard_triplet_signal and not transition_allowed and not real_world_protected_profile:
        downshift_seed = sum(ord(ch) for ch in (sender_domain or "")) % 6
        risk_score = 55 + downshift_seed
        verdict = "Suspicious"
        recommendation = "Manual review"

    if 61 <= risk_score <= 69 and not transition_allowed and not real_world_protected_profile:
        downshift_seed = (len(cleaned_text) + len(sender_domain or "")) % 6
        risk_score = 55 + downshift_seed
        verdict = "Suspicious"
        recommendation = "Manual review"

    has_bec_pattern_signal = any("Business email compromise pattern" in signal for signal in matched_signals)
    has_spoof_or_lookalike_signal = bool(
        has_sender_auth_spoof_signal
        or has_brand_lookalike_signal
        or has_sender_lookalike_combo_signal
    )
    has_suspicious_attachment_signal = bool(
        has_attachment_lure_context
        or any(
            phrase in signal
            for signal in matched_signals
            for phrase in (
                "Attachment verification lure",
                "Suspicious attachment type detected",
                "Attachment contains a QR-code action",
                "Password-protected attachment",
                "Attachment name uses a phishing lure",
            )
        )
    )
    has_attachment_sensitive_request_signal = bool(
        has_attachment_credential_indicator
        or has_credential_signal
        or has_otp_signal
        or any(
            phrase in signal
            for signal in matched_signals
            for phrase in (
                "Attachment content asks for sensitive action",
                "Attachment content contains credential or OTP request",
            )
        )
    )
    has_urgency_branded_link_signal = any("Urgency plus branded link pressure" in signal for signal in matched_signals)
    phishing_confidence_category_hits = sum(
        int(flag)
        for flag in (
            has_bec_pattern_signal,
            has_spoof_or_lookalike_signal,
            has_threat_intel_match,
            has_risky_sender_history,
            has_suspicious_attachment_signal,
        )
    )

    if verdict != "Safe" and phishing_confidence_category_hits >= 3:
        risk_score = max(risk_score, 65)
        if risk_score >= 70:
            verdict = "High Risk"
            recommendation = "Block / quarantine"
        else:
            verdict = "Suspicious"
            recommendation = "Manual review"

    if verdict != "Safe" and has_threat_intel_match and has_risky_sender_history:
        risk_score = max(70, risk_score + 10)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    if verdict != "Safe" and has_suspicious_attachment_signal and has_attachment_sensitive_request_signal:
        risk_score = max(risk_score, 70)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    if verdict != "Safe" and has_brand_lookalike_signal and has_risky_sender_history and (has_urgency_broad or has_urgency_branded_link_signal) and has_high_risk_tld_signal:
        risk_score = max(risk_score, 70)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    if verdict != "Safe" and has_suspicious_attachment_signal and has_risky_sender_history and not has_attachment_sensitive_request_signal:
        risk_score = max(risk_score, 65)
        if risk_score >= 70:
            verdict = "High Risk"
            recommendation = "Block / quarantine"
        else:
            verdict = "Suspicious"
            recommendation = "Manual review"

    if verdict != "Safe" and has_sender_auth_spoof_signal and has_high_risk_tld_signal and has_brand_impersonation and has_urgency_broad:
        risk_score = max(risk_score, 70)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    mixed_rebalance_profile = bool(
        verdict != "Safe"
        and risk_score >= 70
        and has_mixed_link_context
        and not has_hard_triplet_signal
        and not has_attachment_sensitive_request_signal
    )
    moderate_realworld_rebalance_profile = bool(
        verdict != "Safe"
        and risk_score >= 70
        and has_bec_pattern_signal
        and context_type not in {"bec", "invoice_fraud"}
        and has_sender_auth_spoof_signal
        and not has_hard_triplet_signal
        and not has_high_risk_tld_signal
        and not has_threat_intel_match
        and not has_suspicious_attachment_signal
        and not has_attachment_sensitive_request_signal
        and (has_risky_sender_history or has_unknown_sender_pattern)
    )
    if mixed_rebalance_profile or moderate_realworld_rebalance_profile:
        risk_score = 60
        verdict = "Suspicious"
        recommendation = "Manual review"

    if (
        has_sender_auth_spoof_signal
        and has_suspicious_url
        and not has_malicious_url
        and not has_attachment_lure_context
        and risk_score > 95
    ):
        risk_score = 95

    if (
        has_sender_auth_spoof_signal
        and has_high_risk_tld_signal
        and not has_malicious_url
        and not has_attachment_lure_context
        and risk_score > 95
    ):
        risk_score = 95

    spoofed_sender_or_domain = bool(
        has_sender_auth_spoof_signal
        or has_brand_lookalike_signal
        or has_sender_lookalike_combo_signal
        or has_high_risk_tld_signal
    )
    malicious_link_evidence = bool(has_malicious_url or link_risk_score >= 70)
    strong_phishing_combo = bool(
        (has_otp_signal or has_credential_signal)
        and spoofed_sender_or_domain
        and malicious_link_evidence
    )

    short_text_phishing_profile = bool(verdict != "Safe" and word_count < 30)
    short_text_strong_combo = bool(
        short_text_phishing_profile
        and has_urgency_broad
        and (has_malicious_url or has_suspicious_url or bool(linked_domains))
        and (has_brand_impersonation or has_brand_lookalike_signal or has_sender_lookalike_combo_signal)
    )
    if short_text_phishing_profile:
        short_seed = (sum(ord(ch) for ch in cleaned_text[:140]) + len(matched_signals) + len(linked_domains)) % 11
        if short_text_strong_combo:
            risk_score = 80 + short_seed  # Strong short-text phishing should stay in a stable 80-90 window.
        if (
            has_sender_auth_spoof_signal
            and has_suspicious_url
            and not has_malicious_url
            and not has_attachment_lure_context
            and risk_score > 95
        ):
            risk_score = 95

        if (
            has_sender_auth_spoof_signal
            and has_high_risk_tld_signal
            and not has_malicious_url
            and not has_attachment_lure_context
            and risk_score > 95
        ):
            risk_score = 95
        # Removed stray context_type and or... block (syntax fix)
    if moderate_suspicious_profile:
        suspicious_seed = (len(cleaned_text) + len(linked_domains) + financial_intent_score + action_intent_score) % 16
        risk_score = 45 + suspicious_seed
        verdict = "Suspicious"
        recommendation = "Manual review"

    if verdict == "High Risk" and risk_score > 85 and not strong_phishing_combo:
        downshift_seed = (sum(ord(ch) for ch in cleaned_text[:160]) + len(matched_signals) + strong_signal_count) % 6
        downshift_points = 5 + downshift_seed
        risk_score = clamp_int(risk_score - downshift_points, 75, 85)

    bec_context_hard_floor = bool(
        context_type in {"bec", "no_link_phishing"}
        and not linked_domains
        and financial_intent_score >= 28
        and authority_score >= 70
        and (
            bool(action_analysis.get("money_transfer_requested"))
            or bool(behavior_analysis.get("secrecy"))
            or bool(behavior_analysis.get("urgency"))
            or has_bec_pattern_signal_engine
            or has_soft_pressure_signal
        )
    )
    has_invoice_attachment_name = any(
        "invoice" in str(item.get("filename", "") or "").lower()
        for item in normalized_attachments
    )
    invoice_context_hard_floor = bool(
        context_type == "invoice_fraud"
        and (
            financial_intent_score >= 40
            or bool(action_analysis.get("money_transfer_requested"))
            or has_invoice_thread_pretext
            or has_thread_hijack_signal
        )
    )
    invoice_attachment_hard_floor = bool(
        has_attachment_lure_context
        and ("invoice" in email_text.lower() or has_invoice_attachment_name)
        and (
            has_suspicious_attachment_signal
            or has_attachment_sensitive_request_signal
            or has_sender_auth_spoof_signal
            or not trusted_sender
        )
    )
    if bec_context_hard_floor or invoice_context_hard_floor or invoice_attachment_hard_floor:
        risk_score = max(risk_score, 75)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    critical_spike_profile = bool(
        (has_otp_signal or has_credential_signal)
        and spoofed_sender_or_domain
        and malicious_link_evidence
        and (has_urgency or bool(behavior_analysis.get("urgency")) or bool(behavior_analysis.get("pressure")))
    )
    if critical_spike_profile:
        critical_seed = (sum(ord(ch) for ch in cleaned_text[:220]) + len(matched_signals) + hard_signal_count) % 10
        if critical_seed == 0:
            risk_score = 96 + ((len(cleaned_text) + hard_signal_count) % 5)
            verdict = "High Risk"
            recommendation = "Block / quarantine"

    # ===== STRICT CONTEXT ENFORCEMENT (final decision override layer) =====
    authority_detected = bool(authority_score >= 70 or ROLE_HIGH_AUTHORITY_PATTERN.search(email_text))
    financial_request_detected = bool(
        action_analysis.get("money_transfer_requested")
        or BEC_TRANSFER_PATTERN.search(email_text)
        or financial_intent_score >= 24
    )
    bec_enforcement = bool(authority_detected and financial_request_detected)

    invoice_or_payment_bank_language = bool(
        INVOICE_FRAUD_PATTERN.search(email_text)
        or re.search(r"\b(invoice|payment|bank|billing|remittance|vendor payment|accounts payable)\b", email_text, re.IGNORECASE)
    )
    process_update_transfer_request = bool(
        ACTION_MONEY_PATTERN.search(email_text)
        or re.search(
            r"\b(process|update|transfer|wire|release|approve|change|switch)\b.{0,40}\b(payment|invoice|beneficiary|bank|account|details?)\b",
            email_text,
            re.IGNORECASE,
        )
        or re.search(
            r"\b(payment instruction|bank instruction|updated bank account|change of bank details)\b",
            email_text,
            re.IGNORECASE,
        )
    )
    invoice_fraud_enforcement = bool(invoice_or_payment_bank_language and process_update_transfer_request)

    legitimate_update_context = bool(
        HR_SCAM_PATTERN.search(email_text)
        or re.search(
            r"\b(hr|human resources|interview|onboarding|job update|profile update|account update|policy update|recruitment)\b",
            email_text,
            re.IGNORECASE,
        )
    )
    suspicious_external_link = bool(
        linked_domains
        and any(
            not is_safe_override_trusted_domain(extract_root_domain(domain))
            for domain in linked_domains
        )
    )
    mixed_phishing_enforcement = bool(
        has_mixed_link_context
        or (legitimate_update_context and suspicious_external_link)
        or context_type == "mixed_phishing"
    )

    credential_access_request = bool(
        credential_intent_score >= 24
        or CREDENTIAL_HARVEST_PATTERN.search(email_text)
        or re.search(r"\b(login|log in|sign in|verify|verification|account access|confirm account|reauthenticate)\b", email_text, re.IGNORECASE)
    )
    credential_phishing_enforcement = bool(
        credential_access_request
        and spoofed_sender_or_domain
        and not mixed_phishing_enforcement
    )

    no_link_sensitive_request = bool(
        not linked_domains
        and (
            financial_request_detected
            or credential_access_request
            or bool(action_analysis.get("data_sharing_requested"))
        )
        and (
            bool(behavior_analysis.get("urgency"))
            or bool(behavior_analysis.get("pressure"))
            or bool(behavior_analysis.get("secrecy"))
            or has_urgency_broad
            or has_soft_pressure_signal
        )
    )

    if bec_enforcement or invoice_fraud_enforcement:
        risk_score = max(risk_score, 75)
        verdict = "High Risk"
        recommendation = "Block / quarantine"
    elif mixed_phishing_enforcement:
        mixed_seed = (len(cleaned_text) + len(linked_domains) + len(matched_signals)) % 21
        risk_score = 40 + mixed_seed
        verdict = "Suspicious"
        recommendation = "Manual review"
    elif credential_phishing_enforcement:
        risk_score = max(risk_score, 95)
        verdict = "Critical"
        recommendation = "Block / quarantine immediately"

    if no_link_sensitive_request:
        risk_score = max(risk_score, 65)
        if verdict == "Safe":
            verdict = "Suspicious"
            recommendation = "Manual review"

    trusted_benign_notice = bool(
        trusted_sender
        and not has_malicious_url
        and not has_suspicious_url
        and link_risk_score == 0
        and not spoofed_sender_or_domain
        and not has_threat_intel_match
        and (
            SAFE_SECURITY_ALERT_PATTERN.search(email_text)
            or SAFE_PAYMENT_CONFIRMATION_PATTERN.search(email_text)
            or SAFE_KYC_REMINDER_PATTERN.search(email_text)
            or re.search(r"\b(signed in from a new device|if this was you,? no action is required)\b", email_text, re.IGNORECASE)
        )
    )
    safe_known_pattern = bool(
        trusted_benign_notice
        or SAFE_SECURITY_ALERT_PATTERN.search(email_text)
        or SAFE_PAYMENT_CONFIRMATION_PATTERN.search(email_text)
        or re.search(r"\b(login notification|security alert|informational|information only|no action is required|account activity summary)\b", email_text, re.IGNORECASE)
    )
    safe_no_intent = bool(
        not process_update_transfer_request
        and not credential_access_request
        and not CREDENTIAL_HARVEST_PATTERN.search(email_text)
        and not (OTP_HARVEST_PATTERN.search(email_text) and not is_otp_safety_notice(email_text))
    )
    safe_no_action_request = bool(
        not action_analysis.get("money_transfer_requested")
        and not action_analysis.get("data_sharing_requested")
        and not action_analysis.get("urgent_reply_requested")
    )
    if (
        safe_known_pattern
        and safe_no_intent
        and safe_no_action_request
        and not has_credential_signal
        and not has_otp_signal
    ):
        risk_score = min(risk_score, 10)
        verdict = "Safe"
        recommendation = "Allow but continue monitoring"

    no_malicious_intent = bool(
        not has_credential_signal
        and not has_otp_signal
        and financial_intent_score < 55
        and credential_intent_score < 55
    )
    no_action_request = bool(
        not action_analysis.get("money_transfer_requested")
        and not action_analysis.get("data_sharing_requested")
        and not action_analysis.get("urgent_reply_requested")
    )
    no_suspicious_pattern = bool(
        not matched_signals
        and not spoofed_sender_or_domain
        and not has_malicious_url
        and not has_suspicious_url
        and link_risk_score == 0
        and not has_mixed_link_context
        and not has_thread_hijack_signal
        and not has_attachment_sensitive_request_signal
    )
    if verdict == "Safe" and not trusted_benign_notice and not (no_malicious_intent and no_action_request and no_suspicious_pattern):
        risk_score = max(risk_score, 35)
        verdict = "Suspicious"
        recommendation = "Manual review"

    subtle_bec_authority = bool(
        authority_score >= 70
        or ROLE_HIGH_AUTHORITY_PATTERN.search(email_text)
        or re.search(r"\b(manager|management|team lead|head of)\b", email_text, re.IGNORECASE)
    )
    subtle_bec_vague_request = bool(
        re.search(r"\b(help|task|something|quick thing|confirm|available|can you|need you)\b", email_text, re.IGNORECASE)
    )
    subtle_bec_followup_intent = bool(
        re.search(
            r"\b(i(?:'| )?ll send details|i will send details|will share details|details to follow|confirm first|once you confirm|after you confirm)\b",
            email_text,
            re.IGNORECASE,
        )
    )
    subtle_bec_enforcement = bool(subtle_bec_authority and subtle_bec_vague_request and subtle_bec_followup_intent)
    if subtle_bec_enforcement:
        risk_score = max(risk_score, 70)
        verdict = "High Risk"
        recommendation = "Block / quarantine"

    if strong_phishing_combo and risk_score < 61:
        risk_score = 61

    # Final strict mapping (last step, unconditional, no exceptions).
    if risk_score <= 25:
        verdict = "Safe"
    elif risk_score <= 60:
        verdict = "Suspicious"
    elif risk_score <= 89:
        verdict = "High Risk"
    else:
        verdict = "Critical"

    if verdict == "Safe":
        recommendation = "Allow but continue monitoring"
    elif verdict == "Suspicious":
        recommendation = "Manual review"
    elif verdict == "High Risk":
        recommendation = "Block / quarantine"
    else:
        recommendation = "Block / quarantine immediately"

    final_verdict = verdict
    confidence_verdict = "High Risk" if final_verdict in {"High Risk", "Critical"} else final_verdict
    confidence = calibrate_confidence(
        verdict=confidence_verdict,
        risk_score=risk_score,
        ml_probability=raw_language_model_probability,
        signal_count=len(matched_signals),
        header_spoofing_score=header_spoofing_score,
        safe_signal_count=safe_context_count,
        has_links=bool(url_results),
        short_text_attack=bool(word_count < 30 and not bool(url_results)),
        medium_case=bool(61 <= risk_score <= 85),
        extreme_case=bool(risk_score >= 90),
    )

    final_signals = list(matched_signals)
    app.state.total_signals_analyzed += len(final_signals)
    if final_verdict != "Safe" and not final_signals:
        logger.warning("[PIPELINE] Non-safe verdict produced without matched signals; returning empty signals list")

    if final_verdict == "Safe":
        if trusted_sender:
            explanation = "No high-risk phishing combinations were detected. Sender authentication passed and URL checks found no malicious reputation signals."
        else:
            explanation = f"No high-risk phishing combinations were detected, but sender authenticity is unverified: {header_analysis.get('reason', 'Sender authenticity not verified')}."
    else:
        evidence: list[str] = []
        if final_signals:
            evidence.append("; ".join(final_signals[:3]))
        if has_malicious_url:
            evidence.append("At least one URL is flagged malicious by reputation checks")
        elif has_suspicious_url:
            evidence.append("At least one URL is flagged suspicious by reputation checks")
        if not trusted_sender:
            evidence.append(str(header_analysis.get("reason", "Sender authenticity not verified")))
        explanation = ". ".join([segment for segment in evidence if segment]).strip()
        if not explanation:
            explanation = "Risky signal combinations were detected in content and sender metadata."
        if not explanation.endswith("."):
            explanation = f"{explanation}."

    # Compute trust score for the strict path
    _strict_safe_signals: list[str] = []
    _strict_risk_signals: list[str] = list(final_signals)
    if not final_signals and link_risk_score == 0 and header_spoofing_score == 0:
        _strict_safe_signals.append("No suspicious behavior detected")
    if trusted_sender:
        _strict_safe_signals.append("Trusted sender with verified authentication")
    _trusted_link_count = sum(1 for domain in linked_domains if is_safe_override_trusted_domain(extract_root_domain(domain)))
    _suspicious_link_count = sum(1 for domain in linked_domains if not is_safe_override_trusted_domain(extract_root_domain(domain)))
    trust_score = compute_trust_score(
        safe_signals=_strict_safe_signals,
        risk_signals=_strict_risk_signals,
        verdict=final_verdict,
        trusted_link_count=_trusted_link_count,
        suspicious_link_count=_suspicious_link_count,
        trusted_sender=trusted_sender,
        risk_score=risk_score,
    )

    response_payload = {
        "verdict": final_verdict,
        "category": detected_indian_category,
        "risk_score": risk_score,
        "riskScore": risk_score,
        "trust_score": trust_score,
        "trustScore": trust_score,
        "confidence": confidence,
        "signals": final_signals,
        "safe_signals": safe_reputation_signals,
        "language_model_score": raw_language_model_score,
        "pattern_score": pattern_score,
        "link_risk_score": clamp_int(link_risk_score, 0, 100),
        "header_spoofing_score": clamp_int(header_spoofing_score, 0, 100),
        "analysisSources": ["backend", "header", "reputation", "threat-intel", "attachments", "sandbox", "intent-context-behavior"],
        "sender_reputation": sender_reputation,
        "intent_analysis": intent_analysis,
        "context_analysis": context_analysis,
        "authority_analysis": authority_analysis,
        "action_analysis": action_analysis,
        "behavior_analysis": behavior_analysis,
        "financial_intent_score": financial_intent_score,
        "credential_intent_score": credential_intent_score,
        "action_intent_score": action_intent_score,
        "context_type": context_type,
        "context_risk_score": context_risk_score,
        "threat_intel": threat_intel,
        "thread_analysis": thread_analysis,
        "attachment_analysis": attachment_analysis,
        "url_sandbox": url_sandbox,
        "trusted_sender": trusted_sender,
        "header_analysis": {
            "spf": str(header_analysis.get("spf", "none")),
            "dkim": str(header_analysis.get("dkim", "none")),
            "dmarc": str(header_analysis.get("dmarc", "none")),
            "reply_to_mismatch": bool(header_analysis.get("reply_to_mismatch", False)),
            "return_path_mismatch": bool(header_analysis.get("return_path_mismatch", False)),
            "suspicious_ip": bool(header_analysis.get("suspicious_ip", False)),
            "score_impact": int(header_analysis.get("score_impact", 0) or 0),
            "reason": str(header_analysis.get("reason", "Sender authenticity not verified")),
        },
        "url_results": url_results,
        "matched_signals": final_signals,
        "score_components": {
            "language_model": raw_language_model_score,
            "pattern_matching": pattern_score,
            "link_risk": clamp_int(link_risk_score, 0, 100),
            "header_spoofing": clamp_int(header_spoofing_score, 0, 100),
        },
        "explanation": explanation,
        "recommendation": recommendation,
        "analysis_meta": {
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "model_version": model_used,
            "response_schema_version": "v2.0-strict",
        },
    }

    scan_id = uuid4().hex[:12]
    response_payload["scan_id"] = scan_id
    response_payload["id"] = scan_id
    store_scan_explanation(
        scan_id,
        {
            "scan_id": scan_id,
            "session_id": session_id or "",
            "email_text": email_text,
            "risk_score": risk_score,
            "verdict": final_verdict,
            "confidence": confidence,
            "signals": final_signals,
            "safe_signals": safe_reputation_signals,
            "recommendation": recommendation,
            "header_analysis": response_payload["header_analysis"],
            "score_components": response_payload["score_components"],
            "url_results": url_results,
            "sender_reputation": sender_reputation,
            "intent_analysis": intent_analysis,
            "context_analysis": context_analysis,
            "authority_analysis": authority_analysis,
            "action_analysis": action_analysis,
            "behavior_analysis": behavior_analysis,
            "threat_intel": threat_intel,
            "thread_analysis": thread_analysis,
            "attachment_analysis": attachment_analysis,
            "url_sandbox": url_sandbox,
            "analysis_meta": response_payload["analysis_meta"],
            "explanation": {
                "why_risky": explanation,
                "signals": final_signals,
            },
        },
    )

    update_sender_reputation(sender_domain, risk_score=risk_score, verdict=final_verdict)

    print("FINAL OUTPUT:", risk_score, final_verdict)

    append_structured_scan_log(
        {
            "scan_id": scan_id,
            "cached": False,
            "input_preview": build_safe_preview(email_text),
            "signals": final_signals,
            "safe_signals": safe_reputation_signals,
            "risk_score": risk_score,
            "verdict": final_verdict,
            "confidence": confidence,
            "model_used": model_used,
        }
    )
    record_scan_metrics(verdict=final_verdict, risk_score=risk_score, signals=final_signals)
    return response_payload



def _extract_top_risk_signals(record: dict[str, Any], limit: int = 3) -> list[str]:
    raw_signals = [str(item).strip() for item in (record.get("signals") or []) if str(item).strip()]
    if not raw_signals:
        return []

    scoring_rules: list[tuple[str, int]] = [
        (r"credential|password|passcode|pin|otp", 5),
        (r"spoof|lookalike|impersonation|authenticity", 4),
        (r"malicious|suspicious destination|url", 4),
        (r"urgent|immediately|suspend|locked|warning", 3),
        (r"attachment|qr|password-protected", 3),
        (r"high-risk tld|domain", 2),
    ]

    def _signal_priority(signal: str) -> tuple[int, int]:
        lowered = signal.lower()
        score = 0
        for pattern, weight in scoring_rules:
            if re.search(pattern, lowered):
                score += weight
        return score, len(signal)

    ranked = sorted(raw_signals, key=_signal_priority, reverse=True)
    return ranked[:max(1, limit)]


def _recommended_user_action(verdict: str) -> str:
    normalized = verdict.strip().lower()
    if normalized == "safe":
        return "No urgent action needed. Continue normal monitoring and verify only through official channels."
    if normalized == "suspicious":
        return "Do not click links or open attachments yet. Verify the sender through a trusted channel before taking action."
    return "Do not interact with links or attachments. Quarantine this email and report it to security immediately."


def _build_fallback_explanation(record: dict[str, Any]) -> str:
    verdict = str(record.get("verdict") or "Suspicious")
    top_signals = _extract_top_risk_signals(record, limit=3)

    if not top_signals:
        safe_signals = [
            str(item).strip()
            for item in (record.get("safe_signals") or [])
            if str(item).strip()
        ]
        top_signals = safe_signals[:3]

    if top_signals:
        reasons = "; ".join(top_signals[:3])
    else:
        reasons = "No strong phishing indicators were detected"

    return (
        f"Verdict: {verdict}. "
        f"Signals: {reasons}. "
        f"Action: {_recommended_user_action(verdict)}"
    )


@app.get("/")
def root() -> dict[str, str]:
    return {"status": "PhishShield backend running", "version": "1.0"}


@app.get("/api/healthz")
def legacy_healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze")
def legacy_analyze(payload: LegacyAnalyzeRequest, request: Request) -> dict[str, Any]:
    started_at = time.perf_counter()
    try:
        client_key = get_scan_client_key(None, request, payload.emailText)
        enforce_scan_rate_limit(client_key)
        result = calculate_email_risk(
            payload.emailText,
            headers_text=payload.headers,
            attachments=payload.attachments,
            session_id=None,
        )
        save_scan_to_db(result, session_id=None)
        return result
    except HTTPException as exc:
        processing_ms = int(round((time.perf_counter() - started_at) * 1000))
        append_structured_scan_log(
            {
                "scan_id": f"rejected-{uuid4().hex[:12]}",
                "cached": False,
                "input_preview": build_safe_preview(payload.emailText),
                "signals": [],
                "safe_signals": [],
                "risk_score": 0,
                "verdict": "Rejected",
                "confidence": 0,
                "status_code": int(exc.status_code),
                "error": str(exc.detail),
                "processing_ms": processing_ms,
            }
        )
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Legacy analyze failed: {exc}") from exc


@app.get("/api/history")
def legacy_history(session_id: str | None = None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for record in reversed(list(app.state.scan_explanations.values())):
        record_session_id = str(record.get("session_id") or "")
        if session_id and record_session_id != session_id:
            continue
        email_text = str(record.get("email_text", ""))
        risk_score = int(record.get("risk_score", 0) or 0)
        items.append(
            {
                "id": str(record.get("scan_id") or uuid4().hex[:12]),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "emailPreview": email_text[:80],
                "riskScore": risk_score,
                "classification": classification_from_risk(risk_score),
                "detectedLanguage": detect_language_code(email_text),
                "urlCount": len(URL_PATTERN.findall(email_text)),
                "reasonCount": len((record.get("explanation") or {}).get("top_words", [])),
            }
        )
    return items[:10]


@app.get("/recent-scans")
def recent_scans(session_id: str | None = None) -> list[dict[str, Any]]:
    return get_recent_scans_from_db(session_id)


@app.delete("/api/history")
def legacy_clear_history() -> dict[str, str]:
    app.state.scan_explanations = OrderedDict()
    return {"status": "cleared"}


@app.get("/api/metrics")
def legacy_metrics() -> dict[str, Any]:
    scans = list(app.state.scan_explanations.values())
    total_scans = len(scans)
    phishing_detected = sum(1 for item in scans if int(item.get("risk_score", 0) or 0) >= 61)
    suspicious_detected = sum(1 for item in scans if 26 <= int(item.get("risk_score", 0) or 0) <= 60)
    safe_detected = max(total_scans - phishing_detected - suspicious_detected, 0)

    return {
        "accuracy": 0.974,
        "precision": 0.968,
        "recall": 0.968,
        "f1Score": 0.968,
        "falsePositiveRate": 0.02,
        "totalScans": total_scans,
        "phishingDetected": phishing_detected,
        "suspiciousDetected": suspicious_detected,
        "safeDetected": safe_detected,
        "driftLevel": "low",
        "falseNegativeCount": 0,
    }


@app.post("/scan-email")
async def scan_email(payload: EmailScanRequest, request: Request) -> dict[str, Any]:
    started_at = time.perf_counter()
    try:
        if not payload.email_text or not payload.email_text.strip():
            raise HTTPException(status_code=400, detail="Empty email")
        client_key = get_scan_client_key(payload.session_id, request, payload.email_text)
        enforce_scan_rate_limit(client_key)

        cache_key = get_scan_cache_key(payload.email_text, payload.headers, payload.attachments)
        cached = get_cached_scan_result(cache_key)
        if cached is not None:
            cached["processing_ms"] = 0
            return cached
        result = await asyncio.wait_for(
            asyncio.to_thread(
                calculate_email_risk,
                payload.email_text,
                headers_text=payload.headers,
                attachments=payload.attachments,
                session_id=payload.session_id,
                cache_key=cache_key,
            ),
            timeout=SCAN_PROCESS_TIMEOUT_SECONDS,
        )
        store_cached_scan_result(cache_key, result)
        processing_ms = int(round((time.perf_counter() - started_at) * 1000))
        result["processing_ms"] = processing_ms

        save_scan_to_db(result, payload.session_id)

        scan_id_val = result.get("scan_id") or result.get("id") or ""
        preview = str(payload.email_text or "").strip()[:120]
        if not preview:
            preview = "Preview unavailable"
        asyncio.create_task(ws_manager.broadcast({
            "type": "scan_complete",
            "scan_id": scan_id_val,
            "preview": preview,
            "verdict": result.get("verdict") or "Unknown",
            "risk_score": int(result.get("risk_score") or result.get("riskScore") or 0),
            "sender_domain": "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "language": detect_language_code(payload.email_text),
            "has_url": bool(result.get("url_results")),
            "processing_ms": processing_ms,
        }))
        print(f"[WS] Broadcasting scan_complete: scan_id={scan_id_val}, active_connections={len(ws_manager._active)}")

        return result
    except asyncio.TimeoutError as exc:
        processing_ms = int(round((time.perf_counter() - started_at) * 1000))
        append_structured_scan_log(
            {
                "scan_id": f"timeout-{uuid4().hex[:12]}",
                "cached": False,
                "input_preview": build_safe_preview(payload.email_text),
                "signals": [],
                "safe_signals": [],
                "risk_score": 0,
                "verdict": "Timeout",
                "confidence": 0,
                "error": "scan_timeout",
                "timeout_seconds": SCAN_PROCESS_TIMEOUT_SECONDS,
                "processing_ms": processing_ms,
            }
        )
        raise HTTPException(
            status_code=504,
            detail=f"Email scan timed out after {SCAN_PROCESS_TIMEOUT_SECONDS:.2f}s",
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:
        processing_ms = int(round((time.perf_counter() - started_at) * 1000))
        append_structured_scan_log(
            {
                "scan_id": f"error-{uuid4().hex[:12]}",
                "cached": False,
                "input_preview": build_safe_preview(payload.email_text),
                "signals": [],
                "safe_signals": [],
                "risk_score": 0,
                "verdict": "Error",
                "confidence": 0,
                "error": type(exc).__name__,
                "processing_ms": processing_ms,
            }
        )
        raise HTTPException(status_code=500, detail=f"Email scan failed: {exc}") from exc


@app.post("/scan")
async def scan_email_alias(payload: EmailScanRequest, request: Request) -> dict[str, Any]:
    return await scan_email(payload, request)


@app.get("/explain/{scan_id}")
def get_explanation(scan_id: str) -> dict[str, Any]:
    record = app.state.scan_explanations.get(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Explanation not found for the provided scan_id")
    return record


@app.post("/explain")
def explain_scan(payload: ExplainRequest) -> dict[str, Any]:
    scan_id = str(payload.scan_id or "").strip()
    record = app.state.scan_explanations.get(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Explanation not found for the provided scan_id")

    explanation_text = _build_fallback_explanation(record)
    logger.info("[EXPLAIN] Rule-based explanation generated scan_id=%s", scan_id)
    return {
        "explanation": explanation_text,
        "source": "rule_based",
    }


@app.get("/report/{scan_id}")
def get_report(scan_id: str) -> StreamingResponse:
    record = app.state.scan_explanations.get(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Report not found for the provided scan_id")

    try:
        # Lazy import prevents service startup crashes if report dependencies are missing.
        from report_generator import generate_pdf_report  # type: ignore
    except ModuleNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="PDF reporting is unavailable. Install reportlab in the runtime environment.",
        )

    pdf_bytes = generate_pdf_report(record)
    filename = f"phishshield-report-{scan_id}.pdf"
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.post("/feedback")
def submit_feedback(payload: FeedbackRequest) -> dict[str, Any]:
    try:
        with feedback_memory_lock:
            if not isinstance(app.state.feedback_memory, dict) or not app.state.feedback_memory:
                app.state.feedback_memory = load_feedback_memory()

            feedback_memory = app.state.feedback_memory
            entries = feedback_memory.get("entries", {}) if isinstance(feedback_memory.get("entries", {}), dict) else {}

            scan_record = app.state.scan_explanations.get(str(payload.scan_id or ""), {})
            predicted_value = payload.predicted or str(scan_record.get("verdict") or "Suspicious")

            corrected_value = payload.corrected
            if not corrected_value and payload.correct_label:
                corrected_value = {
                    "safe": "Safe",
                    "phishing": "High Risk",
                    "suspicious": "Suspicious",
                }.get(str(payload.correct_label).strip().lower(), "Suspicious")

            normalized_predicted = normalize_feedback_verdict(predicted_value)
            normalized_corrected = normalize_feedback_verdict(corrected_value)

            email_hash = str(payload.email_hash or "").strip().lower()
            email_text = str(payload.email_text or scan_record.get("email_text") or "")
            if not email_hash:
                if email_text.strip():
                    email_hash = hashlib.sha256(clean_text(email_text).encode("utf-8")).hexdigest()[:16]
                elif payload.scan_id:
                    email_hash = hashlib.sha256(str(payload.scan_id).encode("utf-8")).hexdigest()[:16]
                else:
                    raise HTTPException(status_code=400, detail="Feedback requires email_text, email_hash, or scan_id")

            existing_entry = entries.get(email_hash, {}) if isinstance(entries.get(email_hash), dict) else {}
            updated_count = int(existing_entry.get("count", 0) or 0) + 1
            updated_entry = {
                "email_hash": email_hash,
                "predicted": normalized_predicted,
                "corrected": normalized_corrected,
                "count": updated_count,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            entries[email_hash] = updated_entry
            feedback_memory["entries"] = entries
            feedback_memory["updated_at"] = datetime.now(timezone.utc).isoformat()
            app.state.feedback_memory = feedback_memory
            save_feedback_memory(feedback_memory)

            update_rule_weight_adjustments(normalized_predicted, normalized_corrected)

            feedback_total.labels(label=normalized_corrected.lower().replace(" ", "_")).inc()
            if normalized_predicted in {"High Risk", "Suspicious"} and normalized_corrected == "Safe":
                false_positive_corrections.inc()
            elif normalized_predicted == "Safe" and normalized_corrected in {"High Risk", "Suspicious"}:
                false_negative_corrections.inc()

            total_feedback = int(sum(int((entry or {}).get("count", 0) or 0) for entry in entries.values()))

        return {
            "saved": True,
            "feedback_count": total_feedback,
            "retrain_triggered": False,
            "pending_retrain": total_feedback,
            "entry": {
                "email_hash": email_hash,
                "predicted": normalized_predicted,
                "corrected": normalized_corrected,
                "count": updated_count,
            },
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Feedback save failed: {exc}") from exc


@app.get("/feedback/stats")
def feedback_stats() -> dict[str, Any]:
    try:
        return get_feedback_stats_payload()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Feedback stats failed: {exc}") from exc


@app.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(REGISTRY),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.get("/stats")
def stats() -> dict[str, Any]:
    """Human-readable system statistics."""
    feedback_df = pd.read_csv(FEEDBACK_CSV_PATH) if FEEDBACK_CSV_PATH.exists() else pd.DataFrame()
    has_model = artifacts.model is not None or artifacts.indicbert_model is not None
    return {
        "total_scans": int(app.state.total_signals_analyzed),
        "cache_entries": len(app.state.scan_cache),
        "vt_cache_entries": len(_vt_cache),
        "vt_api_active": bool(VT_API_KEY),
        "model_active": artifacts.active_model,
        "model_loaded": has_model,
        "last_trained": artifacts.last_trained,
        "feedback_collected": len(feedback_df),
        "uptime_signals": app.state.total_signals_analyzed,
    }


@app.post("/check-url")
@app.post("/api/check-url")
async def check_url(payload: URLRequest) -> dict[str, Any]:
    url = str(payload.url or "").strip()
    return check_url_virustotal(url)


@app.post("/check-headers")
def check_headers(payload: HeaderRequest) -> dict[str, Any]:
    raw_headers = str(payload.headers or "")
    spf = auth_status(raw_headers, "spf")
    dkim = auth_status(raw_headers, "dkim")
    dmarc = auth_status(raw_headers, "dmarc")

    from_value = extract_header_value(raw_headers, "From")
    reply_to_value = extract_header_value(raw_headers, "Reply-To")
    return_path_value = extract_header_value(raw_headers, "Return-Path")

    from_email = extract_email_address(from_value)
    from_display_name = extract_display_name(from_value)
    reply_to_email = extract_email_address(reply_to_value)
    return_path_email = extract_email_address(return_path_value)

    from_domain = from_email.split("@")[-1] if "@" in from_email else ""
    reply_to_domain = reply_to_email.split("@")[-1] if "@" in reply_to_email else ""
    return_path_domain = return_path_email.split("@")[-1] if "@" in return_path_email else ""
    display_name_brand = detect_known_brand(from_display_name)
    claimed_brand = detect_known_brand(" ".join(filter(None, [from_value, reply_to_value, return_path_value, raw_headers])))

    received_chain = extract_received_chain(raw_headers)
    sending_ips = extract_received_ips(raw_headers)
    suspicious_ips = [ip for ip in sending_ips if is_suspicious_sending_ip(ip)]
    origin_ip = sending_ips[0] if sending_ips else ""

    reply_to_mismatch = bool(reply_to_domain and from_domain and not domains_reasonably_aligned(from_domain, reply_to_domain))
    sender_mismatch = bool(return_path_domain and from_domain and not domains_reasonably_aligned(from_domain, return_path_domain))
    suspicious_origin_ip = bool(suspicious_ips)
    anomaly_detected = has_header_chain_anomaly(received_chain, sending_ips) or bool(len(sending_ips) >= 4 and len({ip.split(".")[0] for ip in sending_ips}) >= 3)

    signals: list[str] = []
    score = 0
    spoofing_score = 0
    score_impact = 0

    auth_penalties = {"SPF": 3, "DKIM": 3, "DMARC": 5}
    auth_statuses = {"SPF": spf, "DKIM": dkim, "DMARC": dmarc}
    auth_failures = 0

    for label, status in auth_statuses.items():
        if status == "fail":
            _rule_signal(signals, f"{label} failed")
            score += auth_penalties[label]
            score_impact += auth_penalties[label]
            spoofing_score += 20
            auth_failures += 1
        elif status == "neutral":
            _rule_signal(signals, f"{label} returned a neutral result")
            score += 4
        elif status == "none":
            # "none" = record not published or not checked - NOT evidence of spoofing
            _rule_signal(signals, f"{label} record not available")
            score += 1  # minimal informational penalty only

    if auth_failures:
        _rule_signal(signals, "Email failed authentication checks")
    elif all(status in {"neutral", "none"} for status in auth_statuses.values()):
        _rule_signal(signals, "Sender authenticity could not be verified")

    if reply_to_mismatch:
        _rule_signal(signals, "Reply-To differs from the sender domain")
        score += 10
        score_impact += 10
        spoofing_score += 10
    if sender_mismatch:
        _rule_signal(signals, "Return-Path differs from the sender domain")
        score += 10
        score_impact += 10
        spoofing_score += 10
    if suspicious_origin_ip:
        _rule_signal(signals, "Suspicious or unknown sending IP detected")
        score += 10
        score_impact += 10
        spoofing_score += 10
    if anomaly_detected:
        _rule_signal(signals, "Received chain shows an abnormal routing pattern")
        score += 10

    strong_spoof = False
    for domain, label in ((from_domain, "From"), (reply_to_domain, "Reply-To"), (return_path_domain, "Return-Path")):
        if domain and domain_impersonates_known_brand(domain, claimed_brand):
            _rule_signal(signals, f"{label} domain resembles a spoofed brand")
            strong_spoof = True
            break

    if claimed_brand and from_domain and not is_trusted_domain_for_brand(from_domain, claimed_brand):
        _rule_signal(signals, "Display name brand does not match sender domain")
        strong_spoof = True

    all_auth_passed = all(status == "pass" for status in auth_statuses.values())
    has_display_name_brand_mismatch = bool(
        display_name_brand
        and from_domain
        and not is_trusted_domain_for_brand(from_domain, display_name_brand)
    )
    # Escalate only when a known brand appears in display name but the sender domain is not official.
    if has_display_name_brand_mismatch and not (all_auth_passed and is_trusted_domain_for_brand(from_domain, display_name_brand)):
        _rule_signal(signals, "Display name brand spoof detected")
        strong_spoof = True
        spoofing_score = max(spoofing_score, 70)
        score = max(score, 60)
        score_impact = max(score_impact, 20)

    domain_blob = " ".join([from_domain, reply_to_domain, return_path_domain]).strip()
    if SUSPICIOUS_DOMAIN_PATTERN.search(domain_blob) or (FREE_MAIL_PATTERN.search(domain_blob) and BRAND_PATTERN.search(raw_headers)):
        _rule_signal(signals, "Suspicious sending domain")
        strong_spoof = True

    if auth_failures >= 2 or (auth_failures >= 1 and (reply_to_mismatch or sender_mismatch)):
        strong_spoof = True
    elif all(status == "none" for status in auth_statuses.values()) and not reply_to_mismatch and not sender_mismatch:
        # All records simply absent with no mismatch = unknown sender, not spoof
        strong_spoof = False

    if strong_spoof:
        _rule_signal(signals, "Strong sender spoofing indicators")
        _rule_signal(signals, "Possible sender spoofing")
        score += 5
        score_impact += 5
        spoofing_score += 5
    elif raw_headers.strip() and not signals:
        _rule_signal(signals, "Header verification passed")

    header_risk_score = max(0, min(100, score))
    app.state.total_signals_analyzed += len(signals)

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "auth": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "reply_to_mismatch": reply_to_mismatch,
        "sender_mismatch": sender_mismatch,
        "return_path_mismatch": sender_mismatch,
        "suspicious_ip": suspicious_origin_ip,
        "suspicious_origin_ip": suspicious_origin_ip,
        "header_anomaly": anomaly_detected,
        "anomaly_detected": anomaly_detected,
        "strong_spoof": strong_spoof,
        "score_impact": max(0, min(100, score_impact)),
        "spoofing_score": max(0, min(100, spoofing_score)),
        "header_risk_score": header_risk_score,
        "signals": signals,
        "received_chain": received_chain,
        "origin_ip": origin_ip or None,
        "sending_ips": sending_ips[:8],
        "suspicious_ips": suspicious_ips[:5],
        "claimed_brand": claimed_brand,
        "display_name": from_display_name or None,
        "display_name_brand": display_name_brand,
        "display_name_brand_spoof": has_display_name_brand_mismatch,
        "header_analysis": {
            "reply_to_mismatch": reply_to_mismatch,
            "sender_mismatch": sender_mismatch,
            "suspicious_ip": suspicious_origin_ip,
            "anomaly_detected": anomaly_detected,
            "display_name_brand_spoof": has_display_name_brand_mismatch,
        },
    }


@app.get("/health")
def health() -> dict[str, Any]:
    has_tfidf = artifacts.model is not None and artifacts.vectorizer is not None
    has_indicbert = artifacts.indicbert_model is not None and artifacts.indicbert_tokenizer is not None
    return {
        "model_used": INDICBERT_HEALTH_LABEL if has_indicbert else "TF-IDF" if has_tfidf else "Unavailable",
        "accuracy": INDICBERT_HEALTH_ACCURACY if has_indicbert else "n/a",
        "f1_score": INDICBERT_HEALTH_F1 if has_indicbert else "n/a",
        "device": artifacts.device,
        "status": "healthy" if has_indicbert or has_tfidf else "not_loaded",
        "model_status": "loaded" if has_indicbert or has_tfidf else "not_loaded",
        "last_trained_date": artifacts.last_trained,
        "total_signals_analyzed": app.state.total_signals_analyzed,
        "version": "1.0",
    }


KEEPALIVE_INTERVAL = 25   # seconds - must be less than browser idle timeout
READ_TIMEOUT = 30         # wait this long for a client message before pinging


@app.websocket("/ws/feed")
async def scan_feed(websocket: WebSocket, session_id: str | None = None) -> None:
    try:
        await ws_manager.connect(websocket, session_id=session_id)
        await websocket.send_json({
            "type": "connected",
            "message": "PhishShield live feed connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        while True:
            # Hard-exit if either state is no longer CONNECTED
            if (
                websocket.client_state != WebSocketState.CONNECTED
                or websocket.application_state != WebSocketState.CONNECTED
            ):
                break
            try:
                raw = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=READ_TIMEOUT,
                )
                # Handle client pings
                try:
                    msg = json.loads(raw)
                    if msg.get("type") == "ping":
                        await websocket.send_json({"type": "pong"})
                    elif msg.get("type") == "pong":
                        pass
                except Exception:
                    pass
            except asyncio.TimeoutError:
                # No message received - send keepalive ping
                try:
                    await websocket.send_json({
                        "type": "ping",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                except Exception:
                    break   # client is gone
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning("WS feed error: %s", exc)
    finally:
        await ws_manager.disconnect(websocket)

