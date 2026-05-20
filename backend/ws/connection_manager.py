from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import WebSocket
from starlette.websockets import WebSocketState

logger = logging.getLogger("phishshield.ws")


class ConnectionManager:
    """Manages active WebSocket connections for live scan feed."""

    def __init__(self) -> None:
        self._active: dict[str, WebSocket] = {}
        self._session_by_ws: dict[WebSocket, str] = {}
        self._lock = asyncio.Lock()
        self._pending: list[tuple[dict[str, Any], datetime]] = []
        self._PENDING_MAX = 20
        self._PENDING_TTL_SECONDS = 60

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
            logger.info("[WS] Connection accepted; replaying %s pending events", len(fresh))

        if replaced_ws is not None and replaced_ws is not ws:
            try:
                await replaced_ws.close(code=1000)
            except Exception:
                pass

        for event in fresh:
            try:
                await ws.send_json(event)
            except Exception:
                break

        logger.info("[WS] Client connected (%s active)", len(self._active))
        return session_key

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            session_key = self._session_by_ws.pop(ws, None)
            if session_key and self._active.get(session_key) is ws:
                self._active.pop(session_key, None)
            else:
                for key, active_ws in list(self._active.items()):
                    if active_ws is ws:
                        self._active.pop(key, None)
                        break
            logger.info("[WS] Client disconnected (%s active)", len(self._active))

    async def broadcast(self, message: dict[str, Any]) -> None:
        async with self._lock:
            snapshot = list(self._active.items())

        if not snapshot:
            async with self._lock:
                self._pending.append((message, datetime.now(timezone.utc)))
                if len(self._pending) > self._PENDING_MAX:
                    self._pending = self._pending[-self._PENDING_MAX :]
            logger.debug("[WS] No active connections; event queued")
            return

        dead: list[tuple[str, WebSocket]] = []
        for session_key, ws in snapshot:
            if not self._is_open(ws):
                dead.append((session_key, ws))
                continue
            try:
                await asyncio.wait_for(ws.send_json(message), timeout=3.0)
            except (asyncio.TimeoutError, Exception):
                dead.append((session_key, ws))

        if dead:
            async with self._lock:
                for session_key, ws in dead:
                    if self._active.get(session_key) is ws:
                        self._active.pop(session_key, None)
                    self._session_by_ws.pop(ws, None)

    async def ping_all(self) -> None:
        return
