#!/usr/bin/env python3
"""Test WebSocket broadcast after scan."""
import asyncio
import json
import aiohttp
import websockets
from uuid import uuid4

async def test_websocket_broadcast():
    """Test that broadcasts are received by connected clients."""
    backend_url = "http://127.0.0.1:8000"
    ws_url = "ws://127.0.0.1:8000/ws/feed"
    
    session_id = str(uuid4())
    print(f"🧪 Testing with session_id: {session_id}")
    
    async with aiohttp.ClientSession() as session:
        # Connect to WebSocket
        async with websockets.connect(ws_url) as ws:
            print("✅ WebSocket connected")
            
            # Receive initial messages (pings, etc)
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=2)
                data = json.loads(msg)
                print(f"📨 Received: {data.get('type')}")
            except asyncio.TimeoutError:
                print("⏱️  No initial message (expected)")
            
            # Trigger a scan
            print("\n🔍 Triggering scan...")
            async with session.post(
                f"{backend_url}/scan-email",
                json={
                    "email_text": "Subject: Verify Account\n\nClick: http://suspicious-bank.tk",
                    "session_id": session_id
                }
            ) as resp:
                result = await resp.json()
                print(f"✅ Scan response: {result.get('verdict')} ({result.get('risk_score')})")
            
            # Wait for broadcast to arrive
            print("\n📡 Waiting for broadcast event...")
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=5)
                data = json.loads(msg)
                print(f"✅ **RECEIVED**: {data.get('type')}")
                print(f"   Session: {data.get('session_id')} (expected: {session_id})")
                print(f"   Scan ID: {data.get('scan_id')}")
                print(f"   Verdict: {data.get('verdict')}")
                print(f"   Risk Score: {data.get('risk_score')}")
                
                if data.get('session_id') == session_id:
                    print("✅ **SESSION ID MATCHED - BROADCAST WORKS!**")
                else:
                    print(f"❌ SESSION ID MISMATCH: got '{data.get('session_id')}', expected '{session_id}'")
            except asyncio.TimeoutError:
                print("❌ **NO BROADCAST RECEIVED - TIMEOUT**")

if __name__ == "__main__":
    asyncio.run(test_websocket_broadcast())
