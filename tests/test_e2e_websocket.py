#!/usr/bin/env python3
"""End-to-end WebSocket broadcast test."""
import asyncio
import json
from uuid import uuid4
from typing import Optional

async def test_websocket_event():
    """Simulate frontend connecting and receiving scanned event."""
    
    try:
        import websockets
        import aiohttp
    except ImportError:
        print("❌ Required packages not installed. Install with: pip install websockets aiohttp")
        return
    
    backend_url = "http://127.0.0.1:8000"
    ws_url = "ws://127.0.0.1:8000/ws/feed"
    session_id = str(uuid4())
    
    print(f"🧪 END-TO-END TEST")
    print(f"📍 Session ID: {session_id}\n")
    
    received_events: list = []
    
    async def connect_and_wait():
        """Connect to WebSocket and wait for events."""
        print("🔌 Connecting to WebSocket...")
        async with websockets.connect(ws_url) as ws:
            print("✅ Connected!")
            
            # Wait for first message (should be ping)
            print("⏳ Waiting for broadcast... (max 10 seconds)")
            start_time = asyncio.get_event_loop().time()
            
            while asyncio.get_event_loop().time() - start_time < 10:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=1.0)
                    data = json.loads(msg)
                    print(f"📨 Received message type: {data.get('type')}")
                    
                    if data.get('type') == 'scan_complete':
                        print(f"🎯 **BROADCAST RECEIVED**")
                        print(f"   ├─ scan_id: {data.get('scan_id')}")
                        print(f"   ├─ verdict: {data.get('verdict')}")
                        print(f"   ├─ risk_score: {data.get('risk_score')}")
                        print(f"   ├─ session_id: {data.get('session_id')}")
                        print(f"   └─ category: {data.get('category')}")
                        
                        if data.get('session_id') == session_id:
                            print(f"✅ **SESSION MATCH**")
                            received_events.append(data)
                        else:
                            print(f"⚠️  Session mismatch: expected {session_id}, got {data.get('session_id')}")                        break
                    elif data.get('type') == 'ping':
                        print(f"⏰ Ping received (heartbeat), waiting for scan_complete...")
                        
                except asyncio.TimeoutError:
                    pass
    
    # Start WebSocket listener in background
    listener_task = asyncio.create_task(connect_and_wait())
    
    # Give WebSocket time to connect
    await asyncio.sleep(0.5)
    
    # Run scan
    print("\n📤 Posting scan...")
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{backend_url}/scan-email",
            json={
                "email_text": "Subject: Urgent Verify\n\nClick: http://phishing-domain.tk/verify-now",
                "session_id": session_id
            }
        ) as resp:
            result = await resp.json()
            print(f"✅ Scan complete:")
            print(f"   ├─ verdict: {result.get('verdict')}")
            print(f"   ├─ risk_score: {result.get('risk_score')}")
            print(f"   └─ returned_session_id: {result.get('session_id')}")
    
    # Wait for WebSocket event
    await listener_task
    
    # Report
    print(f"\n{'='*50}")
    if received_events:
        print(f"✅ **SUCCESS**: Received {len(received_events)} broadcast event(s)")
        print(f"👉 Frontend should now display the event in Live Feed")
    else:
        print(f"❌ **FAILED**: No broadcast received")
        print(f"👉 Check backend logs for broadcast errors")
    print(f"{'='*50}")

if __name__ == "__main__":
    asyncio.run(test_websocket_event())
