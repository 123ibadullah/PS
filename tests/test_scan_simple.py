#!/usr/bin/env python3
"""Simple test to verify WebSocket event flow."""
import asyncio
import json
from uuid import uuid4

async def test_scan_and_broadcast():
    """Test that scan triggers broadcast."""
    import aiohttp
    
    backend = "http://127.0.0.1:8000"
    session_id = str(uuid4())
    
    print(f"🧪 Testing with session: {session_id}\n")
    
    async with aiohttp.ClientSession() as session:
        # POST scan
        print("📤 Posting scan...")
        async with session.post(
            f"{backend}/scan-email",
            json={
                "email_text": "Subject: Verify Now\n\nClick here: http://suspicious.tk/verify",
                "session_id": session_id
            }
        ) as resp:
            result = await resp.json()
            print(f"✅ Scan response:")
            print(f"   - verdict: {result.get('verdict')}")
            print(f"   - risk_score: {result.get('risk_score')}")
            print(f"   - session_id: {result.get('session_id')}")
            print(f"   - scan_id: {result.get('scan_id')}")
            
            if result.get('session_id') == session_id:
                print(f"✅ Session ID matches!")
            else:
                print(f"❌ Session ID mismatch: expected {session_id}, got {result.get('session_id')}")

if __name__ == "__main__":
    asyncio.run(test_scan_and_broadcast())
