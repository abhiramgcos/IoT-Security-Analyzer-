#!/usr/bin/env python3
"""
Test script to verify WebSocket traffic endpoint
"""
import asyncio
import websockets
import json

async def test_websocket():
    uri = "ws://localhost:8000/api/traffic/live/eth0"
    print(f"Connecting to {uri}...")
    
    try:
        async with websockets.connect(uri) as websocket:
            print("✅ Connected!")
            
            # Receive a few packets
            for i in range(10):
                msg = await websocket.recv()
                data = json.loads(msg)
                print(f"Packet {i+1}: {data.get('protocol')} {data.get('src')} -> {data.get('dst')}")
                
            print("\n✅ Test passed!")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    asyncio.run(test_websocket())
