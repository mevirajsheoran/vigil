"""
WebSocket for real-time dashboard traffic feed.

HOW IT WORKS:
1. Dashboard opens WebSocket connection to /ws/live-feed
2. Server subscribes to Redis Pub/Sub channel "vigil:live_feed"
3. Background worker publishes events to that channel
4. Server forwards events to dashboard in real-time

WHY REDIS PUB/SUB:
If you run 3 API instances, each has its own WebSocket
connections. Redis Pub/Sub broadcasts to ALL instances,
so every dashboard gets every event regardless of which
API instance it's connected to.

RECONNECTION:
If the WebSocket disconnects (network blip, server restart),
the dashboard's useLiveFeed hook automatically reconnects
after 3 seconds (handled on the frontend side).
"""

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from Vigil.cache.client import get_redis
from Vigil.config import logger

router = APIRouter()


@router.websocket("/ws/live-feed")
async def live_feed(websocket: WebSocket):
    """
    Real-time event feed for the dashboard.

    Each connected dashboard gets a stream of JSON events:
    {
        "fingerprint": "a1b2c3d4...",
        "ip": "1.2.3.4",
        "method": "GET",
        "path": "/api/users/5",
        "threat_score": 0.87,
        "action": "block",
        "timestamp": 1705000001.5
    }
    """
    await websocket.accept()

    redis = get_redis()
    pubsub = redis.pubsub()
    await pubsub.subscribe("vigil:live_feed")

    try:
        # Listen for messages from Redis Pub/Sub
        # and forward them to the WebSocket client
        while True:
            message = await pubsub.get_message(
                ignore_subscribe_messages=True,
                timeout=1.0,
            )
            if message and message["type"] == "message":
                data = message["data"]
                await websocket.send_text(data)

            # Small sleep to prevent busy-waiting
            # when there are no messages
            await asyncio.sleep(0.1)

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.warning(
            "WebSocket error",
            extra={"error": str(e)},
        )
    finally:
        await pubsub.unsubscribe("vigil:live_feed")