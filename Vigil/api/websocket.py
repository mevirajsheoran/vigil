"""
WebSocket for real-time dashboard live feed.

HOW IT WORKS:
1. Browser opens WebSocket connection to /ws/live-feed
2. Server subscribes to Redis Pub/Sub channel "vigil:live_feed"
3. Background worker publishes events to that channel
4. Server receives events and forwards to browser

WHY get_message() INSTEAD OF listen():
listen() is a blocking generator — it waits forever for the
next message and never gives control back to FastAPI.
Under load this causes timeouts and dropped connections.

get_message() checks once and returns immediately whether
a message arrived or not. We loop manually with asyncio.sleep()
between checks. This gives FastAPI time to handle other requests
between each check, keeping the connection alive.

The 0.05 second sleep means we check 20 times per second.
Fast enough for real-time feel, gentle enough not to 
overwhelm the server.
"""

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from Vigil.cache.client import get_redis
from Vigil.config import logger

router = APIRouter()


@router.websocket("/ws/live-feed")
async def live_feed(websocket: WebSocket):
    """Real-time event stream for dashboard."""
    await websocket.accept()
    logger.info("WebSocket client connected")

    redis = get_redis()
    pubsub = redis.pubsub()

    try:
        await pubsub.subscribe("vigil:live_feed")
        logger.info("Subscribed to vigil:live_feed")

        while True:
            try:
                # Check for a message — returns immediately
                # whether a message arrived or not
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=0.0,
                )

                if message and message["type"] == "message":
                    # Forward to browser
                    await websocket.send_text(message["data"])

                # Sleep 50ms then check again
                # This prevents busy-waiting and keeps 
                # FastAPI responsive
                await asyncio.sleep(0.05)

            except WebSocketDisconnect:
                # Browser closed the tab or navigated away
                logger.info("WebSocket client disconnected")
                break
            except Exception as e:
                logger.warning(
                    "WebSocket send error",
                    extra={"error": str(e)},
                )
                break

    except Exception as e:
        logger.error(
            "WebSocket setup error",
            extra={"error": str(e)},
        )
    finally:
        try:
            await pubsub.unsubscribe("vigil:live_feed")
        except Exception:
            pass
        logger.info("WebSocket cleaned up")