import { useState, useEffect, useRef, useCallback } from "react";
import { getWebSocketUrl } from "../lib/api";
import type { LiveEvent } from "../lib/types";

/*
useLiveFeed manages the WebSocket connection to the backend.

WHY useRef for pausedRef?
When the user clicks "Pause", we set isPaused to true.
But inside the WebSocket onmessage callback, the stale
closure would still see isPaused as false (old value).

useRef solves this — ref.current always has the LATEST value,
even inside old closures. We update both:
  - isPaused (state) → triggers re-render so button label changes
  - pausedRef.current → what the WebSocket callback actually checks

WHY MAX_EVENTS = 200?
Storing infinite events would eventually crash the browser tab.
200 is enough to show meaningful history without memory issues.
We keep the most recent 200, dropping older ones.

WHY reconnect after 3 seconds?
If the backend restarts or network blips, the WebSocket closes.
Without reconnection, the dashboard goes dead forever.
3 seconds is short enough to feel responsive, long enough
to not spam reconnection attempts.
*/

const MAX_EVENTS = 200;

export function useLiveFeed() {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const pausedRef = useRef(false);

  useEffect(() => {
    let ws: WebSocket;
    let reconnectTimeout: ReturnType<typeof setTimeout>;

    function connect() {
      ws = new WebSocket(getWebSocketUrl());

      ws.onopen = () => {
        setIsConnected(true);
      };

      ws.onclose = () => {
        setIsConnected(false);
        // Try to reconnect after 3 seconds
        reconnectTimeout = setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        setIsConnected(false);
      };

      ws.onmessage = (event) => {
        // If paused, ignore incoming events
        if (pausedRef.current) return;

        try {
          const data: LiveEvent = JSON.parse(event.data);
          setEvents((prev) =>
            [data, ...prev].slice(0, MAX_EVENTS)
          );
        } catch (e) {
          console.error("Failed to parse WebSocket message:", e);
        }
      };
    }

    connect();

    // Cleanup when component unmounts
    return () => {
      clearTimeout(reconnectTimeout);
      ws?.close();
    };
  }, []);

  const togglePause = useCallback(() => {
    setIsPaused((prev) => {
      pausedRef.current = !prev;
      return !prev;
    });
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  return {
    events,
    isConnected,
    isPaused,
    togglePause,
    clearEvents,
  };
}