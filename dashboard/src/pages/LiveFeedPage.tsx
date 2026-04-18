import { useLiveFeed } from "../hooks/useLiveFeed";
import LiveFeedTable from "../components/tables/LiveFeedTable";

/*
LiveFeedPage shows real-time requests as they happen.

It uses the useLiveFeed hook which maintains a WebSocket
connection to the backend. Every request that passes
through Vigil shows up here instantly.

WHY PAUSE BUTTON?
When studying a specific request in the table, new events
keep pushing it down. Pause freezes the list so you can
read without it moving.

WHY CLEAR BUTTON?
After running a load test, you might have 200 events in
the table. Clear wipes them so you can start fresh.

The connection indicator (green/red dot) tells you if
the WebSocket is connected. If red, the backend is down
or the worker hasn't published any events yet.
*/
export default function LiveFeedPage() {
  const {
    events,
    isConnected,
    isPaused,
    togglePause,
    clearEvents,
  } = useLiveFeed();

  return (
    <div className="space-y-4">
      {/* Header with controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <h1 className="text-2xl font-bold text-white">
            Live Traffic Feed
          </h1>
          {/* Connection status indicator */}
          <div className="flex items-center gap-2 text-xs">
            <div
              className={`w-2 h-2 rounded-full ${
                isConnected
                  ? "bg-green-500 animate-pulse"
                  : "bg-red-500"
              }`}
            />
            <span className="text-gray-500">
              {isConnected ? "Connected" : "Reconnecting..."}
            </span>
          </div>
        </div>

        {/* Pause and Clear buttons */}
        <div className="flex gap-2">
          <button
            onClick={togglePause}
            className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
              isPaused
                ? "bg-green-800 text-green-200 hover:bg-green-700"
                : "bg-yellow-800 text-yellow-200 hover:bg-yellow-700"
            }`}
          >
            {isPaused ? "▶ Resume" : "⏸ Pause"}
          </button>
          <button
            onClick={clearEvents}
            className="px-3 py-1.5 text-xs rounded-lg bg-gray-800 text-gray-300 hover:bg-gray-700 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Event count */}
      <p className="text-xs text-gray-500">
        Showing {events.length} most recent events
        {isPaused && (
          <span className="ml-2 text-yellow-400">
            (paused)
          </span>
        )}
      </p>

      {/* The live feed table */}
      {events.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center">
          <p className="text-gray-500 text-sm">
            Waiting for events...
          </p>
          <p className="text-gray-600 text-xs mt-2">
            Make sure the background worker is running:
            python -m Vigil.workers.stream_consumer
          </p>
        </div>
      ) : (
        <LiveFeedTable events={events} />
      )}
    </div>
  );
}