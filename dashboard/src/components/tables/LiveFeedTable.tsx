import type { LiveEvent } from "../../lib/types";
import { formatScore, scoreColor } from "../../lib/utils";

interface Props {
  events: LiveEvent[];
}

/*
LiveFeedTable shows real-time request events from the WebSocket.

Used on the Live Feed page to show every request as it happens, including fingerprint,
path, method, and threat score.
*/
export default function LiveFeedTable({ events }: Props) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-auto max-h-[600px]">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-850 text-gray-500 text-xs uppercase border-b border-gray-800 sticky top-0">
            <th className="py-3 px-4 text-left">Fingerprint</th>
            <th className="py-3 px-4 text-left">Method</th>
            <th className="py-3 px-4 text-left">Path</th>
            <th className="py-3 px-4 text-right">Score</th>
            <th className="py-3 px-4 text-center">Action</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, index) => (
            <tr
              key={index}
              className="border-b border-gray-800 hover:bg-gray-850 transition-colors"
            >
              <td className="py-2 px-4 font-mono text-xs text-gray-300">
                {event.fingerprint.slice(0, 12)}...
              </td>
              <td className="py-2 px-4">
                <span className="text-xs font-medium px-2 py-0.5 rounded bg-gray-800 text-gray-300">
                  {event.method}
                </span>
              </td>
              <td className="py-2 px-4 text-gray-300 font-mono text-xs truncate max-w-[300px]">
                {event.path}
              </td>
              <td className={`py-2 px-4 text-right font-mono font-bold ${scoreColor(event.threat_score)}`}>
                {formatScore(event.threat_score)}
              </td>
              <td className="py-2 px-4 text-center">
                <span
                  className={`text-xs px-2 py-0.5 rounded ${
                    event.action === "block"
                      ? "bg-red-900/50 text-red-300"
                      : event.action === "challenge"
                      ? "bg-yellow-900/50 text-yellow-300"
                      : "bg-green-900/50 text-green-300"
                  }`}
                >
                  {event.action}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}