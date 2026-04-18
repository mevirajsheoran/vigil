import { Link } from "react-router-dom";
import type { AttackSession } from "../../lib/types";
import { severityColor } from "../../lib/utils";

interface Props {
  data: AttackSession[];
}

/*
AttackTable shows a list of detected attack sessions as cards.

WHY CARDS instead of a regular table?
Attack sessions have variable-length AI explanations.
A fixed-column table would look broken with long text.
Cards flex to fit the content naturally.

Each card is color-coded by severity:
- High   → red border
- Medium → yellow border
- Low    → blue border

The "View Details" link navigates to /attacks/:id which
renders AttackDetailPage with full information and
feedback buttons.
*/
export default function AttackTable({ data }: Props) {
  return (
    <div className="space-y-3">
      {data.map((attack) => (
        <div
          key={attack.id}
          className={`border rounded-lg p-5 ${severityColor(
            attack.severity
          )}`}
        >
          {/* Top row: type + badges + timestamp */}
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <span className="text-sm font-bold uppercase">
                {attack.type.replace("_", " ")}
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-black/20">
                {attack.severity}
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-black/20">
                {attack.status}
              </span>
            </div>
            <span className="text-xs opacity-60">
              {attack.started_at
                ? new Date(attack.started_at).toLocaleString()
                : "Unknown time"}
            </span>
          </div>

          {/* Stats row */}
          <div className="flex items-center gap-6 text-xs opacity-80 mb-3">
            <span>Requests: {attack.total_requests}</span>
            <span>IPs: {attack.total_ips}</span>
            {attack.ai_confidence && (
              <span>
                AI Confidence:{" "}
                {(attack.ai_confidence * 100).toFixed(0)}%
              </span>
            )}
          </div>

          {/* AI explanation if available */}
          {attack.ai_explanation && (
            <p className="text-sm opacity-90 leading-relaxed mb-3">
              {attack.ai_explanation}
            </p>
          )}

          {/* View Details link */}
          <div className="mt-2">
            <Link
              to={`/attacks/${attack.id}`}
              className="text-xs px-3 py-1.5 rounded bg-black/20 hover:bg-black/40 transition-colors"
            >
              View Details →
            </Link>
          </div>
        </div>
      ))}
    </div>
  );
}