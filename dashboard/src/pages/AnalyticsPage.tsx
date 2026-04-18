import { useState } from "react";
import { useTimeline } from "../hooks/useTimeline";
import { useTopThreats } from "../hooks/useTopThreats";
import { useTopEndpoints } from "../hooks/useTopEndpoints";
import { useScoreDistribution } from "../hooks/useScoreDistribution";
import BlockRateLine from "../components/charts/BlockRateLine";
import ScoreHistogram from "../components/charts/ScoreHistogram";
import TopThreatsBar from "../components/charts/TopThreatsBar";
import LoadingState from "../components/shared/LoadingState";
import ErrorState from "../components/shared/ErrorState";
import EmptyState from "../components/shared/EmptyState";
import { formatScore, scoreColor } from "../lib/utils";

/*
AnalyticsPage is the deep-dive page with complex SQL-backed charts.

This page exists specifically to prove PostgreSQL depth in interviews.
Every chart here maps to a PostgreSQL query using window functions,
FILTER clauses, date_trunc, etc.

WHY THE TIME RANGE BUTTONS (24h / 7d / 30d)?
Different time ranges need different insights:
- 24h: "What's happening right now?"
- 7d: "Any weekly patterns?"
- 30d: "Long-term trends?"

Changing the hours value re-triggers all hooks with the new value.
React Query automatically refetches with the updated queryKey.
*/
export default function AnalyticsPage() {
  const [hours, setHours] = useState(24);

  const { data: timeline, isLoading, error, refetch } = useTimeline(hours);
  const { data: threats } = useTopThreats(hours);
  const { data: endpoints } = useTopEndpoints(hours);
  const { data: scores } = useScoreDistribution(hours);

  if (isLoading) return <LoadingState />;
  if (error)
    return (
      <ErrorState
        message="Failed to load analytics data"
        onRetry={refetch}
      />
    );

  return (
    <div className="space-y-6">
      {/* Header with time range selector */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">
          Analytics
        </h1>
        <div className="flex gap-2">
          {[
            { label: "24h", value: 24 },
            { label: "7d", value: 168 },
            { label: "30d", value: 720 },
          ].map((option) => (
            <button
              key={option.label}
              onClick={() => setHours(option.value)}
              className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                hours === option.value
                  ? "bg-blue-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:bg-gray-700"
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {/* Block Rate Over Time */}
      {timeline && timeline.length > 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-1">
            Block Rate Over Time
          </h2>
          <p className="text-xs text-gray-500 mb-4">
            Powered by: date_trunc + FILTER + GROUP BY
          </p>
          <BlockRateLine data={timeline} />
        </div>
      ) : (
        <EmptyState
          title="No timeline data"
          message="Traffic timeline will appear here after requests are processed."
        />
      )}

      {/* Score Distribution */}
      {scores && scores.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-1">
            Threat Score Distribution
          </h2>
          <p className="text-xs text-gray-500 mb-4">
            Powered by: CASE expression bucketing
          </p>
          <ScoreHistogram data={scores} />
        </div>
      )}

      {/* Top Threats + Top Endpoints side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Top Threatening Fingerprints */}
        {threats && threats.length > 0 ? (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-1">
              Top Threats
            </h2>
            <p className="text-xs text-gray-500 mb-4">
              Powered by: GROUP BY + HAVING + AVG
            </p>
            <TopThreatsBar data={threats} />
          </div>
        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <EmptyState
              title="No threats"
              message="No high-score fingerprints detected yet."
            />
          </div>
        )}

        {/* Top Targeted Endpoints */}
        {endpoints && endpoints.length > 0 ? (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-1">
              Top Targeted Endpoints
            </h2>
            <p className="text-xs text-gray-500 mb-4">
              Powered by: GROUP BY path + COUNT FILTER
            </p>
            <div className="space-y-2">
              {endpoints.map((ep) => (
                <div
                  key={ep.path}
                  className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg"
                >
                  <div>
                    <p className="font-mono text-xs text-gray-300">
                      {ep.path}
                    </p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      {ep.total_requests} requests ·{" "}
                      {ep.blocked_count} blocked
                    </p>
                  </div>
                  <span
                    className={`font-mono text-sm font-bold ${scoreColor(ep.avg_threat_score)}`}
                  >
                    {formatScore(ep.avg_threat_score)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <EmptyState
              title="No attack targets"
              message="No endpoints have been targeted yet."
            />
          </div>
        )}
      </div>
    </div>
  );
}