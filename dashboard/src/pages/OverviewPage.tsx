import { useOverview } from "../hooks/useOverview";
import { useTimeline } from "../hooks/useTimeline";
import { useScoreDistribution } from "../hooks/useScoreDistribution";
import { useAttackTypes } from "../hooks/useAttackTypes";
import MetricCard from "../components/cards/MetricCard";
import TrafficTimeline from "../components/charts/TrafficTimeline";
import ScoreHistogram from "../components/charts/ScoreHistogram";
import AttackTypePie from "../components/charts/AttackTypePie";
import LoadingState from "../components/shared/LoadingState";
import ErrorState from "../components/shared/ErrorState";
import EmptyState from "../components/shared/EmptyState";

/*
OverviewPage is the HOME page of the dashboard.

It shows the most important stats at a glance:
- Total requests, blocked, allowed (MetricCards)
- Traffic over time (TrafficTimeline chart)
- Score distribution (ScoreHistogram chart)
- Attack type breakdown (AttackTypePie chart)

WHY MULTIPLE HOOKS?
Each hook fetches different data. They all run in parallel
(React Query handles this automatically), so the page
loads as fast as the slowest individual request, not
the sum of all requests.

WHY CHECK overview.total_requests === 0?
If no data exists yet (fresh install, no traffic sent),
we show a helpful EmptyState instead of empty charts
that look broken.
*/
export default function OverviewPage() {
  const {
    data: overview,
    isLoading,
    error,
    refetch,
  } = useOverview(24);

  const { data: timeline } = useTimeline(24);
  const { data: scores } = useScoreDistribution(24);
  const { data: attackTypes } = useAttackTypes(24);

  if (isLoading) return <LoadingState />;
  if (error)
    return (
      <ErrorState
        message="Failed to load overview data"
        onRetry={refetch}
      />
    );
  if (!overview) return <LoadingState />;

  // No data yet — show helpful message
  if (overview.total_requests === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-white">
          Dashboard Overview
        </h1>
        <EmptyState
          title="No traffic data yet"
          message="Send requests to POST /v1/analyze to start seeing data. Run: python scripts/seed_data.py for demo data."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">
        Dashboard Overview
      </h1>

      {/* Top metric cards — 4 columns */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Total Requests"
          value={overview.total_requests}
          color="blue"
        />
        <MetricCard
          label="Allowed"
          value={overview.allowed}
          color="green"
        />
        <MetricCard
          label="Blocked"
          value={overview.blocked}
          color="red"
        />
        <MetricCard
          label="Block Rate"
          value={`${overview.block_rate_pct}%`}
          color="yellow"
        />
      </div>

      {/* Second row of metric cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Challenged"
          value={overview.challenged}
          color="yellow"
        />
        <MetricCard
          label="Unique Fingerprints"
          value={overview.unique_fingerprints}
          color="blue"
        />
        <MetricCard
          label="Unique IPs"
          value={overview.unique_ips}
          color="blue"
        />
        <MetricCard
          label="Avg Threat Score"
          value={overview.avg_threat_score.toFixed(4)}
          color="red"
        />
      </div>

      {/* Traffic timeline chart */}
      {timeline && timeline.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">
            Traffic Timeline (Last 24h)
          </h2>
          <TrafficTimeline data={timeline} />
        </div>
      )}

      {/* Bottom two charts side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {scores && scores.length > 0 && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">
              Threat Score Distribution
            </h2>
            <ScoreHistogram data={scores} />
          </div>
        )}

        {attackTypes && attackTypes.length > 0 && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">
              Attack Types
            </h2>
            <AttackTypePie data={attackTypes} />
          </div>
        )}
      </div>
    </div>
  );
}