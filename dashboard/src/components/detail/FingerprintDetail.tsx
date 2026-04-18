import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "../../lib/api";
import type { ThreatDetail } from "../../lib/types";
import { formatScore, scoreColor } from "../../lib/utils";
import LoadingState from "../shared/LoadingState";
import  ErrorState  from "../shared/ErrorState";

/*
FingerprintDetail shows detailed information about a single fingerprint.

Used on the /fingerprints/:id page to show full details about a fingerprint, including:
- Average threat score
- Total requests
- Times blocked
- Distinct IPs used
- First/last seen times
- Unique paths accessed
- Failure rate
*/
export default function FingerprintDetail() {
  const { id } = useParams<{ id: string }>();

  const { data: fingerprint, isLoading, error, refetch } = useQuery({
    queryKey: ["fingerprint", id],
    queryFn: () =>
      fetchApi<ThreatDetail[]>("/v1/analytics/top-threats", { hours: 24 }).then((threats) =>
        threats.find((t) => t.fingerprint_hash === id)
      ),
    enabled: !!id,
  });

  if (isLoading) return <LoadingState />;
  if (error) return <ErrorState message="Failed to load fingerprint details" onRetry={refetch} />;
  if (!fingerprint) return <ErrorState message="Fingerprint not found" />;

  return (
    <div className="space-y-6">
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-2xl font-bold text-white">Fingerprint Detail</h1>
            <p className="text-gray-500 font-mono text-sm mt-1">
              {fingerprint.fingerprint_hash}
            </p>
          </div>
          <div className={`text-xl font-bold ${scoreColor(fingerprint.avg_threat_score)}`}>
            {formatScore(fingerprint.avg_threat_score)}
          </div>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-sm mb-4">
          <div>
            <p className="text-xs opacity-60">Total Requests</p>
            <p>{fingerprint.total_requests}</p>
          </div>
          <div>
            <p className="text-xs opacity-60">Times Blocked</p>
            <p>{fingerprint.times_blocked}</p>
          </div>
          <div>
            <p className="text-xs opacity-60">Distinct IPs</p>
            <p>{fingerprint.distinct_ips}</p>
          </div>
          <div>
            <p className="text-xs opacity-60">Failure Rate</p>
            <p>{fingerprint.failure_rate_pct.toFixed(1)}%</p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-xs opacity-60">First Seen</p>
            <p>{new Date(fingerprint.first_seen).toLocaleString()}</p>
          </div>
          <div>
            <p className="text-xs opacity-60">Last Seen</p>
            <p>{new Date(fingerprint.last_seen).toLocaleString()}</p>
          </div>
        </div>
      </div>
    </div>
  );
}