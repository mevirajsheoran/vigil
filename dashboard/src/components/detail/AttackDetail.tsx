
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "../../lib/api";
import type { AttackSession } from "../../lib/types";
import { severityColor, formatScore } from "../../lib/utils";
import LoadingState from "../shared/LoadingState";
import ErrorState from "../shared/ErrorState";

/*
AttackDetail shows detailed information about a single attack session.

Used on the /attacks/:id page to show full details about an attack, including:
- Attack type
- Severity
- Status
- Total requests
- IPs involved
- AI explanation
- Timeline of when the attack started/ended
*/
export default function AttackDetail() {
  const { id } = useParams<{ id: string }>();

  const { data: attack, isLoading, error, refetch } = useQuery({
    queryKey: ["attack", id],
    queryFn: () =>
      fetchApi<AttackSession[]>("/v1/attacks", { limit: 50 }).then((attacks) =>
        attacks.find((a) => a.id === id)
      ),
    enabled: !!id,
  });

  if (isLoading) return <LoadingState />;
  if (error) return <ErrorState message="Failed to load attack details" onRetry={refetch} />;
  if (!attack) return <ErrorState message="Attack not found" />;

  return (
    <div className="space-y-6">
      <div className={`border rounded-lg p-6 ${severityColor(attack.severity)}`}>
        <div className="flex items-center gap-3 mb-4">
          <span className="text-lg font-bold uppercase">
            {attack.type.replace("_", " ")}
          </span>
          <span className="text-xs px-2 py-1 rounded bg-black/20">
            {attack.severity}
          </span>
          <span className="text-xs px-2 py-1 rounded bg-black/20">
            {attack.status}
          </span>
        </div>

        <div className="grid grid-cols-3 gap-4 text-sm mb-4">
          <div>
            <p className="text-xs opacity-60">Started</p>
            <p>{new Date(attack.started_at).toLocaleString()}</p>
          </div>
          <div>
            <p className="text-xs opacity-60">Total Requests</p>
            <p>{attack.total_requests}</p>
          </div>
          <div>
            <p className="text-xs opacity-60">Unique IPs</p>
            <p>{attack.total_ips}</p>
          </div>
        </div>

        {attack.ai_explanation && (
          <div className="bg-black/20 rounded-lg p-4 mt-4">
            <p className="text-xs uppercase tracking-wider opacity-60 mb-2">
              AI Analysis
            </p>
            <p className="text-sm leading-relaxed">
              {attack.ai_explanation}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}