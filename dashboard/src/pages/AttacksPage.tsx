import { useState } from "react";
import { useAttacks } from "../hooks/useAttacks";
import AttackTable from "../components/tables/AttackTable";
import LoadingState from "../components/shared/LoadingState";
import ErrorState from "../components/shared/ErrorState";
import EmptyState from "../components/shared/EmptyState";

/*
AttacksPage lists all detected attack sessions.

WHY STATUS FILTER?
Admins want to quickly see:
- "active" attacks that need attention
- "resolved" attacks for historical reference
- "false_positive" attacks to review detection accuracy

The filter is passed as a query parameter to the backend,
so only matching records are returned. This is more efficient
than fetching all attacks and filtering on the frontend.
*/
export default function AttacksPage() {
  const [statusFilter, setStatusFilter] = useState<
    string | undefined
  >(undefined);

  const { data, isLoading, error, refetch } = useAttacks(20);

  if (isLoading) return <LoadingState />;
  if (error)
    return (
      <ErrorState
        message="Failed to load attack sessions"
        onRetry={refetch}
      />
    );

  // Filter on frontend since our hook doesn't support
  // dynamic status filtering yet
  const filtered = statusFilter
    ? (data || []).filter((a) => a.status === statusFilter)
    : data || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">
          Attack Sessions
        </h1>

        {/* Status filter buttons */}
        <div className="flex gap-2">
          {[
            { label: "All", value: undefined },
            { label: "Active", value: "active" },
            { label: "Mitigated", value: "mitigated" },
            {
              label: "False Positive",
              value: "false_positive",
            },
          ].map((option) => (
            <button
              key={option.label}
              onClick={() => setStatusFilter(option.value)}
              className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                statusFilter === option.value
                  ? "bg-blue-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:bg-gray-700"
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          title="No attack sessions found"
          message={
            statusFilter
              ? `No ${statusFilter} attacks found. Try a different filter.`
              : "No attacks detected yet. Run python scripts/seed_data.py to generate demo attacks."
          }
        />
      ) : (
        <AttackTable data={filtered} />
      )}
    </div>
  );
}