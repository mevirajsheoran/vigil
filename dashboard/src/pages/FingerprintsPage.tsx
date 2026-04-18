import { useState } from "react";
import { useFingerprints } from "../hooks/useFingerprints";
import { useQueryClient } from "@tanstack/react-query";
import { postApi } from "../lib/api";
import FingerprintTable from "../components/tables/FingerprintTable";
import LoadingState from "../components/shared/LoadingState";
import ErrorState from "../components/shared/ErrorState";
import EmptyState from "../components/shared/EmptyState";

/*
FingerprintsPage lists all detected fingerprints.

WHY useQueryClient?
After blocking or allowlisting a fingerprint, we want
the table to immediately reflect the change. useQueryClient
lets us manually tell React Query "this cached data is stale,
fetch it again now." Without this, the table wouldn't update
until the next automatic refetch (every 5 seconds).

blockedOnly filter: lets admins quickly see ONLY the
fingerprints that are currently blocked.
*/
export default function FingerprintsPage() {
  const [blockedOnly, setBlockedOnly] = useState(false);
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useFingerprints(
    50
  );

  if (isLoading) return <LoadingState />;
  if (error)
    return (
      <ErrorState
        message="Failed to load fingerprints"
        onRetry={refetch}
      />
    );

  // Apply blocked-only filter on the frontend
  // (avoids an extra API call)
  const filtered = blockedOnly
    ? (data || []).filter((fp) => fp.is_blocked)
    : data || [];

  const handleBlock = async (hash: string) => {
    try {
      await postApi(
        `/v1/fingerprints/${hash}/block`,
        { reason: "manual_block", duration_hours: 24 }
      );
      // Tell React Query to refetch fingerprints immediately
      queryClient.invalidateQueries({
        queryKey: ["fingerprints"],
      });
    } catch (e) {
      alert("Failed to block fingerprint");
    }
  };

  const handleAllow = async (hash: string) => {
    try {
      await postApi(`/v1/fingerprints/${hash}/allow`, {});
      queryClient.invalidateQueries({
        queryKey: ["fingerprints"],
      });
    } catch (e) {
      alert("Failed to allowlist fingerprint");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">
          Fingerprints
        </h1>

        {/* Filter toggle */}
        <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
          <input
            type="checkbox"
            checked={blockedOnly}
            onChange={(e) => setBlockedOnly(e.target.checked)}
            className="rounded"
          />
          Blocked only
        </label>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          title="No fingerprints found"
          message={
            blockedOnly
              ? "No blocked fingerprints. All traffic is currently allowed."
              : "No fingerprints detected yet. Send requests to /v1/analyze to start."
          }
        />
      ) : (
        /*
        We pass handleBlock and handleAllow into FingerprintTable
        so the table rows can trigger these actions.
        We need to update FingerprintTable to accept these props.
        */
        <FingerprintTableWithActions
          data={filtered}
          onBlock={handleBlock}
          onAllow={handleAllow}
        />
      )}
    </div>
  );
}

/*
WHY A SEPARATE COMPONENT HERE?
The original FingerprintTable only shows data and a "Details" link.
On this page, we also need Block and Allow buttons per row.
Instead of modifying FingerprintTable (which would break its usage
elsewhere), we create a local wrapper that adds the action buttons.
This is the "Open/Closed Principle" — open for extension, closed for modification.
*/
function FingerprintTableWithActions({
  data,
  onBlock,
  onAllow,
}: {
  data: ReturnType<typeof useFingerprints>["data"] & object[];
  onBlock: (hash: string) => void;
  onAllow: (hash: string) => void;
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 text-xs uppercase border-b border-gray-800">
            <th className="py-3 px-4 text-left">
              Fingerprint
            </th>
            <th className="py-3 px-4 text-right">
              Threat Score
            </th>
            <th className="py-3 px-4 text-center">
              Status
            </th>
            <th className="py-3 px-4 text-right">
              Actions
            </th>
          </tr>
        </thead>
        <tbody>
          {data.map((fp) => (
            <tr
              key={fp.fingerprint}
              className="border-b border-gray-800 hover:bg-gray-800/30 transition-colors"
            >
              <td className="py-3 px-4 font-mono text-xs text-gray-300">
                {fp.fingerprint}
              </td>
              <td
                className={`py-3 px-4 text-right font-mono font-bold ${
                  fp.threat_score >= 0.85
                    ? "text-red-400"
                    : fp.threat_score >= 0.65
                    ? "text-yellow-400"
                    : "text-green-400"
                }`}
              >
                {fp.threat_score.toFixed(2)}
              </td>
              <td className="py-3 px-4 text-center">
                {fp.is_blocked ? (
                  <span className="text-xs px-2 py-1 rounded bg-red-900/50 text-red-300">
                    Blocked
                  </span>
                ) : fp.is_allowlisted ? (
                  <span className="text-xs px-2 py-1 rounded bg-green-900/50 text-green-300">
                    Allowlisted
                  </span>
                ) : (
                  <span className="text-xs px-2 py-1 rounded bg-gray-800 text-gray-300">
                    Active
                  </span>
                )}
              </td>
              <td className="py-3 px-4 text-right">
                <div className="flex justify-end gap-2">
                  {!fp.is_blocked && (
                    <button
                      onClick={() =>
                        onBlock(fp.fingerprint)
                      }
                      className="text-xs px-2 py-1 rounded bg-red-900/40 text-red-300 hover:bg-red-900/70 transition-colors"
                    >
                      Block
                    </button>
                  )}
                  {!fp.is_allowlisted && (
                    <button
                      onClick={() =>
                        onAllow(fp.fingerprint)
                      }
                      className="text-xs px-2 py-1 rounded bg-green-900/40 text-green-300 hover:bg-green-900/70 transition-colors"
                    >
                      Allow
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}