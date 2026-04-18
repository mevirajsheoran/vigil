import { useEffect, useState } from "react";
import { fetchApi } from "../../lib/api";
import type { OverviewMetrics } from "../../lib/types";

/*
Header shows current block rate and system status.

It fetches overview metrics every 10 seconds to show the live block rate.
This is a simple way to show live data without WebSocket for static header info.
*/
export default function Header() {
  const [blockRate, setBlockRate] = useState<number>(0);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchBlockRate = async () => {
      try {
        const data = await fetchApi<OverviewMetrics>(
          "/v1/analytics/overview",
          { hours: 1 }
        );
        setBlockRate(data.block_rate_pct);
      } catch (e) {
        console.error("Failed to fetch block rate:", e);
      } finally {
        setIsLoading(false);
      }
    };

    fetchBlockRate();
    const interval = setInterval(fetchBlockRate, 10000);

    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-16 bg-gray-950 border-b border-gray-800 px-6 flex items-center justify-between">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-xs">
          <div
            className={`w-2 h-2 rounded-full ${
              isLoading ? "animate-pulse bg-blue-500" : "bg-green-500"
            }`}
          />
          <span className="text-gray-500">
            {isLoading ? "Loading..." : "Connected"}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500">Block Rate:</span>
          <span
            className={`text-sm font-bold ${
              blockRate > 30 ? "text-red-400" : blockRate > 15 ? "text-yellow-400" : "text-green-400"
            }`}
          >
            {isLoading ? "--" : `${blockRate.toFixed(1)}%`}
          </span>
        </div>
      </div>
    </header>
  );
}