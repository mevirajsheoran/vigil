import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "../lib/api";
import type { OverviewMetrics } from "../lib/types";

export function useOverview(hours: number = 24) {
  return useQuery({
    queryKey: ["overview", hours],
    queryFn: () =>
      fetchApi<OverviewMetrics>("/v1/analytics/overview", {
        hours,
      }),
    refetchInterval: 5000,
  });
}