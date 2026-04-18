import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "../lib/api";
import type { ScoreBucket } from "../lib/types";

export function useScoreDistribution(hours: number = 24) {
  return useQuery({
    queryKey: ["score-dist", hours],
    queryFn: () =>
      fetchApi<ScoreBucket[]>("/v1/analytics/score-distribution", {
        hours,
      }),
    refetchInterval: 15000,
  });
}