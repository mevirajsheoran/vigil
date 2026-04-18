import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "../lib/api";
import type { ThreatDetail } from "../lib/types";

export function useTopThreats(hours: number = 24) {
  return useQuery({
    queryKey: ["top-threats", hours],
    queryFn: () =>
      fetchApi<ThreatDetail[]>("/v1/analytics/top-threats", {
        hours,
      }),
    refetchInterval: 10000,
  });
}