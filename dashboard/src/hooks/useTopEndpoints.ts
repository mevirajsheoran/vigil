import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "../lib/api";
import type { TargetedEndpoint } from "../lib/types";

export function useTopEndpoints(hours: number = 24) {
  return useQuery({
    queryKey: ["top-endpoints", hours],
    queryFn: () =>
      fetchApi<TargetedEndpoint[]>(
        "/v1/analytics/top-targeted-endpoints",
        { hours }
      ),
    refetchInterval: 15000,
  });
}