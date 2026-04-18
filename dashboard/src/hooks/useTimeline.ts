import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "../lib/api";
import type { TimelineBucket } from "../lib/types";

export function useTimeline(hours: number = 24) {
  return useQuery({
    queryKey: ["timeline", hours],
    queryFn: () =>
      fetchApi<TimelineBucket[]>("/v1/analytics/timeline", {
        hours,
      }),
    refetchInterval: 10000,
  });
}