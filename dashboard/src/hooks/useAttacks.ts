import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "../lib/api";
import type { AttackSession } from "../lib/types";

export function useAttacks(limit: number = 20) {
  return useQuery({
    queryKey: ["attacks", limit],
    queryFn: () =>
      fetchApi<AttackSession[]>("/v1/attacks", {
        limit,
      }),
    refetchInterval: 10000,
  });
}