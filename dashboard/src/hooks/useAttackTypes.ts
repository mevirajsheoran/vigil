import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "../lib/api";
import type { AttackTypeCount } from "../lib/types";

export function useAttackTypes(hours: number = 24) {
  return useQuery({
    queryKey: ["attack-types", hours],
    queryFn: () =>
      fetchApi<AttackTypeCount[]>(
        "/v1/analytics/attack-type-distribution",
        { hours }
      ),
    refetchInterval: 15000,
  });
}