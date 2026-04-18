import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "../lib/api";
import type { FingerprintSummary } from "../lib/types";

export function useFingerprints(limit: number = 50) {
  return useQuery({
    queryKey: ["fingerprints", limit],
    queryFn: () =>
      fetchApi<FingerprintSummary[]>("/v1/fingerprints", {
        limit,
      }),
    refetchInterval: 5000,
  });
}