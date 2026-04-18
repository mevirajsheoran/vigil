import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "../lib/api";

export interface FingerprintHistory {
  minute: string;
  requests: number;
  avg_score: number;
  blocked: number;
}

export function useFingerprintHistory(
  fingerprintHash: string,
  hours: number = 24
) {
  return useQuery({
    queryKey: ["fingerprint-history", fingerprintHash, hours],
    queryFn: () =>
      fetchApi<FingerprintHistory[]>(
        `/v1/analytics/fingerprint/${fingerprintHash}/history`,
        { hours }
      ),
    enabled: !!fingerprintHash,
    refetchInterval: 10000,
  });
}