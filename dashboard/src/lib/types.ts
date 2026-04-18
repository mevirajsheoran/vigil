export interface OverviewMetrics {
  total_requests: number;
  allowed: number;
  blocked: number;
  challenged: number;
  shadowbanned: number;
  suspicious: number;
  unique_fingerprints: number;
  unique_ips: number;
  avg_threat_score: number;
  block_rate_pct: number;
}

export interface TimelineBucket {
  time_bucket: string;
  total: number;
  blocked: number;
  allowed: number;
  unique_fingerprints: number;
  avg_score: number;
}

export interface FingerprintSummary {
  fingerprint: string;
  threat_score: number;
  is_blocked: boolean;
  is_allowlisted: boolean;
}

export interface AttackSession {
  id: string;
  fingerprint_hash: string;
  type: string;
  severity: string;
  status: string;
  total_requests: number;
  total_ips: number;
  started_at: string;
  ai_confidence: number;
  ai_explanation: string | null;
  created_at: string;
}

export interface ThreatDetail {
  fingerprint_hash: string;
  total_requests: number;
  times_blocked: number;
  distinct_ips: number;
  avg_threat_score: number;
  max_threat_score: number;
  first_seen: string;
  last_seen: string;
  unique_paths: number;
  failure_rate_pct: number;
}

export interface ScoreBucket {
  bucket: string;
  count: number;
}

export interface AttackTypeCount {
  attack_type: string;
  count: number;
  percentage: number;
}

export interface LiveEvent {
  fingerprint: string;
  ip: string;
  method: string;
  path: string;
  threat_score: number;
  action: string;
  timestamp: number;
}

export interface TargetedEndpoint {
  path: string;
  total_requests: number;
  blocked_count: number;
  avg_threat_score: number;
}