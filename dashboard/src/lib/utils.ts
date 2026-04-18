export function formatNumber(n: number): string {
  return n.toLocaleString();
}

export function formatScore(score: number): string {
  return score.toFixed(2);
}

export function scoreColor(score: number): string {
  if (score >= 0.85) return "text-red-400";
  if (score >= 0.65) return "text-yellow-400";
  if (score >= 0.4) return "text-orange-400";
  return "text-green-400";
}

export function severityColor(severity: string): string {
  switch (severity) {
    case "high":
      return "bg-red-900/40 text-red-300 border-red-800";
    case "medium":
      return "bg-yellow-900/40 text-yellow-300 border-yellow-800";
    case "low":
      return "bg-blue-900/40 text-blue-300 border-blue-800";
    default:
      return "bg-gray-800 text-gray-300 border-gray-700";
  }
}