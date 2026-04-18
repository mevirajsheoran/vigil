import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { ThreatDetail } from "../../lib/types";
import { formatScore, scoreColor } from "../../lib/utils";

interface Props {
  data: ThreatDetail[];
}

/*
TopThreatsBar shows the top threatening fingerprints by average threat score as a bar chart.

Used on the Analytics page to show which fingerprints are the most dangerous.
*/
export default function TopThreatsBar({ data }: Props) {
  const chartData = data.map((item) => ({
    fingerprint: item.fingerprint_hash.slice(0, 8),
    avgScore: item.avg_threat_score,
    requests: item.total_requests,
  }));

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={chartData} layout="vertical">
        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
        <XAxis type="number" stroke="#666" fontSize={12} />
        <YAxis
          type="category"
          dataKey="fingerprint"
          stroke="#666"
          fontSize={11}
          width={100}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "#1a1a1a",
            border: "1px solid #333",
            borderRadius: "8px",
          }}
          formatter={(value: number) => [`${formatScore(value)}`, "Avg Threat Score"]}
        />
        <Bar
          dataKey="avgScore"
          fill="#60a5fa"
          radius={[0, 4, 4, 0]}
          name="Avg Threat Score"
        />
      </BarChart>
    </ResponsiveContainer>
  );
}