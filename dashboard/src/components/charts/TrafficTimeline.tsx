import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { TimelineBucket } from "../../lib/types";

interface Props {
  data: TimelineBucket[];
}

/*
TrafficTimeline shows allowed vs blocked requests over time as a stacked area chart.

WHY ResponsiveContainer? It makes the chart automatically resize to fit its parent container.
Perfect for dashboard layouts where screen sizes vary.

WHY AreaChart instead of LineChart? Area charts are better for showing proportions
(how much of the total traffic is blocked vs allowed).
*/
export default function TrafficTimeline({ data }: Props) {
  const chartData = data.map((item) => ({
    time: new Date(item.time_bucket).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    }),
    allowed: item.allowed,
    blocked: item.blocked,
  }));

  return (
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
        <XAxis dataKey="time" stroke="#666" fontSize={12} />
        <YAxis stroke="#666" fontSize={12} />
        <Tooltip
          contentStyle={{
            backgroundColor: "#1a1a1a",
            border: "1px solid #333",
            borderRadius: "8px",
          }}
        />
        <Area
          type="monotone"
          dataKey="allowed"
          stackId="1"
          stroke="#4ade80"
          fill="#4ade8033"
          name="Allowed"
        />
        <Area
          type="monotone"
          dataKey="blocked"
          stackId="1"
          stroke="#f87171"
          fill="#f8717133"
          name="Blocked"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}