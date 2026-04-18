import {
  LineChart,
  Line,
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
BlockRateLine shows block rate over time as a line chart.

Used on the Analytics page to show how block rate changes throughout the day.
*/
export default function BlockRateLine({ data }: Props) {
  const chartData = data.map((item) => ({
    time: new Date(item.time_bucket).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    }),
    blockRate: item.total > 0 ? Math.round((item.blocked / item.total) * 100) : 0,
  }));

  return (
    <ResponsiveContainer width="100%" height={250}>
      <LineChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
        <XAxis dataKey="time" stroke="#666" fontSize={12} />
        <YAxis
          stroke="#666"
          fontSize={12}
          tickFormatter={(v) => `${v}%`}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "#1a1a1a",
            border: "1px solid #333",
            borderRadius: "8px",
          }}
          formatter={(value: number) => [`${value}%`, "Block Rate"]}
        />
        <Line
          type="monotone"
          dataKey="blockRate"
          stroke="#f87171"
          strokeWidth={2}
          dot={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}