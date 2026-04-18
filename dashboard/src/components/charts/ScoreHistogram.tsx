import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { ScoreBucket } from "../../lib/types";

interface Props {
  data: ScoreBucket[];
}

/*
ScoreHistogram shows the distribution of threat scores as a bar chart.

Used on the Analytics page to show how many requests fall into each score bucket.
*/
export default function ScoreHistogram({ data }: Props) {
  return (
    <ResponsiveContainer width="100%" height={250}>
      <BarChart data={data}>
        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
        <XAxis dataKey="bucket" stroke="#666" fontSize={10} />
        <YAxis stroke="#666" fontSize={12} />
        <Tooltip
          contentStyle={{
            backgroundColor: "#1a1a1a",
            border: "1px solid #333",
            borderRadius: "8px",
          }}
        />
        <Bar
          dataKey="count"
          fill="#60a5fa"
          radius={[4, 4, 0, 0]}
          name="Requests"
        />
      </BarChart>
    </ResponsiveContainer>
  );
}