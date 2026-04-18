import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import type { AttackTypeCount } from "../../lib/types";

interface Props {
  data: AttackTypeCount[];
}

/*
AttackTypePie shows the distribution of attack types as a pie chart.

Used on the Analytics page to show what percentage of attacks are enumeration,
credential stuffing, etc.
*/
const COLORS = ["#f87171", "#fbbf24", "#60a5fa", "#4ade80", "#a78bfa"];

export default function AttackTypePie({ data }: Props) {
  return (
    <ResponsiveContainer width="100%" height={250}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={90}
          paddingAngle={3}
          dataKey="count"
          nameKey="attack_type"
        >
          {data.map((_, index) => (
            <Cell
              key={`cell-${index}`}
              fill={COLORS[index % COLORS.length]}
            />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            backgroundColor: "#1a1a1a",
            border: "1px solid #333",
            borderRadius: "8px",
          }}
        />
        <Legend
          wrapperStyle={{ fontSize: "12px", color: "#888" }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}