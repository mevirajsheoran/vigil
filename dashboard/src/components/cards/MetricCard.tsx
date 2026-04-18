import { formatNumber } from "../../lib/utils";

interface Props {
  label: string;
  value: number | string;
  color: "blue" | "green" | "red" | "yellow";
}

/*
MetricCard shows a single metric (e.g., Total Requests, Blocked Requests).

Used on the Overview page to display key stats in a clean, visual way.
*/
const colorMap = {
  blue: "text-blue-400",
  green: "text-green-400",
  red: "text-red-400",
  yellow: "text-yellow-400",
};

export default function MetricCard({ label, value, color }: Props) {
  const formatted = typeof value === "number" ? formatNumber(value) : value;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
      <p className="text-xs uppercase tracking-wider text-gray-500 font-medium">
        {label}
      </p>
      <p className={`text-3xl font-bold mt-2 ${colorMap[color]}`}>
        {formatted}
      </p>
    </div>
  );
}