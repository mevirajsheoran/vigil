import { Link } from "react-router-dom";
import type { FingerprintSummary } from "../../lib/types";
import { formatScore, scoreColor } from "../../lib/utils";

interface Props {
  data: FingerprintSummary[];
}

/*
FingerprintTable shows a list of fingerprints with their threat scores and status.

Used on the Fingerprints page to let users see all detected fingerprints and navigate to their detail pages.
*/
export default function FingerprintTable({ data }: Props) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-850 text-gray-500 text-xs uppercase border-b border-gray-800">
            <th className="py-3 px-4 text-left">Fingerprint</th>
            <th className="py-3 px-4 text-right">Threat Score</th>
            <th className="py-3 px-4 text-center">Status</th>
            <th className="py-3 px-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {data.map((fp) => (
            <tr
              key={fp.fingerprint}
              className="border-b border-gray-800 hover:bg-gray-850 transition-colors"
            >
              <td className="py-3 px-4 font-mono text-xs text-gray-300">
                {fp.fingerprint}
              </td>
              <td className={`py-3 px-4 text-right font-mono font-bold ${scoreColor(fp.threat_score)}`}>
                {formatScore(fp.threat_score)}
              </td>
              <td className="py-3 px-4 text-center">
                {fp.is_blocked ? (
                  <span className="text-xs px-2 py-1 rounded bg-red-900/50 text-red-300">
                    Blocked
                  </span>
                ) : fp.is_allowlisted ? (
                  <span className="text-xs px-2 py-1 rounded bg-green-900/50 text-green-300">
                    Allowlisted
                  </span>
                ) : (
                  <span className="text-xs px-2 py-1 rounded bg-gray-800 text-gray-300">
                    Active
                  </span>
                )}
              </td>
              <td className="py-3 px-4 text-right">
                <Link
                  to={`/fingerprints/${fp.fingerprint}`}
                  className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                >
                  Details →
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}