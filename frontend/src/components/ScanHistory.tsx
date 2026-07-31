import type { ScanResult } from "../api";

interface Props {
  scans: ScanResult[];
}

export default function ScanHistory({ scans }: Props) {
  if (scans.length === 0) return null;

  return (
    <div className="mt-8">
      <h2 className="text-lg font-semibold mb-3">Scan History</h2>
      <div className="space-y-2">
        {scans.map((s) => (
          <div
            key={s.id}
            className="flex items-center gap-3 bg-gray-900 border border-gray-800 rounded-lg px-4 py-3"
          >
            <span className="text-sm font-mono text-gray-500">{s.id}</span>
            <span
              className={`text-xs font-semibold px-2 py-0.5 rounded ${
                s.status === "blocked"
                  ? "bg-red-900/50 text-red-300"
                  : "bg-emerald-900/50 text-emerald-300"
              }`}
            >
              {s.status.toUpperCase()}
            </span>
            <span className="text-xs text-gray-600 ml-auto">
              {new Date(s.timestamp).toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
