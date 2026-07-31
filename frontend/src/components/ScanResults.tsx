import type { ScanResult } from "../api";

interface Props {
  result: ScanResult;
}

export default function ScanResults({ result }: Props) {
  const isBlocked = result.status === "blocked";

  return (
    <div
      className={`rounded-lg border p-4 ${
        isBlocked ? "border-red-800 bg-red-950/30" : "border-emerald-800 bg-emerald-950/30"
      }`}
    >
      <div className="flex items-center gap-2 mb-3">
        <span
          className={`text-2xl ${isBlocked ? "" : ""}`}
        >
          {isBlocked ? "\u274C" : "\u2705"}
        </span>
        <h3 className="text-lg font-bold">
          {isBlocked ? "BLOCKED" : "PASSED"}
        </h3>
        <span className="text-sm text-gray-500 ml-auto">
          {new Date(result.timestamp).toLocaleTimeString()}
        </span>
      </div>

      {isBlocked && result.findings.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm text-gray-400">Findings:</p>
          {result.findings.map((f, i) => (
            <div
              key={i}
              className={`text-sm px-3 py-1.5 rounded ${
                f.rule === "CRITICAL"
                  ? "bg-red-900/50 text-red-300"
                  : "bg-orange-900/50 text-orange-300"
              }`}
            >
              {f.rule}: {f.count} issue{f.count > 1 ? "s" : ""}
            </div>
          ))}
        </div>
      )}

      {!isBlocked && (
        <p className="text-sm text-emerald-400">
          No security issues found. Deployment can proceed.
        </p>
      )}
    </div>
  );
}
