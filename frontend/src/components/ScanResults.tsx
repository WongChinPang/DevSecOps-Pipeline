import type { ScanResult } from "../api";

interface Props {
  result: ScanResult;
}

const RISK_COLORS: Record<string, string> = {
  CRITICAL: "border-red-600 bg-red-950/40 text-red-300",
  HIGH: "border-orange-600 bg-orange-950/40 text-orange-300",
  MEDIUM: "border-amber-600 bg-amber-950/40 text-amber-300",
  LOW: "border-blue-600 bg-blue-950/40 text-blue-300",
};

export default function ScanResults({ result }: Props) {
  const isBlocked = result.status === "blocked";
  const hasDetails = result.details && result.details.length > 0;

  return (
    <div
      className={`rounded-lg border p-4 ${
        isBlocked ? "border-red-800 bg-red-950/20" : "border-emerald-800 bg-emerald-950/20"
      }`}
    >
      <div className="flex items-center gap-2 mb-4">
        <span className="text-2xl">{isBlocked ? "\u274C" : "\u2705"}</span>
        <h3 className="text-lg font-bold">
          {isBlocked ? "BLOCKED — Security Issues Found" : "PASSED — No Issues Detected"}
        </h3>
        <span className="text-xs text-gray-500 ml-auto">
          Scan #{result.id}
        </span>
      </div>

      {isBlocked && (
        <p className="text-sm text-red-400 mb-4">
          This configuration contains security vulnerabilities that would prevent deployment.
          Fix the issues below and scan again.
        </p>
      )}

      {hasDetails && (
        <div className="space-y-3">
          {result.details.map((d, i) => (
            <div
              key={i}
              className={`border rounded-lg p-3 ${RISK_COLORS[d.risk_level] || "border-gray-700 bg-gray-900 text-gray-300"}`}
            >
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-mono font-bold px-1.5 py-0.5 rounded bg-black/30">
                  {d.rule_id}
                </span>
                <span className={`text-xs font-semibold px-1.5 py-0.5 rounded ${
                  d.risk_level === "CRITICAL" ? "bg-red-700 text-red-200" :
                  d.risk_level === "HIGH" ? "bg-orange-700 text-orange-200" :
                  d.risk_level === "MEDIUM" ? "bg-amber-700 text-amber-200" :
                  "bg-blue-700 text-blue-200"
                }`}>
                  {d.risk_level}
                </span>
              </div>
              <p className="text-sm mt-1">{d.finding}</p>
              <p className="text-xs mt-1 opacity-70">
                Fix: {d.remediation}
              </p>
            </div>
          ))}
        </div>
      )}

      {isBlocked && !hasDetails && (
        <div className="space-y-2">
          {result.findings.map((f, i) => (
            <div
              key={i}
              className={`text-sm px-3 py-1.5 rounded ${
                f.rule === "CRITICAL"
                  ? "bg-red-900/50 text-red-300"
                  : "bg-orange-900/50 text-orange-300"
              }`}
            >
              {f.rule}: {f.count} issue{f.count > 1 ? "s" : ""} detected
            </div>
          ))}
        </div>
      )}

      {!isBlocked && (
        <p className="text-sm text-emerald-400">
          No security issues found. This configuration is safe to deploy.
        </p>
      )}

      {result.code_findings && result.code_findings.length > 0 && (
        <div className="mt-4 pt-4 border-t border-gray-700">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-lg">{'\u26A0\uFE0F'}</span>
            <h4 className="text-sm font-semibold text-amber-300">
              Application Code Warnings ({result.code_findings.length})
            </h4>
          </div>
          <p className="text-xs text-amber-400/70 mb-3">
            These are non-blocking warnings. Fix them to improve code security.
          </p>
          <div className="space-y-2">
            {result.code_findings.map((cf, i) => (
              <div key={i}
                className={`border rounded-lg p-3 ${RISK_COLORS[cf.risk_level] || "border-gray-700 bg-gray-900 text-gray-300"}`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono font-bold px-1.5 py-0.5 rounded bg-black/30">
                    {cf.rule_id}
                  </span>
                  <span className={`text-xs font-semibold px-1.5 py-0.5 rounded ${
                    cf.risk_level === "CRITICAL" ? "bg-red-700 text-red-200" :
                    cf.risk_level === "HIGH" ? "bg-orange-700 text-orange-200" :
                    cf.risk_level === "MEDIUM" ? "bg-amber-700 text-amber-200" :
                    "bg-blue-700 text-blue-200"
                  }`}>
                    {cf.risk_level}
                  </span>
                  <span className="text-xs text-gray-500 ml-auto">Line {cf.line}</span>
                </div>
                <p className="text-xs text-gray-400 font-mono mt-1 truncate">{cf.code}</p>
                <p className="text-sm mt-1">{cf.finding}</p>
                <p className="text-xs mt-1 opacity-70">Fix: {cf.remediation}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
