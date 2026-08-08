import { useState, useEffect } from "react";
import type { AuditLogEntry, AuditReportDetail, DetailedFinding } from "../api";
import { fetchAuditLog, fetchAuditDetail } from "../api";

const RISK_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-900/50 text-red-300 border-red-700",
  HIGH: "bg-orange-900/50 text-orange-300 border-orange-700",
  MEDIUM: "bg-amber-900/50 text-amber-300 border-amber-700",
  LOW: "bg-blue-900/50 text-blue-300 border-blue-700",
};

const RISK_DETAIL_COLORS: Record<string, string> = {
  CRITICAL: "border-red-600 bg-red-950/40 text-red-300",
  HIGH: "border-orange-600 bg-orange-950/40 text-orange-300",
  MEDIUM: "border-amber-600 bg-amber-950/40 text-amber-300",
  LOW: "border-blue-600 bg-blue-950/40 text-blue-300",
};

const FILTERS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [filter, setFilter] = useState("ALL");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [detail, setDetail] = useState<AuditReportDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const loadEntries = async (risk?: string) => {
    const data = await fetchAuditLog(risk === "ALL" ? undefined : risk);
    setEntries(data);
    setExpanded(null);
    setDetail(null);
  };

  useEffect(() => {
    loadEntries(filter);
  }, [filter]);

  const toggleExpand = async (reportKey: string) => {
    if (expanded === reportKey) {
      setExpanded(null);
      setDetail(null);
      return;
    }
    setExpanded(reportKey);
    setLoadingDetail(true);
    try {
      const fileName = reportKey.replace("reports/", "");
      const data = await fetchAuditDetail(fileName);
      setDetail(data);
    } catch {
      setDetail(null);
    }
    setLoadingDetail(false);
  };

  return (
    <div>
      <h2 className="text-lg font-semibold mb-4">Audit Reports (S3)</h2>

      <div className="flex gap-2 mb-4">
        {FILTERS.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`text-xs px-3 py-1 rounded cursor-pointer transition-colors ${
              filter === f
                ? "bg-emerald-700 text-white"
                : "bg-gray-800 text-gray-400 hover:bg-gray-700"
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 border-b border-gray-800">
              <th className="pb-2 font-medium">Report</th>
              <th className="pb-2 font-medium">Date</th>
              <th className="pb-2 font-medium">Risk</th>
              <th className="pb-2 font-medium">Passed</th>
              <th className="pb-2 font-medium">Failed</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <>
                <tr
                  key={e.report}
                  onClick={() => toggleExpand(e.report)}
                  className="border-b border-gray-800/50 hover:bg-gray-900/50 cursor-pointer transition-colors"
                >
                  <td className="py-2.5 font-mono text-xs text-gray-400 truncate max-w-[200px]">
                    {e.report.replace("reports/", "").replace(".json", "")}
                  </td>
                  <td className="py-2.5 text-gray-400">
                    {new Date(e.timestamp).toLocaleDateString()}
                  </td>
                  <td className="py-2.5">
                    <span className={`text-xs px-2 py-0.5 rounded border ${RISK_COLORS[e.overall_risk] || "bg-gray-800 text-gray-300 border-gray-700"}`}>
                      {e.overall_risk}
                    </span>
                  </td>
                  <td className="py-2.5 text-emerald-400">{e.passed}</td>
                  <td className="py-2.5 text-red-400">{e.failed}</td>
                </tr>
                {expanded === e.report && (
                  <tr>
                    <td colSpan={5} className="pb-4 pt-2">
                      {loadingDetail ? (
                        <p className="text-sm text-gray-500">Loading...</p>
                      ) : detail ? (
                        <div className="space-y-2">
                          {detail.details.map((d: DetailedFinding, i: number) => (
                            <div
                              key={i}
                              className={`border rounded-lg p-3 text-sm ${RISK_DETAIL_COLORS[d.risk_level] || "border-gray-700 bg-gray-900 text-gray-300"}`}
                            >
                              <div className="flex items-center gap-2 mb-1">
                                <span className="text-xs font-mono font-bold px-1.5 py-0.5 rounded bg-black/30">
                                  {d.rule_id}
                                </span>
                                <span className="text-xs font-semibold px-1.5 py-0.5 rounded bg-black/30">
                                  {d.risk_level}
                                </span>
                                <span className={`text-xs ${d.status === "FAIL" ? "text-red-400" : "text-emerald-400"}`}>
                                  {d.status}
                                </span>
                              </div>
                              <p className="mt-1">{d.finding}</p>
                              <p className="text-xs mt-1 opacity-70">Fix: {d.remediation}</p>
                            </div>
                          ))}
                          {detail.remediation_summary && (
                            <p className="text-xs text-gray-500 italic mt-2">
                              {detail.remediation_summary}
                            </p>
                          )}
                        </div>
                      ) : (
                        <p className="text-sm text-gray-500">Failed to load report</p>
                      )}
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>

      {entries.length === 0 && (
        <p className="text-sm text-gray-500 py-8 text-center">No audit reports found.</p>
      )}
    </div>
  );
}
