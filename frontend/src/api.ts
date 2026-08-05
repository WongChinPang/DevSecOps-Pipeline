export interface ScanRequest {
  iac_content: string;
  dockerfile_content: string;
  trigger_pipeline: boolean;
}

export interface DetailedFinding {
  rule_id: string;
  status: string;
  risk_level: string;
  finding: string;
  remediation: string;
}

export interface ScanResult {
  id: string;
  timestamp: string;
  status: "passed" | "blocked";
  findings: { rule: string; count: number }[];
  details: DetailedFinding[];
  iac_snippet: string;
  dockerfile_snippet: string;
  pipeline?: {
    success: boolean;
    results: { file: string; committed: boolean }[];
    pipeline_url: string | null;
  };
}

const BASE = "/api";

export async function submitScan(data: ScanRequest): Promise<ScanResult> {
  const res = await fetch(`${BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error("Scan failed");
  return res.json();
}

export async function fetchScans(): Promise<ScanResult[]> {
  const res = await fetch(`${BASE}/scans`);
  if (!res.ok) throw new Error("Failed to fetch scans");
  return res.json();
}
