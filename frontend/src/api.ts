export interface ScanRequest {
  iac_content: string;
  dockerfile_content: string;
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
}

export interface AuditLogEntry {
  report: string;
  timestamp: string;
  total_checks: number;
  passed: number;
  failed: number;
  overall_risk: string;
}

export interface AuditReportDetail {
  summary: { total_checks: number; passed: number; failed: number; overall_risk: string };
  details: DetailedFinding[];
  remediation_summary?: string;
}

const BASE = "/api";
const TOKEN_KEY = "devsecops_token";

function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function login(username: string, password: string): Promise<boolean> {
  const res = await fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) return false;
  const data = await res.json();
  if (data.success) {
    localStorage.setItem(TOKEN_KEY, data.token);
    return true;
  }
  return false;
}

export function logout() {
  localStorage.removeItem(TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return getToken() !== null;
}

export async function submitScan(data: ScanRequest): Promise<ScanResult> {
  const res = await fetch(`${BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error("Scan failed");
  return res.json();
}

export async function fetchScans(): Promise<ScanResult[]> {
  const res = await fetch(`${BASE}/scans`, {
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error("Failed to fetch scans");
  return res.json();
}

export async function fetchAuditLog(risk?: string): Promise<AuditLogEntry[]> {
  const params = risk ? `?risk=${risk}` : "";
  const res = await fetch(`${BASE}/audit-log${params}`, {
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error("Failed to fetch audit log");
  return res.json();
}

export async function fetchAuditDetail(reportKey: string): Promise<AuditReportDetail> {
  const res = await fetch(`${BASE}/audit-log/${reportKey}`, {
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error("Failed to fetch report detail");
  return res.json();
}
