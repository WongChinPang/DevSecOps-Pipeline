import { useState, useEffect, useCallback } from "react";
import UploadForm from "./components/UploadForm";
import ScanResults from "./components/ScanResults";
import ScanHistory from "./components/ScanHistory";
import AuditLog from "./components/AuditLog";
import LoginForm from "./components/LoginForm";
import { submitScan, fetchScans, isAuthenticated, logout } from "./api";
import type { ScanRequest, ScanResult } from "./api";

type Tab = "scanner" | "audit";

export default function App() {
  const [loggedIn, setLoggedIn] = useState(isAuthenticated());
  const [tab, setTab] = useState<Tab>("scanner");
  const [latest, setLatest] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (loggedIn) {
      fetchScans().then(setHistory).catch(() => {});
    }
  }, [loggedIn]);

  const handleLogin = useCallback(() => setLoggedIn(true), []);

  const handleLogout = useCallback(() => {
    logout();
    setLoggedIn(false);
    setLatest(null);
    setHistory([]);
  }, []);

  const handleScan = useCallback(async (data: ScanRequest) => {
    setLoading(true);
    try {
      const result = await submitScan(data);
      setLatest(result);
      setHistory((prev) => [result, ...prev]);
    } catch {
      setLatest(null);
    }
    setLoading(false);
  }, []);

  if (!loggedIn) {
    return <LoginForm onLogin={handleLogin} />;
  }

  return (
    <div className="max-w-5xl mx-auto px-4 py-8">
      <header className="mb-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">DevSecOps Scanner</h1>
          <button
            onClick={handleLogout}
            className="text-xs text-gray-500 hover:text-gray-300 cursor-pointer"
          >
            Sign Out
          </button>
        </div>
        <div className="flex gap-1 mt-3">
          <button
            onClick={() => setTab("scanner")}
            className={`text-sm px-4 py-1.5 rounded-lg cursor-pointer transition-colors ${
              tab === "scanner"
                ? "bg-emerald-700 text-white"
                : "bg-gray-800 text-gray-400 hover:bg-gray-700"
            }`}
          >
            Scanner
          </button>
          <button
            onClick={() => setTab("audit")}
            className={`text-sm px-4 py-1.5 rounded-lg cursor-pointer transition-colors ${
              tab === "audit"
                ? "bg-emerald-700 text-white"
                : "bg-gray-800 text-gray-400 hover:bg-gray-700"
            }`}
          >
            Audit Log
          </button>
        </div>
      </header>

      {tab === "scanner" && (
        <>
          <p className="text-gray-400 text-sm mb-4">
            Scan your CloudFormation IaC templates and Dockerfiles for security vulnerabilities.
          </p>
          <div className="flex flex-wrap gap-2 mb-4">
            <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">IAM Policies</span>
            <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">Security Groups</span>
            <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">S3 Encryption</span>
            <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">KMS Keys</span>
            <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">SSH/DB Ports</span>
            <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">Dockerfile Root</span>
          </div>
          <UploadForm onScan={handleScan} loading={loading} />
          {latest && (
            <div className="mt-6">
              <ScanResults result={latest} />
            </div>
          )}
          <ScanHistory scans={history} />
        </>
      )}

      {tab === "audit" && <AuditLog />}
    </div>
  );
}
