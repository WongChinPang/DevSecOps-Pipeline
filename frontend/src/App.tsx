import { useState, useEffect, useCallback } from "react";
import UploadForm from "./components/UploadForm";
import ScanResults from "./components/ScanResults";
import ScanHistory from "./components/ScanHistory";
import LoginForm from "./components/LoginForm";
import { submitScan, fetchScans, isAuthenticated, logout } from "./api";
import type { ScanRequest, ScanResult } from "./api";

export default function App() {
  const [loggedIn, setLoggedIn] = useState(isAuthenticated());
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
        <p className="text-gray-400 text-sm mt-1">
          Scan your CloudFormation IaC templates and Dockerfiles for security vulnerabilities.
          The scanner checks 8 security rules: IAM policies, network exposure, data encryption, and container security.
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">IAM Policies</span>
          <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">Security Groups</span>
          <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">S3 Encryption</span>
          <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">KMS Keys</span>
          <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">SSH/DB Ports</span>
          <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">Dockerfile Root</span>
        </div>
      </header>

      <UploadForm onScan={handleScan} loading={loading} />

      {latest && (
        <div className="mt-6">
          <ScanResults result={latest} />
        </div>
      )}

      <ScanHistory scans={history} />
    </div>
  );
}
