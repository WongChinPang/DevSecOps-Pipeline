import { useState, useEffect, useCallback } from "react";
import UploadForm from "./components/UploadForm";
import ScanResults from "./components/ScanResults";
import ScanHistory from "./components/ScanHistory";
import { submitScan, fetchScans } from "./api";
import type { ScanRequest, ScanResult } from "./api";

export default function App() {
  const [latest, setLatest] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchScans().then(setHistory).catch(() => {});
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

  return (
    <div className="max-w-5xl mx-auto px-4 py-8">
      <header className="mb-8">
        <h1 className="text-2xl font-bold">DevSecOps Scanner</h1>
        <p className="text-gray-500 text-sm mt-1">
          Upload IaC templates and Dockerfiles for automated security scanning
        </p>
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
