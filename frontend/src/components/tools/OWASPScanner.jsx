import { useState } from "react";
import TopBar from "../layout/TopBar";
import FindingCard, { FindingSummary } from "./FindingCard";
import { owaspApi } from "../../api";

const CHECKS = [
  { id: "headers", label: "Security headers", cat: "A02" },
  { id: "cookies", label: "Cookie flags",      cat: "A07" },
  { id: "forms",   label: "CSRF / forms",      cat: "A01" },
  { id: "sqli",    label: "SQL injection",     cat: "A04" },
  { id: "info",    label: "Info disclosure",   cat: "A02" },
];

function sortFindings(findings) {
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  return [...findings].sort((a, b) => 
    (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0)
  );
}

export default function OWASPScanner() {
  const [url, setUrl]       = useState("");
  const [checks, setChecks] = useState([]);
  const [state, setState]   = useState("idle");
  const [result, setResult] = useState(null);
  const [error, setError]   = useState(null);

  const toggleCheck = (id) => 
    setChecks(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);

  const resetScanner = () => { 
    setState("idle"); 
    setResult(null); 
    setError(null); 
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setState("running"); 
    setError(null); 
    setResult(null);

    try {
      const data = await owaspApi.scan(url.trim(), checks.length ? checks : undefined);
      setResult(data);
      setState("complete");
    } catch (err) {
      setError(err?.response?.data?.detail ?? "Scan failed. Please check the URL and try again.");
      setState("error");
    }
  };

  const findings = result?.findings ? sortFindings(result.findings) : [];

  return (
    <div className="flex flex-col h-full">
      <TopBar 
        title="OWASP scanner" 
        subtitle="Test a URL against OWASP Top 10 vulnerability categories"
        badge={state === "complete" ? { 
          label: `${findings.length} findings`, 
          color: findings.length > 0 ? "red" : "green" 
        } : undefined} 
      />

      <div className="flex-1 overflow-y-auto p-6 space-y-5 max-w-3xl">
        <div className="card space-y-4 p-4 border rounded-lg bg-white">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1.5">Target URL</label>
              <div className="flex gap-2">
                <input 
                  className="input flex-1 border rounded px-3 py-2 outline-none focus:border-indigo-500" 
                  type="url" 
                  placeholder="https://example.com"
                  value={url} 
                  onChange={e => setUrl(e.target.value)} 
                  required 
                  disabled={state === "running"} 
                />
                <button 
                  className="btn-primary bg-indigo-600 text-white px-4 py-2 rounded disabled:opacity-50 flex items-center gap-2" 
                  type="submit" 
                  disabled={state === "running" || !url}
                >
                  {state === "running" ? (
                    <>
                      <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      Scanning...
                    </>
                  ) : "Scan"}
                </button>
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-2">
                Check categories <span className="text-gray-400 font-normal">(empty = run all)</span>
              </label>
              <div className="flex flex-wrap gap-2">
                {CHECKS.map(({ id, label, cat }) => (
                  <button 
                    key={id} 
                    type="button" 
                    onClick={() => toggleCheck(id)}
                    className={`text-xs px-3 py-1.5 rounded-full border transition-all
                      ${checks.includes(id) 
                        ? "bg-indigo-600 text-white border-indigo-600" 
                        : "bg-white text-gray-600 border-gray-200 hover:border-indigo-300"}`}
                  >
                    <span className="font-mono text-gray-400 mr-1">{cat}</span>{label}
                  </button>
                ))}
              </div>
            </div>
          </form>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-sm text-red-700">
            {error} <button onClick={resetScanner} className="ml-3 underline text-xs">Dismiss</button>
          </div>
        )}

        {state === "running" && (
          <div className="space-y-3">
            {[1, 2, 3].map(i => (
              <div key={i} className="card animate-pulse p-4 border rounded-lg">
                <div className="flex gap-3">
                  <div className="w-2 h-2 rounded-full bg-gray-200 mt-1.5" />
                  <div className="flex-1 space-y-2">
                    <div className="h-3 bg-gray-200 rounded w-2/3" />
                    <div className="h-2.5 bg-gray-100 rounded w-full" />
                  </div>
                  <div className="w-12 h-5 bg-gray-200 rounded-full" />
                </div>
              </div>
            ))}
          </div>
        )}

        {state === "complete" && result && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {[
                { label: "Target",   value: result.target ?? "-", mono: true },
                { label: "Status",   value: result.status ?? "Finished" },
                { label: "Findings", value: String(findings.length), red: findings.length > 0 },
              ].map(({ label, value, mono, red }) => (
                <div key={label} className="bg-gray-50 rounded-lg px-4 py-3">
                  <div className="text-xs text-gray-400 mb-1">{label}</div>
                  <div className={`text-sm font-medium truncate ${red ? "text-red-600" : "text-gray-800"} ${mono ? "font-mono" : ""}`}>
                    {value}
                  </div>
                </div>
              ))}
            </div>
            
            <FindingSummary findings={findings} />
            
            {findings.length === 0 ? (
              <div className="card text-center py-8 text-sm text-gray-400 border rounded-lg">
                No vulnerabilities found.
              </div>
            ) : (
              <div className="space-y-2">
                {findings.map((f, i) => (
                  <FindingCard key={f.id || i} finding={f} />
                ))}
              </div>
            )}
            
            <button 
              onClick={resetScanner} 
              className="btn-secondary text-xs border px-3 py-1.5 rounded-lg hover:bg-gray-50"
            >
              New scan
            </button>
          </div>
        )}
      </div>
    </div>
  );
}