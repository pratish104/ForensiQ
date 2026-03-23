import { useRef, useState } from "react";
import TopBar from "../layout/TopBar";
import FindingCard, { FindingSummary } from "./FindingCard";
import { logApi } from "../../api"; // Ensure api.js is also converted!

const LOG_TYPES = [
  { value: "auto",   label: "Auto-detect" },
  { value: "auth",   label: "auth.log / syslog" },
  { value: "apache", label: "Apache access log" },
  { value: "nginx",  label: "Nginx access log" },
];

function sortFindings(findings) {
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  return [...findings].sort((a, b) => 
    (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0)
  );
}

export default function LogAnalyzer() {
  const fileRef = useRef(null);
  const [mode, setMode]         = useState("file");
  const [logType, setLogType]   = useState("auto");
  const [text, setText]         = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [state, setState]       = useState("idle");
  const [result, setResult]     = useState(null);
  const [error, setError]       = useState(null);

  const runAnalysis = async (apiCall) => {
    setState("running"); 
    setError(null); 
    setResult(null);
    try { 
      const data = await apiCall(); 
      setResult(data); 
      setState("complete"); 
    } catch (err) { 
      setError(err?.response?.data?.detail ?? "Analysis failed"); 
      setState("error"); 
    }
  };

  const reset = () => { 
    setState("idle"); 
    setResult(null); 
    setError(null); 
    setText("");
  };

  const findings = result?.findings ? sortFindings(result.findings) : [];

  return (
    <div className="flex flex-col h-full">
      <TopBar 
        title="Log analyzer" 
        subtitle="Detect brute force, anomalies and intrusions in server logs"
        badge={result ? { 
          label: `${findings.length} anomalies`, 
          color: findings.length > 0 ? "red" : "green" 
        } : undefined} 
      />
      
      <div className="flex-1 overflow-y-auto p-6 space-y-5 max-w-3xl">

        {state === "idle" && (
          <div className="card space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1.5">Log type</label>
              <div className="flex flex-wrap gap-2">
                {LOG_TYPES.map(({ value, label }) => (
                  <button key={value} type="button" onClick={() => setLogType(value)}
                    className={`text-xs px-3 py-1.5 rounded-full border transition-all
                      ${logType === value ? "bg-indigo-600 text-white border-indigo-600" : "bg-white text-gray-600 border-gray-200 hover:border-indigo-300"}`}>
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex gap-1 border-b border-gray-100">
              {["file", "paste"].map(m => (
                <button key={m} onClick={() => setMode(m)}
                  className={`px-4 py-2 text-sm transition-colors ${mode === m ? "text-indigo-600 border-b-2 border-indigo-500 font-medium" : "text-gray-500 hover:text-gray-700"}`}>
                  {m === "file" ? "Upload file" : "Paste logs"}
                </button>
              ))}
            </div>

            {mode === "file" && (
              <div
                onClick={() => fileRef.current?.click()}
                onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={e => { 
                  e.preventDefault(); 
                  setDragOver(false); 
                  const f = e.dataTransfer.files?.[0]; 
                  if (f) runAnalysis(() => logApi.analyzeFile(f, logType)); 
                }}
                className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors
                  ${dragOver ? "border-indigo-400 bg-indigo-50" : "border-gray-200 hover:border-gray-400 hover:bg-gray-50"}`}
              >
                <input ref={fileRef} type="file" accept=".log,.txt" className="hidden"
                  onChange={e => { 
                    const f = e.target.files?.[0]; 
                    if (f) runAnalysis(() => logApi.analyzeFile(f, logType)); 
                  }} />
                <div className="text-3xl mb-3">📄</div>
                <p className="text-sm font-medium text-gray-700">Drop a log file or click to upload</p>
                <p className="text-xs text-gray-400 mt-1">auth.log · access.log · syslog · .txt</p>
              </div>
            )}

            {mode === "paste" && (
              <div className="space-y-3">
                <textarea
                  className="input h-48 font-mono text-xs resize-none w-full p-3 border rounded-lg" 
                  value={text}
                  placeholder={"Paste raw log lines here...\n\nExample:\nFailed password for root from 192.168.1.5 port 22"}
                  onChange={e => setText(e.target.value)}
                />
                <button className="btn-primary w-full py-2 bg-indigo-600 text-white rounded-lg disabled:opacity-50" 
                  disabled={!text.trim()}
                  onClick={() => runAnalysis(() => logApi.analyzeText(text, logType))}>
                  Analyze
                </button>
              </div>
            )}
          </div>
        )}

        {state === "running" && (
          <div className="card flex items-center gap-3 text-sm text-gray-500 p-4 border rounded-lg">
            <span className="w-4 h-4 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin flex-shrink-0" />
            Analyzing log entries...
          </div>
        )}

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-sm text-red-700">
            {error} <button onClick={reset} className="ml-3 underline text-xs">Try again</button>
          </div>
        )}

        {state === "complete" && result && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { label: "Total lines",   value: result.stats?.total_lines?.toLocaleString() ?? "0" },
                { label: "Log type",      value: result.log_type ?? "Unknown" },
                { label: "Anomalies",     value: String(findings.length),         red: findings.length > 0 },
                { label: "High severity", value: String(result.stats?.high_count ?? 0), red: (result.stats?.high_count ?? 0) > 0 },
              ].map(({ label, value, red }) => (
                <div key={label} className="bg-gray-50 rounded-lg px-4 py-3">
                  <div className="text-xs text-gray-400 mb-1">{label}</div>
                  <div className={`text-lg font-semibold ${red ? "text-red-600" : "text-gray-900"}`}>{value}</div>
                </div>
              ))}
            </div>
            
            <FindingSummary findings={findings} />
            
            {findings.length === 0
              ? <div className="card text-center py-8 text-sm text-gray-400 border rounded-lg">No anomalies detected.</div>
              : <div className="space-y-2">{findings.map((f, i) => <FindingCard key={f.id || i} finding={f} />)}</div>}
            
            <button onClick={reset} className="btn-secondary text-xs border px-3 py-1.5 rounded-lg hover:bg-gray-50">
              Analyze another log
            </button>
          </div>
        )}
      </div>
    </div>
  );
}