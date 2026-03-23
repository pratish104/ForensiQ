import { useRef, useState } from "react";
import TopBar from "../layout/TopBar";
import FindingCard, { FindingSummary } from "./FindingCard";
import { pcapApi } from "../../api";

function sortFindings(findings) {
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  return [...findings].sort((a, b) => 
    (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0)
  );
}

export default function PcapAnalyzer() {
  const fileRef = useRef(null);
  const [dragOver, setDragOver] = useState(false);
  const [state, setState]   = useState("idle");
  const [result, setResult] = useState(null);
  const [error, setError]   = useState(null);

  const handleFile = async (file) => {
    setState("running"); 
    setError(null); 
    setResult(null);
    try { 
      const data = await pcapApi.analyze(file);
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
  };

  const findings = result?.findings ? sortFindings(result.findings) : [];

  return (
    <div className="flex flex-col h-full">
      <TopBar 
        title="PCAP analyzer" 
        subtitle="Inspect network captures for credentials, scans and exfiltration"
        badge={result ? { 
          label: `${findings.length} findings`, 
          color: findings.length > 0 ? "red" : "green" 
        } : undefined} 
      />
      
      <div className="flex-1 overflow-y-auto p-6 space-y-5 max-w-3xl">

        {state === "idle" && (
          <>
            <div
              onClick={() => fileRef.current?.click()}
              onDragOver={e => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={e => { 
                e.preventDefault(); 
                setDragOver(false); 
                const f = e.dataTransfer.files?.[0]; 
                if (f) handleFile(f); 
              }}
              className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-colors
                ${dragOver ? "border-indigo-400 bg-indigo-50" : "border-gray-200 hover:border-gray-400 hover:bg-gray-50"}`}
            >
              <input ref={fileRef} type="file" accept=".pcap,.pcapng,.cap" className="hidden"
                onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
              <div className="text-3xl mb-3">🌐</div>
              <p className="text-sm font-medium text-gray-700">Drop a capture file or click to upload</p>
              <p className="text-xs text-gray-400 mt-1">.pcap · .pcapng · captured with Wireshark or tcpdump</p>
            </div>
            <div className="bg-blue-50 border border-blue-100 rounded-lg px-4 py-3 text-xs text-blue-700 space-y-1">
              <div className="font-medium">How to capture traffic for testing</div>
              <div className="font-mono">sudo tcpdump -i eth0 -w capture.pcap</div>
            </div>
          </>
        )}

        {state === "running" && (
          <div className="card flex items-center gap-3 text-sm text-gray-500 p-4 border rounded-lg">
            <span className="w-4 h-4 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin flex-shrink-0" />
            Parsing packets... this may take a moment for large captures.
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
                { label: "Packets",     value: result.stats?.total_packets?.toLocaleString() ?? "0" },
                { label: "Unique IPs",  value: String(result.stats?.unique_ips ?? "0") },
                { label: "DNS queries", value: String(result.stats?.dns_queries ?? "0") },
                { label: "Findings",    value: String(findings.length), red: findings.length > 0 },
              ].map(({ label, value, red }) => (
                <div key={label} className="bg-gray-50 rounded-lg px-4 py-3">
                  <div className="text-xs text-gray-400 mb-1">{label}</div>
                  <div className={`text-lg font-semibold ${red ? "text-red-600" : "text-gray-900"}`}>{value}</div>
                </div>
              ))}
            </div>
            
            {result.stats?.top_talker && Array.isArray(result.stats.top_talker) && (
              <div className="bg-amber-50 border border-amber-100 rounded-lg px-4 py-2.5 text-xs text-amber-800">
                <span className="font-medium">Top talker: </span>
                <span className="font-mono">{result.stats.top_talker[0]}</span>
                <span className="text-amber-600 ml-1">({result.stats.top_talker[1]?.toLocaleString()} packets)</span>
              </div>
            )}

            <FindingSummary findings={findings} />
            
            {findings.length === 0 ? (
              <div className="card text-center py-8 text-sm text-gray-400 border rounded-lg">
                No suspicious traffic detected.
              </div>
            ) : (
              <div className="space-y-2">
                {findings.map((f, i) => (
                  <FindingCard key={f.id || i} finding={f} />
                ))}
              </div>
            )}
            
            <button onClick={reset} className="btn-secondary text-xs border px-3 py-1.5 rounded-lg hover:bg-gray-50">
              Analyze another capture
            </button>
          </div>
        )}
      </div>
    </div>
  );
}