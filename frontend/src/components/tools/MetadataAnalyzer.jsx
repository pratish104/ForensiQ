import { useRef, useState } from "react";
import TopBar from "../layout/TopBar";
import FindingCard from "./FindingCard";
import { metadataApi } from "../../api";

export default function MetadataAnalyzer() {
  const fileRef = useRef(null);
  const [dragOver, setDragOver]   = useState(false);
  const [activeTab, setActiveTab] = useState("risks");
  const [state, setState]   = useState("idle");
  const [result, setResult] = useState(null);
  const [error, setError]   = useState(null);

  const handleFile = async (file) => {
    setActiveTab("risks"); 
    setState("running"); 
    setError(null); 
    setResult(null);
    try { 
      const data = await metadataApi.analyze(file);
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

  return (
    <div className="flex flex-col h-full">
      <TopBar 
        title="Metadata analyzer" 
        subtitle="Extract hidden EXIF, GPS, author and device data from files"
        badge={result ? { 
          label: `${result.risks?.length || 0} risks`, 
          color: (result.risks?.length || 0) > 0 ? "red" : "green" 
        } : undefined} 
      />
      
      <div className="flex-1 overflow-y-auto p-6 space-y-5 max-w-3xl">

        {state === "idle" && (
          <div
            onDragOver={e => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={e => { 
              e.preventDefault(); 
              setDragOver(false); 
              const f = e.dataTransfer.files?.[0]; 
              if (f) handleFile(f); 
            }}
            onClick={() => fileRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-colors
              ${dragOver ? "border-indigo-400 bg-indigo-50" : "border-gray-200 hover:border-gray-400 hover:bg-gray-50"}`}
          >
            <input ref={fileRef} type="file" accept=".jpg,.jpeg,.png,.tiff,.heic,.pdf,.docx,.doc"
              className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
            <div className="text-3xl mb-3">📎</div>
            <p className="text-sm font-medium text-gray-700">Drop a file or click to upload</p>
            <p className="text-xs text-gray-400 mt-1">JPG · PNG · PDF · DOCX · TIFF — max 50 MB</p>
          </div>
        )}

        {state === "running" && (
          <div className="card flex items-center gap-3 text-sm text-gray-500 p-4 border rounded-lg">
            <span className="w-4 h-4 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin flex-shrink-0" />
            Extracting metadata...
          </div>
        )}

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-sm text-red-700">
            {error} <button onClick={reset} className="ml-3 underline text-xs">Try again</button>
          </div>
        )}

        {state === "complete" && result && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="bg-gray-50 rounded-lg px-4 py-3">
                <div className="text-xs text-gray-400 mb-1">File</div>
                <div className="text-sm font-medium text-gray-800 truncate">{result.filename}</div>
                <div className="text-xs text-gray-400 capitalize mt-0.5">{result.file_type}</div>
              </div>
              <div className="bg-gray-50 rounded-lg px-4 py-3">
                <div className="text-xs text-gray-400 mb-1">Metadata tags</div>
                <div className="text-2xl font-semibold text-gray-900">{result.summary?.total_tags || 0}</div>
              </div>
              <div className={`rounded-lg px-4 py-3 ${(result.risks?.length || 0) > 0 ? "bg-red-50" : "bg-green-50"}`}>
                <div className="text-xs text-gray-400 mb-1">Privacy risks</div>
                <div className={`text-2xl font-semibold ${(result.risks?.length || 0) > 0 ? "text-red-700" : "text-green-700"}`}>
                  {result.risks?.length || 0}
                </div>
                {result.summary?.has_gps && <div className="text-xs text-red-500 mt-0.5 font-medium">GPS detected</div>}
              </div>
            </div>

            <div className="flex gap-1 border-b border-gray-100">
              {["risks", "all"].map(tab => (
                <button key={tab} onClick={() => setActiveTab(tab)}
                  className={`px-4 py-2 text-sm transition-colors
                    ${activeTab === tab ? "text-indigo-600 border-b-2 border-indigo-500 font-medium" : "text-gray-500 hover:text-gray-700"}`}>
                  {tab === "risks" ? `Privacy risks (${result.risks?.length || 0})` : `All metadata (${result.summary?.total_tags || 0})`}
                </button>
              ))}
            </div>

            {activeTab === "risks" && (
              <div className="space-y-2">
                {!result.risks || result.risks.length === 0
                  ? <div className="card text-center py-8 text-sm text-gray-400 border rounded-lg">No privacy risks found.</div>
                  : result.risks.map((r, i) => <FindingCard key={i} finding={r} />)}
              </div>
            )}

            {activeTab === "all" && result.metadata && (
              <div className="border border-gray-100 rounded-xl overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-50 border-b border-gray-100">
                      <th className="text-left text-xs font-medium text-gray-500 px-4 py-2 w-2/5">Tag</th>
                      <th className="text-left text-xs font-medium text-gray-500 px-4 py-2">Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(result.metadata).map(([key, val], i) => (
                      <tr key={i} className="border-b border-gray-50 hover:bg-gray-50">
                        <td className="px-4 py-2 text-xs text-gray-500 font-mono">{key}</td>
                        <td className={`px-4 py-2 text-xs font-mono break-all ${key.toLowerCase().includes("gps") ? "text-red-600 font-medium" : "text-gray-800"}`}>
                          {String(val)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <button onClick={reset} className="btn-secondary text-xs border px-3 py-1.5 rounded-lg hover:bg-gray-50">
              Analyze another file
            </button>
          </div>
        )}
      </div>
    </div>
  );
}