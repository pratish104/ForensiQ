import { useState } from "react";

const SEV_BADGE = {
  critical: "bg-purple-100 text-purple-700",
  high:     "bg-red-100    text-red-700",
  medium:   "bg-amber-100  text-amber-700",
  low:       "bg-blue-100   text-blue-700",
  info:     "bg-gray-100   text-gray-600",
};

const SEV_DOT = {
  critical: "bg-purple-500",
  high:     "bg-red-500",
  medium:   "bg-amber-500",
  low:       "bg-blue-400",
  info:     "bg-gray-400",
};

const SEV_BORDER = {
  critical: "border-l-purple-400",
  high:     "border-l-red-400",
  medium:   "border-l-amber-400",
  low:       "border-l-blue-300",
  info:     "border-l-gray-300",
};

export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const sev = finding.severity;

  return (
    <div className={`bg-white border border-gray-100 border-l-4 ${SEV_BORDER[sev]} rounded-lg transition-all duration-150 hover:border-gray-200`}>
      <button onClick={() => setExpanded(e => !e)} className="w-full flex items-start gap-3 px-4 py-3 text-left">
        <span className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${SEV_DOT[sev]}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-gray-900 leading-snug">{finding.title}</span>
            {finding.category && <span className="text-xs text-gray-400 font-mono">{finding.category}</span>}
          </div>
          {!expanded && finding.description && (
            <p className="text-xs text-gray-500 mt-0.5 truncate">{finding.description}</p>
          )}
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium capitalize ${SEV_BADGE[sev]}`}>{sev}</span>
          <svg className={`w-4 h-4 text-gray-400 transition-transform ${expanded ? "rotate-180" : ""}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-gray-50 pt-3">
          {finding.description && (
            <div>
              <div className="text-xs font-medium text-gray-500 mb-1">Description</div>
              <p className="text-sm text-gray-700 leading-relaxed">{finding.description}</p>
            </div>
          )}
          {finding.remediation && (
            <div className="bg-amber-50 border border-amber-100 rounded-lg px-3 py-2.5">
              <div className="text-xs font-medium text-amber-700 mb-1">Remediation</div>
              <p className="text-sm text-amber-800 leading-relaxed">{finding.remediation}</p>
            </div>
          )}
          {finding.raw_evidence && (
            <div>
              <div className="text-xs font-medium text-gray-500 mb-1">Evidence</div>
              <pre className="text-xs font-mono bg-gray-900 text-gray-100 rounded-lg px-3 py-2.5 overflow-x-auto whitespace-pre-wrap break-all">
                {finding.raw_evidence}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function FindingSummary({ findings }) {
  const counts = {};
  if (findings) {
    for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }

  const items = [
    { key: "critical", label: "Critical", color: "bg-purple-100 text-purple-700" },
    { key: "high",     label: "High",     color: "bg-red-100    text-red-700"    },
    { key: "medium",   label: "Medium",   color: "bg-amber-100  text-amber-700"  },
    { key: "low",      label: "Low",      color: "bg-blue-100   text-blue-700"   },
    { key: "info",     label: "Info",     color: "bg-gray-100   text-gray-600"   },
  ].filter(i => counts[i.key]);

  if (!items.length) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {items.map(({ key, label, color }) => (
        <span key={key} className={`text-xs px-2.5 py-1 rounded-full font-medium ${color}`}>
          {counts[key]} {label}
        </span>
      ))}
    </div>
  );
}