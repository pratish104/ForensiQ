const DIFF_STYLE = {
  beginner:     "bg-green-100 text-green-700",
  intermediate: "bg-amber-100 text-amber-700",
  advanced:     "bg-red-100   text-red-700",
};

const CAT_DOT = {
  owasp:    "bg-purple-500",
  metadata: "bg-orange-500",
  logs:     "bg-amber-500",
  pcap:     "bg-teal-500",
  network:  "bg-blue-500",
};

export default function LabList({ labs, onSelect }) {
  const groups = {
    beginner:     labs.filter(l => l.difficulty === "beginner"),
    intermediate: labs.filter(l => l.difficulty === "intermediate"),
    advanced:     labs.filter(l => l.difficulty === "advanced"),
  };

  return (
    <div className="space-y-6">
      {Object.entries(groups).map(([diff, items]) => {
        if (!items.length) return null;
        return (
          <div key={diff}>
            <div className="flex items-center gap-2 mb-3">
              <span className={`text-xs px-2.5 py-1 rounded-full font-medium capitalize ${DIFF_STYLE[diff] ?? ""}`}>
                {diff}
              </span>
              <span className="text-xs text-gray-400">{items.length} challenges</span>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {items.map(lab => (
                <button
                  key={lab.id}
                  onClick={() => onSelect(lab)}
                  className="card text-left hover:border-indigo-200 hover:shadow-sm transition-all duration-150 group"
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${CAT_DOT[lab.category] ?? "bg-gray-400"}`} />
                      <span className="text-sm font-medium text-gray-900 group-hover:text-indigo-700 transition-colors leading-snug">
                        {lab.title}
                      </span>
                    </div>
                    {lab.owasp_ref && (
                      <span className="text-xs font-mono text-gray-400 flex-shrink-0">{lab.owasp_ref}</span>
                    )}
                  </div>
                  <p className="text-xs text-gray-500 ml-4 mb-3 line-clamp-2">{lab.description}</p>
                  <div className="ml-4">
                    <div className="flex justify-between text-xs text-gray-400 mb-1">
                      <span>
                        {lab.progress === 100
                          ? "Completed"
                          : lab.progress > 0
                            ? "In progress"
                            : "Not started"}
                      </span>
                      <span>{lab.progress ?? 0}%</span>
                    </div>
                    <div className="h-1 bg-gray-100 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${lab.progress === 100 ? "bg-green-500" : "bg-indigo-500"}`}
                        style={{ width: `${lab.progress ?? 0}%` }}
                      />
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}