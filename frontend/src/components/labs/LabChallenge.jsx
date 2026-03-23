import { useState } from "react";

const DIFF_STYLE = {
  beginner:     "bg-green-100 text-green-700",
  intermediate: "bg-amber-100 text-amber-700",
  advanced:     "bg-red-100   text-red-700",
};

export default function LabChallenge({ lab, onBack, onComplete }) {
  const [step, setStep]           = useState(0);
  const [showHint, setShowHint]   = useState(false);
  const [hintIdx, setHintIdx]     = useState(0);
  const [completed, setCompleted] = useState(new Set());

  const current  = lab.steps[step];
  const isLast   = step === lab.steps.length - 1;
  const isDone   = lab.steps.every((_, i) => completed.has(i));
  const progress = Math.round((completed.size / lab.steps.length) * 100);

  const markDone = () => {
    const next = new Set(completed).add(step);
    setCompleted(next);
    if (isLast) {
      onComplete(lab.id);
    } else {
      setStep(s => s + 1);
      setShowHint(false);
      setHintIdx(0);
    }
  };

  return (
    <div className="space-y-5 max-w-2xl">
      <div>
        <button onClick={onBack} className="text-xs text-gray-400 hover:text-gray-700 mb-3 flex items-center gap-1">
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Back to labs
        </button>
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-gray-900">{lab.title}</h2>
            <p className="text-sm text-gray-500 mt-1">{lab.objective}</p>
          </div>
          <span className={`text-xs px-2.5 py-1 rounded-full font-medium flex-shrink-0 capitalize ${DIFF_STYLE[lab.difficulty] ?? ""}`}>
            {lab.difficulty}
          </span>
        </div>
      </div>

      <div>
        <div className="flex justify-between text-xs text-gray-400 mb-1">
          <span>Step {Math.min(step + 1, lab.steps.length)} of {lab.steps.length}</span>
          <span>{progress}%</span>
        </div>
        <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden">
          <div className="h-full bg-indigo-500 rounded-full transition-all" style={{ width: `${progress}%` }} />
        </div>
      </div>

      <div className="flex gap-1.5 flex-wrap">
        {lab.steps.map((_, i) => (
          <button key={i} onClick={() => setStep(i)}
            className={`w-7 h-7 rounded-full text-xs font-medium transition-all
              ${i === step
                ? "bg-indigo-600 text-white"
                : completed.has(i)
                  ? "bg-green-500 text-white"
                  : "bg-gray-100 text-gray-500 hover:bg-gray-200"}`}>
            {completed.has(i) ? "✓" : i + 1}
          </button>
        ))}
      </div>

      <div className="card space-y-4">
        <div>
          <div className="text-xs font-medium text-gray-400 mb-1">Step {step + 1}</div>
          <h3 className="text-sm font-semibold text-gray-900 mb-2">{current.title}</h3>
          <p className="text-sm text-gray-700 leading-relaxed whitespace-pre-line">{current.instruction}</p>
        </div>

        {current.tool_hint && (
          <div className="bg-blue-50 border border-blue-100 rounded-lg px-3 py-2.5 text-xs text-blue-700">
            <span className="font-medium">Tool: </span>{current.tool_hint}
          </div>
        )}

        {current.expected && (
          <div>
            <div className="text-xs font-medium text-gray-500 mb-1">What to look for</div>
            <pre className="text-xs font-mono bg-gray-900 text-green-400 rounded-lg px-3 py-2.5 overflow-x-auto whitespace-pre-wrap">
              {current.expected}
            </pre>
          </div>
        )}

        {lab.hints.length > 0 && (
          <div>
            {!showHint ? (
              <button onClick={() => setShowHint(true)} className="text-xs text-indigo-600 hover:underline">
                Show hint ({lab.hints.length} available)
              </button>
            ) : (
              <div className="bg-amber-50 border border-amber-100 rounded-lg px-3 py-2.5">
                <div className="text-xs font-medium text-amber-700 mb-1">
                  Hint {hintIdx + 1} of {lab.hints.length}
                </div>
                <p className="text-xs text-amber-800">{lab.hints[hintIdx]}</p>
                {hintIdx < lab.hints.length - 1 && (
                  <button onClick={() => setHintIdx(i => i + 1)} className="text-xs text-amber-600 hover:underline mt-1.5 block">
                    Next hint →
                  </button>
                )}
              </div>
            )}
          </div>
        )}

        <div className="flex gap-2 pt-1">
          {step > 0 && (
            <button onClick={() => setStep(s => s - 1)} className="btn-secondary text-xs">Previous</button>
          )}
          <button onClick={markDone} className="btn-primary text-xs">
            {isLast ? "Complete lab" : "Mark done & next →"}
          </button>
        </div>
      </div>

      {isDone && (
        <div className="bg-green-50 border border-green-200 rounded-xl px-5 py-4 text-center">
          <div className="text-2xl mb-2">🎉</div>
          <div className="text-sm font-semibold text-green-800">Lab completed!</div>
          <p className="text-xs text-green-700 mt-1">You finished all {lab.steps.length} steps.</p>
          <button onClick={onBack} className="btn-primary text-xs mt-3">Back to labs</button>
        </div>
      )}
    </div>
  );
}