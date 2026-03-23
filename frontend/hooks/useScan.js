import { useState, useCallback } from "react";
import { owaspApi, metadataApi, logApi, pcapApi } from "../api";

function useScanBase() {
  const [state, setState]   = useState("idle");
  const [result, setResult] = useState(null);
  const [error, setError]   = useState(null);

  const reset = useCallback(() => {
    setState("idle"); setResult(null); setError(null);
  }, []);

  const run = useCallback(async (fn) => {
    setState("running"); setError(null); setResult(null);
    try {
      setResult(await fn());
      setState("complete");
    } catch (err) {
      setError(err?.response?.data?.detail ?? err?.message ?? "Scan failed");
      setState("error");
    }
  }, []);

  return { state, result, error, reset, run };
}

export function useOwaspScan() {
  const base = useScanBase();
  const scan = useCallback((url, checks) =>
    base.run(() => owaspApi.scan(url, checks)), [base]);
  return { ...base, scan };
}

export function useMetadataScan() {
  const base = useScanBase();
  const analyze = useCallback((file) =>
    base.run(() => metadataApi.analyze(file)), [base]);
  return { ...base, analyze };
}

export function useLogScan() {
  const base = useScanBase();
  const analyzeFile = useCallback((file, logType = "auto") =>
    base.run(() => logApi.analyzeFile(file, logType)), [base]);
  const analyzeText = useCallback((content, logType = "auto") =>
    base.run(() => logApi.analyzeText(content, logType)), [base]);
  return { ...base, analyzeFile, analyzeText };
}

export function usePcapScan() {
  const base = useScanBase();
  const analyze = useCallback((file) =>
    base.run(() => pcapApi.analyze(file)), [base]);
  return { ...base, analyze };
}

export function sortFindings(findings) {
  const o = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  return [...findings].sort((a, b) => (o[b.severity] ?? 0) - (o[a.severity] ?? 0));
}