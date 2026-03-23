// ── Severity ──────────────────────────────────────────────────────────────────
export type Severity = "critical" | "high" | "medium" | "low" | "info";

// ── Auth ──────────────────────────────────────────────────────────────────────
export interface User {
  id: string;
  email: string;
  full_name?: string;
  created_at: string;
}

// ── Findings & Scans ──────────────────────────────────────────────────────────
export interface Finding {
  id: string;
  title: string;
  description?: string;
  severity: Severity;
  category?: string;
  remediation?: string;
  raw_evidence?: string;
}

export interface Scan {
  id: string;
  tool: "owasp" | "metadata" | "logs" | "pcap";
  target?: string;
  status: "pending" | "running" | "complete" | "failed";
  created_at: string;
  completed_at?: string;
  findings: Finding[];
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
export interface DashboardStats {
  total_scans: number;
  total_findings: number;
  high_severity: number;
  labs_completed: number;
}

export interface RecentFinding {
  id: string;
  title: string;
  severity: Severity;
  category?: string;
  tool: string;
  target?: string;
}

// ── Tool results ──────────────────────────────────────────────────────────────
export interface MetadataResult {
  scan_id: string;
  filename: string;
  file_type: string;
  metadata: Record<string, string | number>;
  risks: Finding[];
  summary: {
    total_tags: number;
    has_gps: boolean;
    risk_count: number;
  };
}

export interface LogResult {
  scan_id: string;
  log_type: string;
  stats: {
    total_lines: number;
    total_findings: number;
    high_count: number;
    medium_count: number;
  };
  findings: Finding[];
}

export interface PcapResult {
  scan_id: string;
  filename: string;
  stats: {
    total_packets: number;
    unique_ips: number;
    dns_queries: number;
    top_talker?: [string, number];
  };
  findings: Finding[];
  summary: {
    total_packets: number;
    total_findings: number;
    critical_count: number;
    high_count: number;
  };
}

// ── Labs ──────────────────────────────────────────────────────────────────────
export type LabDifficulty = "beginner" | "intermediate" | "advanced";
export type LabCategory   = "owasp" | "metadata" | "logs" | "pcap" | "network";

export interface Lab {
  id: string;
  title: string;
  category: LabCategory;
  difficulty: LabDifficulty;
  owasp_ref?: string;         // e.g. "A04"
  description: string;
  objective: string;
  hints: string[];
  steps: LabStep[];
  completed?: boolean;
  progress?: number;          // 0–100
}

export interface LabStep {
  id: string;
  title: string;
  instruction: string;
  expected?: string;
  tool_hint?: string;
}

// ── UI helpers ────────────────────────────────────────────────────────────────
export interface NavItem {
  label: string;
  path: string;
  dot: string;
}
