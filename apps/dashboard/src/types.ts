// Wire shapes the console renders. These mirror the gateway's read API
// (apps/gateway/src/types.ts) and the Rust scanner's Finding (the napi
// boundary in crates/tripwire-core). Kept in lockstep by hand so the
// dashboard builds standalone, with no cross-package import.

export type PolicyAction = "allow" | "redact" | "block";
export type Provider = "anthropic" | "openai";

export type FindingKind = "Injection" | "Exfiltration" | "Obfuscation";
export type Severity = "Info" | "Low" | "Medium" | "High" | "Critical";
export type FindingSource =
  | "User"
  | "System"
  | "Tool"
  | "Document"
  | "McpDescription"
  | "ModelOutput";

export interface Finding {
  kind: FindingKind;
  /** Machine label for the specific pattern, e.g. instruction_override. */
  label: string;
  severity: Severity;
  /** 0.0..=1.0, calibrated per label. */
  score: number;
  /** Byte offset of the match start in the original text. */
  start: number;
  /** Byte offset of the match end in the original text. */
  end: number;
  source: FindingSource;
  detail?: string;
}

export interface RequestRecord {
  id: string;
  ts: string; // ISO 8601
  provider: Provider;
  model: string;
  action: PolicyAction;
  inboundFindings: Finding[];
  outboundFindings: Finding[];
  inputTokens: number;
  outputTokens: number;
  /** USD; null when the model id is not in the price table (never fabricated). */
  costUsd: number | null;
  costUnpriced: boolean;
  latencyMs: number;
  schemaValidated: boolean;
  schemaValid: boolean | null;
  retries: number;
  blocked: boolean;
  error: string | null;
}

export interface StoreStats {
  count: number;
  totalCostUsd: number;
  blocked: number;
  findings: number;
}

export interface RequestsResponse {
  requests: RequestRecord[];
  stats: StoreStats;
}

// Shape of evals/results.json (read the real file for current values).
export interface ClassMetric {
  precision: number;
  recall: number;
  f1: number;
  tp: number;
  fp: number;
  fn: number;
}

export interface Bucket {
  label: "injection" | "exfiltration" | "benign";
  count: number;
  detected: number;
  rate: number;
}

export interface EvalResults {
  generatedBy: string;
  metrics: {
    corpusSize: number;
    labelCounts: { injection: number; exfiltration: number; benign: number };
    threshold: number;
    perClass: { injection: ClassMetric; exfiltration: ClassMetric };
    overall: ClassMetric;
    benignFalsePositiveRate: number;
    recallAt1pctFpr: { threshold: number; recall: number; allowedFp: number };
    confusion: { tp: number; fp: number; fn: number; tn: number };
    buckets: Record<string, Bucket>;
  };
  performance: {
    perScanMsP50: number;
    perScanMsP95: number;
    scansTimed: number;
  };
}
