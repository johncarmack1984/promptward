// Gateway-domain types. The scanner's Finding/Kind/Severity come from the Rust
// core via @promptward/tripwire; everything here is the proxy's own vocabulary.
import type { Finding } from "@promptward/tripwire";

export type { Finding };

export type PolicyAction = "allow" | "redact" | "block";
export type Provider = "anthropic" | "openai";

/** What policy decided for one direction of one request. */
export interface PolicyOutcome {
  action: PolicyAction;
  /** Findings at or above the decision threshold that drove the action. */
  findings: Finding[];
  /** Human-readable labels of what was redacted (never the secret values). */
  redacted: string[];
}

/** A single proxied request, recorded to the event store. */
export interface RequestRecord {
  id: string;
  ts: string; // ISO 8601
  provider: Provider;
  model: string;
  /** allow | redact | block -- the effective action taken. */
  action: PolicyAction;
  inboundFindings: Finding[];
  outboundFindings: Finding[];
  inputTokens: number;
  outputTokens: number;
  /** USD; null when the model id is not in the price table (never fabricated). */
  costUsd: number | null;
  costUnpriced: boolean;
  latencyMs: number;
  /** Structured-output validation, when the caller supplied a schema. */
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
