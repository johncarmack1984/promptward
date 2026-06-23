// The proxy pipeline, provider-agnostic via a ProviderAdapter. Per request:
// inbound scan -> policy -> provider call -> structured-output validation +
// bounded retry -> outbound scan -> policy -> record. Block/redact decisions and
// the cost meter are applied here; the adapter only knows the provider's wire
// shape and how to call it.
import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import type { Config } from "./config.js";
import { computeCost } from "./cost.js";
import { decide, redactText } from "./policy.js";
import { scan, type Source } from "./scan.js";
import type { EventStore } from "./store.js";
import type { Finding, PolicyAction, PolicyOutcome, Provider, RequestRecord } from "./types.js";
import { validateOutput } from "./validate.js";

export interface ProviderResult {
  text: string;
  inputTokens: number;
  outputTokens: number;
  model: string;
  raw: unknown;
}

export interface WireResponse {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

/** A scannable unit of the request/response and where it lives in the body, so
 *  redaction can rewrite exactly that text in place. */
export interface ScanPart {
  source: Source;
  text: string;
  /** JSON path to this text inside the body/raw, e.g. ["messages", 2, "content"]. */
  path: Array<string | number>;
}

/** A redaction to apply at a specific JSON path. */
export interface RedactedPart {
  path: Array<string | number>;
  text: string;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface ProviderAdapter {
  name: Provider;
  /** Every scannable inbound part with its TRUE source -- system prompt, every
   *  user turn, tool results, and tool/MCP descriptions, not just the last turn. */
  inputParts(body: any): ScanPart[];
  /** A JSON Schema if the caller asked for structured output, else null. */
  schema(body: any): object | null;
  /** Return a copy of the request with the given parts redacted in place. */
  redactInput(body: any, redactions: RedactedPart[]): any;
  /** Return a copy of the request with a corrective instruction appended. */
  withCorrection(body: any, correction: string): any;
  /** Call the provider; resolves with text + token usage. Throws on failure. */
  call(body: any): Promise<ProviderResult>;
  /** Every scannable outbound text part of the raw response (every block, every
   *  choice) -- so multi-block / n>1 responses are scanned and redacted in full. */
  outputParts(raw: any): ScanPart[];
  /** Build the success wire response, applying outbound redactions in place. */
  buildResponse(raw: unknown, redactions: RedactedPart[], redactedLabels: string[]): WireResponse;
  /** Build a provider-shaped error response. */
  errorResponse(status: number, message: string): WireResponse;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

const RANK: Record<PolicyAction, number> = { allow: 0, redact: 1, block: 2 };
function moreSevere(a: PolicyAction, b: PolicyAction): PolicyAction {
  return RANK[a] >= RANK[b] ? a : b;
}

/** Redact each scanned part that has at-or-above-threshold exfiltration findings,
 *  using that part's own byte offsets. Only changed parts are returned. */
function redactionsFor(
  scanned: Array<{ part: ScanPart; findings: Finding[] }>,
  threshold: number,
): RedactedPart[] {
  const out: RedactedPart[] = [];
  for (const { part, findings } of scanned) {
    const active = findings.filter((f) => f.score >= threshold);
    const redacted = redactText(part.text, active);
    if (redacted !== part.text) out.push({ path: part.path, text: redacted });
  }
  return out;
}

export async function handle(
  adapter: ProviderAdapter,
  body: unknown,
  store: EventStore,
  config: Config,
): Promise<WireResponse> {
  const t0 = performance.now();
  const id = randomUUID();
  let inputTokens = 0;
  let outputTokens = 0;
  let retries = 0;
  let schemaValidated = false;
  let schemaValid: boolean | null = null;

  const record = (rec: Partial<RequestRecord>): Promise<void> =>
    store.record({
      id,
      ts: new Date().toISOString(),
      provider: adapter.name,
      model: rec.model ?? "unknown",
      action: rec.action ?? "allow",
      inboundFindings: rec.inboundFindings ?? [],
      outboundFindings: rec.outboundFindings ?? [],
      inputTokens,
      outputTokens,
      costUsd: rec.costUsd ?? null,
      costUnpriced: rec.costUnpriced ?? false,
      latencyMs: performance.now() - t0,
      schemaValidated,
      schemaValid,
      retries,
      blocked: rec.blocked ?? false,
      error: rec.error ?? null,
    });

  // 1. Inbound scan + policy. A security checkpoint must fail CLOSED: if the
  //    scanner or adapter throws, the request is NOT forwarded. Every scannable
  //    part is scanned with its true source, not just the last user turn.
  let inbound: Finding[];
  let inPolicy: PolicyOutcome;
  let reqBody: unknown;
  try {
    const scanned = adapter.inputParts(body).map((part) => ({
      part,
      findings: scan(part.text, "Inbound", part.source),
    }));
    inbound = scanned.flatMap((s) => s.findings);
    inPolicy = decide(inbound, config.threshold);
    if (inPolicy.action === "block") {
      await record({ action: "block", inboundFindings: inbound, blocked: true, error: "inbound blocked by policy" });
      return adapter.errorResponse(403, "request blocked by promptward policy (prompt injection)");
    }
    reqBody =
      inPolicy.action === "redact"
        ? adapter.redactInput(body, redactionsFor(scanned, config.threshold))
        : body;
  } catch (e) {
    await record({ action: "block", blocked: true, error: `inbound scan failed (fail-closed): ${(e as Error).message}` });
    return adapter.errorResponse(502, "promptward scan error; request not forwarded (fail-closed)");
  }

  // 2. Provider call + structured-output validation with bounded retry.
  const schema = adapter.schema(body);
  schemaValidated = schema != null;
  let result: ProviderResult;
  let errors: string | null = null;
  for (;;) {
    try {
      result = await adapter.call(reqBody);
    } catch (e) {
      await record({ action: inPolicy.action, inboundFindings: inbound, error: `provider error: ${(e as Error).message}` });
      return adapter.errorResponse(502, "upstream provider error");
    }
    inputTokens += result.inputTokens;
    outputTokens += result.outputTokens;
    if (!schema) break;
    const v = validateOutput(result.text, schema);
    schemaValid = v.valid;
    errors = v.errors;
    if (v.valid || retries >= config.maxRetries) break;
    retries++;
    reqBody = adapter.withCorrection(
      reqBody,
      `Your previous output failed schema validation: ${errors}. Return only JSON that matches the schema.`,
    );
  }

  const cost = computeCost(result.model, inputTokens, outputTokens);

  if (schema && schemaValid === false) {
    await record({
      action: inPolicy.action,
      inboundFindings: inbound,
      model: result.model,
      costUsd: cost.costUsd,
      costUnpriced: cost.unpriced,
      error: "structured output failed validation",
    });
    return adapter.errorResponse(
      422,
      `structured output failed schema validation after ${retries} retries: ${errors}`,
    );
  }

  // 3. Outbound scan + policy -- every response part (each block, each choice),
  //    also fail-closed so a scanner error never returns unscanned model output.
  try {
    const scanned = adapter.outputParts(result.raw).map((part) => ({
      part,
      findings: scan(part.text, "Outbound", "ModelOutput"),
    }));
    const outbound = scanned.flatMap((s) => s.findings);
    const outPolicy = decide(outbound, config.threshold);
    if (outPolicy.action === "block") {
      await record({
        action: "block",
        inboundFindings: inbound,
        outboundFindings: outbound,
        model: result.model,
        costUsd: cost.costUsd,
        costUnpriced: cost.unpriced,
        blocked: true,
        error: "response blocked by policy",
      });
      return adapter.errorResponse(403, "response blocked by promptward policy (data exfiltration)");
    }
    const redactions = outPolicy.action === "redact" ? redactionsFor(scanned, config.threshold) : [];
    const response = adapter.buildResponse(result.raw, redactions, outPolicy.redacted);
    await record({
      action: moreSevere(inPolicy.action, outPolicy.action),
      inboundFindings: inbound,
      outboundFindings: outbound,
      model: result.model,
      costUsd: cost.costUsd,
      costUnpriced: cost.unpriced,
    });
    return response;
  } catch (e) {
    await record({
      action: inPolicy.action,
      inboundFindings: inbound,
      model: result.model,
      costUsd: cost.costUsd,
      costUnpriced: cost.unpriced,
      error: `outbound scan failed (fail-closed): ${(e as Error).message}`,
    });
    return adapter.errorResponse(502, "promptward outbound scan error (fail-closed)");
  }
}
