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
import { scan } from "./scan.js";
import type { EventStore } from "./store.js";
import type { PolicyAction, PolicyOutcome, Provider, RequestRecord } from "./types.js";
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

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface ProviderAdapter {
  name: Provider;
  /** The scannable user text (the new turn). */
  inputText(body: any): string;
  /** A JSON Schema if the caller asked for structured output, else null. */
  schema(body: any): object | null;
  /** Return a copy of the request with the user text replaced (redaction). */
  redactInput(body: any, redactedText: string): any;
  /** Return a copy of the request with a corrective instruction appended. */
  withCorrection(body: any, correction: string): any;
  /** Call the provider; resolves with text + token usage. Throws on failure. */
  call(body: any): Promise<ProviderResult>;
  /** Build the success wire response, applying any outbound redaction. */
  buildResponse(raw: unknown, outboundText: string, redacted: string[]): WireResponse;
  /** Build a provider-shaped error response. */
  errorResponse(status: number, message: string): WireResponse;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

const RANK: Record<PolicyAction, number> = { allow: 0, redact: 1, block: 2 };
function moreSevere(a: PolicyAction, b: PolicyAction): PolicyAction {
  return RANK[a] >= RANK[b] ? a : b;
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

  // 1. Inbound scan + policy.
  const input = adapter.inputText(body);
  const inbound = scan(input, "Inbound", "User");
  const inPolicy: PolicyOutcome = decide(inbound, config.threshold);
  if (inPolicy.action === "block") {
    await record({ action: "block", inboundFindings: inbound, blocked: true, error: "inbound blocked by policy" });
    return adapter.errorResponse(403, "request blocked by promptward policy (prompt injection)");
  }
  let reqBody =
    inPolicy.action === "redact" ? adapter.redactInput(body, redactText(input, inPolicy.findings)) : body;

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

  // 3. Outbound scan + policy.
  const outbound = scan(result.text, "Outbound", "ModelOutput");
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
  const outText = outPolicy.action === "redact" ? redactText(result.text, outPolicy.findings) : result.text;

  await record({
    action: moreSevere(inPolicy.action, outPolicy.action),
    inboundFindings: inbound,
    outboundFindings: outbound,
    model: result.model,
    costUsd: cost.costUsd,
    costUnpriced: cost.unpriced,
  });
  return adapter.buildResponse(result.raw, outText, outPolicy.redacted);
}
