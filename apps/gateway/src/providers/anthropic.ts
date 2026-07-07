// Anthropic-compatible provider adapter. promptward is wire-compatible, so the
// incoming body IS the Anthropic /v1/messages body -- we forward it as-is
// (after any inbound redaction) rather than reconstruct it through the SDK.
import type { Config } from "../config.js";
import type { ProviderAdapter, ProviderResult, ScanPart, WireResponse } from "../pipeline.js";
import { applyRedactions, arr, rec, stringLeafParts, textParts } from "./shared.js";

// Every scannable inbound part: the system prompt, each user turn's text, the
// contents of tool_result blocks (tagged Tool), and tool/MCP descriptions --
// the surfaces where 2026 indirect injection and tool poisoning actually land.
// Assistant turns are prior model output and are not re-scanned inbound.
function inputParts(body: unknown): ScanPart[] {
  const parts: ScanPart[] = [];
  const b = rec(body);
  if (b.system != null) parts.push(...textParts(b.system, "System", ["system"]));

  arr(b.messages).forEach((mv, i) => {
    const m = rec(mv);
    if (m.role !== "user") return;
    const base = ["messages", i, "content"];
    parts.push(...textParts(m.content, "User", base));
    arr(m.content).forEach((bv, j) => {
      if (rec(bv).type === "tool_result") {
        parts.push(...textParts(rec(bv).content, "Tool", [...base, j, "content"]));
      }
    });
  });

  arr(b.tools).forEach((tv, i) => {
    const t = rec(tv);
    if (typeof t.description === "string") {
      parts.push({
        source: "McpDescription",
        text: t.description,
        path: ["tools", i, "description"],
      });
    }
  });
  return parts;
}

// Joined text of the response (for structured-output validation).
function responseText(raw: unknown): string {
  return arr(rec(raw).content)
    .flatMap((bv) => {
      const b = rec(bv);
      return b.type === "text" && typeof b.text === "string" ? [b.text] : [];
    })
    .join("");
}

// Each outbound text block, addressable for in-place redaction (no block is
// blanked or collapsed).
function outputParts(raw: unknown): ScanPart[] {
  const parts: ScanPart[] = [];
  arr(rec(raw).content).forEach((bv, i) => {
    const b = rec(bv);
    if (b.type === "text" && typeof b.text === "string") {
      parts.push({ source: "ModelOutput", text: b.text, path: ["content", i, "text"] });
    } else if (b.type === "tool_use" && b.input && typeof b.input === "object") {
      // Exfiltration can ride out inside a tool-call argument; scan every string
      // leaf of the structured input and redact it in place if needed.
      parts.push(...stringLeafParts(b.input, "ModelOutput", ["content", i, "input"]));
    }
  });
  return parts;
}

export function anthropicAdapter(config: Config): ProviderAdapter {
  return {
    name: "anthropic",
    wantsStreaming: (body) => rec(body).stream === true,
    inputParts,
    schema: (body) => {
      const b = rec(body);
      const s = rec(rec(b.response_format).json_schema).schema ?? rec(b.promptward).schema ?? null;
      return typeof s === "object" ? s : null;
    },
    redactInput: (body, redactions) => applyRedactions(body, redactions),
    withCorrection: (body, correction) => ({
      ...rec(body),
      system: [rec(body).system, correction].filter(Boolean).join("\n\n"),
    }),
    async call(body, auth): Promise<ProviderResult> {
      const res = await fetch(`${config.anthropicBaseUrl}/v1/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          // Forward the caller's key; fall back to the server's configured key.
          "x-api-key": auth ?? config.anthropicApiKey ?? "",
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify(body),
      });
      const json: unknown = await res.json();
      const j = rec(json);
      if (!res.ok) {
        const msg = rec(j.error).message;
        throw new Error(typeof msg === "string" ? msg : `provider returned ${res.status}`);
      }
      const usage = rec(j.usage);
      const fallbackModel = rec(body).model;
      return {
        text: responseText(json),
        inputTokens: typeof usage.input_tokens === "number" ? usage.input_tokens : 0,
        outputTokens: typeof usage.output_tokens === "number" ? usage.output_tokens : 0,
        model:
          typeof j.model === "string"
            ? j.model
            : typeof fallbackModel === "string"
              ? fallbackModel
              : "unknown",
        raw: json,
      };
    },
    outputParts,
    buildResponse: (raw, redactions, redactedLabels): WireResponse => ({
      status: 200,
      body: applyRedactions(raw, redactions),
      headers: redactedLabels.length
        ? { "x-promptward-redacted": redactedLabels.join(",") }
        : undefined,
    }),
    errorResponse: (status, message): WireResponse => ({
      status,
      body: { type: "error", error: { type: "promptward_policy_error", message } },
    }),
  };
}
