// Anthropic-compatible provider adapter. promptward is wire-compatible, so the
// incoming body IS the Anthropic /v1/messages body -- we forward it as-is
// (after any inbound redaction) rather than reconstruct it through the SDK.
import type { Config } from "../config.js";
import type { ProviderAdapter, ProviderResult, ScanPart, WireResponse } from "../pipeline.js";
import { applyRedactions, stringLeafParts, textParts } from "./shared.js";

/* eslint-disable @typescript-eslint/no-explicit-any */

// Every scannable inbound part: the system prompt, each user turn's text, the
// contents of tool_result blocks (tagged Tool), and tool/MCP descriptions --
// the surfaces where 2026 indirect injection and tool poisoning actually land.
// Assistant turns are prior model output and are not re-scanned inbound.
function inputParts(body: any): ScanPart[] {
  const parts: ScanPart[] = [];
  if (body?.system != null) parts.push(...textParts(body.system, "System", ["system"]));

  const msgs = Array.isArray(body?.messages) ? body.messages : [];
  msgs.forEach((m: any, i: number) => {
    if (m?.role !== "user") return;
    const base = ["messages", i, "content"];
    parts.push(...textParts(m.content, "User", base));
    if (Array.isArray(m.content)) {
      m.content.forEach((b: any, j: number) => {
        if (b?.type === "tool_result") {
          parts.push(...textParts(b.content, "Tool", [...base, j, "content"]));
        }
      });
    }
  });

  const tools = Array.isArray(body?.tools) ? body.tools : [];
  tools.forEach((t: any, i: number) => {
    if (typeof t?.description === "string") {
      parts.push({ source: "McpDescription", text: t.description, path: ["tools", i, "description"] });
    }
  });
  return parts;
}

// Joined text of the response (for structured-output validation).
function responseText(raw: any): string {
  return (raw?.content ?? [])
    .filter((b: any) => b?.type === "text")
    .map((b: any) => b.text as string)
    .join("");
}

// Each outbound text block, addressable for in-place redaction (no block is
// blanked or collapsed).
function outputParts(raw: any): ScanPart[] {
  const parts: ScanPart[] = [];
  (raw?.content ?? []).forEach((b: any, i: number) => {
    if (b?.type === "text" && typeof b.text === "string") {
      parts.push({ source: "ModelOutput", text: b.text, path: ["content", i, "text"] });
    } else if (b?.type === "tool_use" && b.input && typeof b.input === "object") {
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
    wantsStreaming: (body) => body?.stream === true,
    inputParts,
    schema: (body) => body?.response_format?.json_schema?.schema ?? body?.promptward?.schema ?? null,
    redactInput: (body, redactions) => applyRedactions(body, redactions),
    withCorrection: (body, correction) => ({
      ...body,
      system: [body?.system, correction].filter(Boolean).join("\n\n"),
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
      const json: any = await res.json();
      if (!res.ok) throw new Error(json?.error?.message ?? `provider returned ${res.status}`);
      return {
        text: responseText(json),
        inputTokens: json?.usage?.input_tokens ?? 0,
        outputTokens: json?.usage?.output_tokens ?? 0,
        model: json?.model ?? body?.model ?? "unknown",
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
/* eslint-enable @typescript-eslint/no-explicit-any */
