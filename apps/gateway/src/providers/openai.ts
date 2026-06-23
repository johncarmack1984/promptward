// OpenAI-compatible provider adapter (/v1/chat/completions). Same pipeline as
// Anthropic; only the wire shape differs.
import type { Config } from "../config.js";
import type { ProviderAdapter, ProviderResult, ScanPart, WireResponse } from "../pipeline.js";
import { applyRedactions, textParts } from "./shared.js";

/* eslint-disable @typescript-eslint/no-explicit-any */

// Every scannable inbound part: the system message, each user turn (string or
// vision text parts), tool-result messages (tagged Tool), and tool/function
// descriptions. Assistant turns are prior model output and are not re-scanned.
function inputParts(body: any): ScanPart[] {
  const parts: ScanPart[] = [];
  const msgs = Array.isArray(body?.messages) ? body.messages : [];
  msgs.forEach((m: any, i: number) => {
    const base = ["messages", i, "content"];
    if (m?.role === "system") parts.push(...textParts(m.content, "System", base));
    else if (m?.role === "user") parts.push(...textParts(m.content, "User", base));
    else if (m?.role === "tool") parts.push(...textParts(m.content, "Tool", base));
    // assistant: prior model output, not re-scanned inbound
  });

  const tools = Array.isArray(body?.tools) ? body.tools : [];
  tools.forEach((t: any, i: number) => {
    const d = t?.function?.description;
    if (typeof d === "string") {
      parts.push({ source: "McpDescription", text: d, path: ["tools", i, "function", "description"] });
    }
  });
  return parts;
}

function responseText(raw: any): string {
  return raw?.choices?.[0]?.message?.content ?? "";
}

// Every choice's message content (n>1 included), each addressable for in-place
// redaction so no choice is returned unscanned.
function outputParts(raw: any): ScanPart[] {
  const parts: ScanPart[] = [];
  (raw?.choices ?? []).forEach((ch: any, i: number) => {
    const content = ch?.message?.content;
    if (typeof content === "string") {
      parts.push({ source: "ModelOutput", text: content, path: ["choices", i, "message", "content"] });
    }
  });
  return parts;
}

export function openaiAdapter(config: Config): ProviderAdapter {
  return {
    name: "openai",
    inputParts,
    schema: (body) =>
      body?.response_format?.json_schema?.schema ?? body?.response_format?.schema ?? null,
    redactInput: (body, redactions) => applyRedactions(body, redactions),
    withCorrection: (body, correction) => ({
      ...body,
      messages: [...(body?.messages ?? []), { role: "system", content: correction }],
    }),
    async call(body): Promise<ProviderResult> {
      const res = await fetch(`${config.openaiBaseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${config.openaiApiKey ?? ""}`,
        },
        body: JSON.stringify(body),
      });
      const json: any = await res.json();
      if (!res.ok) throw new Error(json?.error?.message ?? `provider returned ${res.status}`);
      return {
        text: responseText(json),
        inputTokens: json?.usage?.prompt_tokens ?? 0,
        outputTokens: json?.usage?.completion_tokens ?? 0,
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
      body: { error: { message, type: "promptward_policy_error" } },
    }),
  };
}
/* eslint-enable @typescript-eslint/no-explicit-any */
