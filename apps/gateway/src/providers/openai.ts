// OpenAI-compatible provider adapter (/v1/chat/completions). Same pipeline as
// Anthropic; only the wire shape differs.
import type { Config } from "../config.js";
import type { ProviderAdapter, ProviderResult, ScanPart, WireResponse } from "../pipeline.js";
import { applyRedactions, arr, rec, textParts } from "./shared.js";

// Every scannable inbound part: the system message, each user turn (string or
// vision text parts), tool-result messages (tagged Tool), and tool/function
// descriptions. Assistant turns are prior model output and are not re-scanned.
function inputParts(body: unknown): ScanPart[] {
  const parts: ScanPart[] = [];
  arr(rec(body).messages).forEach((mv, i) => {
    const m = rec(mv);
    const base = ["messages", i, "content"];
    if (m.role === "system") parts.push(...textParts(m.content, "System", base));
    else if (m.role === "user") parts.push(...textParts(m.content, "User", base));
    else if (m.role === "tool") parts.push(...textParts(m.content, "Tool", base));
    // assistant: prior model output, not re-scanned inbound
  });

  arr(rec(body).tools).forEach((tv, i) => {
    const d = rec(rec(tv).function).description;
    if (typeof d === "string") {
      parts.push({
        source: "McpDescription",
        text: d,
        path: ["tools", i, "function", "description"],
      });
    }
  });
  return parts;
}

function responseText(raw: unknown): string {
  const content = rec(rec(arr(rec(raw).choices)[0]).message).content;
  return typeof content === "string" ? content : "";
}

// Every choice's message content (n>1 included), each addressable for in-place
// redaction so no choice is returned unscanned.
function outputParts(raw: unknown): ScanPart[] {
  const parts: ScanPart[] = [];
  arr(rec(raw).choices).forEach((cv, i) => {
    const message = rec(rec(cv).message);
    const content = message.content;
    if (typeof content === "string") {
      parts.push({
        source: "ModelOutput",
        text: content,
        path: ["choices", i, "message", "content"],
      });
    }
    // Tool-call arguments are a JSON string; scan it for exfiltration. Redacting
    // a secret inside a quoted value keeps the surrounding JSON valid (the
    // placeholder contains no quote or backslash).
    arr(message.tool_calls).forEach((tv, j) => {
      const args = rec(rec(tv).function).arguments;
      if (typeof args === "string" && args.length > 0) {
        parts.push({
          source: "ModelOutput",
          text: args,
          path: ["choices", i, "message", "tool_calls", j, "function", "arguments"],
        });
      }
    });
  });
  return parts;
}

export function openaiAdapter(config: Config): ProviderAdapter {
  return {
    name: "openai",
    wantsStreaming: (body) => rec(body).stream === true,
    inputParts,
    schema: (body) => {
      const rf = rec(rec(body).response_format);
      const s = rec(rf.json_schema).schema ?? rf.schema ?? null;
      return typeof s === "object" ? s : null;
    },
    redactInput: (body, redactions) => applyRedactions(body, redactions),
    withCorrection: (body, correction) => ({
      ...rec(body),
      messages: [...arr(rec(body).messages), { role: "system", content: correction }],
    }),
    async call(body, auth): Promise<ProviderResult> {
      const res = await fetch(`${config.openaiBaseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          // Forward the caller's Authorization (already "Bearer ..."); fall back
          // to the server's configured key.
          authorization: auth ?? `Bearer ${config.openaiApiKey ?? ""}`,
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
        inputTokens: typeof usage.prompt_tokens === "number" ? usage.prompt_tokens : 0,
        outputTokens: typeof usage.completion_tokens === "number" ? usage.completion_tokens : 0,
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
      body: { error: { message, type: "promptward_policy_error" } },
    }),
  };
}
