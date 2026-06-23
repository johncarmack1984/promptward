// OpenAI-compatible provider adapter (/v1/chat/completions). Same pipeline as
// Anthropic; only the wire shape differs.
import type { Config } from "../config.js";
import type { ProviderAdapter, ProviderResult, WireResponse } from "../pipeline.js";

/* eslint-disable @typescript-eslint/no-explicit-any */

function lastUserText(body: any): string {
  const msgs = Array.isArray(body?.messages) ? body.messages : [];
  for (let i = msgs.length - 1; i >= 0; i--) {
    if (msgs[i]?.role === "user") {
      const c = msgs[i].content;
      if (typeof c === "string") return c;
      if (Array.isArray(c)) {
        return c
          .filter((p) => p?.type === "text")
          .map((p) => p.text as string)
          .join("\n");
      }
    }
  }
  return "";
}

function replaceLastUserText(body: any, text: string): any {
  const clone = structuredClone(body);
  const msgs = clone.messages ?? [];
  for (let i = msgs.length - 1; i >= 0; i--) {
    if (msgs[i]?.role === "user") {
      msgs[i].content = text;
      break;
    }
  }
  return clone;
}

function responseText(raw: any): string {
  return raw?.choices?.[0]?.message?.content ?? "";
}

function rewriteResponseText(raw: any, text: string): any {
  const clone = structuredClone(raw);
  if (clone?.choices?.[0]?.message) clone.choices[0].message.content = text;
  return clone;
}

export function openaiAdapter(config: Config): ProviderAdapter {
  return {
    name: "openai",
    inputText: (body) => lastUserText(body),
    schema: (body) =>
      body?.response_format?.json_schema?.schema ?? body?.response_format?.schema ?? null,
    redactInput: (body, redactedText) => replaceLastUserText(body, redactedText),
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
    buildResponse: (raw, outboundText, redacted): WireResponse => ({
      status: 200,
      body: redacted.length ? rewriteResponseText(raw, outboundText) : raw,
      headers: redacted.length ? { "x-promptward-redacted": redacted.join(",") } : undefined,
    }),
    errorResponse: (status, message): WireResponse => ({
      status,
      body: { error: { message, type: "promptward_policy_error" } },
    }),
  };
}
/* eslint-enable @typescript-eslint/no-explicit-any */
