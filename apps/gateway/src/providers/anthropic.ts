// Anthropic-compatible provider adapter. promptward is wire-compatible, so the
// incoming body IS the Anthropic /v1/messages body -- we forward it as-is
// (after any inbound redaction) rather than reconstruct it through the SDK.
import type { Config } from "../config.js";
import type { ProviderAdapter, ProviderResult, WireResponse } from "../pipeline.js";

/* eslint-disable @typescript-eslint/no-explicit-any */

function blockText(content: any): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .filter((b) => b?.type === "text")
      .map((b) => b.text as string)
      .join("\n");
  }
  return "";
}

function lastUserText(body: any): string {
  const msgs = Array.isArray(body?.messages) ? body.messages : [];
  for (let i = msgs.length - 1; i >= 0; i--) {
    if (msgs[i]?.role === "user") return blockText(msgs[i].content);
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
  return (raw?.content ?? [])
    .filter((b: any) => b?.type === "text")
    .map((b: any) => b.text as string)
    .join("");
}

function rewriteResponseText(raw: any, text: string): any {
  const clone = structuredClone(raw);
  let replaced = false;
  for (const b of clone.content ?? []) {
    if (b?.type === "text") {
      b.text = replaced ? "" : text;
      replaced = true;
    }
  }
  return clone;
}

export function anthropicAdapter(config: Config): ProviderAdapter {
  return {
    name: "anthropic",
    inputText: (body) => lastUserText(body),
    schema: (body) => body?.response_format?.json_schema?.schema ?? body?.promptward?.schema ?? null,
    redactInput: (body, redactedText) => replaceLastUserText(body, redactedText),
    withCorrection: (body, correction) => ({
      ...body,
      system: [body?.system, correction].filter(Boolean).join("\n\n"),
    }),
    async call(body): Promise<ProviderResult> {
      const res = await fetch(`${config.anthropicBaseUrl}/v1/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": config.anthropicApiKey ?? "",
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
    buildResponse: (raw, outboundText, redacted): WireResponse => {
      const body = redacted.length ? rewriteResponseText(raw, outboundText) : raw;
      return {
        status: 200,
        body,
        headers: redacted.length ? { "x-promptward-redacted": redacted.join(",") } : undefined,
      };
    },
    errorResponse: (status, message): WireResponse => ({
      status,
      body: { type: "error", error: { type: "promptward_policy_error", message } },
    }),
  };
}
/* eslint-enable @typescript-eslint/no-explicit-any */
