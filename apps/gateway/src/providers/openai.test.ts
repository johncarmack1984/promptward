import { afterEach, describe, expect, it, vi } from "vitest";

import { loadConfig } from "../config.js";
import { handle } from "../pipeline.js";
import { InMemoryStore } from "../store.js";
import { openaiAdapter } from "./openai.js";

/** Strict-index helper: fail the test loudly instead of typing around undefined. */
function must<T>(value: T | undefined | null): T {
  if (value == null) throw new Error("expected a value");
  return value;
}

/** The first choice of a wire response body, typed for what these tests read. */
type WireChoice = {
  message: { content?: string; tool_calls?: Array<{ function: { arguments: string } }> };
};
const choice0 = (body: unknown) => must((body as { choices: WireChoice[] }).choices[0]);

function okResponse(text: string): Response {
  return new Response(
    JSON.stringify({
      model: "gpt-test",
      choices: [{ message: { role: "assistant", content: text } }],
      usage: { prompt_tokens: 10, completion_tokens: 5 },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("openai adapter", () => {
  it("forwards the request, maps the response, and records unpriced cost honestly", async () => {
    const fetchMock = vi.fn().mockResolvedValue(okResponse("Here is a summary."));
    vi.stubGlobal("fetch", fetchMock);
    const store = new InMemoryStore();
    const config = loadConfig({} as NodeJS.ProcessEnv);

    const res = await handle(
      openaiAdapter(config),
      { model: "gpt-test", messages: [{ role: "user", content: "summarize this report" }] },
      store,
      config,
    );

    expect(res.status).toBe(200);
    expect(choice0(res.body).message.content).toBe("Here is a summary.");
    expect(fetchMock).toHaveBeenCalledOnce();
    const rec = must((await store.list())[0]);
    expect(rec.costUnpriced).toBe(true);
    expect(rec.costUsd).toBeNull();
  });

  it("redacts a secret in the model output", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(okResponse("your key is AKIAIOSFODNN7EXAMPLE")),
    );
    const store = new InMemoryStore();
    const config = loadConfig({} as NodeJS.ProcessEnv);

    const res = await handle(
      openaiAdapter(config),
      { model: "gpt-test", messages: [{ role: "user", content: "what is my key" }] },
      store,
      config,
    );

    expect(res.status).toBe(200);
    expect(res.headers?.["x-promptward-redacted"]).toContain("aws_access_key");
    expect(choice0(res.body).message.content).toContain("[REDACTED:aws_access_key]");
  });

  it("redacts a secret inside tool_call arguments, keeping valid JSON", async () => {
    const args = JSON.stringify({ to: "ops@corp.test", note: "key AKIAIOSFODNN7EXAMPLE" });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            model: "gpt-test",
            choices: [
              {
                message: {
                  role: "assistant",
                  content: null,
                  tool_calls: [
                    { id: "c1", type: "function", function: { name: "send", arguments: args } },
                  ],
                },
              },
            ],
            usage: { prompt_tokens: 1, completion_tokens: 1 },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const store = new InMemoryStore();
    const config = loadConfig({} as NodeJS.ProcessEnv);
    const res = await handle(
      openaiAdapter(config),
      { model: "gpt-test", messages: [{ role: "user", content: "send the note" }] },
      store,
      config,
    );
    expect(res.status).toBe(200);
    const out = must(must(choice0(res.body).message.tool_calls)[0]).function.arguments;
    expect(out).toContain("[REDACTED:aws_access_key]");
    expect(out).not.toContain("AKIAIOSFODNN7EXAMPLE");
    const parsed = JSON.parse(out); // redaction kept the JSON valid
    expect(parsed.to).toBe("ops@corp.test");
  });

  it("forwards the caller's Authorization, else falls back to the server key", async () => {
    const fetchMock = vi.fn().mockResolvedValue(okResponse("hi"));
    vi.stubGlobal("fetch", fetchMock);
    const config = loadConfig({ OPENAI_API_KEY: "server-key" } as NodeJS.ProcessEnv);
    const body = { model: "gpt-test", messages: [{ role: "user", content: "hi" }] };

    await handle(openaiAdapter(config), body, new InMemoryStore(), config, {
      auth: "Bearer sk-caller",
    });
    expect(
      (must(fetchMock.mock.calls[0])[1] as { headers: Record<string, string> }).headers
        .authorization,
    ).toBe("Bearer sk-caller");

    fetchMock.mockClear();
    await handle(openaiAdapter(config), body, new InMemoryStore(), config);
    expect(
      (must(fetchMock.mock.calls[0])[1] as { headers: Record<string, string> }).headers
        .authorization,
    ).toBe("Bearer server-key");
  });
});
