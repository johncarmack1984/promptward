import { afterEach, describe, expect, it, vi } from "vitest";
import { handle } from "../pipeline.js";
import { openaiAdapter } from "./openai.js";
import { InMemoryStore } from "../store.js";
import { loadConfig } from "../config.js";

/* eslint-disable @typescript-eslint/no-explicit-any */

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
    expect((res.body as any).choices[0].message.content).toBe("Here is a summary.");
    expect(fetchMock).toHaveBeenCalledOnce();
    const [rec] = await store.list();
    expect(rec.costUnpriced).toBe(true);
    expect(rec.costUsd).toBeNull();
  });

  it("redacts a secret in the model output", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(okResponse("your key is AKIAIOSFODNN7EXAMPLE")));
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
    expect((res.body as any).choices[0].message.content).toContain("[REDACTED:aws_access_key]");
  });
});
