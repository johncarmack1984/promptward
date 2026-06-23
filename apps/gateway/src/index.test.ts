import { describe, expect, it } from "vitest";
import { createApp } from "./index.js";
import { loadConfig } from "./config.js";

describe("gateway app", () => {
  it("serves /health and /v1/requests with the in-memory store", async () => {
    const { app } = await createApp(loadConfig({} as NodeJS.ProcessEnv));

    const health = await app.fetch(new Request("http://local/health"));
    expect(health.status).toBe(200);
    expect(await health.json()).toMatchObject({ ok: true, store: "memory" });

    const reqs = await app.fetch(new Request("http://local/v1/requests"));
    expect(reqs.status).toBe(200);
    const body = (await reqs.json()) as { requests: unknown[]; stats: { count: number } };
    expect(body.requests).toEqual([]);
    expect(body.stats.count).toBe(0);
  });
});
