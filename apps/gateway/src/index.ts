/**
 * promptward gateway -- an OpenAI/Anthropic-compatible proxy.
 *
 * Per request: scan inbound -> policy (allow/redact/block) -> provider call ->
 * validate structured output (retry on miss) -> scan outbound -> record tokens,
 * cost, and findings. Point your SDK's baseURL here; it stays wire-compatible.
 *
 * This module wires the app shell (config, event store, dashboard read routes)
 * and mounts the proxy pipeline at /v1/messages (Anthropic) and
 * /v1/chat/completions (OpenAI).
 */
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { pathToFileURL } from "node:url";
import { loadConfig, type Config } from "./config.js";
import { makeStore, type EventStore } from "./store.js";
import { handle } from "./pipeline.js";
import { anthropicAdapter } from "./providers/anthropic.js";
import { openaiAdapter } from "./providers/openai.js";

export interface App {
  app: Hono;
  store: EventStore;
  config: Config;
}

export async function createApp(config: Config = loadConfig()): Promise<App> {
  const store = await makeStore(config.databaseUrl);
  const app = new Hono();

  app.get("/health", (c) =>
    c.json({ ok: true, store: config.databaseUrl ? "postgres" : "memory" }),
  );

  // Read API for the dashboard.
  app.get("/v1/requests", async (c) => {
    const limit = Number(c.req.query("limit") ?? 100);
    const [requests, stats] = await Promise.all([store.list(limit), store.stats()]);
    return c.json({ requests, stats });
  });

  // Wire-compatible proxy routes. Same pipeline; the adapter handles the shape.
  const proxy = (adapter: (cfg: Config) => ReturnType<typeof anthropicAdapter>) =>
    async (c: { req: { json: () => Promise<unknown> } }) => {
      const body: unknown = await c.req.json();
      const res = await handle(adapter(config), body, store, config);
      return new Response(JSON.stringify(res.body), {
        status: res.status,
        headers: { "content-type": "application/json", ...(res.headers ?? {}) },
      });
    };
  // Defense-in-depth: cap the raw request body before it is parsed, so a
  // pathologically large payload cannot exhaust memory ahead of the per-request
  // scan cap (config.maxScanBytes) enforced in the pipeline.
  const limit = bodyLimit({
    maxSize: config.maxScanBytes * 8,
    onError: (c) =>
      c.json({ error: { type: "promptward_policy_error", message: "request body too large" } }, 413),
  });
  app.post("/v1/messages", limit, proxy(anthropicAdapter)); // Anthropic
  app.post("/v1/chat/completions", limit, proxy(openaiAdapter)); // OpenAI

  return { app, store, config };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const { app, config } = await createApp();
  serve({ fetch: app.fetch, port: config.port });
  // eslint-disable-next-line no-console
  console.log(
    `promptward gateway listening on http://localhost:${config.port} (health: /health)`,
  );
}
