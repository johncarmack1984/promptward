import { describe, expect, it } from "vitest";
import { InMemoryStore } from "./store.js";
import type { Finding, RequestRecord } from "./types.js";

const finding = {
  kind: "Exfiltration",
  label: "aws_access_key",
  severity: "Critical",
  score: 0.95,
  start: 0,
  end: 20,
  source: "User",
  detail: undefined,
} as unknown as Finding;

function rec(over: Partial<RequestRecord> = {}): RequestRecord {
  return {
    id: "x",
    ts: new Date(0).toISOString(),
    provider: "anthropic",
    model: "claude-opus-4-8",
    action: "allow",
    inboundFindings: [],
    outboundFindings: [],
    inputTokens: 10,
    outputTokens: 5,
    costUsd: 0,
    costUnpriced: false,
    latencyMs: 1,
    schemaValidated: false,
    schemaValid: null,
    retries: 0,
    blocked: false,
    error: null,
    ...over,
  };
}

describe("InMemoryStore", () => {
  it("lists newest-first and aggregates stats", async () => {
    const s = new InMemoryStore();
    await s.record(rec({ id: "a", costUsd: 0.01 }));
    await s.record(rec({ id: "b", costUsd: 0.02, blocked: true, inboundFindings: [finding] }));

    const list = await s.list();
    expect(list.map((r) => r.id)).toEqual(["b", "a"]);

    const stats = await s.stats();
    expect(stats.count).toBe(2);
    expect(stats.totalCostUsd).toBeCloseTo(0.03);
    expect(stats.blocked).toBe(1);
    expect(stats.findings).toBe(1);
  });

  it("respects the list limit", async () => {
    const s = new InMemoryStore();
    for (let i = 0; i < 5; i++) await s.record(rec({ id: `r${i}` }));
    expect(await s.list(2)).toHaveLength(2);
  });
});
