import { describe, expect, it } from "vitest";

import { loadConfig } from "./config.js";

describe("config", () => {
  it("falls back to defaults on unparseable numerics (never NaN)", () => {
    // A typo must not silently disable enforcement (threshold NaN => f.score >= NaN
    // is always false => nothing ever flags).
    const c = loadConfig({
      PROMPTWARD_THRESHOLD: "high",
      PROMPTWARD_MAX_RETRIES: "lots",
    } as NodeJS.ProcessEnv);
    expect(c.threshold).toBe(0.5);
    expect(c.maxRetries).toBe(2);
  });

  it("clamps the decision threshold to [0, 1]", () => {
    expect(loadConfig({ PROMPTWARD_THRESHOLD: "5" } as NodeJS.ProcessEnv).threshold).toBe(1);
    expect(loadConfig({ PROMPTWARD_THRESHOLD: "-2" } as NodeJS.ProcessEnv).threshold).toBe(0);
  });
});
