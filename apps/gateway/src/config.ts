// Runtime configuration, read from the environment with sane defaults so the
// gateway starts with no setup (in-memory store, no provider keys required to
// boot -- only to actually proxy).

export interface Config {
  port: number;
  databaseUrl: string | null;
  anthropicApiKey: string | null;
  anthropicBaseUrl: string;
  openaiApiKey: string | null;
  openaiBaseUrl: string;
  /** Decision threshold for a finding to drive policy. Matches the eval. */
  threshold: number;
  /** Max structured-output validation retries before surfacing the failure. */
  maxRetries: number;
  /** Max bytes of scannable text per request; larger requests are rejected
   *  (413) so a pathological input cannot block the event loop. */
  maxScanBytes: number;
}

/** Parse a numeric env var with a default and optional clamp. A missing OR
 *  unparseable value falls back to the default -- never NaN, so a typo like
 *  PROMPTWARD_THRESHOLD=high can't silently disable enforcement. */
function num(raw: string | undefined, fallback: number, opts: { min?: number; max?: number } = {}): number {
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(opts.max ?? Infinity, Math.max(opts.min ?? -Infinity, n));
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  return {
    port: num(env.PORT, 8787, { min: 1, max: 65535 }),
    databaseUrl: env.DATABASE_URL ?? null,
    anthropicApiKey: env.ANTHROPIC_API_KEY ?? null,
    anthropicBaseUrl: env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com",
    openaiApiKey: env.OPENAI_API_KEY ?? null,
    openaiBaseUrl: env.OPENAI_BASE_URL ?? "https://api.openai.com/v1",
    threshold: num(env.PROMPTWARD_THRESHOLD, 0.5, { min: 0, max: 1 }),
    maxRetries: num(env.PROMPTWARD_MAX_RETRIES, 2, { min: 0, max: 10 }),
    maxScanBytes: num(env.PROMPTWARD_MAX_SCAN_BYTES, 1_000_000, { min: 1_000 }),
  };
}
