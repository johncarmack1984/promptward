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
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  return {
    port: Number(env.PORT ?? 8787),
    databaseUrl: env.DATABASE_URL ?? null,
    anthropicApiKey: env.ANTHROPIC_API_KEY ?? null,
    anthropicBaseUrl: env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com",
    openaiApiKey: env.OPENAI_API_KEY ?? null,
    openaiBaseUrl: env.OPENAI_BASE_URL ?? "https://api.openai.com/v1",
    threshold: Number(env.PROMPTWARD_THRESHOLD ?? 0.5),
    maxRetries: Number(env.PROMPTWARD_MAX_RETRIES ?? 2),
  };
}
