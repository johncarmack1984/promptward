// Cost metering. Prices are USD per 1M tokens, pinned to exact model ids at
// build time. An unknown model id yields a null cost with `unpriced: true` --
// never a fabricated number.

export interface Price {
  inputPer1M: number;
  outputPer1M: number;
}

export const PRICES: Record<string, Price> = {
  // Anthropic
  "claude-opus-4-8": { inputPer1M: 5.0, outputPer1M: 25.0 },
  "claude-sonnet-4-6": { inputPer1M: 3.0, outputPer1M: 15.0 },
  "claude-haiku-4-5": { inputPer1M: 1.0, outputPer1M: 5.0 },
  "claude-fable-5": { inputPer1M: 10.0, outputPer1M: 50.0 },
  // OpenAI price rows are added with the OpenAI provider path.
};

export interface CostResult {
  costUsd: number | null;
  unpriced: boolean;
}

export function computeCost(model: string, inputTokens: number, outputTokens: number): CostResult {
  const price = PRICES[model];
  if (!price) return { costUsd: null, unpriced: true };
  const costUsd =
    (inputTokens / 1_000_000) * price.inputPer1M + (outputTokens / 1_000_000) * price.outputPer1M;
  return { costUsd, unpriced: false };
}
