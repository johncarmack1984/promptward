import type { RequestsResponse } from "./types";
import { SAMPLE } from "./data/sampleRequests";

export type Source = "live" | "fixture";

export interface LoadResult {
  data: RequestsResponse;
  source: Source;
  error?: string;
}

// In dev, Vite proxies /api -> http://localhost:8787 (same-origin, no CORS).
// In a static build there is no proxy, so we also try the gateway directly;
// either way, a failed fetch falls back to the bundled fixture so the console
// always renders.
const ENDPOINTS = ["/api/v1/requests?limit=100", "http://localhost:8787/v1/requests?limit=100"];

function isResponse(value: unknown): value is RequestsResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    Array.isArray((value as RequestsResponse).requests) &&
    typeof (value as RequestsResponse).stats === "object"
  );
}

export async function loadRequests(signal?: AbortSignal): Promise<LoadResult> {
  let lastError = "gateway unreachable";
  for (const url of ENDPOINTS) {
    try {
      const res = await fetch(url, { signal });
      if (!res.ok) {
        lastError = `gateway returned ${res.status}`;
        continue;
      }
      const json: unknown = await res.json();
      if (isResponse(json)) return { data: json, source: "live" };
      lastError = "unexpected response shape";
    } catch (err) {
      if (signal?.aborted) throw err;
      lastError = err instanceof Error ? err.message : "fetch failed";
    }
  }
  return { data: SAMPLE, source: "fixture", error: lastError };
}
