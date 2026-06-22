/**
 * promptward gateway -- an OpenAI/Anthropic-compatible proxy.
 *
 * Per request:
 *   1. scan inbound text   -> tripwire-core (injection + exfiltration)
 *   2. forward to provider (Anthropic / OpenAI) if allowed by policy
 *   3. validate structured output against the caller's JSON Schema (retry on miss)
 *   4. scan outbound text  -> tripwire-core (exfiltration)
 *   5. record tokens + cost + findings to the event store (Postgres)
 *
 * Drop-in: point your SDK's baseURL here; it stays wire-compatible.
 *
 * TODO(build): implement spec-first -- write tests from the eval datasets, then this pipeline.
 *   - HTTP layer: Hono (light, edge-friendly) or Express.
 *   - tripwire-core binding: napi-rs | wasm | sidecar (decide in SPEC).
 *   - providers: pin exact model ids at build time (see docs/SPEC.md).
 */

export async function handleProxy(_req: Request): Promise<Response> {
  throw new Error("TODO(build): implement the proxy pipeline -- see this file's header and docs/SPEC.md");
}
