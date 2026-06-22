# promptward -- spec (seed)

This is a starting spec. Refine it before implementation: tighten the policy model, pin the core/gateway binding, and lock the eval contract.

## Problem

Teams shipping LLM features lack a fast, measured checkpoint for two failure modes: prompt injection (untrusted text steering the model) and data exfiltration (secrets/PII leaving in a prompt or response). promptward is a drop-in proxy that detects both, validates structured output, meters cost, and -- the differentiator -- ships evals that quantify the detection rate.

## MVP scope (the citable cut)

1. **tripwire-core** (Rust): `scan(text, direction) -> Vec<Finding>` for injection (heuristics) and exfiltration (secret/PII patterns + entropy). Deterministic, allocation-light.
2. **gateway** (TS): OpenAI/Anthropic-compatible proxy. Inbound scan -> policy gate (allow/redact/block) -> provider call -> structured-output validation (JSON Schema, retry on miss) -> outbound scan -> record tokens/cost/findings to Postgres.
3. **evals**: load `evals/datasets/*.jsonl`, run detectors, report precision/recall/F1 + cost. Output is the README table -- numbers must be a real run.
4. **dashboard** (React): request log, findings, cost. Build with the frontend design direction; no generic admin-template look.

Optional LLM-judge stage in the gateway for fuzzy injection cases (cost-tracked, cached).

## Stretch (post-MVP)

- Browser extension (manifest v3) that flags "shadow AI" -- sensitive data pasted into consumer LLM tools (ChatGPT, etc.).
- Tool-calling triage agent that classifies/routes findings.
- Event streaming for the findings pipeline at scale.

## Key decisions to make in spec

- **core <-> gateway binding**: napi-rs (in-process, fastest) vs wasm (portable) vs sidecar (simplest). Default lean: napi-rs.
- **policy model**: per-route allow/redact/block; how redaction is represented to the caller.
- **structured output**: JSON Schema validation + bounded retry; surface the failure honestly when retries exhaust.
- **cost model**: token + price table per model id; pin exact ids at build time.
- **eval contract**: dataset schema (`{text, label, note}`), metrics, determinism, CI re-run.

## Non-goals (for now)

- A full SIEM / log pipeline. promptward emits events; it is not the analytics backend.
- Model hosting or fine-tuning. It proxies hosted providers.
- A policy DSL. Start with code-defined policies; generalize only if needed.

## Principles

- Eval-first: write failing tests from `evals/datasets/*.jsonl`, then implement detectors.
- Honest numbers: the README rate is a measured run, never hand-written.
- Fast path stays fast: deterministic scanners in Rust; the LLM-judge is opt-in and cached.
- ASCII only, concise, declarative.
