# promptward

An LLM gateway that catches what hurts in production: **prompt injection** and **data exfiltration** on the way in and out, with **structured-output validation** and **per-request cost metering** -- and an **eval harness that proves the detection rate** instead of asserting it.

Point your OpenAI or Anthropic SDK at promptward instead of the provider. It stays wire-compatible, scans every request through a fast Rust detection core, blocks or redacts on policy, validates the model's structured output against your schema, and records tokens + cost per call.

## Why this exists

Most teams shipping LLM features have the same two unsolved problems: untrusted text reaching the model (injection) and sensitive data leaving in a prompt or response (exfiltration) -- and no measured handle on either. promptward puts a thin, fast checkpoint in front of the model and, just as importantly, ships the evals that say how well it works.

## Detection rate

Numbers below are produced by `pnpm eval` over the labeled datasets in `evals/datasets/`. They are a measured run, not estimates.

| Category | Precision | Recall | F1 |
|---|---|---|---|
| Prompt injection | _run `pnpm eval`_ | _._ | _._ |
| Data exfiltration | _run `pnpm eval`_ | _._ | _._ |

Overhead: _added p50 latency and $/1k requests, from the same run._

## How it works

```
SDK (baseURL -> promptward)
        |
   [ gateway ]  TypeScript proxy, wire-compatible with OpenAI/Anthropic
        |  1. scan inbound  ->  tripwire-core (Rust)   injection + exfiltration
        |  2. policy gate   ->  allow / redact / block
        |  3. provider call ->  Anthropic / OpenAI
        |  4. validate      ->  structured output vs JSON Schema (retry on miss)
        |  5. scan outbound ->  tripwire-core (Rust)   exfiltration
        |  6. record        ->  tokens + cost + findings  (Postgres)
        v
   [ dashboard ]  React: live request log, findings, cost
```

- **tripwire-core** (`crates/tripwire-core`) -- the hot-path scanners in Rust: injection heuristics, secret/PII detection (pattern + entropy). Deterministic and cheap.
- **gateway** (`apps/gateway`) -- the proxy: policy, provider calls, schema validation, cost metering. Optional LLM-judge stage for the fuzzy cases.
- **evals** (`evals/`) -- runs the detectors over labeled data and reports precision/recall/F1. The README's numbers come from here.
- **dashboard** (`apps/dashboard`) -- request log, findings, and cost at a glance.

## Quickstart

```bash
pnpm install
pnpm core:build      # build the Rust detection core
pnpm eval            # run the detectors over the datasets -> precision/recall/F1
pnpm gateway         # start the proxy
pnpm dashboard       # start the dashboard
```

## Status

Early and active. The architecture, datasets, and eval contract are in place; detectors and the proxy pipeline are landing incrementally (see `docs/SPEC.md`). Built in the open.

## License

MIT
