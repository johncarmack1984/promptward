# dashboard

The promptward console: a dense, dark security surface for the gateway. Three views.

- **Detection** -- the headline. Renders the measured eval artifact: overall precision / recall / F1, the zero-false-positive story, Recall at 0 benign FP, the confusion matrix, and per-bucket recall. The artifact is synced verbatim from canonical `evals/results.json` by `scripts/sync-results.mjs` (run automatically before dev / build / typecheck) into the gitignored `src/data/results.json` -- one source of truth, so the console can never drift from the numbers `pnpm eval` produced. Never hand-written.
- **Requests** -- the live request log. Fetches `GET /v1/requests?limit=100` from the gateway; if it is not running, falls back to a bundled sample fixture so the view always renders. Each row shows time, provider, model, an action badge (allow / redact / block), finding count, cost (or `unpriced`), and latency. Expand a row for inbound and outbound findings with severity, kind, label, score, and byte span.
- **Cost** -- request count, total spend, blocked count, finding count, plus policy-outcome distribution and spend by model.

## Run

```bash
pnpm install            # once, at the repo root
pnpm dashboard          # vite dev server on http://localhost:47306
```

In dev, `/api/*` is proxied to the gateway at `http://localhost:8787` (same-origin, no CORS). Start the gateway with `pnpm gateway` to see live traffic; otherwise the console shows bundled sample data and labels itself as such.

## Build

```bash
pnpm --filter @promptward/dashboard build
```

Self-contained: it type-checks and builds with no gateway running and no network access.

## Design

A dense observability console, not an admin template. Cold steel neutrals (no pure black), one reserved alert-red for block / critical, amber for redact / medium, a calm green for clean / allow; severity is the only thing allowed saturated color, so attention tracks risk. Monospaced tabular numerals throughout, hairline 1px rules instead of cards, and a per-row left spine colored by the row's worst severity. Dark-locked, single theme. Tokens live in `src/index.css`.
