/**
 * promptward external-benchmark harness.
 *
 * Runs the SAME tripwire-core detector as the internal eval (evals/run.ts) over
 * third-party, field-cited prompt-injection benchmarks, and reports honest
 * per-dataset precision / recall / false-positive rate / F1 -- including where
 * the deterministic scanner does poorly. Surviving-or-honestly-failing on
 * public data is the point: these are out-of-distribution corpora the detector
 * was never tuned on.
 *
 * Datasets are declared in datasets.json (HF name + pinned revision + label
 * mapping), fetched from the HuggingFace datasets-server, and cached under
 * .cache/ (gitignored). Scoring is deterministic (the scan is pure); only the
 * fetch touches the network, and only on a cold cache or with --refresh.
 *
 * Usage:
 *   pnpm eval:external            # score all datasets (fetch on cold cache)
 *   pnpm eval:external --refresh  # re-fetch every dataset, then score
 *
 * Output: a markdown table to stdout + evals/external/results-external.json.
 * Numbers are a real run, never hand-written.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "@promptward/tripwire";
import * as tripwire from "@promptward/tripwire";

const scan = tripwire.scan as (text: string, direction: string, source?: string) => Finding[];

const HERE = dirname(fileURLToPath(import.meta.url));
const CACHE = join(HERE, ".cache");
const REFRESH = process.argv.includes("--refresh");

interface AttackSpec {
  field?: string;
  equals?: number | string;
  all?: boolean;
}
interface DatasetCfg {
  name: string;
  title: string;
  hf: string;
  revision: string;
  license: string;
  config: string;
  splits: string[];
  textField: string;
  attack: AttackSpec;
  measures: string;
  cite: string;
}
interface Config {
  threshold: number;
  datasets: DatasetCfg[];
  unavailable: { name: string; title: string; reason: string; source: string }[];
}

const cfg: Config = JSON.parse(readFileSync(join(HERE, "datasets.json"), "utf8"));
const THRESHOLD = cfg.threshold;

interface Row {
  text: string;
  attack: boolean;
}

interface RowsPage {
  rows?: { row: Record<string, unknown> }[];
  num_rows_total?: number;
  num_total_rows?: number;
}

async function fetchRowsPage(url: string): Promise<RowsPage> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const r = await fetch(url);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return (await r.json()) as RowsPage;
    } catch (e) {
      lastErr = e;
      await new Promise((res) => setTimeout(res, 1500 * (attempt + 1)));
    }
  }
  throw new Error(`fetch failed after retries: ${url} (${String(lastErr)})`);
}

function isAttack(row: Record<string, unknown>, spec: AttackSpec): boolean {
  if (spec.all !== undefined) return spec.all;
  return row[spec.field as string] === spec.equals;
}

async function loadDataset(d: DatasetCfg): Promise<Row[]> {
  const cachePath = join(CACHE, `${d.name}.jsonl`);
  if (existsSync(cachePath) && !REFRESH) {
    return readFileSync(cachePath, "utf8")
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as Row);
  }
  const rows: Row[] = [];
  for (const split of d.splits) {
    let offset = 0;
    for (;;) {
      const url =
        `https://datasets-server.huggingface.co/rows?dataset=${encodeURIComponent(d.hf)}` +
        `&config=${encodeURIComponent(d.config)}&split=${encodeURIComponent(split)}` +
        `&offset=${offset}&length=100`;
      const page = await fetchRowsPage(url);
      const batch = page.rows ?? [];
      if (batch.length === 0) break;
      for (const item of batch) {
        const text = item.row[d.textField];
        if (typeof text !== "string") continue;
        rows.push({ text, attack: isAttack(item.row, d.attack) });
      }
      offset += batch.length;
      const total: number | undefined = page.num_rows_total ?? page.num_total_rows;
      if (total && offset >= total) break;
    }
  }
  mkdirSync(CACHE, { recursive: true });
  writeFileSync(cachePath, `${rows.map((r) => JSON.stringify(r)).join("\n")}\n`);
  return rows;
}

function attackScore(text: string): number {
  let m = 0;
  for (const f of scan(text, "Inbound", "User")) m = Math.max(m, f.score);
  return m;
}

interface DatasetResult {
  name: string;
  title: string;
  hf: string;
  revision: string;
  license: string;
  measures: string;
  rows: number;
  attacks: number;
  benign: number;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  recall: number | null;
  precision: number | null;
  falsePositiveRate: number | null;
  f1: number | null;
  contentSha256: string;
  cite: string;
}

function scoreDataset(d: DatasetCfg, rows: Row[]): DatasetResult {
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;
  const hash = createHash("sha256");
  for (const r of rows) {
    hash.update(`${r.attack ? 1 : 0}\t${r.text}\n`);
    const flagged = attackScore(r.text) >= THRESHOLD;
    if (flagged && r.attack) tp++;
    else if (flagged && !r.attack) fp++;
    else if (!flagged && r.attack) fn++;
    else tn++;
  }
  const attacks = tp + fn;
  const benign = tn + fp;
  // Precision and F1 are only meaningful when BOTH classes are present. On an
  // all-attack set precision is a trivial 1.0 (no negatives to get wrong); on an
  // all-benign set it is a meaningless 0. Report them as -- in those cases.
  const bothClasses = attacks > 0 && benign > 0;
  const recall = attacks ? tp / attacks : null;
  const falsePositiveRate = benign ? fp / benign : null;
  const precision = bothClasses ? tp / (tp + fp) : null;
  const f1 =
    bothClasses && precision !== null && recall !== null && precision + recall > 0
      ? (2 * precision * recall) / (precision + recall)
      : null;
  return {
    name: d.name,
    title: d.title,
    hf: d.hf,
    revision: d.revision,
    license: d.license,
    measures: d.measures,
    rows: rows.length,
    attacks,
    benign,
    tp,
    fp,
    fn,
    tn,
    recall,
    precision,
    falsePositiveRate,
    f1,
    contentSha256: hash.digest("hex").slice(0, 16),
    cite: d.cite,
  };
}

function pct(x: number | null): string {
  return x === null ? "  --  " : `${(100 * x).toFixed(1)}%`;
}

async function main(): Promise<void> {
  const results: DatasetResult[] = [];
  for (const d of cfg.datasets) {
    process.stderr.write(`scoring ${d.name} ...\n`);
    const rows = await loadDataset(d);
    results.push(scoreDataset(d, rows));
  }

  const artifact = {
    generatedBy: "pnpm eval:external",
    threshold: THRESHOLD,
    detector: "tripwire-core (same build as the internal eval); direction=Inbound, source=User",
    datasets: results,
    unavailable: cfg.unavailable,
  };
  writeFileSync(join(HERE, "results-external.json"), `${JSON.stringify(artifact, null, 2)}\n`);

  console.log(`\npromptward external benchmarks -- decision threshold ${THRESHOLD}\n`);
  console.log(
    "| dataset                                    |  rows | attack | benign | Recall | Prec  | FP-rate |   F1  |",
  );
  console.log(
    "|--------------------------------------------|-------|--------|--------|--------|-------|---------|-------|",
  );
  for (const r of results) {
    console.log(
      `| ${r.title.padEnd(42)} | ${String(r.rows).padStart(5)} | ${String(r.attacks).padStart(6)} | ${String(r.benign).padStart(6)} | ${pct(r.recall).padStart(6)} | ${pct(r.precision).padStart(5)} | ${pct(r.falsePositiveRate).padStart(7)} | ${pct(r.f1).padStart(5)} |`,
    );
  }
  console.log("\nUnavailable (documented, not scored):");
  for (const u of cfg.unavailable) console.log(`  - ${u.title}: ${u.reason.split(".")[0]}.`);
  console.log("\nWrote evals/external/results-external.json");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
