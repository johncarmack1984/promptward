/**
 * promptward eval harness.
 *
 * Loads datasets/{injection,exfiltration,benign}.jsonl, runs each example through
 * the Rust detection core (via the @promptward/tripwire napi binding), and reports
 * precision / recall / F1 per attack class and per bucket, an attack-vs-benign
 * confusion matrix, Recall @ 0 benign false positives (the honest operating
 * point -- a 1% FPR is not resolvable on a sub-100 benign set), the benign
 * false-positive rate, and scan latency. Deterministic: scan is pure, so the
 * detection numbers are identical across runs (only latency varies).
 *
 * Output is a markdown table (-> README) plus evals/results.json, which the
 * dashboard imports verbatim (synced by apps/dashboard/scripts/sync-results.mjs;
 * single source of truth). Numbers must be a real run, never hand-written.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import type { Finding } from "@promptward/tripwire";
import * as tripwire from "@promptward/tripwire";

// The napi enums are string-valued; call with plain strings to avoid const-enum
// runtime friction.
const scan = tripwire.scan as (text: string, direction: string, source?: string) => Finding[];

const HERE = dirname(fileURLToPath(import.meta.url));
const DATA = join(HERE, "datasets");
const THRESHOLD = 0.5;

type Label = "injection" | "exfiltration" | "benign";
interface Example {
  id: string;
  text: string;
  label: Label;
  bucket: string;
  direction?: "inbound" | "outbound";
  note?: string;
}

function load(file: string): Example[] {
  const raw = readFileSync(join(DATA, file), "utf8");
  return raw
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as Example);
}

function sourceFor(ex: Example): string {
  switch (ex.bucket) {
    case "tool_result_injection":
      return "Tool";
    case "mcp_description_poisoning":
      return "McpDescription";
    case "indirect_injection":
      return "Document";
    case "markdown_image_exfil":
      return "ModelOutput";
    default:
      return ex.direction === "outbound" ? "ModelOutput" : "User";
  }
}

function directionFor(ex: Example): string {
  return ex.direction === "outbound" ? "Outbound" : "Inbound";
}

interface Scored {
  ex: Example;
  inj: number;
  exf: number;
  obf: number;
  attack: number;
  /** Whether the row produced ANY finding (including sub-threshold). */
  hasFinding: boolean;
}

function scoreExample(ex: Example): Scored {
  const findings = scan(ex.text, directionFor(ex), sourceFor(ex));
  let inj = 0;
  let exf = 0;
  let obf = 0;
  for (const f of findings) {
    const k = f.kind as unknown as string;
    if (k === "Injection") inj = Math.max(inj, f.score);
    else if (k === "Exfiltration") exf = Math.max(exf, f.score);
    else if (k === "Obfuscation") obf = Math.max(obf, f.score);
  }
  return { ex, inj, exf, obf, attack: Math.max(inj, exf, obf), hasFinding: findings.length > 0 };
}

interface PRF {
  precision: number;
  recall: number;
  f1: number;
  tp: number;
  fp: number;
  fn: number;
}
function prf(tp: number, fp: number, fn: number): PRF {
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return { precision, recall, f1, tp, fp, fn };
}

/** Per-class metrics: predicted-positive when a finding of `kind` clears the threshold. */
function classMetrics(scored: Scored[], label: Label, pick: (s: Scored) => number): PRF {
  let tp = 0;
  let fp = 0;
  let fn = 0;
  for (const s of scored) {
    const predicted = pick(s) >= THRESHOLD;
    const actual = s.ex.label === label;
    if (predicted && actual) tp++;
    else if (predicted && !actual) fp++;
    else if (!predicted && actual) fn++;
  }
  return prf(tp, fp, fn);
}

// Operating point: the strictest threshold that flags zero benign examples, and
// the attack recall there. We deliberately do NOT call this "Recall @ 1% FPR":
// with a benign set this small, 1% is below the resolution of the corpus --
// floor(0.01 * n) rounds the allowed false positives to 0 for any n < 100 -- so
// the honest operating point is "Recall @ 0 benign FP". The effective FPR is
// reported alongside so the number can never be read as a measured 1%.
function recallAtZeroBenignFp(scored: Scored[]): {
  threshold: number;
  recall: number;
  allowedFp: number;
  benignN: number;
  effectiveFprPct: number;
} {
  const benign = scored.filter((s) => s.ex.label === "benign").map((s) => s.attack);
  const attacks = scored.filter((s) => s.ex.label !== "benign").map((s) => s.attack);
  benign.sort((a, b) => b - a);
  const benignN = benign.length;
  const allowedFp = Math.floor(0.01 * benignN);
  // Lowest threshold that flags at most `allowedFp` benign examples.
  const threshold = (benign[allowedFp] ?? 0) + 1e-9;
  const recall = attacks.filter((a) => a >= threshold).length / (attacks.length || 1);
  const effectiveFprPct = benignN ? (100 * allowedFp) / benignN : 0;
  return { threshold: Number(threshold.toFixed(3)), recall, allowedFp, benignN, effectiveFprPct };
}

function pct(x: number): string {
  return (100 * x).toFixed(1);
}

function main(): void {
  const all = [...load("injection.jsonl"), ...load("exfiltration.jsonl"), ...load("benign.jsonl")];
  const scored = all.map(scoreExample);

  const injection = classMetrics(scored, "injection", (s) => s.inj);
  const exfiltration = classMetrics(scored, "exfiltration", (s) => s.exf);

  // Overall attack-vs-benign.
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;
  for (const s of scored) {
    const flagged = s.attack >= THRESHOLD;
    const attack = s.ex.label !== "benign";
    if (flagged && attack) tp++;
    else if (flagged && !attack) fp++;
    else if (!flagged && attack) fn++;
    else tn++;
  }
  const overall = prf(tp, fp, fn);
  const benignTotal = tn + fp;
  const benignFpr = benignTotal ? fp / benignTotal : 0;
  const ra = recallAtZeroBenignFp(scored);

  // Per-bucket: recall for attack buckets, false-positive rate for benign buckets.
  const buckets: Record<string, { label: Label; count: number; detected: number; rate: number }> =
    {};
  for (const s of scored) {
    const b = (buckets[s.ex.bucket] ??= { label: s.ex.label, count: 0, detected: 0, rate: 0 });
    b.count++;
    if (s.attack >= THRESHOLD) b.detected++;
  }
  for (const b of Object.values(buckets)) b.rate = b.detected / b.count;

  // 3-class confusion (rows = actual label, cols = predicted class by dominant
  // signal). Makes cross-class firing explicit: an exfiltration row that also
  // trips the injection scanner appears off-diagonal, so a per-class "false
  // positive" is visibly a different attack class, not a benign misfire.
  // `benignAnyFinding` is the strict-spec view: benign rows with ANY finding,
  // including sub-threshold informational ones that drive no policy action.
  const confusion3: Record<string, { injection: number; exfiltration: number; clean: number }> = {
    injection: { injection: 0, exfiltration: 0, clean: 0 },
    exfiltration: { injection: 0, exfiltration: 0, clean: 0 },
    benign: { injection: 0, exfiltration: 0, clean: 0 },
  };
  let benignAnyFinding = 0;
  for (const s of scored) {
    const predicted: "injection" | "exfiltration" | "clean" =
      s.attack < THRESHOLD ? "clean" : s.inj >= s.exf ? "injection" : "exfiltration";
    confusion3[s.ex.label][predicted]++;
    if (s.ex.label === "benign" && s.hasFinding) benignAnyFinding++;
  }

  // Latency (informational; not part of the deterministic metrics).
  const reps = 5;
  const times: number[] = [];
  for (let r = 0; r < reps; r++) {
    for (const ex of all) {
      const t0 = performance.now();
      scan(ex.text, directionFor(ex), sourceFor(ex));
      times.push(performance.now() - t0);
    }
  }
  times.sort((a, b) => a - b);
  const p = (q: number) => Number((times[Math.floor(q * times.length)] ?? 0).toFixed(4));

  const metrics = {
    corpusSize: all.length,
    labelCounts: {
      injection: all.filter((e) => e.label === "injection").length,
      exfiltration: all.filter((e) => e.label === "exfiltration").length,
      benign: all.filter((e) => e.label === "benign").length,
    },
    threshold: THRESHOLD,
    perClass: { injection, exfiltration },
    overall,
    benignFalsePositiveRate: benignFpr,
    recallAtZeroBenignFp: ra,
    confusion: { tp, fp, fn, tn },
    confusion3,
    benignAnyFinding,
    buckets,
    caveats: [
      "Scores are calibrated on the same labeled corpus they are measured on (no held-out split); read these as an upper bound for this corpus, not a generalization estimate.",
      `Benign set is small (n=${ra.benignN}); a 1% false-positive rate is not resolvable below n=100, so the operating point is reported as Recall @ 0 benign FP, not Recall @ 1% FPR.`,
      "Static corpus: a fixed dataset overstates robustness against an adaptive attacker; treat the rate as a regression signal, not a security guarantee.",
      "Per-class precision counts a row flagged by a DIFFERENT attack class as a false positive; see confusion3 -- against benign-only negatives both classes have zero false positives.",
      `Benign false-positive rate is operational (a finding at or above the ${THRESHOLD} decision threshold drives an action); benignAnyFinding=${benignAnyFinding} additionally counts benign rows with any sub-threshold informational finding.`,
    ],
  };
  const performanceBlock = {
    perScanMsP50: p(0.5),
    perScanMsP95: p(0.95),
    scansTimed: times.length,
  };
  const artifact = {
    generatedBy: "pnpm eval",
    metrics,
    performance: performanceBlock,
  };
  writeFileSync(join(HERE, "results.json"), JSON.stringify(artifact, null, 2) + "\n");

  // --- human-readable report ---
  const row = (name: string, m: PRF) =>
    `| ${name.padEnd(18)} | ${pct(m.precision).padStart(7)} | ${pct(m.recall).padStart(7)} | ${pct(m.f1).padStart(7)} | ${String(m.tp).padStart(3)} | ${String(m.fp).padStart(3)} | ${String(m.fn).padStart(3)} |`;
  console.log(`\npromptward eval -- ${all.length} examples (decision threshold ${THRESHOLD})\n`);
  console.log("| class              | Prec %  | Rec %   | F1 %    |  TP |  FP |  FN |");
  console.log("|--------------------|---------|---------|---------|-----|-----|-----|");
  console.log(row("Prompt injection", injection));
  console.log(row("Data exfiltration", exfiltration));
  console.log(row("Attack (overall)", overall));
  console.log(`\nBenign false-positive rate: ${pct(benignFpr)}%  (${fp}/${benignTotal})`);
  console.log(
    `Recall @ 0 benign FP: ${pct(ra.recall)}%  (threshold ${ra.threshold}; ${ra.allowedFp}/${ra.benignN} benign flagged, effective FPR ${ra.effectiveFprPct.toFixed(1)}%; 1% FPR unresolvable at n=${ra.benignN})`,
  );
  console.log(`Confusion (attack/benign): TP ${tp}  FP ${fp}  FN ${fn}  TN ${tn}`);
  console.log(
    `Scan latency: p50 ${performanceBlock.perScanMsP50}ms  p95 ${performanceBlock.perScanMsP95}ms\n`,
  );

  console.log("Per-bucket detection:");
  for (const [name, b] of Object.entries(buckets).sort()) {
    const kind = b.label === "benign" ? "FP-rate" : "recall ";
    console.log(
      `  ${name.padEnd(26)} ${kind} ${pct(b.rate).padStart(6)}%  (${b.detected}/${b.count})`,
    );
  }
  console.log("\n3-class confusion (rows = actual, cols = predicted):");
  console.log("                     inj    exf  clean");
  for (const actual of ["injection", "exfiltration", "benign"] as const) {
    const r = confusion3[actual];
    console.log(
      `  ${actual.padEnd(16)} ${String(r.injection).padStart(4)} ${String(r.exfiltration).padStart(6)} ${String(r.clean).padStart(6)}`,
    );
  }
  console.log(
    `Benign rows with any finding (strict, sub-threshold included): ${benignAnyFinding}/${benignTotal}`,
  );

  console.log("\nWrote evals/results.json");

  // CI gate: fail if detection regresses below pinned floors (overridable).
  const minF1 = Number(process.env.PROMPTWARD_MIN_F1 ?? 0.9);
  const minRecall0 = Number(process.env.PROMPTWARD_MIN_RECALL_0FP ?? 0.9);
  if (overall.f1 < minF1 || ra.recall < minRecall0) {
    console.error(
      `\nFAIL: overall F1 ${pct(overall.f1)}% (floor ${pct(minF1)}%) or Recall@0benignFP ${pct(ra.recall)}% (floor ${pct(minRecall0)}%) below threshold`,
    );
    process.exit(1);
  }
  console.log(
    `PASS: F1 ${pct(overall.f1)}% >= ${pct(minF1)}%, Recall@0benignFP ${pct(ra.recall)}% >= ${pct(minRecall0)}%`,
  );
}

main();
