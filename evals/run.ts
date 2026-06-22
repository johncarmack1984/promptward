/**
 * promptward eval harness.
 *
 * Loads datasets/{injection,exfiltration,benign}.jsonl, runs each example through
 * the detectors, and reports precision / recall / F1 per category plus a confusion
 * matrix. Costs (if an LLM-judge stage is enabled) are summed and reported per 1k examples.
 *
 * Output is a markdown table that gets pasted into README.md -- those numbers must be
 * REAL (a measured run), never hand-written. That honesty is the point of the repo.
 *
 * TODO(build): implement via TDD. Keep it deterministic and re-runnable in CI.
 */

type Example = { text: string; label: "injection" | "exfiltration" | "benign"; note?: string };

export async function runEvals(_datasetsDir = "evals/datasets"): Promise<void> {
  // 1. load jsonl -> Example[]
  // 2. for each: detections = scan(text)  (via tripwire-core)
  // 3. score against label; accumulate TP/FP/FN per category
  // 4. print precision/recall/F1 table + cost summary
  throw new Error("TODO(build): implement the eval runner -- see this file's header");
}
