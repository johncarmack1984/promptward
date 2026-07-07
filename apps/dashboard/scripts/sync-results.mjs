// Copies the canonical eval artifact into the dashboard bundle so the console
// always renders the exact numbers `pnpm eval` produced -- one source of truth,
// no hand-copied drift. Runs automatically before dev / build / typecheck.
// The destination (src/data/results.json) is generated and gitignored.
import { copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "../../../evals/results.json");
const dst = join(here, "../src/data/results.json");
copyFileSync(src, dst);
console.log("synced dashboard results.json from evals/results.json");
