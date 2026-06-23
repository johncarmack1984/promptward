// Shared helpers for the provider adapters: walk a request/response into
// scannable parts, and apply redactions back at the same JSON path. Centralized
// so a fix to message-walking is not duplicated across adapters.
import type { RedactedPart, ScanPart } from "../pipeline.js";
import type { Source } from "../scan.js";

/* eslint-disable @typescript-eslint/no-explicit-any */

/** Set a string value at a JSON path inside `obj` (mutates). No-op if the path
 *  does not fully resolve, so a stale path can never corrupt the body. */
function setAtPath(obj: any, path: Array<string | number>, value: string): void {
  if (path.length === 0) return;
  let node = obj;
  for (let i = 0; i < path.length - 1; i++) {
    if (node == null) return;
    node = node[path[i]];
  }
  if (node != null) node[path[path.length - 1]] = value;
}

/** Deep clone of `obj` with each redaction applied at its path. Returns `obj`
 *  unchanged (no clone) when there is nothing to redact. */
export function applyRedactions<T>(obj: T, redactions: RedactedPart[]): T {
  if (!redactions.length) return obj;
  const clone = structuredClone(obj);
  for (const r of redactions) setAtPath(clone, r.path, r.text);
  return clone;
}

/** Turn a string-or-text-block `content` value into scan parts at the right
 *  paths. A string lives at `basePath`; array text blocks at `basePath/i/text`. */
export function textParts(
  content: any,
  source: Source,
  basePath: Array<string | number>,
): ScanPart[] {
  if (typeof content === "string") return [{ source, text: content, path: basePath }];
  if (Array.isArray(content)) {
    const parts: ScanPart[] = [];
    content.forEach((b, i) => {
      if (b?.type === "text" && typeof b.text === "string") {
        parts.push({ source, text: b.text, path: [...basePath, i, "text"] });
      }
    });
    return parts;
  }
  return [];
}
/* eslint-enable @typescript-eslint/no-explicit-any */
