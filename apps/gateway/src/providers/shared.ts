// Shared helpers for the provider adapters: walk a request/response into
// scannable parts, and apply redactions back at the same JSON path. Centralized
// so a fix to message-walking is not duplicated across adapters.
import type { RedactedPart, ScanPart } from "../pipeline.js";
import type { Source } from "../scan.js";

/* eslint-disable @typescript-eslint/no-explicit-any */

/** Set a string value at a JSON path inside `obj` (mutates). No-op if the path
 *  does not fully resolve, so a stale path can never corrupt the body. */
function setAtPath(obj: any, path: Array<string | number>, value: string): void {
  const last = path[path.length - 1];
  if (last === undefined) return;
  let node = obj;
  for (let i = 0; i < path.length - 1; i++) {
    const key = path[i];
    if (node == null || key === undefined) return;
    node = node[key];
  }
  if (node != null) node[last] = value;
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

/** Walk an arbitrary JSON value and emit a scan part for every string leaf,
 *  pathed for in-place redaction. Used to scan structured tool-call arguments
 *  (e.g. Anthropic tool_use.input) where a secret can hide in a nested value. */
export function stringLeafParts(
  value: any,
  source: Source,
  basePath: Array<string | number>,
): ScanPart[] {
  const parts: ScanPart[] = [];
  const walk = (node: any, path: Array<string | number>): void => {
    if (typeof node === "string") {
      parts.push({ source, text: node, path });
    } else if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, [...path, i]));
    } else if (node && typeof node === "object") {
      for (const k of Object.keys(node)) walk(node[k], [...path, k]);
    }
  };
  walk(value, basePath);
  return parts;
}
/* eslint-enable @typescript-eslint/no-explicit-any */
