// Shared helpers for the provider adapters: walk a request/response into
// scannable parts, and apply redactions back at the same JSON path. Centralized
// so a fix to message-walking is not duplicated across adapters.
import type { RedactedPart, ScanPart } from "../pipeline.js";
import type { Source } from "../scan.js";

/** Set a string value at a JSON path inside `obj` (mutates). No-op if the path
 *  does not fully resolve, so a stale path can never corrupt the body. */
function setAtPath(obj: unknown, path: Array<string | number>, value: string): void {
  const last = path[path.length - 1];
  if (last === undefined) return;
  let node: unknown = obj;
  for (let i = 0; i < path.length - 1; i++) {
    const key = path[i];
    if (node == null || key === undefined) return;
    node = typeof key === "number" ? arr(node)[key] : rec(node)[key];
  }
  if (Array.isArray(node) && typeof last === "number") node[last] = value;
  else if (node && typeof node === "object") (node as Record<string, unknown>)[last] = value;
}

/** Deep clone of `obj` with each redaction applied at its path. Returns `obj`
 *  unchanged (no clone) when there is nothing to redact. */
export function applyRedactions<T>(obj: T, redactions: RedactedPart[]): T {
  if (!redactions.length) return obj;
  const clone = structuredClone(obj);
  for (const r of redactions) setAtPath(clone, r.path, r.text);
  return clone;
}

/** Narrowing views over untrusted wire JSON: the object's fields, or nothing.
 *  Adapters read through these so the wire stays typed as unknown end to end. */
export const rec = (v: unknown): Record<string, unknown> =>
  typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};

/** The value as an array, or an empty one. */
export const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/** Turn a string-or-text-block `content` value into scan parts at the right
 *  paths. A string lives at `basePath`; array text blocks at `basePath/i/text`. */
export function textParts(
  content: unknown,
  source: Source,
  basePath: Array<string | number>,
): ScanPart[] {
  if (typeof content === "string") return [{ source, text: content, path: basePath }];
  if (Array.isArray(content)) {
    const parts: ScanPart[] = [];
    content.forEach((bv, i) => {
      const b = rec(bv);
      if (b.type === "text" && typeof b.text === "string") {
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
  value: unknown,
  source: Source,
  basePath: Array<string | number>,
): ScanPart[] {
  const parts: ScanPart[] = [];
  const walk = (node: unknown, path: Array<string | number>): void => {
    if (typeof node === "string") {
      parts.push({ source, text: node, path });
    } else if (Array.isArray(node)) {
      node.forEach((v, i) => {
        walk(v, [...path, i]);
      });
    } else if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) walk(v, [...path, k]);
    }
  };
  walk(value, basePath);
  return parts;
}
