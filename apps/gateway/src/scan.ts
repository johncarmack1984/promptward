// Typed wrapper over the Rust detection core. The napi enums are string-valued;
// this module is the single place that crosses into them.
import * as tripwire from "@promptward/tripwire";
import type { Finding } from "@promptward/tripwire";

const rawScan = tripwire.scan as (
  text: string,
  direction: string,
  source?: string,
) => Finding[];

export type Direction = "Inbound" | "Outbound";
export type Source =
  | "User"
  | "System"
  | "Tool"
  | "Document"
  | "McpDescription"
  | "ModelOutput";

export function scan(text: string, direction: Direction, source: Source): Finding[] {
  return rawScan(text, direction, source);
}

/** Highest finding score in a set, or 0. */
export function maxScore(findings: Finding[]): number {
  return findings.reduce((m, f) => Math.max(m, f.score), 0);
}
