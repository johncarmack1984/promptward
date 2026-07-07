// Policy model: map findings to an action (allow / redact / block) and perform
// redaction. Code-defined (no DSL). Action precedence: block > redact > allow.
import type { Finding, PolicyAction, PolicyOutcome } from "./types.js";

function kindOf(f: Finding): string {
  return f.kind as unknown as string;
}
function sevOf(f: Finding): string {
  return f.severity as unknown as string;
}

/** Default per-finding action. */
function actionFor(f: Finding): PolicyAction {
  switch (kindOf(f)) {
    case "Injection":
      // High-confidence injection is blocked; weaker signals are flagged.
      return sevOf(f) === "High" || sevOf(f) === "Critical" ? "block" : "allow";
    case "Exfiltration":
      // Secrets/PII are redacted in both directions (the model never sees them
      // inbound; the caller never receives them outbound).
      return "redact";
    default:
      // Obfuscation is a carrier; the revealed payload drives the action.
      return "allow";
  }
}

const RANK: Record<PolicyAction, number> = { allow: 0, redact: 1, block: 2 };

export function decide(findings: Finding[], threshold: number): PolicyOutcome {
  const active = findings.filter((f) => f.score >= threshold);
  let action: PolicyAction = "allow";
  for (const f of active) {
    const a = actionFor(f);
    if (RANK[a] > RANK[action]) action = a;
  }
  const redacted =
    action === "redact" ? active.filter((f) => actionFor(f) === "redact").map((f) => f.label) : [];
  return { action, findings: active, redacted };
}

interface Span {
  start: number;
  end: number;
  label: string;
}

function mergeSpans(spans: Span[]): Span[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start);
  const merged: Span[] = [];
  for (const s of sorted) {
    const last = merged[merged.length - 1];
    if (last && s.start <= last.end) last.end = Math.max(last.end, s.end);
    else merged.push({ ...s });
  }
  return merged;
}

/**
 * Replace the exfiltration spans with typed placeholders. The secret value is
 * never copied anywhere -- only its label and span are used.
 *
 * The scanner's spans are UTF-8 BYTE offsets into the original text (see the
 * Rust core), so redaction operates on a UTF-8 Buffer, not on JS UTF-16 string
 * indices -- otherwise any multi-byte char (emoji / CJK / accent) before a
 * secret would drift the cut and leave part of the secret in the clear.
 */
export function redactText(text: string, findings: Finding[]): string {
  const spans = mergeSpans(
    findings
      .filter((f) => kindOf(f) === "Exfiltration")
      .map((f) => ({ start: f.start, end: f.end, label: f.label })),
  ).sort((a, b) => a.start - b.start);
  if (spans.length === 0) return text;

  const buf = Buffer.from(text, "utf8");
  const out: Buffer[] = [];
  let cursor = 0;
  for (const s of spans) {
    // mergeSpans already removed overlaps; skip anything out of range or behind.
    if (s.start < cursor || s.start > s.end || s.end > buf.length) continue;
    out.push(buf.subarray(cursor, s.start));
    out.push(Buffer.from(`[REDACTED:${s.label}]`, "utf8"));
    cursor = s.end;
  }
  out.push(buf.subarray(cursor));
  return Buffer.concat(out).toString("utf8");
}
