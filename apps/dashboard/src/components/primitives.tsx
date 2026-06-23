import type { PolicyAction, FindingKind, Severity, Provider } from "../types";

// A simple geometric shield/tripwire mark. One flat SVG, no gradients -- the
// only hand-drawn vector in the app, used once in the header.
export function BrandMark() {
  return (
    <svg
      className="brand__mark"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M12 2 4 5v6.2c0 4.7 3.2 7.6 8 8.8 4.8-1.2 8-4.1 8-8.8V5l-8-3Z"
        stroke="var(--accent)"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M4 12h5l1.6-3 2.4 6 1.6-3H20"
        stroke="var(--accent)"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function ActionBadge({ action }: { action: PolicyAction }) {
  return <span className={`badge ${action}`}>{action}</span>;
}

export function SeverityTag({ severity }: { severity: Severity }) {
  return <span className={`sev ${severity}`}>{severity}</span>;
}

export function KindTag({ kind }: { kind: FindingKind }) {
  return <span className={`kind ${kind}`}>{kind}</span>;
}

// Compact provider glyph: A for Anthropic, O for OpenAI. Avoids shipping
// trademarked logos while staying scannable in a dense table.
export function ProviderMark({ provider }: { provider: Provider }) {
  return (
    <span className="provider-mark" title={provider}>
      {provider === "anthropic" ? "A" : "O"}
    </span>
  );
}
