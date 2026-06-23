import type { Finding } from "../types";
import { SeverityTag, KindTag } from "../components/primitives";

export function FindingItem({ finding }: { finding: Finding }) {
  const f = finding;
  const span = f.end - f.start;
  return (
    <div className="finding">
      <span className={`finding__spine ${f.severity}`} aria-hidden="true" />
      <div className="finding__main">
        <div className="finding__top">
          <span className="finding__label">{f.label}</span>
          <SeverityTag severity={f.severity} />
          <KindTag kind={f.kind} />
        </div>
        <div className="finding__meta">
          <span>
            <span className="k">source</span> {f.source}
          </span>
          <span>
            <span className="k">bytes</span> [{f.start}, {f.end}){" "}
            <span style={{ color: "var(--text-faint)" }}>({span}b)</span>
          </span>
        </div>
        {f.detail ? <div className="finding__detail">{f.detail}</div> : null}
      </div>
      <div className="finding__score">
        <div className="s">{f.score.toFixed(2)}</div>
        <div className="sl">score</div>
      </div>
    </div>
  );
}

export function Direction({
  label,
  findings,
}: {
  label: string;
  findings: Finding[];
}) {
  return (
    <div className="dir">
      <div className="dir__head">
        <span>{label}</span>
        <span style={{ color: "var(--text-faint)" }}>
          {findings.length} {findings.length === 1 ? "finding" : "findings"}
        </span>
      </div>
      {findings.length === 0 ? (
        <div className="dir__empty">
          <span className="ok">clean</span> no findings on this direction
        </div>
      ) : (
        findings.map((f, i) => <FindingItem key={`${f.label}-${f.start}-${i}`} finding={f} />)
      )}
    </div>
  );
}
