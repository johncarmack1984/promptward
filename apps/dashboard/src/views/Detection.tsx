import resultsRaw from "../data/results.json";
import type { EvalResults, Bucket } from "../types";
import { pct } from "../format";

const results = resultsRaw as EvalResults;

// Stable display order so the table reads injection-then-exfiltration-then-benign.
const CLASS_ORDER: Array<Bucket["label"]> = ["injection", "exfiltration", "benign"];
const CLASS_TITLE: Record<Bucket["label"], string> = {
  injection: "prompt injection",
  exfiltration: "data exfiltration",
  benign: "benign / hard negatives",
};

function BucketRows() {
  const { buckets } = results.metrics;
  const entries = Object.entries(buckets);
  const grouped = CLASS_ORDER.map((cls) => ({
    cls,
    rows: entries.filter(([, b]) => b.label === cls),
  }));

  return (
    <>
      {grouped.map(({ cls, rows }) => (
        <tbody key={cls}>
          <tr className="group-head">
            <td colSpan={4}>
              {CLASS_TITLE[cls]}{" "}
              <span style={{ color: "var(--text-faint)" }}>
                {rows.reduce((s, [, b]) => s + b.count, 0)} examples
              </span>
            </td>
          </tr>
          {rows.map(([name, b]) => {
            const isBenign = b.label === "benign";
            // For benign, "rate" is the false-positive rate (lower is better).
            const meterPct = isBenign ? (1 - b.rate) * 100 : b.rate * 100;
            const full = isBenign ? b.detected === 0 : b.rate === 1;
            return (
              <tr key={name}>
                <td className="bucket-name">{name.replace(/_/g, " ")}</td>
                <td>
                  <span className={`tag-class ${b.label}`}>{b.label}</span>
                </td>
                <td className="r">
                  {isBenign ? `${b.detected}/${b.count} fp` : `${b.detected}/${b.count}`}
                </td>
                <td className="r">
                  <div className="meter">
                    <span className="meter__track">
                      <span
                        className={`meter__fill ${full ? "" : "partial"}`}
                        style={{ width: `${meterPct}%` }}
                      />
                    </span>
                    <span className={`meter__val ${full ? "full" : ""}`}>
                      {isBenign ? pct(b.rate, 0) : pct(b.rate, 0)}
                    </span>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      ))}
    </>
  );
}

export function Detection() {
  const m = results.metrics;
  const p = results.performance;

  return (
    <section aria-labelledby="detection-h">
      <div className="section-title">
        <h2 id="detection-h">Detection rate</h2>
        <p>
          measured by the eval harness over {m.corpusSize} labeled examples, decision
          threshold {m.threshold}
        </p>
      </div>

      <div className="proof">
        <div className="proof__hero">
          <p className="proof__kicker">attack detection, overall</p>
          <div className="proof__big">
            <div className="proof__stat is-good">
              <span className="v">{pct(m.overall.precision, 0)}</span>
              <span className="l">precision</span>
            </div>
            <div className="proof__rule" />
            <div className="proof__stat">
              <span className="v">{pct(m.overall.recall)}</span>
              <span className="l">recall</span>
            </div>
            <div className="proof__rule" />
            <div className="proof__stat">
              <span className="v">{pct(m.overall.f1)}</span>
              <span className="l">F1</span>
            </div>
          </div>
          <p className="proof__note">
            <b>Zero false positives</b> across all {m.labelCounts.benign} benign examples,
            including hard negatives written to trip naive filters: quoted attack text,
            security questions, code with <span className="mono">apiKey</span> variables, git
            SHAs, and benign markdown links. {m.overall.tp} of {m.overall.tp + m.overall.fn}{" "}
            attacks caught; {m.overall.fp} clean prompts misflagged.
          </p>
        </div>

        <div className="proof__side">
          <h3>What it means for a runtime filter</h3>
          <div className="kv">
            <div className="kv__row">
              <span className="kv__k">
                Recall at 0 benign FP
                <span className="kv__sub">
                  n={m.recallAtZeroBenignFp.benignN}; 1% FPR not resolvable
                </span>
              </span>
              <span className="kv__v good">{pct(m.recallAtZeroBenignFp.recall)}</span>
            </div>
            <div className="kv__row">
              <span className="kv__k">
                Benign false-positive rate
                <span className="kv__sub">{m.confusion.tn} clean, 0 flagged</span>
              </span>
              <span className="kv__v good">{pct(m.benignFalsePositiveRate, 0)}</span>
            </div>
            <div className="kv__row">
              <span className="kv__k">
                Confusion
                <span className="kv__sub">tp / fp / fn / tn</span>
              </span>
              <span className="kv__v">
                {m.confusion.tp} / {m.confusion.fp} / {m.confusion.fn} / {m.confusion.tn}
              </span>
            </div>
            <div className="kv__row">
              <span className="kv__k">
                Scan latency
                <span className="kv__sub">deterministic, no model call</span>
              </span>
              <span className="kv__v">
                {p.perScanMsP50.toFixed(3)} / {p.perScanMsP95.toFixed(3)} ms
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="detail-grid" style={{ marginTop: 0 }}>
        <div className="panel">
          <div className="panel__head">
            <h3>Per-class metrics</h3>
            <span className="panel__meta">threshold {m.threshold}</span>
          </div>
          <table className="grid">
            <thead>
              <tr>
                <th>class</th>
                <th className="r">precision</th>
                <th className="r">recall</th>
                <th className="r">F1</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="bucket-name">
                  <span className="tag-class injection">injection</span>
                </td>
                <td className="r">{pct(m.perClass.injection.precision)}</td>
                <td className="r">{pct(m.perClass.injection.recall)}</td>
                <td className="r">{pct(m.perClass.injection.f1)}</td>
              </tr>
              <tr>
                <td className="bucket-name">
                  <span className="tag-class exfiltration">exfiltration</span>
                </td>
                <td className="r full">{pct(m.perClass.exfiltration.precision, 0)}</td>
                <td className="r full">{pct(m.perClass.exfiltration.recall, 0)}</td>
                <td className="r full">{pct(m.perClass.exfiltration.f1, 0)}</td>
              </tr>
            </tbody>
            <tbody>
              <tr className="group-head">
                <td colSpan={4}>corpus composition</td>
              </tr>
              <tr>
                <td className="bucket-name">injection examples</td>
                <td className="r" colSpan={3}>
                  {m.labelCounts.injection}
                </td>
              </tr>
              <tr>
                <td className="bucket-name">exfiltration examples</td>
                <td className="r" colSpan={3}>
                  {m.labelCounts.exfiltration}
                </td>
              </tr>
              <tr>
                <td className="bucket-name">benign examples</td>
                <td className="r" colSpan={3}>
                  {m.labelCounts.benign}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="panel">
          <div className="panel__head">
            <h3>Recall by attack class</h3>
            <span className="panel__meta">detected / total</span>
          </div>
          <table className="grid">
            <thead>
              <tr>
                <th>bucket</th>
                <th>class</th>
                <th className="r">hits</th>
                <th className="r">rate</th>
              </tr>
            </thead>
            <BucketRows />
          </table>
        </div>
      </div>
    </section>
  );
}
