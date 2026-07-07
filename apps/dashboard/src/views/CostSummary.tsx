import { useMemo } from "react";
import { pct, usd } from "../format";
import type { PolicyAction, RequestRecord, StoreStats } from "../types";

interface ModelSpend {
  model: string;
  cost: number;
  calls: number;
  unpriced: number;
}

export function CostSummary({ records, stats }: { records: RequestRecord[]; stats: StoreStats }) {
  const actionCounts = useMemo(() => {
    const c: Record<PolicyAction, number> = { block: 0, redact: 0, allow: 0 };
    for (const r of records) c[r.action] += 1;
    return c;
  }, [records]);

  const byModel = useMemo<ModelSpend[]>(() => {
    const map = new Map<string, ModelSpend>();
    for (const r of records) {
      const cur = map.get(r.model) ?? { model: r.model, cost: 0, calls: 0, unpriced: 0 };
      cur.calls += 1;
      if (r.costUsd !== null) cur.cost += r.costUsd;
      if (r.costUsd === null && r.costUnpriced) cur.unpriced += 1;
      map.set(r.model, cur);
    }
    return [...map.values()].sort((a, b) => b.cost - a.cost);
  }, [records]);

  const total = stats.count || 1;
  const maxAction = Math.max(actionCounts.block, actionCounts.redact, actionCounts.allow, 1);
  const blockedPct = stats.count ? stats.blocked / stats.count : 0;

  return (
    <section aria-labelledby="cost-h">
      <div className="section-title">
        <h2 id="cost-h">Cost and summary</h2>
        <p>token spend and policy outcomes across the recorded window</p>
      </div>

      <div className="strip">
        <div className="cell">
          <p className="cell__l">requests</p>
          <div className="cell__v">{stats.count}</div>
          <div className="cell__sub">recorded</div>
        </div>
        <div className="cell">
          <p className="cell__l">total cost</p>
          <div className="cell__v accent">{usd(stats.totalCostUsd, false)}</div>
          <div className="cell__sub">priced calls only</div>
        </div>
        <div className="cell">
          <p className="cell__l">blocked</p>
          <div className={`cell__v ${stats.blocked ? "danger" : ""}`}>{stats.blocked}</div>
          <div className="cell__sub">{pct(blockedPct, 0)} of traffic</div>
        </div>
        <div className="cell">
          <p className="cell__l">findings</p>
          <div className="cell__v">{stats.findings}</div>
          <div className="cell__sub">across both directions</div>
        </div>
      </div>

      <div className="detail-grid" style={{ marginTop: 0 }}>
        <div className="panel">
          <div className="panel__head">
            <h3>Policy outcomes</h3>
            <span className="panel__meta">{stats.count} requests</span>
          </div>
          <div style={{ padding: "8px 18px 14px" }}>
            <div className="dist">
              {(["block", "redact", "allow"] as PolicyAction[]).map((a) => (
                <div className="dist__row" key={a}>
                  <span className="dist__label">{a}</span>
                  <span className="dist__bar">
                    <span
                      className={a}
                      style={{ width: `${(actionCounts[a] / maxAction) * 100}%` }}
                    />
                  </span>
                  <span className="dist__n">
                    {actionCounts[a]}
                    <span style={{ color: "var(--text-faint)" }}>
                      {" "}
                      {pct(actionCounts[a] / total, 0)}
                    </span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel__head">
            <h3>Spend by model</h3>
            <span className="panel__meta">cost &middot; calls</span>
          </div>
          <div style={{ padding: "6px 18px 14px" }}>
            <div className="spend-list">
              {byModel.map((m) => (
                <div className="spend-row" key={m.model}>
                  <span className="m">{m.model}</span>
                  <span className="c">
                    {m.cost > 0 ? usd(m.cost, false) : m.unpriced ? "unpriced" : "$0"}
                  </span>
                  <span className="n">
                    {m.calls} {m.calls === 1 ? "call" : "calls"}
                    {m.unpriced ? ` - ${m.unpriced} unpriced` : ""}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
