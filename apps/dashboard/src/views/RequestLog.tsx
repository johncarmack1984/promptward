import { useMemo, useState } from "react";

import { ActionBadge, ProviderMark } from "../components/primitives";
import { clockTime, ms, SEVERITY_RANK, tokens, usd } from "../format";
import type { PolicyAction, RequestRecord, Severity } from "../types";
import { Direction } from "./FindingRow";

function worstSeverity(r: RequestRecord): Severity | null {
  const [first, ...rest] = [...r.inboundFindings, ...r.outboundFindings];
  if (!first) return null;
  return rest.reduce<Severity>((worst, f) => {
    return SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst] ? f.severity : worst;
  }, first.severity);
}

const ACTION_FILTERS: PolicyAction[] = ["block", "redact", "allow"];

function Row({ record }: { record: RequestRecord }) {
  const [open, setOpen] = useState(false);
  const r = record;
  const findingCount = r.inboundFindings.length + r.outboundFindings.length;
  const worst = worstSeverity(r);
  const has422 = r.schemaValidated && r.schemaValid === false;

  return (
    <>
      <button
        type="button"
        className="row"
        aria-expanded={open}
        data-worst={worst ?? undefined}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="row__ts">{clockTime(r.ts)}</span>
        <span>
          <ActionBadge action={r.action} />
        </span>
        <span className="row__model">
          <ProviderMark provider={r.provider} />
          {r.model}
          {has422 ? <span className="code422">422</span> : null}
        </span>
        <span className={`r row__find ${findingCount ? "has" : ""}`}>
          {findingCount === 0 ? "--" : findingCount}
        </span>
        <span className={`r row__cost ${r.costUsd === null && r.costUnpriced ? "unpriced" : ""}`}>
          {usd(r.costUsd, r.costUnpriced)}
        </span>
        <span className="r row__tokens" style={{ color: "var(--text-mute)" }}>
          {tokens(r.inputTokens)}/{tokens(r.outputTokens)}
        </span>
        <span className="r row__latency">{ms(r.latencyMs)}</span>
        <span className="chevron" aria-hidden="true">
          &rsaquo;
        </span>
      </button>

      {open ? (
        <div className="expand">
          <div className="expand__cols">
            <Direction label="inbound  /  to model" findings={r.inboundFindings} />
            <Direction label="outbound  /  from model" findings={r.outboundFindings} />
          </div>

          {r.error ? (
            <div className="expand__error">
              <span className="lbl">error</span>
              <span>{r.error}</span>
            </div>
          ) : null}

          <div className="expand__facts">
            <span>
              <span className="k">id</span>
              {r.id}
            </span>
            <span>
              <span className="k">tokens in/out</span>
              {r.inputTokens} / {r.outputTokens}
            </span>
            <span>
              <span className="k">cost</span>
              {usd(r.costUsd, r.costUnpriced)}
            </span>
            <span>
              <span className="k">latency</span>
              {ms(r.latencyMs)}
            </span>
            <span>
              <span className="k">schema</span>
              {r.schemaValidated
                ? r.schemaValid
                  ? "valid"
                  : `invalid (${r.retries} ${r.retries === 1 ? "retry" : "retries"})`
                : "n/a"}
            </span>
          </div>
        </div>
      ) : null}
    </>
  );
}

export function RequestLog({ records }: { records: RequestRecord[] }) {
  const [active, setActive] = useState<Set<PolicyAction>>(new Set());

  const filtered = useMemo(() => {
    if (active.size === 0) return records;
    return records.filter((r) => active.has(r.action));
  }, [records, active]);

  function toggle(a: PolicyAction) {
    setActive((prev) => {
      const next = new Set(prev);
      if (next.has(a)) next.delete(a);
      else next.add(a);
      return next;
    });
  }

  const counts = useMemo(() => {
    const c: Record<PolicyAction, number> = { block: 0, redact: 0, allow: 0 };
    for (const r of records) c[r.action] += 1;
    return c;
  }, [records]);

  return (
    <section aria-labelledby="log-h">
      <div className="section-title">
        <h2 id="log-h">Request log</h2>
        <p>every proxied call, newest first; expand a row for inbound and outbound findings</p>
      </div>

      <div className="log__toolbar">
        {ACTION_FILTERS.map((a) => (
          <button
            key={a}
            type="button"
            className="filter"
            aria-pressed={active.has(a)}
            onClick={() => toggle(a)}
          >
            <span className={`dot ${a}`} />
            {a}
            <span style={{ color: "var(--text-faint)" }}>{counts[a]}</span>
          </button>
        ))}
        <span className="grow" />
        <span className="log__hint">
          {filtered.length} of {records.length} shown
        </span>
      </div>

      <div className="log">
        <div className="log__header">
          <span>time</span>
          <span>action</span>
          <span>provider / model</span>
          <span className="r">finds</span>
          <span className="r">cost</span>
          <span className="r">tok i/o</span>
          <span className="r">latency</span>
          <span />
        </div>
        {filtered.length === 0 ? (
          <div className="state">
            <div className="state__title">no matching requests</div>
            <div className="state__body">clear the action filters above to see the full log.</div>
          </div>
        ) : (
          filtered.map((r) => <Row key={r.id} record={r} />)
        )}
      </div>
    </section>
  );
}
