import { useEffect, useState } from "react";
import { loadRequests, type Source } from "./api";
import { BrandMark } from "./components/primitives";
import type { RequestsResponse } from "./types";
import { CostSummary } from "./views/CostSummary";
import { Detection } from "./views/Detection";
import { RequestLog } from "./views/RequestLog";
import "./app.css";

type Tab = "detection" | "log" | "cost";

const TABS: Array<{ id: Tab; label: string }> = [
  { id: "detection", label: "detection" },
  { id: "log", label: "requests" },
  { id: "cost", label: "cost" },
];

// Stable keys for the loading placeholders (nothing reorders; keys just need
// to not be the map index).
const SKELETON_ROWS = Array.from({ length: 8 }, (_, i) => `row-${i}`);
const SKELETON_CELLS = Array.from({ length: 4 }, (_, i) => `cell-${i}`);

function LogSkeleton() {
  return (
    <div className="log" aria-busy="true">
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
      {SKELETON_ROWS.map((k, i) => (
        <div className="skrow skeleton" key={k} style={{ opacity: 1 - i * 0.08 }} />
      ))}
    </div>
  );
}

const TAB_IDS = new Set<Tab>(["detection", "log", "cost"]);

function tabFromHash(): Tab {
  const h = window.location.hash.replace(/^#/, "") as Tab;
  return TAB_IDS.has(h) ? h : "detection";
}

export default function App() {
  const [tab, setTabState] = useState<Tab>(tabFromHash);

  const setTab = (t: Tab) => {
    setTabState(t);
    if (window.location.hash !== `#${t}`) window.history.replaceState(null, "", `#${t}`);
  };
  const [data, setData] = useState<RequestsResponse | null>(null);
  const [source, setSource] = useState<Source>("fixture");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const ctrl = new AbortController();
    let cancelled = false;
    loadRequests(ctrl.signal)
      .then((res) => {
        if (cancelled) return;
        setData(res.data);
        setSource(res.source);
        setLoading(false);
      })
      .catch(() => {
        // Aborted (StrictMode double-invoke in dev); the retained instance wins.
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, []);

  const reqCount = data?.requests.length ?? 0;
  const findCount = data?.stats.findings ?? 0;

  return (
    <div className="app">
      <header className="app__header">
        <div className="brand">
          <BrandMark />
          <span className="brand__name">
            prompt<b>ward</b>
          </span>
        </div>
        <span className="brand__tag" style={{ alignSelf: "center" }}>
          LLM security gateway
        </span>

        <nav className="tabs" role="tablist" aria-label="views">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              className="tab"
              role="tab"
              id={`tab-${t.id}`}
              aria-controls={`panel-${t.id}`}
              aria-selected={tab === t.id}
              onClick={() => setTab(t.id)}
            >
              {t.label}
              {t.id === "log" && data ? <span className="tab__count">{reqCount}</span> : null}
              {t.id === "cost" && data ? <span className="tab__count">{findCount}</span> : null}
            </button>
          ))}
        </nav>

        <span className="header__spacer" />

        <span
          className="source-pill"
          data-source={source}
          title={
            source === "live"
              ? "connected to the gateway read API"
              : "gateway not reachable -- showing bundled sample data"
          }
        >
          <span className="dot" />
          {source === "live" ? "live gateway" : "sample data"}
        </span>
      </header>

      <main
        className="main"
        role="tabpanel"
        id={`panel-${tab}`}
        aria-labelledby={`tab-${tab}`}
        tabIndex={0}
      >
        {tab === "detection" ? <Detection /> : null}

        {tab === "log" ? (
          loading ? (
            <section>
              <div className="section-title">
                <h2>Request log</h2>
                <p>loading recent requests</p>
              </div>
              <LogSkeleton />
            </section>
          ) : data && data.requests.length > 0 ? (
            <RequestLog records={data.requests} />
          ) : (
            <section>
              <div className="section-title">
                <h2>Request log</h2>
              </div>
              <div className="panel">
                <div className="state">
                  <div className="state__title">no requests recorded yet</div>
                  <div className="state__body">
                    point an OpenAI or Anthropic SDK at the gateway and traffic will appear here,
                    scanned inbound and outbound with per-call cost.
                  </div>
                </div>
              </div>
            </section>
          )
        ) : null}

        {tab === "cost" ? (
          loading || !data ? (
            <section>
              <div className="section-title">
                <h2>Cost and summary</h2>
                <p>loading</p>
              </div>
              <div className="strip">
                {SKELETON_CELLS.map((k) => (
                  <div className="cell" key={k}>
                    <div className="skeleton" style={{ height: 11, width: 64, marginBottom: 12 }} />
                    <div className="skeleton" style={{ height: 26, width: 90 }} />
                  </div>
                ))}
              </div>
            </section>
          ) : (
            <CostSummary records={data.requests} stats={data.stats} />
          )
        ) : null}
      </main>

      <footer className="foot">
        <span>
          promptward console &middot; deterministic Rust detection core, OpenAI/Anthropic
          wire-compatible
        </span>
        <span>
          numbers on the detection tab are from a measured eval run, not estimates &middot;{" "}
          <a href="https://github.com/johncarmack1984/promptward" rel="noreferrer">
            source
          </a>
        </span>
      </footer>
    </div>
  );
}
