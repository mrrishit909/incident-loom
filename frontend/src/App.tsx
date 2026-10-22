import { type MouseEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { TabBoundary } from "./components/Boundary";
import { EmptyState, ErrorState, Segmented } from "./components/Controls";
import { Drawer, type Selection } from "./components/Drawer";
import { Icon } from "./components/Icon";
import { type AppConfig, resolveConfig, type Theme } from "./config";
import { SEVERITY_RANK } from "./data/model";
import { type SiteData, useEvents, useRun, useSiteData } from "./data/site";
import { ago } from "./lib/format";
import { animate } from "./lib/motion";
import { parseRoute, type Route, routeHref, SECTIONS, type SectionId, useRoute } from "./routing";
import { IncidentList, IncidentView } from "./views/Incidents";
import { AboutView, HistoryView, RequestView } from "./views/Pages";
import { DetectorsView, EntitiesView, IngestView, ReplayView, TimelineView } from "./views/Views";
import "./styles/app.css";

function useResolvedTheme(theme: Theme): "light" | "dark" {
  const q = "(prefers-color-scheme: dark)";
  const [system, setSystem] = useState<"light" | "dark">(() => (typeof window !== "undefined" && window.matchMedia?.(q).matches ? "dark" : "light"));
  useEffect(() => {
    const mq = window.matchMedia?.(q);
    if (!mq) return;
    const on = () => setSystem(mq.matches ? "dark" : "light");
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return theme === "auto" ? system : theme;
}

const THEME_KEY = "incident-loom-theme";

/** A per-visitor convenience only; private windows or blocked storage fall back to the default. */
function storedTheme(): Theme | null {
  try {
    const v = window.localStorage.getItem(THEME_KEY);
    return v === "dark" || v === "light" || v === "auto" ? v : null;
  } catch {
    return null;
  }
}

function Skeleton() {
  return (
    <div className="il-skeleton" role="status" aria-live="polite">
      <p className="il-small">Loading the published investigation.</p>
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 260px) minmax(0, 1fr)", gap: 20 }}>
        <div className="il-skel" style={{ height: 320 }} />
        <div style={{ display: "grid", gap: 14 }}>
          <div className="il-skel" style={{ height: 34, width: "60%" }} />
          <div className="il-skel" style={{ height: 220 }} />
        </div>
      </div>
    </div>
  );
}

function runLabel(site: SiteData, id: string): string {
  const entry = site.index.find((r) => r.run_id === id);
  const when = entry?.created_at.slice(0, 16).replace("T", " ") ?? "";
  return `${when} UTC ${entry?.headline ? entry.headline.split(";")[0] : id}`;
}

export function IncidentLoomApp(props: Partial<AppConfig>) {
  const config = useMemo(() => resolveConfig(props), [props.basePath, props.dataUrl, props.theme, props.showShell, props.routing, props.repoUrl, props.siteUrl]); // eslint-disable-line react-hooks/exhaustive-deps
  const [themeChoice, setThemeChoice] = useState<Theme>(() => (config.showShell ? storedTheme() ?? config.theme : config.theme));
  useEffect(() => {
    if (!config.showShell) return;
    try { window.localStorage.setItem(THEME_KEY, themeChoice); } catch { /* storage unavailable: the choice lasts for this visit */ }
  }, [themeChoice, config.showShell]);
  const theme = useResolvedTheme(themeChoice);
  const [route, navigate] = useRoute(config.routing);
  const { state, reload } = useSiteData(config.dataUrl);
  const [tick, setTick] = useState(0);
  const [selection, setSelection] = useState<Selection>(null);
  const body = useRef<HTMLDivElement>(null);
  const prev = useRef<string | null>(null);

  const latest = state.status === "ready" ? state.data.snapshot.latest_run_id : null;
  const runId = route.view === "run" ? route.runId ?? latest : null;
  const run = useRun(config.dataUrl, state.status === "ready" ? runId : null, tick);
  const section: SectionId = route.view === "run" ? route.section : "incidents";
  const base = run.status === "ready" ? run.data.base : null;
  const events = useEvents(base, selection !== null || (route.view === "run" && route.section === "timeline"));

  const refresh = () => { reload(); setTick((t) => t + 1); };
  const close = useCallback(() => setSelection(null), []);
  const openEvent = useCallback((id: string) => setSelection({ kind: "event", eventId: id }), []);

  const incidentId = useMemo(() => {
    if (route.view !== "run" || run.status !== "ready") return null;
    if (route.incidentId && run.data.incidents.some((i) => i.incident_id === route.incidentId)) return route.incidentId;
    const sorted = [...run.data.incidents].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.window.start_utc.localeCompare(b.window.start_utc));
    return sorted[0]?.incident_id ?? null;
  }, [route, run]);

  // Section or incident change: slide the content in, move focus to its heading, close the drawer.
  useEffect(() => {
    const key = route.view === "run" ? `${section}:${incidentId ?? ""}` : null;
    const before = prev.current;
    prev.current = key;
    setSelection(null);
    // The first resolution after data loads (no incident chosen before) is not a navigation: no slide, no focus move.
    if (!key || before === null || before === key || (before.endsWith(":") && before.split(":")[0] === section)) return;
    const dir = SECTIONS.findIndex((s) => s.id === section) >= SECTIONS.findIndex((s) => s.id === before.split(":")[0]) ? 1 : -1;
    animate(body.current, [{ opacity: 0, transform: `translateX(${dir * 12}px)` }, { opacity: 1, transform: "none" }], { duration: 200 });
    body.current?.querySelector<HTMLElement>("[data-incident-heading], [data-section-heading]")?.focus({ preventScroll: true });
  }, [section, incidentId, route.view]);

  const onClick = (e: MouseEvent<HTMLDivElement>) => {
    const a = (e.target as HTMLElement).closest("a");
    const href = a?.getAttribute("href");
    if (!a || !href?.startsWith("#/") || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    if (config.routing === "memory") { e.preventDefault(); navigate(parseRoute(href)); }
  };

  const sectionHref = (s: SectionId) => routeHref({ view: "run", runId: route.view === "run" ? route.runId : undefined, section: s });

  let content: React.ReactNode;
  if (state.status === "loading" || (route.view === "run" && state.status === "ready" && run.status === "loading")) content = <Skeleton />;
  else if (state.status === "error") content = <div className="il-state"><ErrorState title="The investigation snapshot did not load" error={state.error} onRetry={refresh} /></div>;
  else if (route.view === "request") content = <RequestView config={config} />;
  else if (route.view === "about") content = <AboutView config={config} />;
  else if (state.status === "empty") content = <EmptyState requestHref="#/request" />;
  else if (state.status !== "ready") content = <Skeleton />;
  else if (route.view === "history") content = <HistoryView site={state.data} config={config} />;
  else if (run.status === "error") content = <div className="il-state"><ErrorState title={runId && !state.data.snapshot.runs_included.includes(runId) ? `Run ${runId} is not in this snapshot` : "This run did not load"} error={run.error} onRetry={refresh} /></div>;
  else if (run.status === "ready") {
    const model = run.data;
    const incident = model.incidents.find((i) => i.incident_id === incidentId) ?? null;
    let view: React.ReactNode;
    if (section === "incidents") {
      view = model.incidents.length === 0 ? (
        <div className="il-section-head"><h1 className="il-h1" tabIndex={-1} data-section-heading>No incidents in this run.</h1><p className="il-prose">{model.summary.statement}</p></div>
      ) : (
        <div className="il-desk">
          <IncidentList run={model} current={incidentId} runId={route.view === "run" ? route.runId : undefined} />
          <div className="il-incident-pick">
            <label htmlFor="il-incident-select">Incident</label>
            <select id="il-incident-select" value={incidentId ?? ""} onChange={(e) => navigate({ view: "run", runId: route.view === "run" ? route.runId : undefined, section: "incidents", incidentId: e.target.value })}>
              {model.incidents.map((i) => <option key={i.incident_id} value={i.incident_id}>{i.severity}: {i.title}</option>)}
            </select>
          </div>
          {incident && <IncidentView key={incident.incident_id} run={model} incident={incident} select={setSelection} selection={selection} onEvent={openEvent} />}
        </div>
      );
    } else if (section === "timeline") view = <TimelineView run={model} events={events} onEvent={openEvent} />;
    else if (section === "entities") view = <EntitiesView run={model} />;
    else if (section === "detectors") view = <DetectorsView run={model} />;
    else if (section === "replay") view = <ReplayView run={model} />;
    else view = <IngestView run={model} />;
    content = (
      <div className="il-page">
        <p className="il-runline il-wrap">
          {model.summary.headline}. Batches {model.params.batches[0]} to {model.params.batches[model.params.batches.length - 1]}, clock-skew correction {model.params.clockSkewCorrection}
          {model.params.simulateRestartAfter ? `, restarted after batch ${model.params.simulateRestartAfter}` : ""}. Run <span className="il-mono">{model.record.runId}</span>.
        </p>
        <div ref={body} className="il-body">
          <TabBoundary key={`${section}-${incidentId}`} label={SECTIONS.find((s) => s.id === section)!.label}>{view}</TabBoundary>
        </div>
        <Drawer selection={selection} run={model} events={events} onClose={close} onEvent={openEvent} />
      </div>
    );
  } else content = <Skeleton />;

  const snap = state.status === "ready" ? state.data.snapshot : null;
  const release = state.status === "ready" ? state.data.release : null;
  const topLink = (r: Route, label: string, extra = "") => (
    <a className={extra} href={routeHref(r)} aria-current={route.view === r.view ? "page" : undefined}>{label}</a>
  );
  const runs = state.status === "ready" ? state.data.snapshot.runs_included : [];

  return (
    <div className="il-root" data-theme={theme} data-shell={config.showShell} onClick={onClick}>
      <a className="il-skip" href="#il-main" onClick={(e) => { e.preventDefault(); document.getElementById("il-main")?.focus(); }}>Skip to content</a>
      {config.showShell && (
        <header className="il-top">
          <div className="il-top-row">
            <a className="il-wordmark" href="#/">Incident Loom</a>
            <nav className="il-meta-nav" aria-label="Site">
              {topLink({ view: "history" }, "Runs")}
              <a href={routeHref({ view: "request" })} aria-current={route.view === "request" ? "page" : undefined}>Request<span className="il-hide-sm"> a run</span></a>
              {topLink({ view: "about" }, "About", "il-hide-sm")}
              <button type="button" onClick={refresh} aria-label="Refresh data from the published snapshot"><Icon name="refresh" /></button>
            </nav>
          </div>
          {route.view === "run" && (
            <div className="il-top-row il-top-sections">
              <nav className="il-sections" aria-label="Sections">
                {SECTIONS.map((s) => <a key={s.id} href={sectionHref(s.id)} aria-current={s.id === section ? "page" : undefined}>{s.label}</a>)}
              </nav>
              {state.status === "ready" && runs.length > 0 && runId && (
                <div className="il-runpick">
                  <label htmlFor="il-run">Run</label>
                  <select id="il-run" value={runId} onChange={(e) => navigate({ view: "run", runId: e.target.value, section })}>
                    {runs.map((id) => <option key={id} value={id}>{runLabel(state.data, id)}</option>)}
                  </select>
                </div>
              )}
            </div>
          )}
        </header>
      )}
      {snap?.mode === "fixture" && <div className="il-banner" role="note"><Icon name="info" /> Fixture data: a real engine run built for automated browser tests, not a published investigation.</div>}
      {state.status === "ready" && state.stale && snap && (
        <div className="il-banner" role="status">
          <span className="il-tone-uncertain"><Icon name="warn" /></span>
          <span>This snapshot is {ago(snap.generated_at)} old, older than its 14-day freshness window. The results shown are the last ones published.</span>
          <button type="button" className="il-btn" onClick={refresh}><Icon name="refresh" /> Refresh</button>
        </div>
      )}
      {release?.status === "blocked" && <div className="il-banner" role="status"><span className="il-tone-hostile"><Icon name="cross" /></span> The latest release check is blocked.</div>}
      <main id="il-main" tabIndex={-1} style={{ outline: "none" }}>{content}</main>
      {config.showShell && (
        <footer className="il-footer">
          <div style={{ display: "grid", gap: 10 }}>
            <p>Synthetic security logs of a fictional organisation, replayed offline.{snap ? ` Snapshot generated ${snap.generated_at.replace("T", " ").replace("Z", " UTC")}.` : ""}{release ? ` Latest release check: ${release.status}.` : ""}</p>
            <Segmented label="Colour theme" value={themeChoice} options={[{ value: "dark", label: "Dark" }, { value: "light", label: "Light" }, { value: "auto", label: "System" }]} onChange={setThemeChoice} />
          </div>
          <nav aria-label="Project links">
            <a href={config.repoUrl}>Source</a>
            <a href={`${config.repoUrl}/tree/state`}>State branch</a>
            <a href={`${config.repoUrl}/blob/main/docs/ARCHITECTURE.md`}>Architecture</a>
          </nav>
        </footer>
      )}
    </div>
  );
}
