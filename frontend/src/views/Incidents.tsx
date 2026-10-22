import { useMemo, useState } from "react";
import { Segmented } from "../components/Controls";
import type { Selection } from "../components/Drawer";
import { utc } from "../components/Drawer";
import { IncidentGraph } from "../components/Graph";
import { Icon } from "../components/Icon";
import { Loom, type LoomFocus, LoomLegend } from "../components/Loom";
import type { Hypothesis, Incident, RunModel } from "../data/model";
import { entityName, SEVERITY_RANK } from "../data/model";
import { routeHref } from "../routing";

const CONF_RANK = { low: 1, medium: 2, high: 3 } as const;

export function Severity({ level }: { level: string }) {
  const n = { critical: 4, high: 3, medium: 2, low: 1 }[level] ?? 0;
  return (
    <span className="il-sev" data-level={level}>
      <i aria-hidden>{[1, 2, 3, 4].map((k) => <b key={k} data-on={k <= n} />)}</i>{level}
    </span>
  );
}

function Evidence({ ids, onEvent, label }: { ids: string[]; onEvent: (id: string) => void; label: string }) {
  const [all, setAll] = useState(false);
  const shown = all ? ids : ids.slice(0, 4);
  return (
    <span className="il-evidence" aria-label={label}>
      {shown.map((id) => <button key={id} type="button" className="il-chip-link il-mono" onClick={() => onEvent(id)}>{id.slice(0, 11)}</button>)}
      {ids.length > 4 && <button type="button" className="il-chip-link" onClick={() => setAll((v) => !v)}>{all ? "fewer" : `+${ids.length - 4} more`}</button>}
    </span>
  );
}

export function IncidentList({ run, current, runId }: { run: RunModel; current: string | null; runId?: string }) {
  const sorted = [...run.incidents].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.window.start_utc.localeCompare(b.window.start_utc));
  return (
    <nav className="il-cases" aria-label="Incidents">
      <ol>
        {sorted.map((i) => (
          <li key={i.incident_id}>
            <a className="il-case" href={routeHref({ view: "run", runId, section: "incidents", incidentId: i.incident_id })} aria-current={i.incident_id === current ? "page" : undefined}>
              <span className="il-case-title">{i.title}</span>
              <span className="il-case-meta"><Severity level={i.severity} /><span className="il-mono">{utc(i.window.start_utc).slice(5, 16)}</span>{i.gaps.length > 0 && <span className="il-tag il-tone-uncertain">gap</span>}</span>
            </a>
          </li>
        ))}
      </ol>
    </nav>
  );
}

function HypothesisCard({ h, active, onToggle, onAlt, altActive, onEvent }: {
  h: Hypothesis; active: boolean; onToggle: () => void; onAlt: (i: number) => void; altActive: number | null; onEvent: (id: string) => void;
}) {
  const lowered = CONF_RANK[h.confidence] < CONF_RANK[h.confidence_before_gaps];
  return (
    <li className="il-hyp" data-active={active}>
      <div className="il-hyp-head">
        <span className="il-conf" data-level={h.confidence}>{h.confidence} confidence{lowered ? `, lowered from ${h.confidence_before_gaps} by a gap` : ""}</span>
        <button type="button" className="il-btn il-btn-quiet" aria-pressed={active} onClick={onToggle}>{active ? "Showing on loom" : "Show on loom"}</button>
      </div>
      <p>{h.statement}</p>
      <p className="il-small">Basis: {h.confidence_basis}</p>
      <p className="il-small">Supporting <Evidence ids={h.supporting_event_ids} onEvent={onEvent} label="Supporting events" /></p>
      {h.contradicting_event_ids.length > 0 && <p className="il-small">Against <Evidence ids={h.contradicting_event_ids} onEvent={onEvent} label="Contradicting events" /></p>}
      {h.missing_evidence.map((m) => (
        <p key={m.gap_id} className="il-missing"><Icon name="warn" /> Missing: {m.source} silent {utc(m.start_utc).slice(11, 16)} to {utc(m.end_utc).slice(11, 16)} UTC on {m.start_utc.slice(0, 10)}. {m.description}</p>
      ))}
      {h.alternatives.length > 0 && (
        <div className="il-alts">
          <p className="il-h3">Other explanations</p>
          <ul>
            {h.alternatives.map((a, i) => (
              <li key={i} className="il-alt" data-active={altActive === i}>
                <p><span className="il-tag" data-kind={a.kind}>{a.kind}</span> {a.statement}</p>
                <p className="il-small">What would tell them apart: {a.distinguishing_evidence}</p>
                <p className="il-small"><button type="button" className="il-chip-link" aria-pressed={altActive === i} onClick={() => onAlt(i)}>{altActive === i ? "Hide its events" : "Show its events on the loom"}</button></p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </li>
  );
}

export function IncidentView({ run, incident, select, selection, onEvent }: {
  run: RunModel; incident: Incident; select: (s: Selection) => void; selection: Selection; onEvent: (id: string) => void;
}) {
  const [mode, setMode] = useState<"loom" | "graph">("loom");
  const [hyp, setHyp] = useState<string | null>(null);
  const [alt, setAlt] = useState<{ h: string; i: number } | null>(null);
  const [entity, setEntity] = useState<string | null>(null);
  const focus: LoomFocus = useMemo(() => {
    const h = incident.hypotheses.find((x) => x.hypothesis_id === (alt?.h ?? hyp));
    const a = alt && h ? h.alternatives[alt.i] : null;
    const ids = a ? a.event_ids : h ? h.supporting_event_ids : entity ? incident.entities.find((e) => e.entity === entity)?.event_ids ?? null : null;
    return {
      emphasis: ids ? new Set(ids) : null, emphasisTone: a ? "benign" : "hostile",
      selectedEntry: selection?.kind === "entry" ? selection.entry.entry_id : null, entity,
    };
  }, [incident, hyp, alt, entity, selection]);
  const gaps = run.gaps.filter((g) => incident.gaps.includes(g.gap_id));
  const linkFor = (entryId: string) => incident.links.find((l) => l.to === entryId);

  return (
    <article className="il-incident" aria-labelledby="il-incident-title">
      <header className="il-incident-head">
        <p className="il-small"><Severity level={incident.severity} /> <span className="il-mono">{incident.incident_id}</span>, {utc(incident.window.start_utc)} to {utc(incident.window.end_utc).slice(11)}</p>
        <h1 className="il-h1" id="il-incident-title" tabIndex={-1} data-incident-heading>{incident.title}</h1>
        <p className="il-prose il-tone-muted">{incident.severity_basis}</p>
      </header>

      <section className="il-panel il-loom-panel" aria-label="Loom">
        <div className="il-toolbar" style={{ justifyContent: "space-between" }}>
          <Segmented label="View" value={mode} onChange={setMode} options={[{ value: "loom", label: "Loom" }, { value: "graph", label: "Graph" }]} />
          <div className="il-filters" role="group" aria-label="Follow an entity">
            {incident.entities.slice(0, 10).map((e) => (
              <button key={e.entity} type="button" className="il-chip" aria-pressed={entity === e.entity} onClick={() => { setEntity(entity === e.entity ? null : e.entity); setHyp(null); setAlt(null); }}>
                <span className="il-chip-kind">{e.entity.split(":")[0]}</span>{entityName(e.entity)}
              </button>
            ))}
          </div>
        </div>
        {mode === "loom" ? (
          <>
            <Loom incident={incident} gaps={run.gaps} focus={focus} onSelectEntry={(entry) => select({ kind: "entry", entry, incidentId: incident.incident_id })} />
            <LoomLegend />
          </>
        ) : (
          <IncidentGraph incident={incident} correlations={run.correlations} focus={entity} onFocus={(e) => { setEntity(e); setHyp(null); setAlt(null); }} />
        )}
        {gaps.length > 0 && (
          <ul className="il-gaps" aria-label="Evidence gaps in this incident">
            {gaps.map((g) => (
              <li key={g.gap_id}><Icon name="warn" /> <strong>{g.source}</strong> {g.kind === "declared" ? "declared a gap" : "went silent"} {utc(g.start_utc).slice(5, 16)} to {utc(g.end_utc).slice(11, 16)} UTC ({g.duration_minutes} min). {g.reason}</li>
            ))}
          </ul>
        )}
      </section>

      <div className="il-columns">
        <section className="il-panel" aria-labelledby="il-timeline-title">
          <h2 className="il-h2" id="il-timeline-title">Timeline</h2>
          <p className="il-small">Times are corrected for each source's declared clock offset{run.params.clockSkewCorrection === "off" ? " (correction is off in this run)" : ""}. Links say how entries relate: a shared id, or only their order.</p>
          <ol className="il-steps">
            {incident.timeline.map((t) => {
              const link = linkFor(t.entry_id);
              const selected = selection?.kind === "entry" && selection.entry.entry_id === t.entry_id;
              return (
                <li key={t.entry_id} className="il-step" data-detected={t.detection_ids.length > 0} data-selected={selected}>
                  {link && <p className="il-link" data-type={link.link_type}><span className="il-link-mark" aria-hidden />{link.link_type === "causal" ? "Linked by" : "Sequence:"} {link.text}</p>}
                  <button type="button" className="il-step-main" onClick={() => select({ kind: "entry", entry: t, incidentId: incident.incident_id })} aria-pressed={selected}>
                    <span className="il-mono il-step-time">{utc(t.at_utc).slice(11, 19)}</span>
                    <span>{t.text}</span>
                  </button>
                  <Evidence ids={t.event_ids} onEvent={onEvent} label={`Evidence for ${t.entry_id}`} />
                </li>
              );
            })}
          </ol>
        </section>
        <section className="il-panel" aria-labelledby="il-hyp-title">
          <h2 className="il-h2" id="il-hyp-title">Hypotheses</h2>
          <p className="il-small">Each reading cites its events, what is missing, and at least one other explanation. Confidence is a stated rule, not a probability.</p>
          <ul className="il-hyps">
            {incident.hypotheses.map((h) => (
              <HypothesisCard key={h.hypothesis_id} h={h} active={hyp === h.hypothesis_id && !alt}
                onToggle={() => { setAlt(null); setEntity(null); setHyp(hyp === h.hypothesis_id && !alt ? null : h.hypothesis_id); }}
                altActive={alt?.h === h.hypothesis_id ? alt.i : null}
                onAlt={(i) => { setEntity(null); setAlt(alt?.h === h.hypothesis_id && alt.i === i ? null : { h: h.hypothesis_id, i }); }}
                onEvent={onEvent} />
            ))}
          </ul>
        </section>
      </div>
    </article>
  );
}
