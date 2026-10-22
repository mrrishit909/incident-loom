import { useMemo, useState } from "react";
import { utc } from "../components/Drawer";
import { Icon } from "../components/Icon";
import type { EventRecord, MetricsBlock, RunModel, Score } from "../data/model";
import { entityKind, entityName } from "../data/model";
import type { LoadState } from "../data/site";
import { useWidth } from "../lib/useWidth";
import { routeHref } from "../routing";
import { Severity } from "./Incidents";

const ms = (iso: string) => Date.parse(iso);
const fmt = (n: number) => n.toLocaleString("en-US");
const ratio = (x: number | null) => (x === null ? "n/a" : x.toFixed(2));

function Head({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="il-section-head">
      <h1 className="il-h1" tabIndex={-1} data-section-heading>{title}</h1>
      {children && <p className="il-prose il-tone-muted">{children}</p>}
    </div>
  );
}

const Region = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div className="il-table-wrap" tabIndex={0} role="region" aria-label={label}>{children}</div>
);

/* Whole-run timeline ----------------------------------------------------------------------------- */

const KINDS = ["user", "host", "ip", "resource"] as const;

export function TimelineView({ run, events, onEvent }: { run: RunModel; events: LoadState<Map<string, EventRecord>>; onEvent: (id: string) => void }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [kind, setKind] = useState<(typeof KINDS)[number]>("user");
  const all = useMemo(() => (events.status === "ready" ? [...events.data.values()] : []), [events]);
  const span = useMemo(() => {
    const ts = all.map((e) => ms(e.corrected_at_utc));
    return ts.length ? { start: Math.min(...ts), end: Math.max(...ts) } : null;
  }, [all]);
  const [range, setRange] = useState<[number, number]>([0, 100]);
  const inIncident = useMemo(() => new Set(run.incidents.flatMap((i) => i.event_ids)), [run]);

  if (events.status === "error") return <><Head title="Timeline" /><p className="il-tone-hostile">The event file did not load: {events.error.message}</p></>;
  if (events.status !== "ready" || !span) return <><Head title="Timeline" /><p className="il-small" role="status">Loading every event of this run.</p></>;

  const t0 = span.start + ((span.end - span.start) * range[0]) / 100;
  const t1 = Math.max(t0 + 60e3, span.start + ((span.end - span.start) * range[1]) / 100);
  const lanes = run.entities.filter((e) => e.kind === kind).sort((a, b) => b.events - a.events).slice(0, 12).map((e) => e.entity);
  const laneOf = new Map(lanes.map((l, i) => [l, i]));
  const labelW = width < 560 ? 92 : 170;
  const laneH = 28;
  const plotW = Math.max(120, width - labelW - 16);
  const height = lanes.length * laneH + 40;
  const x = (t: number) => labelW + ((t - t0) / (t1 - t0)) * plotW;
  const visible = all.filter((e) => {
    const t = ms(e.corrected_at_utc);
    return t >= t0 && t <= t1;
  });
  const marks = visible.flatMap((e) => [e.actor, e.target, e.src_ip ? `ip:${e.src_ip}` : null]
    .filter((v): v is string => !!v && laneOf.has(v)).map((lane) => ({ e, lane: laneOf.get(lane)! })));
  const days = [...new Set(all.map((e) => e.corrected_at_utc.slice(0, 10)))].sort();
  const setDay = (d: string) => {
    const s = ((ms(`${d}T00:00:00.000Z`) - span.start) / (span.end - span.start)) * 100;
    const en = ((ms(`${d}T23:59:59.999Z`) - span.start) / (span.end - span.start)) * 100;
    setRange([Math.max(0, s), Math.min(100, en)]);
  };

  return (
    <>
      <Head title="Timeline">
        Every normalized event of the run on the threads of the busiest {kind === "ip" ? "addresses" : `${kind}s`}. Filled marks belong to an incident; frayed bands are evidence gaps.
      </Head>
      <div className="il-filters" role="group" aria-label="Entity kind">
        {KINDS.map((k) => <button key={k} type="button" className="il-chip" aria-pressed={kind === k} onClick={() => setKind(k)}>{k === "ip" ? "Addresses" : `${k.charAt(0).toUpperCase()}${k.slice(1)}s`}</button>)}
      </div>
      <div className="il-panel" style={{ display: "grid", gap: 12 }}>
        <div className="il-range" role="group" aria-label="Time window">
          <label>From <input type="range" min={0} max={99} value={range[0]} onChange={(e) => setRange([Math.min(Number(e.target.value), range[1] - 1), range[1]])} /></label>
          <label>To <input type="range" min={1} max={100} value={range[1]} onChange={(e) => setRange([range[0], Math.max(Number(e.target.value), range[0] + 1)])} /></label>
          <span className="il-mono il-small">{utc(new Date(t0).toISOString()).slice(5, 16)} to {utc(new Date(t1).toISOString()).slice(5, 16)} UTC, {fmt(visible.length)} events</span>
        </div>
        <div className="il-filters" role="group" aria-label="Jump to a day">
          <button type="button" className="il-chip" aria-pressed={range[0] === 0 && range[1] === 100} onClick={() => setRange([0, 100])}>All six days</button>
          {days.map((d) => <button key={d} type="button" className="il-chip" onClick={() => setDay(d)}>{d.slice(5)}</button>)}
        </div>
        <div ref={ref}>
          {width > 0 && (
            <svg className="il-runloom" width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img"
              aria-label={`${fmt(marks.length)} event marks on ${lanes.length} threads; the incident list holds the same evidence in readable form.`}>
              {run.gaps.map((g) => {
                const a = Math.max(t0, ms(g.start_utc));
                const b = Math.min(t1, ms(g.end_utc));
                return b > a ? <rect key={g.gap_id} className="il-gap-band" x={x(a)} y={4} width={Math.max(2, x(b) - x(a))} height={height - 34}><title>{`${g.source} gap ${utc(g.start_utc)} to ${utc(g.end_utc)}`}</title></rect> : null;
              })}
              {lanes.map((l, i) => (
                <g key={l} className="il-lane">
                  <path className="il-thread" d={`M${labelW} ${12 + i * laneH} H${labelW + plotW}`} />
                  <text className="il-lane-label" x={labelW - 8} y={16 + i * laneH} textAnchor="end">{entityName(l).length > (width < 560 ? 11 : 20) ? `${entityName(l).slice(0, width < 560 ? 10 : 19)}...` : entityName(l)}</text>
                </g>
              ))}
              {marks.map(({ e, lane }, i) => (
                <g key={`${e.event_id}-${lane}-${i}`} className="il-tickmark" data-incident={inIncident.has(e.event_id)} transform={`translate(${x(ms(e.corrected_at_utc))} ${12 + lane * laneH})`} onClick={() => onEvent(e.event_id)}>
                  <rect x={-1.5} y={-7} width={3} height={14} />
                  <title>{`${e.event_id} ${e.action} ${utc(e.corrected_at_utc)}`}</title>
                </g>
              ))}
              <text className="il-axis" x={labelW} y={height - 8}>{utc(new Date(t0).toISOString()).slice(5, 16)}</text>
              <text className="il-axis" x={labelW + plotW} y={height - 8} textAnchor="end">{utc(new Date(t1).toISOString()).slice(5, 16)}</text>
            </svg>
          )}
        </div>
      </div>
      <h2 className="il-h2">Incidents in this window</h2>
      <ul className="il-list">
        {run.incidents.filter((i) => ms(i.window.end_utc) >= t0 && ms(i.window.start_utc) <= t1).map((i) => (
          <li key={i.incident_id}><Severity level={i.severity} /> <a href={routeHref({ view: "run", runId: undefined, section: "incidents", incidentId: i.incident_id })}>{i.title}</a> <span className="il-mono il-small">{utc(i.window.start_utc).slice(5, 16)}</span></li>
        ))}
      </ul>
    </>
  );
}

/* Entities ------------------------------------------------------------------------------------------ */

export function EntitiesView({ run }: { run: RunModel }) {
  const [kind, setKind] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const list = run.entities.filter((e) => (!kind || e.kind === kind) && (!q || e.entity.toLowerCase().includes(q.toLowerCase())));
  const incTitle = new Map(run.incidents.map((i) => [i.incident_id, i.title]));
  return (
    <>
      <Head title="Entities">Users, hosts, addresses and resources seen in the run, with the incidents they appear in. Countries come from a synthetic address table.</Head>
      <div className="il-toolbar">
        <div className="il-filters" role="group" aria-label="Entity kind">
          <button type="button" className="il-chip" aria-pressed={kind === null} onClick={() => setKind(null)}>All <span className="il-num">{run.entities.length}</span></button>
          {KINDS.map((k) => <button key={k} type="button" className="il-chip" aria-pressed={kind === k} onClick={() => setKind(k)}>{k} <span className="il-num">{run.entities.filter((e) => e.kind === k).length}</span></button>)}
        </div>
        <label className="il-search"><span className="il-sr-only">Filter entities</span><input type="search" placeholder="Filter by name" value={q} onChange={(e) => setQ(e.target.value)} /></label>
      </div>
      <div className="il-wide-only">
        <Region label="Entities">
          <table className="il-table">
            <thead><tr><th scope="col">Entity</th><th scope="col">Kind</th><th scope="col" className="il-num">Events</th><th scope="col">Sources</th><th scope="col">Countries</th><th scope="col">First and last seen (UTC)</th><th scope="col">Incidents</th></tr></thead>
            <tbody>
              {list.map((e) => (
                <tr key={e.entity}>
                  <th scope="row" className="il-mono">{entityName(e.entity)}</th>
                  <td>{e.kind}</td>
                  <td className="il-num">{fmt(e.events)}</td>
                  <td className="il-small">{e.sources.join(", ")}</td>
                  <td className="il-small">{e.countries.join(", ")}</td>
                  <td className="il-mono il-small">{e.first_seen_utc.slice(5, 16).replace("T", " ")} to {e.last_seen_utc.slice(5, 16).replace("T", " ")}</td>
                  <td className="il-small">{e.incident_ids.map((id) => <a key={id} href={routeHref({ view: "run", section: "incidents", incidentId: id })} style={{ display: "block" }}>{incTitle.get(id) ?? id}</a>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Region>
      </div>
      <ul className="il-cards" aria-label="Entities">
        {list.map((e) => (
          <li key={e.entity} className="il-card">
            <p className="il-mono"><strong>{entityName(e.entity)}</strong> <span className="il-small">{entityKind(e.entity)}</span></p>
            <p className="il-small">{fmt(e.events)} events from {e.sources.join(", ")}{e.countries.length ? `; ${e.countries.join(", ")}` : ""}</p>
            {e.incident_ids.map((id) => <a key={id} href={routeHref({ view: "run", section: "incidents", incidentId: id })}>{incTitle.get(id) ?? id}</a>)}
          </li>
        ))}
      </ul>
      {list.length === 0 && <p className="il-note">No entity matches this filter.</p>}
    </>
  );
}

/* Detectors ----------------------------------------------------------------------------------------- */

function ScoreRow({ name, s }: { name: string; s: Score }) {
  return (
    <tr>
      <th scope="row">{name}</th>
      <td className="il-num">{s.tp}</td><td className="il-num">{s.fp}</td><td className="il-num">{s.fn}</td><td className="il-num">{s.tn}</td>
      <td className="il-num">{ratio(s.precision)}</td><td className="il-num">{ratio(s.recall)}</td>
    </tr>
  );
}

function MetricsTable({ block, label }: { block: MetricsBlock; label: string }) {
  return (
    <Region label={label}>
      <table className="il-table">
        <caption className="il-sr-only">{label}</caption>
        <thead><tr><th scope="col">Detector</th><th scope="col" className="il-num">TP</th><th scope="col" className="il-num">FP</th><th scope="col" className="il-num">FN</th><th scope="col" className="il-num">TN</th><th scope="col" className="il-num">Precision</th><th scope="col" className="il-num">Recall</th></tr></thead>
        <tbody>
          <ScoreRow name="All detectors" s={block.overall} />
          {block.per_detector.map((d) => <ScoreRow key={d.detector} name={d.detector.replace(/_/g, " ")} s={d} />)}
        </tbody>
      </table>
    </Region>
  );
}

export function DetectorsView({ run }: { run: RunModel }) {
  const m = run.metrics;
  return (
    <>
      <Head title="Detectors">{m.disclaimer}</Head>
      <p className="il-note" role="note"><Icon name="info" /> Synthetic, held-out: thresholds were chosen on the development scenarios only; the held-out labels are read only by the evaluator. These numbers show the evaluation works, not how the detectors would do on real logs.</p>
      {m.held_out ? (
        <section className="il-panel" aria-labelledby="il-ho">
          <h2 className="il-h2" id="il-ho">Held-out scenarios (synthetic)</h2>
          <p className="il-small">{m.held_out.role}. {m.held_out.scenarios_scored} scenarios scored.</p>
          <MetricsTable block={m.held_out} label="Held-out detector metrics, synthetic" />
          <ul className="il-scenarios" aria-label="Held-out scenario outcomes">
            {m.held_out.scenarios.map((s) => (
              <li key={s.scenario_id}><span className="il-tag" data-outcome={s.outcome}>{s.outcome.toUpperCase()}</span> <span className="il-mono">{s.scenario_id}</span> {s.kind.replace(/_/g, " ")}, expected {s.expected}{s.detected_by.length ? `; flagged by ${s.detected_by.map((d) => d.replace(/_/g, " ")).join(", ")}` : "; not flagged"}</li>
            ))}
          </ul>
        </section>
      ) : <p className="il-note">The labels file was unavailable to the evaluator for this run, so no metrics were computed.</p>}
      {m.development && (
        <details className="il-panel">
          <summary className="il-h3">Development scenarios (tuning data, not an estimate)</summary>
          <p className="il-small">{m.development.role}</p>
          <MetricsTable block={m.development} label="Development detector metrics, tuning data" />
        </details>
      )}
      <section aria-labelledby="il-dets">
        <h2 className="il-h2" id="il-dets">The detectors and their thresholds</h2>
        <ul className="il-list">
          {run.detectors.map((d) => (
            <li key={d.id} className="il-card">
              <p><strong>{d.title}</strong> <Severity level={d.severity} /> <span className="il-small">{d.sources.join(", ")}</span></p>
              <p>{d.description}</p>
              <p className="il-small il-mono">{Object.entries(d.thresholds).map(([k, v]) => `${k} ${String(v)}`).join("; ")}</p>
              <p className="il-small">Tuning: {d.tuning}</p>
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}

/* Replay ------------------------------------------------------------------------------------------------ */

export function ReplayView({ run }: { run: RunModel }) {
  const r = run.replay;
  const cp = run.checkpoint;
  return (
    <>
      <Head title="Replay">Batches are append-only and ingestion is idempotent. A run can be stopped after any batch and resumed from its checkpoint; the evidence must come out byte for byte the same.</Head>
      <section className="il-panel">
        {r.mode === "restart" && r.restart && r.comparison ? (
          <div style={{ display: "grid", gap: 8 }}>
            <p className="il-h3">{r.comparison.identical ? <span className="il-tone-benign"><Icon name="check" /> Restarted run identical to the uninterrupted run</span> : <span className="il-tone-hostile"><Icon name="cross" /> Restarted run differs</span>}</p>
            <p>Stopped after batch <span className="il-mono">{r.restart.stopped_after_batch}</span>, dropped all in-memory state, reloaded the checkpoint and ingested {r.restart.batches_after_resume.join(", ")}.</p>
            <ul className="il-list">
              <li>{r.restart.state_matches_checkpoint ? <Icon name="check" /> : <Icon name="cross" />} State after reload matches the checkpoint (<span className="il-mono">{r.restart.state_sha256_after_reload.slice(0, 16)}</span>)</li>
              <li>{r.restart.reingest_of_last_batch_was_noop ? <Icon name="check" /> : <Icon name="cross" />} Re-ingesting the last batch before the stop changed nothing</li>
              <li>{r.comparison.differing_files.length === 0 ? <Icon name="check" /> : <Icon name="cross" />} Differing evidence files: {r.comparison.differing_files.length ? r.comparison.differing_files.join(", ") : "none"}</li>
            </ul>
          </div>
        ) : (
          <p>This run went straight through (no restart was simulated). Request a run with "Simulate a restart after batch" set to see the comparison; the release gates also check restarts after every batch.</p>
        )}
        <p className="il-small">{r.note}</p>
      </section>
      <section className="il-panel" aria-labelledby="il-cp">
        <h2 className="il-h2" id="il-cp">Checkpoint after each batch</h2>
        <Region label="Checkpoint states">
          <table className="il-table">
            <thead><tr><th scope="col">After batch</th><th scope="col" className="il-num">Events</th><th scope="col" className="il-num">Quarantined</th><th scope="col">State hash</th></tr></thead>
            <tbody>{cp.per_batch.map((b) => <tr key={b.after_batch}><th scope="row" className="il-mono">{b.after_batch}</th><td className="il-num">{fmt(b.events_total)}</td><td className="il-num">{fmt(b.quarantined_total)}</td><td className="il-mono il-small">{b.state_sha256.slice(0, 24)}</td></tr>)}</tbody>
          </table>
        </Region>
      </section>
      <section className="il-panel" aria-labelledby="il-hash">
        <h2 className="il-h2" id="il-hash">Evidence file hashes</h2>
        <Region label="Output hashes">
          <table className="il-table">
            <thead><tr><th scope="col">File</th><th scope="col">sha256</th></tr></thead>
            <tbody>{Object.entries(r.output_hashes).map(([f, h]) => <tr key={f}><th scope="row" className="il-mono">{f}</th><td className="il-mono il-small">{String(h).replace(/^sha256:/, "").slice(0, 32)}</td></tr>)}</tbody>
          </table>
        </Region>
      </section>
    </>
  );
}

/* Ingest ----------------------------------------------------------------------------------------------- */

export function IngestView({ run }: { run: RunModel }) {
  const t = run.ingest.totals;
  return (
    <>
      <Head title="Ingest">
        {fmt(t.received)} records received = {fmt(t.accepted)} events + {fmt(t.duplicates_exact + t.duplicates_redelivered)} duplicates merged + {fmt(t.quarantined)} quarantined. {fmt(t.out_of_order)} arrived out of order.
      </Head>
      <section className="il-panel" aria-labelledby="il-batches">
        <h2 className="il-h2" id="il-batches">Batches and sources</h2>
        <Region label="Ingest by batch and source">
          <table className="il-table">
            <thead><tr><th scope="col">Batch</th><th scope="col">Source</th><th scope="col" className="il-num">Received</th><th scope="col" className="il-num">Accepted</th><th scope="col" className="il-num">Duplicates</th><th scope="col" className="il-num">Out of order</th><th scope="col" className="il-num">Quarantined</th><th scope="col">Clock</th></tr></thead>
            <tbody>
              {run.ingest.batches.flatMap((b) => b.sources.map((s, i) => (
                <tr key={`${b.batch}-${s.source}`}>
                  {i === 0 ? <th scope="row" rowSpan={b.sources.length} className="il-mono">{b.batch}</th> : null}
                  <td>{s.source}</td>
                  <td className="il-num">{s.received}</td><td className="il-num">{s.accepted}</td>
                  <td className="il-num">{s.duplicates_exact + s.duplicates_redelivered}</td><td className="il-num">{s.out_of_order}</td>
                  <td className="il-num">{Object.values(s.quarantined).reduce((a, n) => a + n, 0)}</td>
                  <td className="il-small">{s.skew_applied_seconds ? `corrected ${s.skew_applied_seconds} s` : s.declared_clock_offset_seconds ? `offset ${s.declared_clock_offset_seconds} s, not corrected` : "no offset"}</td>
                </tr>
              )))}
            </tbody>
          </table>
        </Region>
      </section>
      <section className="il-panel" aria-labelledby="il-q">
        <h2 className="il-h2" id="il-q">Quarantined records</h2>
        <ul className="il-list">
          {run.quarantine.records.map((q) => (
            <li key={q.quarantine_id} className="il-card">
              <p><span className="il-tag il-tone-uncertain">{q.reason.replace(/_/g, " ")}</span> <span className="il-mono il-small">{q.raw_ref.file}{q.raw_ref.line ? `:${q.raw_ref.line}` : ""}</span></p>
              <p className="il-small">{q.detail}. {run.quarantine.reasons[q.reason]}</p>
              <pre className="il-code" tabIndex={0} aria-label="Redacted raw excerpt">{q.excerpt}</pre>
            </li>
          ))}
        </ul>
      </section>
      <section className="il-panel" aria-labelledby="il-g">
        <h2 className="il-h2" id="il-g">Evidence gaps</h2>
        <ul className="il-list">
          {run.gaps.map((g) => (
            <li key={g.gap_id}><Icon name="warn" /> <strong>{g.source}</strong>, {g.kind}: {utc(g.start_utc)} to {utc(g.end_utc)} ({g.duration_minutes} min). {g.reason} Affects {g.affected_entities.length} entities and {g.incident_ids.length} incident(s).</li>
          ))}
        </ul>
      </section>
    </>
  );
}
