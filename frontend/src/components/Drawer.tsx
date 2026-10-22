import { useEffect, useRef } from "react";
import type { EventRecord, RunModel, TimelineEntry } from "../data/model";
import type { LoadState } from "../data/site";
import { Icon } from "./Icon";

export type Selection = { kind: "entry"; entry: TimelineEntry; incidentId: string } | { kind: "event"; eventId: string } | null;

export const utc = (iso: string | null | undefined) => (iso ? `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC` : "");

function EventCard({ ev, run }: { ev: EventRecord; run: RunModel }) {
  const rows: [string, string | null][] = [
    ["Time (corrected)", utc(ev.corrected_at_utc)],
    ["Time as logged", ev.skew_applied_seconds ? `${ev.observed_at_raw} (corrected by ${ev.skew_applied_seconds} s for the source's declared clock offset)` : ev.observed_at_raw],
    ["Source", `${ev.source}, batch ${ev.batch}`],
    ["Action", `${ev.action}${ev.outcome ? `, ${ev.outcome}` : ""}`],
    ["Actor", ev.actor], ["Target", ev.target],
    ["Address", ev.src_ip ? `${ev.src_ip}${ev.geo ? ` (${ev.geo}, synthetic geo table)` : ""}` : null],
    ["Session", ev.session_id], ["Request", ev.request_id], ["Process", ev.process_id], ["Parent", ev.parent_id],
    ["Raw record", `${ev.raw_ref.file}${ev.raw_ref.line ? `:${ev.raw_ref.line}` : ev.raw_ref.pointer ? `#${ev.raw_ref.pointer}` : ""}`],
  ];
  const incidents = run.incidents.filter((i) => i.event_ids.includes(ev.event_id) || i.context_event_ids.includes(ev.event_id));
  return (
    <article className="il-event" aria-label={`Event ${ev.event_id}`}>
      <p className="il-mono il-event-id">{ev.event_id}{ev.out_of_order ? <span className="il-tag il-tone-uncertain">arrived out of order</span> : null}</p>
      <dl className="il-kv">
        {rows.filter(([, v]) => v).map(([k, v]) => (
          <div key={k} style={{ display: "contents" }}>
            <dt>{k}</dt>
            <dd className={/Time|Address|Session|Request|Process|Parent|Raw/.test(k) ? "il-mono" : undefined}>{v}</dd>
          </div>
        ))}
      </dl>
      {Object.keys(ev.details).length > 0 && (
        <pre className="il-code" tabIndex={0} aria-label="Event details">{JSON.stringify(ev.details, null, 2)}</pre>
      )}
      {ev.duplicates.length > 0 && (
        <p className="il-small">Delivered {ev.duplicates.length + 1} times; merged as {ev.duplicates.map((d) => `${d.kind.replace(/_/g, " ")} in batch ${d.batch}`).join(", ")}.</p>
      )}
      {incidents.length > 0 && <p className="il-small">Part of {incidents.map((i) => i.title).join("; ")}.</p>}
    </article>
  );
}

export function Drawer({ selection, run, events, onClose, onEvent }: {
  selection: Selection;
  run: RunModel;
  events: LoadState<Map<string, EventRecord>>;
  onClose: () => void;
  onEvent: (id: string) => void;
}) {
  const ref = useRef<HTMLElement>(null);
  const open = selection !== null;
  useEffect(() => {
    if (!open) return;
    const el = ref.current;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    el?.addEventListener("keydown", onKey);
    el?.focus({ preventScroll: true });
    return () => el?.removeEventListener("keydown", onKey);
  }, [open, selection, onClose]);

  let body: React.ReactNode = null;
  const lookup = (id: string) => (events.status === "ready" ? events.data.get(id) : undefined);
  if (selection?.kind === "entry") {
    const e = selection.entry;
    const dets = run.detections.filter((d) => e.detection_ids.includes(d.detection_id));
    body = (
      <>
        <p className="il-small"><span className="il-mono">{e.entry_id}</span>, {e.source}</p>
        <h2 className="il-h2">{e.text}</h2>
        <p className="il-mono il-small">
          {utc(e.at_utc)}{e.end_utc ? ` to ${utc(e.end_utc)}` : ""}
          {e.raw_at_utc && e.skew_applied_seconds ? ` (logged ${utc(e.raw_at_utc)}; corrected by ${e.skew_applied_seconds} s)` : ""}
        </p>
        {dets.length > 0 && (
          <ul className="il-list" aria-label="Detections on this entry">
            {dets.map((d) => <li key={d.detection_id}><span className="il-tag il-tone-hostile">{d.detector.replace(/_/g, " ")}</span> {d.summary}</li>)}
          </ul>
        )}
        <h3 className="il-h3">{e.event_ids.length} source {e.event_ids.length === 1 ? "event" : "events"}</h3>
        {events.status === "ready" ? e.event_ids.slice(0, 12).map((id) => { const ev = lookup(id); return ev ? <EventCard key={id} ev={ev} run={run} /> : <p key={id} className="il-mono">{id} (not in this run)</p>; })
          : events.status === "error" ? <p className="il-tone-hostile">The event file did not load: {events.error.message}</p>
          : <p className="il-small" role="status">Loading the events.</p>}
        {e.event_ids.length > 12 && <p className="il-small">{e.event_ids.length - 12} more: {e.event_ids.slice(12).map((id) => <button key={id} type="button" className="il-chip-link il-mono" onClick={() => onEvent(id)}>{id}</button>)}</p>}
      </>
    );
  } else if (selection?.kind === "event") {
    const ev = lookup(selection.eventId);
    body = ev ? <EventCard ev={ev} run={run} />
      : events.status === "loading" ? <p className="il-small" role="status">Loading the event.</p>
      : <p className="il-mono">{selection.eventId} is not among this run's events.</p>;
  }

  return (
    <>
      <div className="il-scrim" data-open={open} onClick={onClose} aria-hidden />
      <aside className="il-drawer" data-open={open} aria-label="Event details" tabIndex={-1} ref={ref}>
        <button type="button" className="il-btn il-drawer-close" onClick={onClose}><Icon name="cross" /> Close</button>
        {body}
      </aside>
    </>
  );
}
