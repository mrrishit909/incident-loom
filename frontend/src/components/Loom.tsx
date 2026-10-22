import { useEffect, useMemo, useRef } from "react";
import type { Gap, Incident, TimelineEntry } from "../data/model";
import { entityName } from "../data/model";
import { animate, drawStroke, prefersReducedMotion } from "../lib/motion";
import { useWidth } from "../lib/useWidth";

const ms = (iso: string) => Date.parse(iso);

export interface LoomFocus {
  /** Event ids to emphasise (a hypothesis or an alternative); others dim. */
  emphasis: Set<string> | null;
  emphasisTone: "hostile" | "benign";
  selectedEntry: string | null;
  entity: string | null;
}

function ticks(start: number, end: number, max: number): number[] {
  const span = end - start;
  const steps = [60e3, 5 * 60e3, 15 * 60e3, 30 * 60e3, 3600e3, 3 * 3600e3, 6 * 3600e3, 12 * 3600e3, 86400e3];
  const step = steps.find((s) => span / s <= max) ?? 86400e3;
  const out: number[] = [];
  for (let t = Math.ceil(start / step) * step; t <= end; t += step) out.push(t);
  return out;
}

const hhmm = (t: number) => new Date(t).toISOString().slice(11, 16);
const dayLabel = (t: number) => new Date(t).toISOString().slice(5, 10);

/**
 * The loom: one thread per entity, a knot per timeline entry on each thread it touches, weft between linked
 * entries (solid when causal, dashed when only temporal) and frayed segments where a source was silent.
 * Horizontal on wide screens; on narrow screens time runs down and threads become columns.
 */
export function Loom({ incident, gaps, focus, onSelectEntry, maxLanes = 8 }: {
  incident: Incident;
  gaps: Gap[];
  focus: LoomFocus;
  onSelectEntry: (entry: TimelineEntry) => void;
  maxLanes?: number;
}) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const svg = useRef<SVGSVGElement>(null);
  const vertical = width > 0 && width < 560;

  const lanes = useMemo(() => {
    const firstAt = (ids: string[]) => Math.min(...incident.timeline.filter((t) => t.event_ids.some((e) => ids.includes(e))).map((t) => ms(t.at_utc)), Infinity);
    const sorted = [...incident.entities].sort((a, b) => firstAt(a.event_ids) - firstAt(b.event_ids) || a.entity.localeCompare(b.entity));
    const primary = sorted.findIndex((e) => e.entity === incident.primary_entity);
    if (primary > 0) sorted.unshift(...sorted.splice(primary, 1));
    const limit = vertical ? Math.min(4, maxLanes) : maxLanes;
    if (focus.entity && !sorted.slice(0, limit).some((e) => e.entity === focus.entity)) {
      const i = sorted.findIndex((e) => e.entity === focus.entity);
      if (i >= 0) sorted.splice(limit - 1, 0, ...sorted.splice(i, 1));
    }
    return { shown: sorted.slice(0, limit), hidden: sorted.length - Math.min(limit, sorted.length) };
  }, [incident, vertical, maxLanes, focus.entity]);

  const start = ms(incident.window.start_utc);
  const end = Math.max(ms(incident.window.end_utc), start + 60e3);
  const pad = (end - start) * 0.06;
  const t0 = start - pad;
  const t1 = end + pad;

  const laneGap = vertical ? Math.max(64, (width - 40) / Math.max(1, lanes.shown.length)) : 40;
  const labelW = vertical ? 0 : Math.min(190, Math.max(120, width * 0.18));
  const top = vertical ? 46 : 18;
  const timeLen = vertical ? Math.max(360, incident.timeline.length * 46) : Math.max(200, width - labelW - 24);
  const height = vertical ? top + timeLen + 30 : top + lanes.shown.length * laneGap + 34;
  const scale = (t: number) => ((t - t0) / (t1 - t0)) * timeLen;
  const pos = (t: number, lane: number) => vertical
    ? { x: 20 + lane * laneGap + laneGap / 2, y: top + scale(t) }
    : { x: labelW + scale(t), y: top + lane * laneGap + laneGap / 2 };

  const laneIndex = new Map(lanes.shown.map((l, i) => [l.entity, i]));
  const knots = incident.timeline.flatMap((entry) =>
    lanes.shown
      .filter((l) => l.event_ids.some((e) => entry.event_ids.includes(e)))
      .map((l) => ({ entry, lane: laneIndex.get(l.entity)!, ...pos(ms(entry.at_utc), laneIndex.get(l.entity)!),
        end: entry.end_utc ? pos(ms(entry.end_utc), laneIndex.get(l.entity)!) : null })),
  );
  const firstKnot = (entryId: string) => knots.find((k) => k.entry.entry_id === entryId);
  const incidentGaps = gaps.filter((g) => incident.gaps.includes(g.gap_id));

  useEffect(() => {
    if (!width || prefersReducedMotion()) return;
    const root = svg.current;
    if (!root) return;
    root.querySelectorAll<SVGPathElement>(".il-thread").forEach((p) => drawStroke(p, 380));
    root.querySelectorAll(".il-knot").forEach((k, i) => animate(k, [{ opacity: 0, transform: "scale(0.4)" }, { opacity: 1, transform: "none" }], { duration: 180, delay: 300 + Math.min(400, i * 12) }));
    root.querySelectorAll(".il-weft").forEach((w) => animate(w, [{ opacity: 0 }, { opacity: 1 }], { duration: 200, delay: 620 }));
    // Plays once per incident; re-renders (focus changes) must not replay it.
  }, [incident.incident_id, width > 0]); // eslint-disable-line react-hooks/exhaustive-deps

  const dim = (ids: string[]) => focus.emphasis !== null && !ids.some((e) => focus.emphasis!.has(e));
  const tickList = ticks(t0, t1, vertical ? 6 : Math.max(3, Math.floor(timeLen / 110)));
  const multiDay = dayLabel(t0) !== dayLabel(t1);

  return (
    <div ref={ref} className="il-loom-wrap">
      {width > 0 && (
        <svg ref={svg} className="il-loom" width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img"
          aria-label={`Loom for ${incident.title}: ${lanes.shown.length} entities over ${incident.timeline.length} timeline entries, ${incidentGaps.length} evidence gap(s). The same entries are listed in the timeline below.`}>
          {/* time axis */}
          {tickList.map((t) => {
            const a = pos(t, 0);
            return vertical ? (
              <g key={t} className="il-tick"><line x1={10} x2={width - 10} y1={a.y} y2={a.y} /><text x={width - 12} y={a.y - 4} textAnchor="end">{multiDay ? `${dayLabel(t)} ` : ""}{hhmm(t)}</text></g>
            ) : (
              <g key={t} className="il-tick"><line x1={a.x} x2={a.x} y1={top - 8} y2={height - 24} /><text x={a.x} y={height - 8} textAnchor="middle">{multiDay ? `${dayLabel(t)} ` : ""}{hhmm(t)}</text></g>
            );
          })}
          {/* threads */}
          {lanes.shown.map((l, i) => {
            const a = pos(t0, i);
            const b = pos(t1, i);
            return (
              <g key={l.entity} className="il-lane" data-focus={focus.entity === l.entity}>
                <path className="il-thread" d={`M${a.x} ${a.y} L${b.x} ${b.y}`} />
                {vertical
                  ? <text className="il-lane-label" x={a.x} y={18} textAnchor="middle">{short(entityName(l.entity), 12)}</text>
                  : <text className="il-lane-label" x={labelW - 12} y={a.y + 4} textAnchor="end">{short(entityName(l.entity), 22)}</text>}
                {!vertical && <text className="il-lane-kind" x={labelW - 12} y={a.y + 17} textAnchor="end">{l.entity.split(":")[0]}</text>}
              </g>
            );
          })}
          {/* frayed segments where a source was silent */}
          {incidentGaps.flatMap((g) => lanes.shown.filter((l) => g.affected_entities.includes(l.entity)).map((l) => {
            const i = laneIndex.get(l.entity)!;
            const a = pos(Math.max(t0, ms(g.start_utc)), i);
            const b = pos(Math.min(t1, ms(g.end_utc)), i);
            const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
            return (
              <g key={`${g.gap_id}-${l.entity}`} className="il-gap">
                <path className="il-gap-mask" d={`M${a.x} ${a.y} L${b.x} ${b.y}`} />
                <path className="il-gap-line" d={`M${a.x} ${a.y} L${b.x} ${b.y}`} />
                <text x={vertical ? mid.x + 10 : mid.x} y={vertical ? mid.y : mid.y - 9} textAnchor={vertical ? "start" : "middle"}>?</text>
              </g>
            );
          }))}
          {/* weft between linked entries */}
          {incident.links.map((link) => {
            const a = firstKnot(link.from);
            const b = firstKnot(link.to);
            if (!a || !b) return null;
            const d = vertical
              ? `M${a.x} ${a.y} C ${a.x} ${(a.y + b.y) / 2}, ${b.x} ${(a.y + b.y) / 2}, ${b.x} ${b.y}`
              : `M${a.x} ${a.y} C ${(a.x + b.x) / 2} ${a.y}, ${(a.x + b.x) / 2} ${b.y}, ${b.x} ${b.y}`;
            return <path key={link.link_id} className="il-weft" data-type={link.link_type} data-dim={dim(link.event_ids)} d={d} />;
          })}
          {/* knots */}
          {knots.map((k) => {
            const detected = k.entry.detection_ids.length > 0;
            const selected = focus.selectedEntry === k.entry.entry_id;
            const emphasised = focus.emphasis !== null && k.entry.event_ids.some((e) => focus.emphasis!.has(e));
            return (
              <g key={`${k.entry.entry_id}-${k.lane}`} className="il-knot" data-kind={detected ? "detected" : "context"} data-dim={dim(k.entry.event_ids)}
                data-selected={selected} data-tone={emphasised ? focus.emphasisTone : undefined} transform={`translate(${k.x} ${k.y})`}
                onClick={() => onSelectEntry(k.entry)}>
                {k.end && <path className="il-span" d={`M0 0 L${k.end.x - k.x} ${k.end.y - k.y}`} />}
                {detected ? <rect x={-5.5} y={-5.5} width={11} height={11} transform="rotate(45)" /> : <circle r={5.5} />}
                {selected && <circle className="il-ring" r={11} />}
                <title>{`${k.entry.entry_id}: ${k.entry.text}`}</title>
              </g>
            );
          })}
        </svg>
      )}
      {lanes.hidden > 0 && <p className="il-small">{lanes.hidden} more {lanes.hidden === 1 ? "entity" : "entities"} not drawn; filter by entity below to bring one onto the loom.</p>}
    </div>
  );
}

function short(s: string, n: number) {
  return s.length > n ? `${s.slice(0, n - 1)}...` : s;
}

/** Legend for the loom's marks; every mark is a shape as well as a colour. */
export function LoomLegend() {
  return (
    <ul className="il-legend" aria-label="Loom legend">
      <li><svg width="16" height="16" aria-hidden><rect x="4" y="4" width="8" height="8" transform="rotate(45 8 8)" className="il-lg-detected" /></svg>Flagged by a detector</li>
      <li><svg width="16" height="16" aria-hidden><circle cx="8" cy="8" r="4.5" className="il-lg-context" /></svg>Context event</li>
      <li><svg width="28" height="16" aria-hidden><path d="M2 8 H26" className="il-lg-causal" /></svg>Causal link (shared id)</li>
      <li><svg width="28" height="16" aria-hidden><path d="M2 8 H26" className="il-lg-temporal" /></svg>Order in time only</li>
      <li><svg width="28" height="16" aria-hidden><path d="M2 8 H26" className="il-lg-gap" /></svg>Source silent (gap)</li>
    </ul>
  );
}
