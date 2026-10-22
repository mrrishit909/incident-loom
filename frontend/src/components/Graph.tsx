import { useMemo } from "react";
import type { Correlations, Incident } from "../data/model";
import { entityKind, entityName } from "../data/model";
import { useWidth } from "../lib/useWidth";

interface Pair {
  a: string;
  b: string;
  count: number;
  actions: Set<string>;
  causal: boolean;
}

/**
 * Entities of one incident around a circle. Two entities are joined when a single event of the incident names
 * both (attribution: the record names its actor, target and address); a thicker line means more such events.
 * Event-to-event causal links are drawn as a ring on the entities they touch. Nothing here asserts that one
 * event produced another.
 */
export function IncidentGraph({ incident, correlations, focus, onFocus }: {
  incident: Incident;
  correlations: Correlations;
  focus: string | null;
  onFocus: (entity: string | null) => void;
}) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const { nodes, pairs, causalEntities } = useMemo(() => {
    const entitySet = new Set(incident.entities.map((e) => e.entity));
    const eventSet = new Set([...incident.event_ids, ...incident.context_event_ids]);
    const byEvent = new Map<string, string[]>();
    const actionOf = new Map(correlations.nodes.filter((n) => n.kind === "event").map((n) => [n.id, n.action ?? ""]));
    for (const e of correlations.edges) {
      if (e.link_type !== "attribution" || !eventSet.has(e.from) || !entitySet.has(e.to)) continue;
      byEvent.set(e.from, [...(byEvent.get(e.from) ?? []), e.to]);
    }
    const pairMap = new Map<string, Pair>();
    for (const [ev, ents] of byEvent) {
      const uniq = [...new Set(ents)].sort();
      for (let i = 0; i < uniq.length; i++)
        for (let j = i + 1; j < uniq.length; j++) {
          const key = `${uniq[i]}|${uniq[j]}`;
          const p = pairMap.get(key) ?? { a: uniq[i]!, b: uniq[j]!, count: 0, actions: new Set<string>(), causal: false };
          p.count += 1;
          p.actions.add(actionOf.get(ev) ?? "");
          pairMap.set(key, p);
        }
    }
    const causalEvents = new Set(correlations.edges.filter((e) => e.link_type === "causal" && e.incident_id === incident.incident_id).flatMap((e) => [e.from, e.to]));
    const causal = new Set<string>();
    for (const [ev, ents] of byEvent) if (causalEvents.has(ev)) ents.forEach((x) => causal.add(x));
    return { nodes: incident.entities.map((e) => e.entity), pairs: [...pairMap.values()], causalEntities: causal };
  }, [incident, correlations]);

  const size = Math.min(width, 560);
  const r = size / 2 - 70;
  const cx = width / 2;
  const cy = size / 2;
  const at = (i: number) => {
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(1, nodes.length);
    return { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle), angle };
  };
  const index = new Map(nodes.map((n, i) => [n, i]));
  const maxCount = Math.max(1, ...pairs.map((p) => p.count));

  return (
    <figure ref={ref} className="il-graph-wrap">
      {width > 0 && nodes.length > 0 && (
        <svg className="il-graph" width={width} height={size} viewBox={`0 0 ${width} ${size}`} role="img"
          aria-label={`Graph of ${nodes.length} entities in ${incident.title}; lines join entities named together by the same event.`}>
          {pairs.map((p) => {
            const a = at(index.get(p.a)!);
            const b = at(index.get(p.b)!);
            const on = focus === null || focus === p.a || focus === p.b;
            return <line key={`${p.a}|${p.b}`} className="il-g-edge" data-dim={!on} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              strokeWidth={1 + (3 * p.count) / maxCount}><title>{`${entityName(p.a)} and ${entityName(p.b)}: named together by ${p.count} event(s) (${[...p.actions].join(", ")})`}</title></line>;
          })}
          {nodes.map((n, i) => {
            const p = at(i);
            const right = Math.cos(p.angle) >= 0;
            const kind = entityKind(n);
            return (
              <g key={n} className="il-g-node" data-kind={kind} data-focus={focus === n} data-causal={causalEntities.has(n)}
                transform={`translate(${p.x} ${p.y})`} onClick={() => onFocus(focus === n ? null : n)}>
                {causalEntities.has(n) && <circle className="il-g-causal" r={13} />}
                {kind === "user" ? <circle r={8} /> : kind === "host" ? <rect x={-7} y={-7} width={14} height={14} rx={2} />
                  : kind === "ip" ? <path d="M0 -9 L8 5 L-8 5 Z" /> : <rect x={-7} y={-7} width={14} height={14} transform="rotate(45)" />}
                <text x={right ? 16 : -16} y={4} textAnchor={right ? "start" : "end"}>{entityName(n).length > 24 ? `${entityName(n).slice(0, 23)}...` : entityName(n)}</text>
              </g>
            );
          })}
        </svg>
      )}
      <figcaption className="il-small">
        Lines join entities that one event names together (attribution, not causation); thicker lines mean more events. A ring marks entities on a
        causal link (a shared session, request, process or parent id). Select an entity, here or in the list, to follow its thread on the loom.
      </figcaption>
    </figure>
  );
}
