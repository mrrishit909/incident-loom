import { useCallback, useEffect, useState } from "react";
import type { Routing } from "./config";

export const SECTIONS = [
  { id: "incidents", label: "Incidents" },
  { id: "timeline", label: "Timeline" },
  { id: "entities", label: "Entities" },
  { id: "detectors", label: "Detectors" },
  { id: "replay", label: "Replay" },
  { id: "ingest", label: "Ingest" },
] as const;

export type SectionId = (typeof SECTIONS)[number]["id"];

export type Route =
  | { view: "run"; runId?: string; section: SectionId; incidentId?: string }
  | { view: "history" }
  | { view: "request" }
  | { view: "about" };

const IDS = new Set<string>(SECTIONS.map((s) => s.id));

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  const [head, a, b, c] = parts;
  if (head === "runs" && a) {
    if (b === "incidents" && c) return { view: "run", runId: a, section: "incidents", incidentId: c };
    if (b && IDS.has(b)) return { view: "run", runId: a, section: b as SectionId };
    return { view: "run", runId: a, section: "incidents" };
  }
  if (head === "runs") return { view: "history" };
  if (head === "incidents" && a) return { view: "run", section: "incidents", incidentId: a };
  if (head && IDS.has(head)) return { view: "run", section: head as SectionId };
  if (head === "request") return { view: "request" };
  if (head === "about") return { view: "about" };
  return { view: "run", section: "incidents" };
}

export function routeHref(route: Route): string {
  const enc = encodeURIComponent;
  switch (route.view) {
    case "run": {
      const tail = route.section === "incidents" && route.incidentId ? `incidents/${enc(route.incidentId)}` : route.section;
      if (route.runId) return `#/runs/${enc(route.runId)}/${tail}`;
      return tail === "incidents" ? "#/" : `#/${tail}`;
    }
    case "history":
      return "#/runs";
    case "request":
      return "#/request";
    case "about":
      return "#/about";
  }
}

export function useRoute(mode: Routing): [Route, (r: Route) => void] {
  const [route, setRoute] = useState<Route>(() => (mode === "hash" ? parseRoute(window.location.hash) : { view: "run", section: "incidents" }));
  useEffect(() => {
    if (mode !== "hash") return;
    const onHash = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [mode]);
  const navigate = useCallback(
    (r: Route) => {
      if (mode === "hash") window.location.hash = routeHref(r).slice(1);
      else setRoute(r);
    },
    [mode],
  );
  return [route, navigate];
}
