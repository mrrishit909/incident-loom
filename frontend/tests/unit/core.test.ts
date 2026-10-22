import { describe, expect, it } from "vitest";
import { utc } from "../../src/components/Drawer";
import { entityKind, entityName } from "../../src/data/model";
import { isStale, type Snapshot } from "../../src/data/site";
import { parseRoute, type Route, routeHref } from "../../src/routing";

describe("routing", () => {
  it("round-trips every route", () => {
    const routes: Route[] = [
      { view: "run", section: "incidents" },
      { view: "run", section: "incidents", incidentId: "inc-0123456789" },
      { view: "run", section: "detectors" },
      { view: "run", runId: "incident-loom-1", section: "replay" },
      { view: "run", runId: "incident-loom-1", section: "incidents", incidentId: "inc-abc" },
      { view: "history" }, { view: "request" }, { view: "about" },
    ];
    for (const r of routes) expect(parseRoute(routeHref(r))).toEqual(r);
  });
  it("falls back to incidents for unknown paths", () => {
    expect(parseRoute("#/nope")).toEqual({ view: "run", section: "incidents" });
  });
});

describe("formatting", () => {
  it("shows UTC times without converting zones", () => {
    expect(utc("2026-10-14T13:20:00.000Z")).toBe("2026-10-14 13:20:00 UTC");
    expect(utc(null)).toBe("");
  });
  it("splits entity ids on the first colon only", () => {
    expect(entityKind("ip:2001:db8::1")).toBe("ip");
    expect(entityName("ip:2001:db8::1")).toBe("2001:db8::1");
    expect(entityName("resource:app/hr-portal")).toBe("app/hr-portal");
  });
});

describe("staleness", () => {
  const snap: Snapshot = { project: "incident-loom", mode: "state-snapshot", generated_at: "2026-10-01T00:00:00Z", source_commit: "x", state_commit: "y", latest_run_id: "r", runs_included: ["r"], stale_after_hours: 336 };
  it("flags snapshots older than the window", () => {
    expect(isStale(snap, Date.parse("2026-10-10T00:00:00Z"))).toBe(false);
    expect(isStale(snap, Date.parse("2026-10-20T00:00:00Z"))).toBe(true);
  });
});
