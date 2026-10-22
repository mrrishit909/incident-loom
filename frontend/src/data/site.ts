import { useCallback, useEffect, useRef, useState } from "react";
import { fetchJson } from "./load";
import type { EventRecord, RunModel } from "./model";

export interface Snapshot {
  project: string;
  mode: "state-snapshot" | "fixture";
  generated_at: string;
  source_commit: string;
  state_commit: string;
  latest_run_id: string | null;
  runs_included: string[];
  stale_after_hours: number;
  files?: { release: boolean; memory: boolean };
}

export interface IndexEntry {
  run_id: string;
  request_id: string;
  status: string;
  attempt: number;
  created_at: string;
  completed_at: string | null;
  source: string;
  issue: number | null;
  headline: string | null;
}

export interface Release {
  release_id: string;
  status: "released" | "blocked";
  created_at: string;
}

export interface SiteData {
  snapshot: Snapshot;
  index: IndexEntry[];
  release: Release | null;
}

export type LoadState<T> =
  | { status: "loading" }
  | { status: "error"; error: Error }
  | { status: "empty" }
  | { status: "ready"; data: T; stale: boolean };

export function isStale(s: Snapshot, now = Date.now()): boolean {
  const t = Date.parse(s.generated_at);
  return Number.isFinite(t) && now - t > s.stale_after_hours * 3600_000;
}

export function useSiteData(dataUrl: string): { state: LoadState<SiteData>; reload: () => void } {
  const [state, setState] = useState<LoadState<SiteData>>({ status: "loading" });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const ctrl = new AbortController();
    setState({ status: "loading" });
    (async () => {
      try {
        const snapshot = await fetchJson<Snapshot>(`${dataUrl}snapshot.json`, ctrl.signal);
        const index = await fetchJson<{ runs: IndexEntry[] }>(`${dataUrl}index.json`, ctrl.signal);
        const release = snapshot.files?.release ? await fetchJson<Release>(`${dataUrl}release.json`, ctrl.signal) : null;
        if (!snapshot.latest_run_id) {
          setState({ status: "empty" });
          return;
        }
        setState({ status: "ready", data: { snapshot, index: index.runs, release }, stale: isStale(snapshot) });
      } catch (err) {
        if (!ctrl.signal.aborted) setState({ status: "error", error: err as Error });
      }
    })();
    return () => ctrl.abort();
  }, [dataUrl, tick]);
  return { state, reload: useCallback(() => setTick((t) => t + 1), []) };
}

/* eslint-disable @typescript-eslint/no-explicit-any */
async function loadRun(dataUrl: string, runId: string, signal: AbortSignal): Promise<RunModel> {
  const base = `${dataUrl}runs/${encodeURIComponent(runId)}/`;
  const files = ["run.json", "manifest.json", "summary.json", "incidents.json", "gaps.json", "correlations.json", "detections.json",
    "detector_metrics.json", "ingest.json", "quarantine.json", "entities.json", "replay.json", "checkpoint.json", "checks.json"] as const;
  const [run, manifest, summary, incidents, gaps, correlations, detections, metrics, ingest, quarantine, entities, replay, checkpoint, checks] =
    await Promise.all(files.map((f) => fetchJson<any>(base + f, signal)));
  return {
    record: {
      runId: String(run.run_id), status: String(run.status), attempt: Number(run.attempt ?? 1), createdAt: String(run.created_at),
      sourceCommit: String(run.source_commit ?? ""), workflowRunId: run.workflow_run_id ?? null,
      requestSource: { type: String(run.request_source?.type ?? "manual"), issue: run.request_source?.issue_number ?? null },
    },
    params: {
      batches: manifest.params.batches, clockSkewCorrection: manifest.params.clock_skew_correction,
      simulateRestartAfter: Number(manifest.params.simulate_restart_after ?? 0),
    },
    summary,
    incidents: incidents.incidents ?? [],
    gaps: gaps.gaps ?? [],
    correlations,
    detectors: detections.detectors ?? [],
    detections: detections.detections ?? [],
    metrics,
    ingest,
    quarantine,
    entities: entities.entities ?? [],
    replay,
    checkpoint,
    checks,
    base,
    reportUrl: `${base}report.md`,
  };
}

export function useRun(dataUrl: string, runId: string | null, tick: number): LoadState<RunModel> {
  const cache = useRef(new Map<string, RunModel>());
  const [state, setState] = useState<LoadState<RunModel>>({ status: "loading" });
  useEffect(() => { cache.current.clear(); }, [tick]);
  useEffect(() => {
    if (!runId) {
      setState({ status: "empty" });
      return;
    }
    const hit = cache.current.get(runId);
    if (hit) {
      setState({ status: "ready", data: hit, stale: false });
      return;
    }
    const ctrl = new AbortController();
    setState({ status: "loading" });
    loadRun(dataUrl, runId, ctrl.signal).then(
      (data) => { cache.current.set(runId, data); setState({ status: "ready", data, stale: false }); },
      (error) => { if (!ctrl.signal.aborted) setState({ status: "error", error }); },
    );
    return () => ctrl.abort();
  }, [dataUrl, runId, tick]);
  return state;
}

/** events.json is the largest file (about 1 MB); it loads only when a view needs individual events. */
export function useEvents(base: string | null, wanted: boolean): LoadState<Map<string, EventRecord>> {
  const [state, setState] = useState<LoadState<Map<string, EventRecord>>>({ status: "loading" });
  const loaded = useRef<string | null>(null);
  useEffect(() => {
    if (!base || !wanted || loaded.current === base) return;
    const ctrl = new AbortController();
    setState({ status: "loading" });
    fetchJson<{ events: EventRecord[] }>(`${base}events.json`, ctrl.signal).then(
      (d) => { loaded.current = base; setState({ status: "ready", data: new Map(d.events.map((e) => [e.event_id, e])), stale: false }); },
      (error) => { if (!ctrl.signal.aborted) setState({ status: "error", error }); },
    );
    return () => ctrl.abort();
  }, [base, wanted]);
  return state;
}
