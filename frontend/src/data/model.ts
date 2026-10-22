/* Types for the engine's output files (schemas/outputs.schema.json). Field names follow the files. */

export type Severity = "critical" | "high" | "medium" | "low";
export type LinkType = "causal" | "temporal" | "attribution";

export interface TimelineEntry {
  entry_id: string;
  at_utc: string;
  end_utc: string | null;
  raw_at_utc: string | null;
  raw_end_utc: string | null;
  skew_applied_seconds: number;
  source: string;
  action: string;
  count: number;
  text: string;
  event_ids: string[];
  detection_ids: string[];
}

export interface IncidentLink {
  link_id: string;
  from: string;
  to: string;
  link_type: "causal" | "temporal";
  evidence_type: string | null;
  evidence_value: string | null;
  event_ids: string[];
  text: string;
}

export interface MissingEvidence {
  gap_id: string;
  source: string;
  start_utc: string;
  end_utc: string;
  description: string;
}

export interface Alternative {
  kind: string;
  statement: string;
  event_ids: string[];
  distinguishing_evidence: string;
}

export interface Hypothesis {
  hypothesis_id: string;
  statement: string;
  supporting_event_ids: string[];
  contradicting_event_ids: string[];
  missing_evidence: MissingEvidence[];
  depends_on_gaps: string[];
  expected_sources: string[];
  confidence: "low" | "medium" | "high";
  confidence_before_gaps: "low" | "medium" | "high";
  confidence_basis: string;
  alternatives: Alternative[];
}

export interface IncidentEntity {
  entity: string;
  roles: string[];
  event_ids: string[];
}

export interface Incident {
  incident_id: string;
  title: string;
  severity: Severity;
  severity_basis: string;
  primary_entity: string;
  window: { start_utc: string; end_utc: string };
  detection_ids: string[];
  detectors: string[];
  event_ids: string[];
  context_event_ids: string[];
  entities: IncidentEntity[];
  timeline: TimelineEntry[];
  links: IncidentLink[];
  hypotheses: Hypothesis[];
  gaps: string[];
  gaps_hypotheses_depend_on: string[];
}

export interface Gap {
  gap_id: string;
  kind: "declared" | "silent";
  source: string;
  batch: string;
  start_utc: string;
  end_utc: string;
  duration_minutes: number;
  reason: string;
  affected_entities: string[];
  bounding_event_ids: string[];
  events_inside_window: number;
  incident_ids: string[];
  hypothesis_refs: string[];
}

export interface EventRecord {
  event_id: string;
  source: string;
  source_record_id: string | null;
  batch: string;
  observed_at_raw: string;
  observed_at_utc: string;
  corrected_at_utc: string;
  skew_applied_seconds: number;
  actor: string | null;
  target: string | null;
  action: string;
  outcome: string | null;
  src_ip: string | null;
  geo: string | null;
  session_id: string | null;
  request_id: string | null;
  parent_id: string | null;
  process_id: string | null;
  details: Record<string, unknown>;
  delivery_id: string | null;
  raw_ref: { file: string; line?: number; pointer?: string };
  duplicates: { batch: string; delivery_id: string | null; kind: string; raw_ref: { file: string; line?: number } }[];
  out_of_order: boolean;
}

export interface CorrelationNode {
  id: string;
  kind: string;
  source?: string;
  action?: string;
  at_utc?: string;
  incident_ids?: string[];
}

export interface CorrelationEdge {
  edge_id: string;
  from: string;
  to: string;
  relation: string;
  link_type: LinkType;
  evidence_type: string | null;
  evidence_value?: string | null;
  event_ids: string[];
  incident_id?: string | null;
  text?: string;
}

export interface Correlations {
  link_types: Record<string, string>;
  nodes: CorrelationNode[];
  edges: CorrelationEdge[];
}

export interface Detector {
  id: string;
  title: string;
  severity: Severity;
  sources: string[];
  description: string;
  tuning: string;
  thresholds: Record<string, unknown>;
}

export interface Detection {
  detection_id: string;
  detector: string;
  severity: Severity;
  entity: string;
  related_entities: string[];
  start_utc: string;
  end_utc: string;
  event_ids: string[];
  summary: string;
}

export interface Score {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number | null;
  recall: number | null;
}

export interface MetricsBlock {
  role: string;
  scenarios_scored: number;
  overall: Score;
  per_detector: (Score & { detector: string; relevant_incident_scenarios: number })[];
  scenarios: { scenario_id: string; kind: string; expected: string; techniques: string[]; detected_by: string[]; outcome: string }[];
  excluded: unknown[];
}

export interface DetectorMetrics {
  synthetic: boolean;
  disclaimer: string;
  scoring: string | Record<string, unknown>;
  labels_status: "loaded" | "unavailable";
  held_out: MetricsBlock | null;
  development: MetricsBlock | null;
}

export interface IngestSource {
  source: string;
  file: string;
  format: string;
  timezone: string;
  declared_clock_offset_seconds: number;
  skew_applied_seconds: number;
  received: number;
  accepted: number;
  duplicates_exact: number;
  duplicates_redelivered: number;
  out_of_order: number;
  quarantined: Record<string, number>;
}

export interface Ingest {
  clock_skew_correction: string;
  batches: { batch: string; sources: IngestSource[] }[];
  totals: { received: number; accepted: number; duplicates_exact: number; duplicates_redelivered: number; out_of_order: number; quarantined: number };
  quarantined_by_reason: Record<string, number>;
}

export interface QuarantineRecord {
  quarantine_id: string;
  batch: string;
  source: string;
  raw_ref: { file: string; line?: number };
  reason: string;
  detail: string;
  excerpt: string;
}

export interface Quarantine {
  count: number;
  by_reason: Record<string, number>;
  reasons: Record<string, string>;
  records: QuarantineRecord[];
}

export interface EntityRecord {
  entity: string;
  kind: string;
  events: number;
  sources: string[];
  countries: string[];
  first_seen_utc: string;
  last_seen_utc: string;
  incident_ids: string[];
}

export interface Replay {
  simulate_restart_after: number;
  mode: "uninterrupted" | "restart";
  restart: null | {
    stopped_after_batch: string;
    checkpoint_sha256: string;
    state_sha256_before_stop: string;
    state_sha256_after_reload: string;
    state_matches_checkpoint: boolean;
    reingest_of_last_batch_was_noop: boolean;
    batches_after_resume: string[];
  };
  comparison: null | { against: string; identical: boolean; differing_files: string[]; uninterrupted_output_hashes: Record<string, string> };
  output_hashes: Record<string, string>;
  manifest_sha256: string;
  note: string;
}

export interface Checkpoint {
  batches_ingested: string[];
  events: number;
  quarantined: number;
  event_ids_sha256: string;
  high_water_utc: Record<string, string>;
  per_batch: { after_batch: string; events_total: number; quarantined_total: number; state_sha256: string }[];
  state_sha256: string;
  note: string;
}

export interface Summary {
  synthetic: boolean;
  batches: string[];
  clock_skew_correction: string;
  counts: Record<string, number>;
  incidents_by_severity: Record<string, number>;
  headline: string;
  statement: string;
}

export interface Checks {
  passed: boolean;
  checks: { check: string; passed: boolean; description: string; problem_count: number }[];
}

export interface RunRecordLite {
  runId: string;
  status: string;
  attempt: number;
  createdAt: string;
  sourceCommit: string;
  workflowRunId: number | null;
  requestSource: { type: string; issue: number | null };
}

export interface RunModel {
  record: RunRecordLite;
  params: { batches: string[]; clockSkewCorrection: "on" | "off"; simulateRestartAfter: number };
  summary: Summary;
  incidents: Incident[];
  gaps: Gap[];
  correlations: Correlations;
  detectors: Detector[];
  detections: Detection[];
  metrics: DetectorMetrics;
  ingest: Ingest;
  quarantine: Quarantine;
  entities: EntityRecord[];
  replay: Replay;
  checkpoint: Checkpoint;
  checks: Checks;
  base: string;
  reportUrl: string;
}

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export const entityKind = (e: string) => e.slice(0, e.indexOf(":"));
export const entityName = (e: string) => e.slice(e.indexOf(":") + 1);
