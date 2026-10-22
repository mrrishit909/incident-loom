# Incident Loom

A replayable security-log investigation workspace. Four **synthetic** sources (identity sign-ins,
cloud audit, host authentication and resource access) arrive as six append-only daily batches. Each
record is parsed, normalized to one event schema, corrected for its source's declared clock offset,
de-duplicated across deliveries, or quarantined with a reason. Correlation rules flag patterns;
flagged events become incidents with an evidence-linked timeline, hypotheses that cite their events,
alternative explanations, and the evidence gaps that lower confidence. A run can be stopped after any
batch and resumed from its checkpoint without changing a byte of evidence.

- **Live site:** https://mrrishit909.github.io/incident-loom/
- **Current release record:** [`releases/current.json` on the state branch](https://github.com/mrrishit909/incident-loom/blob/state/releases/current.json)
- **Run records and results:** the [`state` branch](https://github.com/mrrishit909/incident-loom/tree/state)

## What it does

| Part | Where |
|---|---|
| Six synthetic daily batches with injected anomalies, benign admin activity, duplicates, out-of-order records, clock skew, a declared gap and malformed records; labelled development and held-out scenarios; a synthetic address-to-country table | `fixtures/` (`python -m incidentloom fixtures`) |
| Ingestion, normalization, deduplication, skew correction, quarantine, checkpoint and restart | `src/incidentloom/ingest.py`, `pipeline.py` |
| Eight correlation rules with documented thresholds | `src/incidentloom/detect.py` |
| Incidents, timelines, causal and temporal links, hypotheses, alternatives, gaps, correlation graph | `src/incidentloom/investigate.py` |
| Held-out evaluation (the only code that reads the labels) | `src/incidentloom/evaluate.py` |
| GitHub-native harness: intake, admission, publication, reconciler, outcome loop, memory | `harness/` |
| Static, embeddable investigation workspace | `frontend/` |

## Results on the committed batches

All six batches, clock-skew correction on: 1,534 records received, 1,502 events accepted, 19
duplicate deliveries merged, 13 records quarantined, 9 out of order. Ten incidents (2 critical, 5
high, 3 medium) from 20 detections; two evidence gaps (one declared host-log gap, one silent
resource-log window), each lowering the confidence of the hypotheses that depend on it. On the eight
held-out synthetic scenarios: precision 0.8 and recall 0.8 (one designed false positive, one slow
password spray missed). These numbers describe synthetic labels written by the same author as the
detectors; they show that the evaluation works, not how the detectors would do on real logs.

## Use it

- Browse investigations anonymously: incidents and their loom (one thread per entity, a knot per
  event group, solid links for shared ids, dashed links for order only, frayed threads where a source
  was silent), hypotheses and alternatives, event details, the whole-run timeline, entities, detector
  metrics, replay and ingest accounting.
- Request a run: open the *Investigation run request* issue form. The owner's requests run
  automatically; anyone else's wait for the owner's `job:approved` label. See
  [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Documents

[Architecture](docs/ARCHITECTURE.md), [operations](docs/OPERATIONS.md),
[state model](docs/STATE_MODEL.md), [security](docs/SECURITY.md),
[cost limits](docs/COST_LIMITS.md), [verification](docs/VERIFICATION.md),
[portfolio integration](docs/PORTFOLIO_INTEGRATION.md), [design contract](docs/DESIGN_CONTRACT.md),
[portfolio manifest](portfolio-manifest.json).

## Limitations

Synthetic batches only, for a fictional organisation; no real logs, no uploads, no response actions.
Thresholds were chosen by inspecting the development scenarios (no automated sweep); four rules have a
single development case, so their windows are partly a-priori. Confidence is a documented, uncalibrated
point rule, and hypotheses and alternatives are templates per detector type. Deduplication decides exact
versus re-delivered copies by delivery id and keeps the first delivery; it does not compare conflicting
content between deliveries. Incidents are grouped by primary entity within 24 hours, so a spray address
and its targets are separate incidents. The 120-minute silence threshold assumes steady background
traffic. Causal wording is checked against a fixed phrase list. The optional AI grader runs only if the
owner adds an inference secret; release records state whether it ran.
