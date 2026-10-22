# Architecture

```
 GitHub Issue (form)          workflow_dispatch / weekly schedule
        |                                  |
   intake.yml  -- validate, authorize -->  run.yml
                                           |
          admit (state: running|blocked, idempotency, ceilings)
                                           |
          compute (read-only token, no secrets): python -m harness compute -> incidentloom.pipeline.run
                                           |  artifact run-<run_id> (14 days)
          publish (validate outputs, immutable runs/<run_id>/, latest.json)
                                           |
          pages.yml (workflow_call): snapshot state -> build -> deploy -> smoke
                                           |
          outcome.yml: hard gates + live browser evidence + optional grader -> release record
                                           |
          memory.yml: deterministic lesson proposals -> type:memory issue
```

## Investigation pipeline (`src/incidentloom`)

1. **Ingest** each batch in order: per-source parsers (JSON lines, nested JSON, syslog-like text, CSV),
   explicit timestamp formats and zones, the manifest's declared clock offset (when correction is on),
   stable event ids from source and record id (or the raw line), deduplication of exact and re-delivered
   copies with every delivery recorded, out-of-order flags, and quarantine with reason codes and a
   redacted excerpt. A checkpoint records the ingested batches and the state hash after each one.
2. **Detect** with eight correlation rules whose thresholds and tuning notes are part of the output.
3. **Investigate**: detections are grouped into incidents per primary entity; each incident gets an
   ordered timeline, links between entries (causal only with a shared session, request, process or
   parent id; otherwise temporal and worded as sequence), hypotheses with supporting, contradicting and
   missing evidence, confidence with its basis, and at least one alternative explanation.
4. **Gaps**: declared gaps from manifests and silent windows longer than 120 minutes become explicit
   records with affected entities; a hypothesis that depends on a gap names it and drops one confidence
   level.
5. **Evaluate**: precision and recall per detector on held-out scenarios only; development numbers are
   reported separately as tuning data; everything is labelled synthetic.
6. **Replay**: hashes of every evidence file; a simulated restart stops after batch N, drops in-memory
   state, reloads the checkpoint, re-ingests (a no-op for ingested batches) and must reproduce the hashes.
7. **Self-checks** that can fail: referential integrity, no causal wording outside causal links, causal
   links re-verified from the cited records, attribution edges name their entity, temporal links worded
   as sequence, every event id re-derived from its raw record, dedup accounting, gaps lower confidence,
   synthetic labelling, evidence hashes recorded.

## Decisions

| Decision | Why |
|---|---|
| Three link types: causal, temporal, attribution | "Happened next" and "the same record names it" are not causation; the site and the checks keep them apart |
| Gaps as first-class records | Missing logs must read as uncertainty, never as a quiet, innocent period |
| Labels read only by the evaluator | Detection output is identical with the labels file missing or altered, so the held-out numbers cannot leak into tuning |
| Checkpoint per batch, idempotent ingestion | Append-only sources are replayed after failures in practice; a restart must not double count |
| Synthetic geo table | Countries for impossible-travel checks without a real geo database or network call |
| No SQL | pandas covers the correlation joins; if SQL is ever added it must be in-memory SQLite only |
| Shared harness, distinct site | Operations are identical across the five projects; the visual layer is per product |

The harness, state model and workflows are documented in [STATE_MODEL.md](STATE_MODEL.md),
[SECURITY.md](SECURITY.md) and [OPERATIONS.md](OPERATIONS.md).
