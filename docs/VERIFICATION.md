# Verification

**The single current release record is `releases/current.json` on the `state` branch.** It is
written only by the Outcome Verification Loop and only when every hard gate passed. Every attempt,
including blocked ones, is in `releases/history.json`, with findings and small evidence files in
`outcomes/<release_id>/`. This document explains the checks; it does not restate their status.

## Hard gates (objective; rubric locked by `rubric/rubric.lock`)

| Gate | What it proves | How |
|---|---|---|
| investigation-gates | every factual claim links to source events; causality is never asserted from time proximity alone; replay is byte-identical (also under another hash seed and working directory); a restart after any batch reproduces the evidence and never double counts; detector metrics use held-out labelled scenarios whose labels detection code never reads; synthetic performance is labelled synthetic; missing logs produce explicit gaps and lowered confidence, never invented events | `pytest -m gate tests/incidentloom` (7 tests) |
| harness | state machine, idempotency, duplicate detection, compare-and-swap concurrency, immutability, intake authorization by identity, injection-safe parsing, ceilings, repair-round bounds, memory guard, artifact downloads that never forward the token | `pytest tests/harness` |
| secret-scan | no credential patterns in tracked files or in the live site's HTML, JS and CSS | `scripts/secret_scan.py --live` |
| live-site | the Pages URL serves the app and its snapshot points at the state branch's latest run | HTTP checks |
| published-matches-state | every published result file of the latest run is byte-identical to the state branch | `python -m harness verify-published` |
| browser | 16 checks x 3 widths (390, 768, 1440), all 48 must pass, against the live site: incident list, loom and legend; a timeline entry opening its events in the drawer; a hypothesis and an alternative highlighted on the loom; the graph and entity focus; an incident with a gap showing frayed threads and lowered confidence and no causal wording; evidence chips opening events; every section by link with focus and back button; the whole-run timeline with window controls; entity filters; held-out metrics labelled synthetic; replay checkpoints and ingest accounting; skip link and focus; light theme (axe plus a direct primary-action contrast check); reduced motion; loading / empty / error-retry / stale states; the portfolio preview image; axe (WCAG 2.2 AA serious and critical), horizontal overflow, console errors and failed same-origin requests | Playwright, `frontend/tests/e2e/site.spec.ts` |

## Independent evidence review

A separate evidence reviewer (an agent that did not build the engine) attacked the claim-to-evidence,
causality, replay, deduplication, timestamp, quarantine, held-out evaluation, gap and request
guarantees with crafted batches, recording each confirmed defect as a strict-xfail test in
`tests/incidentloom/test_il_adversarial.py`. It confirmed 23 defects (IL-01 to IL-23). The blockers:
quarantine excerpts leaked secrets written as JSON fields, underscore-prefixed keys or Bearer headers;
a placeholder session id ("-") shared by two accounts became a causal link and pulled the other
account's event into the incident; and a source missing from a batch manifest produced no gap, so a
run could say "No evidence gaps found". Majors included reused process ids becoming causal links,
declared gaps hiding longer silences, timeline entries and summaries stating parameters or hosts the
cited events did not have, secrets in accepted records published verbatim, malformed records aborting
the run instead of being quarantined, records far outside their batch window accepted silently, and a
validator that re-derived only event ids, never the claims. None was reachable with the committed
batches except two wording defects (a confidence factor that called a previously used address unseen,
and a float restart value skipping the restart bound). All 23 are fixed and their tests now pass as
plain regression tests, next to 13 tests for claims that held. The run's own check now re-ingests the
raw batches and re-renders every evidence file to compare them field by field. The headline numbers on
the committed batches did not change.

## Subjective review (separate from gates)

The rubric's subjective criteria (hierarchy, typography, spacing, palette, motion, responsive
adaptation, distinctiveness, evidence honesty, fidelity to `docs/DESIGN_CONTRACT.md`) are scored by an
independent grader only when the repository has an inference secret; otherwise the release record
says the grader did not run. Scores never change a gate result. Screenshots from every outcome run are
kept as Actions artifacts for 14 days and a small representative set is committed with the release
evidence.

## Repairs

A failing gate opens or updates one `type:repair` issue per gate. The same failing set on a new
commit counts as another repair round; after three rounds the release is marked blocked for human
review and its evidence is kept.

## Reproduce locally (optional)

```sh
uv sync --frozen && uv run pytest
cd frontend && npm ci && npm run build && npx playwright install chromium && npm run e2e
```
