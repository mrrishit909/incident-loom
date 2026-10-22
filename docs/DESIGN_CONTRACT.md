# Design contract: Incident Loom

The transferable design rules for this site. Graders and repair workers read this file; it
contains no private preferences or credentials.

## Character

A **chronological investigation workspace**. The site is a loom: time runs left to right as the
warp, every entity in an investigation (a user, a host, an address, a resource) is a thread, and
every event is a knot on its thread. An incident is a weave that crosses several threads. Links
between knots are drawn as weft: solid when the evidence ties them causally (the same session,
request or parent id), dashed when they are only close in time. Missing logs fray the thread: a
dotted, broken segment with a question mark, so a gap reads as a gap and never as a quiet period.

The loom is the one bold element. It opens every incident and the whole-run timeline; everything
else (hypotheses, evidence, metrics) is set in quiet, readable panels around it.

Distinct from the siblings: Quant Foundry is an ivory serif research note, Data Refinery a gridded
light workbench under a dark band, Policy Forge an oat desk with paper sheets and folder tabs. Incident
Loom is dark-first (a warm charcoal room for long investigations, with a full light theme), set in a
characterful grotesk with ink traps, and its structure is a lane timeline rather than a document,
bench or folder.

## Process record

| Directive stage | Playbook steps | Done here |
|---|---|---|
| 1 Discovery | 1 brief, 3 direction | Character given by the brief; direction delegated and chosen above |
| 2 Content | 2 audience and content | Audience: security analysts, detection engineers, technical reviewers. Their questions: what happened, in what order, which events prove each claim, what else could explain it, what evidence is missing, how good are the detectors on data they were not tuned on, does a replay or restart change anything. Primary action: open an incident and follow its evidence |
| 3 Staging | 4 references, 5 design plan, 6 assets | No external visual references adopted (the named motion reference could not be verified). Tokens below. No imagery: events are the material |
| 4 Component adaptation | 7 architecture | Hand-built SVG loom and graph, no chart or UI library; the engineering kit (data loading, states, routing, embedding, e2e harness) is shared with the siblings, the visual layer is not |
| (build) | 8 build and debug | Verified in a browser before any fix is claimed |
| 5 Batch polish | 9, 10 | One coordinated batch after first review; one restrained treatment per flat section |
| 6 Mobile pass | 11 | Deliberate 390 px composition below |
| 7 Browser evidence | 12 | Playwright at 390 / 768 / 1440 in CI and on the live site; screenshots read by a person |
| 8 Deployment | 13 | GitHub Pages from Actions; live URL verified |

Skills invoked for this design: `website-playbook`, `frontend-design:frontend-design`, `ui-ux-pro-max`
(its "Dark Mode (OLED)" style kept only for its rules: 4.5:1 text, visible focus, reduced motion; its
near-black slate palette with operational green and alarm red, and JetBrains Mono everywhere, rejected
as the generic "security terminal" default the brief's warm palette rules out).

## Tokens

| Token | Dark (default) | Light | Role |
|---|---|---|---|
| canvas | #1C1613 | #FFF6E8 | page |
| surface | #262019 | #FFFBF4 | panels, drawer |
| surface-2 | #30281F | #F3E8D6 | table heads, code, lanes background |
| ink | #FFF6E8 | #29201B | primary text |
| ink-2 | #C9B8A4 | #5E5248 | secondary text (7.5:1 or more) |
| thread | #6E5E50 | #A39177 | entity lane lines, decorative only |
| edge | #8A7866 | #8C7A62 | control boundaries (>= 3.4:1) |
| hostile | #EC8F78 | #9A3622 | events and links supporting a malicious reading |
| benign | #BBBE8E | #545537 | events supporting a benign reading |
| uncertain | #E3BC66 | #6F520F | gaps, low confidence, missing evidence |
| focus | #E8D7BF | #5A171B | selection, primary action, keyboard focus ring |

Every status pairs a shape or word with colour: hostile knots are filled diamonds, benign knots open
circles, uncertain knots dashed squares, gaps a broken dotted segment with "?", causal links solid,
temporal links dashed. Text pairs are >= 4.5:1 and boundaries >= 3:1 in both themes (checked with a
contrast script).

## Type

- **Bricolage Grotesque Variable** (optical size, weight): incident titles 700 at large optical size;
  UI and body 400/500 at 15 px / 1.55.
- **Spline Sans Mono Variable**: timestamps, event ids, IPs, raw fields. Used only for those, never for
  labels.
- Scale (px): 12, 13, 15, 18, 22, 30, 40. Sentence case; no all-caps labels, no eyebrows, no middle-dot
  meta strings, no arrows on links.

## Layout

- Desktop 1440: a top bar (wordmark, sections Incidents, Timeline, Entities, Detectors, Replay, Ingest,
  and the run picker); on Incidents, a left list of incidents (severity, confidence, gap marker, time
  span) and the selected incident on the right: its title and one-sentence summary, the loom (entity
  lanes over the incident's time span, brushable), then two columns: the ordered timeline with evidence
  chips, and the hypotheses with their alternatives. Selecting a knot or an evidence chip opens the
  event drawer on the right with the normalized event, its raw source reference, and its clock-skew
  correction.
- Tablet 768: the incident list collapses into a select above the incident; timeline and hypotheses stack;
  the event drawer becomes a bottom sheet.
- Mobile 390: the loom turns vertical (time runs down, threads become columns, at most four in view with
  the rest reachable by a lane filter); tables become cards; the drawer is a full-height sheet with a close
  button.
- Left aligned. Radius 6 px on panels, 4 px on controls, round knots. Panels have a 1 px edge; only the
  drawer has a shadow.

## Motion (durations in ms)

| Moment | Treatment | Duration |
|---|---|---|
| Incident open (once per incident) | threads draw left to right, then knots appear in time order, then weft links | 380 threads, 12 per knot (max 400), 200 links |
| Brush / zoom on the loom | time scale eases to the new window; knots move, nothing re-enters | 240 |
| Evidence chip or knot selected | the knot rings once and its links brighten; the drawer slides in | 200 ring, 220 drawer |
| Hypothesis switched | supporting knots brighten, others dim; cross-fade | 180 |
| Section change | content slides 12 px in the nav direction and fades | 200 in, 140 out |
| Expand / collapse | height transition | 200 open, 140 close |

Easing: decelerate on arrival, accelerate on exit. Reduced motion: all durations 0, the loom renders
complete. Nothing essential waits for animation; no scroll hijacking, no intro, no perpetual motion, no
hover-only controls (every knot is reachable from the timeline list and by keyboard).

## Language rules

The site words time-only links as sequence ("followed", "preceded", "within 4 minutes of") and uses causal
wording only where the engine marks a link causal. Every factual statement shows its evidence ids. Detector
numbers always carry the words "synthetic, held-out" and never read as an estimate of real-world
performance.

## States

loading (skeleton shaped like the list and loom), empty (no runs yet + how to request one), error (which
file failed, Retry), stale (snapshot older than 14 days: banner with age + Refresh), fixture notice,
success; per view: no incident in this filter, no gap, restart not simulated in this run.
