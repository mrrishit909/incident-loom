"""Output rendering, self-checks, the causal-language checker and `validate(out_dir)`.

All JSON is canonical (sorted keys, compact, ASCII) and contains no wall-clock time or absolute path,
so the same request always produces the same bytes.
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from . import __version__
from .detect import DETECTORS
from .ingest import (
    EARLY_TOLERANCE_MINUTES,
    KNOWN_SOURCES,
    LATE_TOLERANCE_HOURS,
    REASONS,
    batch_summary,
    ingest_batch,
    new_state,
    raw_record,
    record_event_id,
)
from .investigate import PROCESS_WINDOW, SESSION_WINDOW, SILENCE_MINUTES, explicit_link
from .util import (
    CAUSAL_RE,
    EVENT_ID_RE,
    HOUR,
    QUOTED_RE,
    SCHEMAS,
    SYNTHETIC_DISCLAIMER,
    data,
    iso_ms,
    jbytes,
    parse_utc,
    sha256,
)

MAX_BYTES = 1_900_000
EVIDENCE_FILES = [
    "ingest.json",
    "events.json",
    "quarantine.json",
    "entities.json",
    "detections.json",
    "incidents.json",
    "correlations.json",
    "gaps.json",
    "detector_metrics.json",
    "checkpoint.json",
    "summary.json",
    "report.md",
    "checks.json",
]
REQUIRED_FILES = sorted(EVIDENCE_FILES + ["manifest.json", "replay.json"])
RAW_KEYS = {"details", "excerpt", "observed_at_raw"}  # raw record data, never the engine's own words
SEQUENCE_RE = re.compile(r"\b(followed|preceded|within|after|before)\b")
CAUSAL_EVIDENCE = ("same_session", "same_request", "same_process", "parent_id")
ATTRIBUTION_EVIDENCE = ("record_field", "audit_actor_target")
REASON_TEXT = {
    "parse_error": "the record could not be parsed",
    "wrong_field_count": "a CSV row with the wrong number of fields",
    "missing_required_field": "a required field is missing or empty",
    "invalid_timestamp": "the timestamp is missing an explicit zone, malformed or out of range",
    "invalid_field": "a field has the wrong type or an unusable value (any other per-record failure lands here too)",
    "outside_batch_window": "the event time lies outside its batch coverage beyond the late and early tolerances",
    "conflicting_redelivery": "a record id already ingested arrived again with different content; the first copy "
    "is kept and this delivery is listed under ingest.json conflicts",
}
LINK_TYPES = {
    "causal": "event to event, backed by a shared session, request or process id or a recorded parent id",
    "temporal": "event to event, only the order in time is known; worded as sequence",
    "attribution": "a single record names this entity as its actor, target or address; nothing more is claimed",
}


def causal_phrases(text: str) -> list[str]:
    """Causal wording in the engine's own words; double-quoted spans are raw data (see util.data) and skipped."""
    return [m.group(0) for m in CAUSAL_RE.finditer(QUOTED_RE.sub(" ", text))]


def public(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: public(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [public(v) for v in obj]
    return obj


# ---- rendering ------------------------------------------------------------------------------------
def render_evidence(state: dict[str, Any], params: dict[str, Any], per_batch: list[dict[str, Any]]) -> dict[str, bytes]:
    docs = build_docs(state, params, per_batch)
    files = {name: (doc.encode("ascii") if name.endswith(".md") else jbytes(doc)) for name, doc in docs.items()}
    files["checks.json"] = jbytes(run_checks(docs, files))
    return files


def build_docs(state: dict[str, Any], params: dict[str, Any], per_batch: list[dict[str, Any]]) -> dict[str, Any]:
    """Every evidence document except checks.json, from an ingest state."""
    from .detect import detect
    from .evaluate import evaluate
    from .investigate import correlations, entities, find_gaps, investigate

    correction = params["clock_skew_correction"]
    events = sorted(state["events"].values(), key=lambda e: (e["corrected_ms"], e["event_id"]))
    dets = detect(events)
    gaps = find_gaps(state, events, KNOWN_SOURCES)
    incidents = investigate(events, dets, gaps, correction)
    by_id = {e["event_id"]: e for e in events}
    metrics = evaluate(dets, set(by_id))
    stats = state["stats"]
    totals = {
        k: sum(s[k] for s in stats)
        for k in ("received", "accepted", "duplicates_exact", "duplicates_redelivered", "out_of_order")
    }
    totals["quarantined"] = len(state["quarantine"])
    by_reason = {r: sum(s["quarantined"].get(r, 0) for s in stats) for r in REASONS}
    docs: dict[str, Any] = {
        "ingest.json": {
            "synthetic": True,
            "clock_skew_correction": correction,
            "batches": [
                {"batch": b, "sources": [s for s in stats if s["batch"] == b]} for b in state["batches_ingested"]
            ],
            "totals": totals,
            "quarantined_by_reason": by_reason,
            "rules": {
                "dedup_key": "event_id = 'ev-' + sha256(source + '|' + source record id)[:16]; host lines have "
                "no record id, so the whole raw line is the key",
                "duplicate_kinds": "exact_duplicate: same delivery id; redelivery: same record id, different "
                "delivery id. The first delivery wins; later ones are listed on the event.",
                "out_of_order": "an accepted event whose time precedes its batch's coverage start or the "
                "latest time already ingested from the same source",
                "skew": "corrected_at_utc = observed_at_utc - declared_clock_offset_seconds when correction "
                "is on; equal to observed_at_utc when it is off",
                "accounting": "received = accepted + duplicates_exact + duplicates_redelivered + quarantined",
                "batch_window": f"an event must fall between its batch coverage start minus {LATE_TOLERANCE_HOURS} h "
                f"(late delivery) and coverage end plus {EARLY_TOLERANCE_MINUTES} min plus the declared clock offset; "
                "anything else is quarantined as outside_batch_window",
                "conflicts": "a record id seen again with different content is quarantined as conflicting_redelivery "
                "and listed under conflicts; the first copy stays the event",
                "redaction": "secret-looking values (password=, token=, api_key=, client_secret=, Bearer headers and "
                "similar) are replaced by [REDACTED] in quarantine excerpts and in every published event detail; "
                "events list the redacted fields in redacted_fields",
                "explicit_ids": f"a session or request id links events only for the same actor within "
                f"{SESSION_WINDOW // HOUR} h, a process or parent id within {PROCESS_WINDOW // HOUR} h; placeholder "
                "ids such as '-', '0', 'null' or 'unknown' never link",
            },
            "conflicts": [
                {
                    k: q[k]
                    for k in ("quarantine_id", "batch", "source", "raw_ref", "conflicts_with", "conflicting_fields")
                }
                for q in sorted(state["quarantine"], key=lambda q: (q["batch"], q["source"], q["quarantine_id"]))
                if q["reason"] == "conflicting_redelivery"
            ],
        },
        "events.json": {
            "synthetic": True,
            "count": len(events),
            "events": [{k: v for k, v in e.items() if k != "corrected_ms"} for e in events],
        },
        "quarantine.json": {
            "count": len(state["quarantine"]),
            "by_reason": by_reason,
            "reasons": REASON_TEXT,
            "records": sorted(state["quarantine"], key=lambda q: (q["batch"], q["source"], q["quarantine_id"])),
        },
        "entities.json": {"entities": entities(events, incidents)},
        "detections.json": {
            "detectors": [{**d, "thresholds": metrics["thresholds"][d["id"]]} for d in DETECTORS],
            "detections": public(dets),
        },
        "incidents.json": {"incidents": incidents},
        "correlations.json": {"link_types": LINK_TYPES, **correlations(incidents, by_id)},
        "gaps.json": {"silence_threshold_minutes": SILENCE_MINUTES, "gaps": public(gaps)},
        "detector_metrics.json": metrics,
        "checkpoint.json": {
            "batches_ingested": state["batches_ingested"],
            "events": len(events),
            "quarantined": len(state["quarantine"]),
            "event_ids_sha256": sha256("\n".join(sorted(by_id)).encode("ascii")),
            "high_water_utc": {k: iso_ms(v) for k, v in sorted(state["high_water"].items())},
            "per_batch": per_batch,
            "state_sha256": per_batch[-1]["state_sha256"],
            "note": "The full checkpoint (the complete ingest state) is written to the run's working directory after "
            "every batch and removed when the run ends; this file summarises it.",
        },
    }
    docs["summary.json"] = summary(docs, params)
    docs["report.md"] = report(docs, params)
    return docs


def rederive(params: dict[str, Any]) -> dict[str, Any]:
    """Recompute every evidence document from the raw batches: the reference that validation compares against."""
    state, per_batch = new_state(params["clock_skew_correction"]), []
    for batch in params["batches"]:
        ingest_batch(state, batch)
        per_batch.append(batch_summary(state, batch))
    return build_docs(state, params, per_batch)


def summary(docs: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    t = docs["ingest.json"]["totals"]
    incs = docs["incidents.json"]["incidents"]
    gaps = docs["gaps.json"]["gaps"]
    sev = {s: sum(1 for i in incs if i["severity"] == s) for s in ("critical", "high", "medium", "low")}
    held = (docs["detector_metrics.json"]["held_out"] or {}).get("overall")
    gap_text = "; ".join(
        f"{data(g['source'])} {g['kind']} {g['start_utc'][:16]}Z to {g['end_utc'][:16]}Z" for g in gaps
    )
    batches = params["batches"]
    statement = (
        f"{len(batches)} batch(es) {batches[0]} to {batches[-1]}, "
        f"clock-skew correction {params['clock_skew_correction']}: "
        f"{t['accepted']} normalized events from {t['received']} records "
        f"({t['duplicates_exact'] + t['duplicates_redelivered']} duplicates merged, {t['quarantined']} quarantined). "
        f"{len(incs)} incident(s): "
        + ", ".join(f"{n} {s}" for s, n in sev.items() if n)
        + ". "
        + (f"Evidence gaps: {gap_text}. " if gaps else "No evidence gaps found. ")
        + SYNTHETIC_DISCLAIMER
    )
    headline = (
        f"{len(incs)} incidents ({sev['critical']} critical, {sev['high']} high) from {t['accepted']} synthetic "
        f"events; {len(gaps)} evidence gap(s)"
        + (f"; held-out precision {held['precision']}, recall {held['recall']} (synthetic labels)" if held else "")
    )
    return {
        "synthetic": True,
        "batches": batches,
        "clock_skew_correction": params["clock_skew_correction"],
        "counts": {
            "records_received": t["received"],
            "events": t["accepted"],
            "quarantined": t["quarantined"],
            "duplicates_exact": t["duplicates_exact"],
            "duplicates_redelivered": t["duplicates_redelivered"],
            "out_of_order": t["out_of_order"],
            "detections": len(docs["detections.json"]["detections"]),
            "incidents": len(incs),
            "gaps": len(gaps),
            "entities": len(docs["entities.json"]["entities"]),
        },
        "incidents_by_severity": sev,
        "incidents": [
            {
                "incident_id": i["incident_id"],
                "title": i["title"],
                "severity": i["severity"],
                "event_ids": i["event_ids"][:1],
                "gaps": i["gaps"],
            }
            for i in incs
        ],
        "gaps": [{k: g[k] for k in ("gap_id", "kind", "source", "start_utc", "end_utc")} for g in gaps],
        "held_out_metrics": held,
        "headline": headline,
        "statement": statement,
    }


def report(docs: dict[str, Any], params: dict[str, Any]) -> str:
    s = docs["summary.json"]
    out = [
        "# Incident Loom run report",
        "",
        f"> {SYNTHETIC_DISCLAIMER}",
        "",
        s["statement"],
        "",
        "## Ingestion",
        "",
        "| batch | source | received | accepted | exact dup | redelivered | out of order | "
        "quarantined | skew applied (s) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for b in docs["ingest.json"]["batches"]:
        for x in b["sources"]:
            out.append(
                f"| {data(x['batch'])} | {data(x['source'])} | {x['received']} | {x['accepted']} | "
                f"{x['duplicates_exact']} | "
                f"{x['duplicates_redelivered']} | {x['out_of_order']} | {sum(x['quarantined'].values())} | "
                f"{x['skew_applied_seconds']} |"
            )
    out += [
        "",
        "Quarantined by reason: " + ", ".join(f"{k} {v}" for k, v in docs["quarantine.json"]["by_reason"].items()),
        "",
        "## Evidence gaps",
        "",
    ]
    for g in docs["gaps.json"]["gaps"]:
        out.append(
            f"- `{g['gap_id']}` {g['kind']} gap in {g['source']}, {g['start_utc']} to {g['end_utc']} "
            f"({g['duration_minutes']} min). {g['reason']}. Incidents: {', '.join(g['incident_ids']) or 'none'}."
        )
    if not docs["gaps.json"]["gaps"]:
        out.append("No gaps found.")
    out += [
        "",
        "## Incidents",
        "",
        "Links marked causal rest on an explicit identifier in the records; links marked temporal only state order. "
        "In correlations.json, attribution edges only state that a record names an entity.",
        "",
    ]
    for inc in docs["incidents.json"]["incidents"]:
        out += [
            f"### {inc['incident_id']} ({inc['severity']}): {inc['title']}",
            "",
            f"Window {inc['window']['start_utc']} to {inc['window']['end_utc']}; {len(inc['event_ids'])} events; "
            f"gaps: {', '.join(inc['gaps']) or 'none'}.",
            "",
            "Timeline:",
            "",
        ]
        for t in inc["timeline"]:
            raw = f" (raw {t['raw_at_utc']})" if t["raw_at_utc"] and t["raw_at_utc"] != t["at_utc"] else ""
            out.append(
                f"- {t['entry_id']} {t['at_utc']}{raw}: {t['text']} [{', '.join(t['event_ids'][:3])}"
                + (f", +{len(t['event_ids']) - 3} more" if len(t["event_ids"]) > 3 else "")
                + "]"
            )
        out += [
            "",
            "Links: "
            + "; ".join(
                f"{lk['from']}->{lk['to']} {lk['link_type']}"
                + (f" ({lk['evidence_type']})" if lk["evidence_type"] else "")
                for lk in inc["links"]
            ),
            "",
            "Hypotheses:",
            "",
        ]
        for h in inc["hypotheses"]:
            out.append(
                f"- {h['hypothesis_id']} [{h['confidence']}; before gaps {h['confidence_before_gaps']}] "
                f"{h['statement']} Basis: {h['confidence_basis']}."
            )
            for a in h["alternatives"]:
                out.append(
                    f"  - alternative ({a['kind']}): {a['statement']} Distinguish by: {a['distinguishing_evidence']}"
                )
        out.append("")
    m = docs["detector_metrics.json"]
    out += ["## Detector metrics (synthetic)", "", m["disclaimer"], "", m["scoring"], ""]
    for split in ("held_out", "development"):
        block = m[split]
        if not block:
            out.append(f"{split}: labels unavailable.")
            continue
        o = block["overall"]
        out += [
            f"### {split.replace('_', '-')} ({block['role']})",
            "",
            f"Overall on {block['scenarios_scored']} scenarios: tp {o['tp']}, fp {o['fp']}, fn {o['fn']}, "
            f"tn {o['tn']}, "
            f"precision {o['precision']}, recall {o['recall']}.",
            "",
            "| detector | tp | fp | fn | tn | precision | recall |",
            "|---|---|---|---|---|---|---|",
        ]
        out += [
            f"| {p['detector']} | {p['tp']} | {p['fp']} | {p['fn']} | {p['tn']} | {p['precision']} | {p['recall']} |"
            for p in block["per_detector"]
        ]
        out += (
            [""]
            + [
                f"- {r['scenario_id']} {r['kind']} expected {r['expected']}: {r['outcome']}"
                + (f" (detected by {', '.join(r['detected_by'])})" if r["detected_by"] else "")
                for r in block["scenarios"]
            ]
            + [""]
        )
    out += [
        "## Limitations",
        "",
        "- All data, entities and labels are synthetic and describe a fictional organisation.",
        "- The same author wrote the fixtures and the detectors, so held-out numbers are optimistic.",
        "- Confidence levels come from a documented point rule, not a calibrated model.",
        "- Temporal links state order only; absence of an explicit identifier is not proof of independence.",
        "",
    ]
    # every value interpolated above is engine text or data() output; this last pass keeps the file one ASCII line
    # per entry whatever a raw value contained
    lines = [re.sub(r"[\x00-\x1f\x7f]", " ", line) for line in out]
    return "\n".join(lines).encode("ascii", "backslashreplace").decode("ascii")


# ---- checks (shared by the pipeline and validate) -------------------------------------------------
def walk_narrative(obj: Any, path: str, hits: list[str], exempt: bool = False) -> None:
    """Collect causal wording in every published prose string (any string with a space, under any key) except raw
    record data; only the strings of a link object typed causal may use it."""
    if isinstance(obj, str):
        if not exempt and " " in obj and causal_phrases(obj):
            hits.append(f"{path}: {', '.join(sorted(set(causal_phrases(obj))))}")
    elif isinstance(obj, dict):
        causal = obj.get("link_type") == "causal"
        for k, v in obj.items():
            if k not in RAW_KEYS:
                walk_narrative(v, f"{path}/{k}", hits, causal and isinstance(v, str))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            walk_narrative(v, f"{path}/{i}", hits)


def ids_in(obj: Any) -> list[str]:
    return EVENT_ID_RE.findall(json.dumps(obj) if not isinstance(obj, str) else obj)


def iter_links(docs: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    out = [
        (f"incidents/{i['incident_id']}/links/{lk['link_id']}", lk)
        for i in docs["incidents.json"]["incidents"]
        for lk in i["links"]
    ]
    out += [(f"correlations/edges/{e['edge_id']}", e) for e in docs["correlations.json"]["edges"]]
    return out


def verify_link(lk: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> str | None:
    """Recompute a causal link's evidence from the two events it cites; return a problem or None."""
    ids = lk.get("event_ids") or []
    if any(i not in by_id for i in ids):
        return "cites an unknown event"
    kind = lk.get("evidence_type")
    if kind not in CAUSAL_EVIDENCE:
        return f"causal link without an explicit identifier evidence type ({kind})"
    if len(ids) != 2:
        return "needs exactly two events"
    hit = explicit_link(by_id[ids[0]], by_id[ids[1]])
    if hit is None or hit[0] != kind or hit[1] != lk.get("evidence_value"):
        return f"claimed {kind} {lk.get('evidence_value')} but the two events do not share it"
    return None


def verify_attribution(edge: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> str | None:
    """An attribution edge must cite one event that itself names the entity (or actor and target) it points at."""
    ids = edge.get("event_ids") or []
    if len(ids) != 1 or ids[0] not in by_id:
        return "must cite exactly one known event"
    e, kind = by_id[ids[0]], edge.get("evidence_type")
    if kind == "record_field":
        names = {"actor": e["actor"], "target": e["target"], "address": f"ip:{e['src_ip']}" if e["src_ip"] else None}
        ok = edge.get("from") == ids[0] and names.get(edge.get("relation")) == edge.get("to")
        return None if ok else "the cited record does not name that entity"
    if kind == "audit_actor_target":
        ok = e["source"] == "cloud_audit" and e["actor"] == edge.get("from") and e["target"] == edge.get("to")
        return None if ok else "the cited audit record does not name that actor and target"
    return f"attribution edge with evidence type {kind!r}"


def run_checks(docs: dict[str, Any], files: dict[str, bytes]) -> dict[str, Any]:
    events = docs["events.json"]["events"]
    by_id = {e["event_id"]: e for e in events}
    valid = set(by_id) | {q["quarantine_id"] for q in docs["quarantine.json"]["records"]}
    checks: list[dict[str, Any]] = []
    params = {
        "batches": [b.get("batch") for b in docs["ingest.json"].get("batches", [])],
        "clock_skew_correction": docs["ingest.json"].get("clock_skew_correction"),
    }
    try:
        fresh: dict[str, Any] | None = rederive(params)
        ref_error = None
    except Exception as exc:  # tampered parameters or unreadable inputs: report, never crash
        fresh, ref_error = None, f"re-derivation from the raw batches failed ({type(exc).__name__})"

    def check(name: str, problems: list[str], what: str) -> None:
        checks.append(
            {
                "check": name,
                "passed": not problems,
                "description": what,
                "problems": problems[:20],
                "problem_count": len(problems),
            }
        )

    unknown = sorted({i for name, doc in docs.items() for i in ids_in(doc) if i not in valid})
    empty = []
    for inc in docs["incidents.json"]["incidents"]:
        p = f"incidents/{inc['incident_id']}"
        items = [
            ("", inc),
            *((f"/timeline/{t['entry_id']}", t) for t in inc["timeline"]),
            *((f"/entities/{e['entity']}", e) for e in inc["entities"]),
            *((f"/links/{lk['link_id']}", lk) for lk in inc["links"]),
        ]
        for sub, item in items:
            if not item["event_ids"]:
                empty.append(p + sub)
        for h in inc["hypotheses"]:
            if not h["supporting_event_ids"]:
                empty.append(f"{p}/{h['hypothesis_id']}")
            empty += [f"{p}/{h['hypothesis_id']}/alternative" for a in h["alternatives"] if not a["event_ids"]]
            if not h["alternatives"]:
                empty.append(f"{p}/{h['hypothesis_id']} has no alternative explanation")
    empty += [f"detections/{d['detection_id']}" for d in docs["detections.json"]["detections"] if not d["event_ids"]]
    empty += [f"correlations/{e['edge_id']}" for e in docs["correlations.json"]["edges"] if not e["event_ids"]]
    check(
        "referential_integrity",
        [f"unknown id {i}" for i in unknown] + [f"no event ids: {x}" for x in empty],
        "every id-shaped token in every output is a normalized event or a quarantined record of this run, and every "
        "timeline entry, hypothesis, alternative, link, edge, detection and incident entity cites at least one",
    )

    hits: list[str] = []
    for name, doc in docs.items():
        if name == "events.json":
            continue
        if isinstance(doc, str):
            hits += [
                f"{name}:{n}: {', '.join(causal_phrases(line))}"
                for n, line in enumerate(doc.split("\n"), 1)
                if causal_phrases(line)
            ]
        else:
            walk_narrative(doc, name, hits)
    check(
        "no_causal_language_outside_causal_links",
        hits,
        "narrative text uses no causal wording except on links whose type is causal",
    )

    bad_links, bad_temporal, bad_attr = [], [], []
    for where, lk in iter_links(docs):
        allowed = ("causal", "temporal", "attribution") if where.startswith("correlations/") else ("causal", "temporal")
        ltype = lk.get("link_type")
        event_to_event = (
            lk.get("from") in by_id and lk.get("to") in by_id if where.startswith("correlations/") else True
        )
        if ltype not in allowed:
            bad_links.append(f"{where}: link_type {ltype!r}")
        elif ltype == "attribution":
            problem = verify_attribution(lk, by_id)
            if problem:
                bad_attr.append(f"{where}: {problem}")
        elif not event_to_event:
            bad_links.append(f"{where}: a {ltype} edge must join two events, not an entity")
        elif ltype == "causal":
            problem = verify_link(lk, by_id)
            if problem:
                bad_links.append(f"{where}: {problem}")
        elif "text" in lk and (not SEQUENCE_RE.search(lk["text"]) or causal_phrases(lk["text"])):
            bad_temporal.append(f"{where}: temporal link not worded as sequence")
    check(
        "causal_links_verified",
        bad_links,
        "every link has a valid link_type; causal and temporal links join two events; every causal link's shared "
        "session, request or process id or recorded parent id is recomputed from the two cited events",
    )
    check(
        "attribution_edges_name_their_entity",
        bad_attr,
        "every attribution edge cites one event that itself names the entity it points at (actor, target or "
        "address), or for audit edges names both the actor and the target",
    )
    check(
        "temporal_links_worded_as_sequence",
        bad_temporal,
        "temporal links say followed, preceded, within, after or before, and nothing causal",
    )

    fabricated = []
    fmt = {"idp_signin": "jsonl", "cloud_audit": "json", "host_auth": "syslog", "resource_access": "csv"}
    for e in events:
        for ref in [e["raw_ref"]] + [d["raw_ref"] for d in e["duplicates"]]:
            raw = raw_record(ref)
            if raw is None or record_event_id(e["source"], fmt[e["source"]], raw) != e["event_id"]:
                fabricated.append(f"{e['event_id']} does not re-derive from {ref}")
    for q in docs["quarantine.json"]["records"]:
        if raw_record(q["raw_ref"]) is None:
            fabricated.append(f"{q['quarantine_id']} points at no input record")
    if fresh is None:
        fabricated.append(str(ref_error))
    else:
        derived = {e["event_id"]: e for e in fresh["events.json"]["events"]}
        for e in events:
            r = derived.get(e["event_id"])
            if r is None:
                fabricated.append(f"{e['event_id']} is not produced by the raw batches")
            elif r != e:
                fields = ", ".join(sorted(k for k in set(e) | set(r) if e.get(k) != r.get(k)))
                fabricated.append(f"{e['event_id']}: {fields} differ from what its raw record normalizes to")
        fabricated += [
            f"{i} from the raw batches is missing from events.json" for i in sorted(set(derived) - set(by_id))
        ]
        ref_q = {q["quarantine_id"]: q for q in fresh["quarantine.json"]["records"]}
        fabricated += [
            f"{q['quarantine_id']} differs from the raw batches"
            for q in docs["quarantine.json"]["records"]
            if ref_q.get(q["quarantine_id"]) != q
        ]
    check(
        "no_fabricated_events",
        fabricated,
        "every event (and every duplicate delivery) re-derives its event id from the raw input record it cites, and "
        "every normalized field (times, actor, target, action, outcome, address, ids, details) equals what that raw "
        "record normalizes to; no raw record is missing; every quarantined record matches its raw input record",
    )
    check(
        "outputs_rederived",
        [str(ref_error)]
        if fresh is None
        else [
            f"{name} differs from its re-derivation from the raw batches"
            for name in sorted(fresh)
            if docs.get(name) != fresh[name]
        ],
        "every evidence file (timeline text and links, detections and their member events, gaps, hypotheses and "
        "their confidence, graph, entities, metrics arithmetic, summary counts and the report) equals a fresh "
        "computation from the raw batches with the same batches and clock-skew setting",
    )

    acct = []
    for b in docs["ingest.json"]["batches"]:
        for s in b["sources"]:
            parts = s["accepted"] + s["duplicates_exact"] + s["duplicates_redelivered"] + sum(s["quarantined"].values())
            if s["received"] != parts:
                acct.append(f"{s['batch']}/{s['source']}: received {s['received']} != {parts}")
    t = docs["ingest.json"]["totals"]
    if t["accepted"] != len(events):
        acct.append(f"accepted {t['accepted']} != events {len(events)}")
    dups = sum(len(e["duplicates"]) for e in events)
    if dups != t["duplicates_exact"] + t["duplicates_redelivered"]:
        acct.append(
            f"duplicate deliveries on events {dups} != counted {t['duplicates_exact'] + t['duplicates_redelivered']}"
        )
    if t["quarantined"] != len(docs["quarantine.json"]["records"]):
        acct.append("quarantine count mismatch")
    check(
        "dedup_accounting",
        acct,
        "received = accepted + duplicates + quarantined for every batch and source, and the "
        "totals match the events and quarantine files",
    )

    gap_list = docs["gaps.json"]["gaps"]
    gap_ids = {g["gap_id"] for g in gap_list}
    gap_probs = []
    refs: dict[str, list[str]] = {g["gap_id"]: [] for g in gap_list}
    for inc in docs["incidents.json"]["incidents"]:
        for h in inc["hypotheses"]:
            times = [parse_utc(by_id[i]["corrected_at_utc"]) for i in h["supporting_event_ids"] if i in by_id]
            if times:  # recompute the dependencies independently of what the hypothesis declares
                lo, hi = min(times), max(times) + 2 * HOUR
                expected = [
                    g["gap_id"]
                    for g in gap_list
                    if g["source"] in h["expected_sources"]
                    and parse_utc(g["start_utc"]) < hi
                    and parse_utc(g["end_utc"]) > lo
                ]
                if expected != h["depends_on_gaps"]:
                    gap_probs.append(
                        f"{inc['incident_id']}/{h['hypothesis_id']}: depends on {expected} by its "
                        f"supporting events and expected sources, declares {h['depends_on_gaps']}"
                    )
            for gid in h["depends_on_gaps"]:
                refs.setdefault(gid, []).append(f"{inc['incident_id']}/{h['hypothesis_id']}")
            for gid in h["depends_on_gaps"]:
                if (
                    gid not in gap_ids
                    or gid not in h["statement"]
                    or gid not in {m["gap_id"] for m in h["missing_evidence"]}
                ):
                    gap_probs.append(f"{inc['incident_id']}/{h['hypothesis_id']}: gap {gid} not stated or unknown")
            order = ["low", "medium", "high"]
            drop = order.index(h["confidence_before_gaps"]) - order.index(h["confidence"])
            if h["depends_on_gaps"] and not (drop == 1 or h["confidence_before_gaps"] == "low" == h["confidence"]):
                gap_probs.append(f"{inc['incident_id']}/{h['hypothesis_id']}: confidence not lowered for its gap")
            if not h["depends_on_gaps"] and drop:
                gap_probs.append(f"{inc['incident_id']}/{h['hypothesis_id']}: confidence lowered without a gap")
    gap_probs += [
        f"{g['gap_id']}: hypothesis_refs {g['hypothesis_refs']} != {refs.get(g['gap_id'])}"
        for g in gap_list
        if sorted(g["hypothesis_refs"]) != sorted(refs.get(g["gap_id"], []))
    ]
    check(
        "gaps_lower_confidence",
        gap_probs,
        "each hypothesis's gap dependencies are recomputed from its supporting events and expected sources; those "
        "that depend on a gap name it, list it as missing evidence and drop one confidence level (unless already low)",
    )

    m, s = docs["detector_metrics.json"], docs["summary.json"]
    synth = []
    if not (m.get("synthetic") is True and SYNTHETIC_DISCLAIMER == m.get("disclaimer")):
        synth.append("detector_metrics.json lacks the synthetic disclaimer")
    if not (s.get("synthetic") is True and SYNTHETIC_DISCLAIMER in s.get("statement", "")):
        synth.append("summary.json statement lacks the synthetic disclaimer")
    if SYNTHETIC_DISCLAIMER not in docs["report.md"]:
        synth.append("report.md lacks the synthetic disclaimer")
    check(
        "synthetic_labelling",
        synth,
        "metrics, summary and report state that data and labels are synthetic and the "
        "numbers do not estimate real-world performance",
    )

    hashes = {name: sha256(data) for name, data in sorted(files.items()) if name != "checks.json"}
    check(
        "evidence_hashes_recorded",
        [n for n in EVIDENCE_FILES if n != "checks.json" and n not in hashes],
        "sha256 of every other evidence file is recorded here and re-verified by validate()",
    )
    return {"passed": all(c["passed"] for c in checks), "checks": checks, "evidence_hashes": hashes}


# ---- validation -----------------------------------------------------------------------------------
@cache
def schema(name: str) -> dict[str, Any]:
    return json.loads((SCHEMAS / name).read_text(encoding="ascii"))


def schema_problems(name: str, doc: Any) -> list[str]:
    root = schema("outputs.schema.json")
    validator = Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": root["$defs"]})
    probs = [
        f"{name}: {'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message[:160]}"
        for e in validator.iter_errors(doc)
    ]
    if name == "events.json" and isinstance(doc, dict):
        ev = Draft202012Validator(schema("event.schema.json"))
        for e in doc.get("events", []):
            probs += [f"events.json/{e.get('event_id')}: {x.message[:160]}" for x in ev.iter_errors(e)][:5]
    return probs[:20]


def validate(out_dir: Path) -> list[str]:
    """Empty list means the run's outputs are valid."""
    out_dir = Path(out_dir)
    if not out_dir.is_dir():
        return [f"{out_dir} is not a directory"]
    present = sorted(p.name for p in out_dir.iterdir())
    problems = [f"missing output {n}" for n in REQUIRED_FILES if n not in present]
    problems += [f"unexpected entry {n}" for n in present if n not in REQUIRED_FILES]
    if any(p.startswith("missing") for p in problems):
        return problems
    files = {n: (out_dir / n).read_bytes() for n in REQUIRED_FILES}
    total = sum(len(b) for b in files.values())
    if total > MAX_BYTES:
        problems.append(f"outputs total {total} bytes, above {MAX_BYTES}")
    docs: dict[str, Any] = {}
    for n, blob in files.items():
        try:
            text = blob.decode("ascii")
        except UnicodeDecodeError:
            problems.append(f"{n} is not ASCII")
            continue
        if n.endswith(".md"):
            docs[n] = text
            continue
        try:
            docs[n] = json.loads(text)
        except ValueError:
            problems.append(f"{n} is not valid JSON")
            continue
        problems += schema_problems(n, docs[n])
    if problems:
        return problems
    man = docs["manifest.json"]
    if (
        not re.fullmatch(r"sha256:[0-9a-f]{64}", str(man.get("input_manifest_hash")))
        or man.get("version") != __version__
    ):
        problems.append("manifest.json input_manifest_hash or version is wrong")
    replay = docs["replay.json"]
    if replay["manifest_sha256"] != sha256(files["manifest.json"]):
        problems.append("replay.json manifest_sha256 does not match manifest.json")
    for n, h in replay["output_hashes"].items():
        if n not in files or sha256(files[n]) != h:
            problems.append(f"replay.json hash for {n} does not match the file")
    if replay["comparison"] is not None and not replay["comparison"]["identical"]:
        problems.append(
            "restarted run differs from the uninterrupted run: " + ", ".join(replay["comparison"]["differing_files"])
        )
    recorded = docs["checks.json"]
    for n, h in recorded["evidence_hashes"].items():
        if sha256(files.get(n, b"")) != h:
            problems.append(f"checks.json hash for {n} does not match the file")
    fresh = run_checks(
        {n: docs[n] for n in EVIDENCE_FILES if n != "checks.json"}, {n: files[n] for n in EVIDENCE_FILES}
    )
    problems += [
        f"check {c['check']} failed: {'; '.join(c['problems'][:3])}" for c in fresh["checks"] if not c["passed"]
    ]
    if [c["passed"] for c in recorded["checks"]] != [c["passed"] for c in fresh["checks"]] or not recorded["passed"]:
        problems.append("checks.json does not match a fresh run of the checks, or records a failure")
    return problems
