"""The seven hard release gates, one test each. Each proves the property on real output and that an
injected violation is caught."""

import builtins
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

from incidentloom import detect, evaluate, ingest, investigate, outputs, pipeline
from incidentloom.ingest import record_event_id, state_digest
from incidentloom.util import BATCH_IDS, EVENT_ID_RE, FIXTURES, ROOT, SYNTHETIC_DISCLAIMER

from .conftest import FULL, copy_run, load, rewrite, scratch

EVIDENCE_ONLY = [n for n in outputs.REQUIRED_FILES if n not in ("manifest.json", "replay.json")]
DETECTION_FILES = ["ingest.json", "events.json", "quarantine.json", "entities.json", "detections.json",
                   "incidents.json", "correlations.json", "gaps.json", "checkpoint.json"]


def all_files(out):
    return {p.name: p.read_bytes() for p in sorted(out.iterdir())}


@pytest.mark.gate
def test_gate_1_every_claim_links_to_source_events(full_run):
    assert outputs.validate(full_run) == []
    events = {e["event_id"] for e in load(full_run, "events.json")["events"]}
    valid = events | {q["quarantine_id"] for q in load(full_run, "quarantine.json")["records"]}
    claims = []
    for inc in load(full_run, "incidents.json")["incidents"]:
        claims.append(inc["event_ids"])
        claims += [t["event_ids"] for t in inc["timeline"]]
        claims += [e["event_ids"] for e in inc["entities"]]
        claims += [lk["event_ids"] for lk in inc["links"]]
        for h in inc["hypotheses"]:
            claims.append(h["supporting_event_ids"])
            assert h["alternatives"], "every hypothesis needs an alternative explanation"
            claims += [a["event_ids"] for a in h["alternatives"]]
    claims += [e["event_ids"] for e in load(full_run, "correlations.json")["edges"]]
    claims += [d["event_ids"] for d in load(full_run, "detections.json")["detections"]]
    assert len(claims) > 500
    for ids in claims:
        assert ids and set(ids) <= valid
    for name in outputs.REQUIRED_FILES:  # no id-shaped token anywhere that is not a real record of this run
        assert set(EVENT_ID_RE.findall((full_run / name).read_text())) <= valid, name

    bad = copy_run(full_run, scratch("gate1-fabricated"))

    def fabricate(doc):
        doc["incidents"][0]["hypotheses"][0]["alternatives"][0]["event_ids"].append("ev-0000000000000000")
        return doc

    rewrite(bad, "incidents.json", fabricate)
    assert any("referential_integrity" in p and "ev-0000000000000000" in p for p in outputs.validate(bad))


@pytest.mark.gate
def test_gate_2_causality_needs_explicit_evidence(full_run):
    events = {e["event_id"]: e for e in load(full_run, "events.json")["events"]}
    incidents = load(full_run, "incidents.json")["incidents"]
    inc_links = [lk for i in incidents for lk in i["links"]]
    edges = load(full_run, "correlations.json")["edges"]
    assert {lk["link_type"] for lk in inc_links} == {"causal", "temporal"}
    assert {e["link_type"] for e in edges} == {"causal", "temporal", "attribution"}
    for lk in inc_links + edges:
        if lk["link_type"] == "causal":
            assert outputs.verify_link(lk, events) is None, lk
        elif lk["link_type"] == "attribution":
            assert outputs.verify_attribution(lk, events) is None, lk
        else:
            assert outputs.SEQUENCE_RE.search(lk["text"]) and not outputs.causal_phrases(lk["text"]), lk
    for e in edges:  # causal and temporal edges only ever join two events
        if e["link_type"] != "attribution":
            assert e["from"] in events and e["to"] in events, e
    hits = []
    for name in outputs.REQUIRED_FILES:
        if name == "report.md":
            hits += outputs.causal_phrases(load(full_run, name))
        elif name != "events.json":
            outputs.walk_narrative(load(full_run, name), name, hits)
    assert hits == []
    # A bucket made public and the anonymous mass download a few minutes later share no identifier:
    # proximity alone, so the link must be temporal and worded as sequence.
    mira = next(i for i in incidents if i["primary_entity"] == "user:mira.quellon")
    entries = {t["entry_id"]: t for t in mira["timeline"]}
    expo = next(lk for lk in mira["links"] if entries[lk["from"]]["action"] == "storage.bucket.set_acl"
                and entries[lk["to"]]["action"] == "resource.read")
    assert expo["link_type"] == "temporal" and expo["evidence_type"] is None and "followed" in expo["text"]

    worded = copy_run(full_run, scratch("gate2-worded"))
    rewrite(worded, "incidents.json", lambda d: _edit_link(d, "text", "the exposure caused the download"))
    assert any("no_causal_language" in p for p in outputs.validate(worded))
    forged = copy_run(full_run, scratch("gate2-forged"))
    rewrite(forged, "incidents.json", lambda d: _edit_link(d, "forge", None))
    assert any("causal_links_verified" in p for p in outputs.validate(forged))


def _edit_link(doc, what, text):
    for inc in doc["incidents"]:
        for lk in inc["links"]:
            if lk["link_type"] == "temporal":
                if what == "text":
                    lk["text"] = text
                else:
                    lk.update(link_type="causal", evidence_type="same_session", evidence_value="s-forged00")
                return doc
    raise AssertionError("no temporal link")


@pytest.mark.gate
def test_gate_3_replay_is_deterministic(full_run):
    again = scratch("gate3-again")
    pipeline.run(FULL, again)
    assert all_files(again) == all_files(full_run)
    req = scratch("gate3-req.json")
    req.write_text(json.dumps(FULL))
    for seed, cwd in (("0", scratch("gate3-cwd-a")), ("4242", scratch("gate3-cwd-b"))):
        cwd.mkdir()
        out = cwd / "out"
        env = {**os.environ, "PYTHONHASHSEED": seed}
        proc = subprocess.run([sys.executable, "-m", "incidentloom", "run", "--request", str(req), "--out", str(out)],
                              cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stderr
        assert all_files(out) == all_files(full_run), f"PYTHONHASHSEED={seed}"


@pytest.mark.gate
def test_gate_4_restart_does_not_duplicate_events(full_run):
    base = all_files(full_run)
    events = load(full_run, "events.json")["events"]
    ids = [e["event_id"] for e in events]
    assert len(ids) == len(set(ids)) == load(full_run, "checkpoint.json")["events"]
    for n in range(1, 6):
        out = scratch(f"gate4-restart-{n}")
        pipeline.run({**FULL, "simulate_restart_after": n}, out)
        assert outputs.validate(out) == []
        got = all_files(out)
        assert {k: v for k, v in got.items() if k in EVIDENCE_ONLY} == {k: v for k, v in base.items()
                                                                         if k in EVIDENCE_ONLY}, n
        replay = load(out, "replay.json")
        assert replay["mode"] == "restart" and replay["comparison"]["identical"] is True
        assert replay["restart"]["stopped_after_batch"] == BATCH_IDS[n - 1]
        assert replay["restart"]["state_matches_checkpoint"] and replay["restart"]["reingest_of_last_batch_was_noop"]
        assert replay["output_hashes"] == load(full_run, "replay.json")["output_hashes"]
        man, man0 = load(out, "manifest.json"), load(full_run, "manifest.json")
        assert {k for k in man if man[k] != man0[k]} == {"params", "input_manifest_hash"}
        assert man["params"] == {**man0["params"], "simulate_restart_after": n}
    # Re-ingesting an already-ingested batch is a no-op, record by record.
    state = ingest.new_state("on")
    for batch in BATCH_IDS[:3]:
        ingest.ingest_batch(state, batch)
    before = state_digest(state)
    assert ingest.ingest_batch(state, BATCH_IDS[2]) is False and state_digest(state) == before


@pytest.mark.gate
def test_gate_5_metrics_use_held_out_labels_only(full_run, monkeypatch):
    src = ROOT / "src" / "incidentloom"
    for path in sorted(src.glob("*.py")):
        if path.name not in ("evaluate.py", "fixtures.py"):  # the generator writes the labels; nothing else may touch them
            text = path.read_text()
            assert "scenarios.json" not in text and "LABELS_PATH" not in text and "labels/" not in text, path.name
    for name in ("detect.py", "ingest.py", "investigate.py"):  # detection code never imports the evaluator
        assert not re.search(r"^\s*(from|import)\s+\S*evaluate", (src / name).read_text(), re.M), name

    labels = str(evaluate.LABELS_PATH)
    touched = []
    real_open, real_read_text, real_read_bytes = builtins.open, pathlib.Path.read_text, pathlib.Path.read_bytes
    monkeypatch.setattr(builtins, "open", lambda f, *a, **k: (touched.append(str(f)), real_open(f, *a, **k))[1])
    monkeypatch.setattr(pathlib.Path, "read_text", lambda s, *a, **k: (touched.append(str(s)), real_read_text(s, *a, **k))[1])
    monkeypatch.setattr(pathlib.Path, "read_bytes", lambda s: (touched.append(str(s)), real_read_bytes(s))[1])
    state = ingest.new_state("on")
    for batch in BATCH_IDS:
        ingest.ingest_batch(state, batch)
    evs = list(state["events"].values())
    dets = detect.detect(evs)
    investigate.investigate(evs, dets, investigate.find_gaps(state, evs), "on")
    assert touched and labels not in touched
    monkeypatch.undo()

    held = load(full_run, "detector_metrics.json")
    truth = json.loads(evaluate.LABELS_PATH.read_text())["scenarios"]
    assert {r["scenario_id"] for r in held["held_out"]["scenarios"]} == {k for k, v in truth.items()
                                                                         if v["split"] == "held_out"}
    assert {r["scenario_id"] for r in held["development"]["scenarios"]} == {k for k, v in truth.items()
                                                                            if v["split"] == "development"}
    assert "tuning" in held["development"]["role"] and "never used" in held["held_out"]["role"]
    assert sum(1 for v in truth.values() if v["split"] == "development") >= 4
    assert sum(1 for v in truth.values() if v["split"] == "held_out") >= 6

    altered = scratch("gate5-labels.json")
    flipped = {k: {**v, "expected": "benign" if v["expected"] == "incident" else "incident", "events": v["events"][:1]}
               for k, v in truth.items()}
    altered.write_text(json.dumps({"scenarios": flipped}))
    for label_path, status in ((altered, "loaded"), (scratch("gate5-missing.json"), "unavailable")):
        monkeypatch.setattr(evaluate, "LABELS_PATH", label_path)
        out = scratch(f"gate5-{status}")
        pipeline.run(FULL, out)
        for name in DETECTION_FILES:
            assert (out / name).read_bytes() == (full_run / name).read_bytes(), (status, name)
        metrics = load(out, "detector_metrics.json")
        assert metrics["labels_status"] == status
        assert metrics != held
        assert outputs.validate(out) == []


@pytest.mark.gate
def test_gate_6_synthetic_performance_is_labelled(full_run):
    metrics = load(full_run, "detector_metrics.json")
    assert metrics["synthetic"] is True and metrics["disclaimer"] == SYNTHETIC_DISCLAIMER
    assert "synthetic" in SYNTHETIC_DISCLAIMER.lower() and "do not estimate real-world performance" in SYNTHETIC_DISCLAIMER
    summary = load(full_run, "summary.json")
    assert summary["synthetic"] is True and SYNTHETIC_DISCLAIMER in summary["statement"]
    assert "synthetic labels" in summary["headline"]
    report = load(full_run, "report.md")
    assert SYNTHETIC_DISCLAIMER in report and "## Detector metrics (synthetic)" in report
    assert metrics["held_out"]["overall"]["precision"] is not None  # numbers exist and sit next to the label

    stripped = copy_run(full_run, scratch("gate6-stripped"))
    rewrite(stripped, "report.md", lambda text: text.replace(SYNTHETIC_DISCLAIMER, "Detector results."))
    assert any("synthetic_labelling" in p for p in outputs.validate(stripped))
    unlabelled = copy_run(full_run, scratch("gate6-unlabelled"))
    rewrite(unlabelled, "detector_metrics.json", lambda d: {**d, "disclaimer": "Detector results."})
    assert any("synthetic_labelling" in p for p in outputs.validate(unlabelled))


@pytest.mark.gate
def test_gate_7_missing_logs_produce_uncertainty(full_run):
    gaps = {g["gap_id"]: g for g in load(full_run, "gaps.json")["gaps"]}
    assert {(g["kind"], g["source"]) for g in gaps.values()} >= {("declared", "host_auth"), ("silent", "resource_access")}
    events = {e["event_id"]: e for e in load(full_run, "events.json")["events"]}
    for g in gaps.values():
        assert g["affected_entities"] and g["incident_ids"] and g["hypothesis_refs"]
        assert len(g["bounding_event_ids"]) == 2 and set(g["bounding_event_ids"]) <= set(events)
        assert g["events_inside_window"] == 0
        inside = [e for e in events.values() if e["source"] == g["source"]
                  and g["start_utc"] < e["corrected_at_utc"] < g["end_utc"]]
        assert inside == []
    dependent = []
    for inc in load(full_run, "incidents.json")["incidents"]:
        for h in inc["hypotheses"]:
            if h["depends_on_gaps"]:
                dependent.append(h)
                for gid in h["depends_on_gaps"]:
                    assert gid in gaps and gid in h["statement"] and gid in inc["gaps"]
                    assert gid in {m["gap_id"] for m in h["missing_evidence"]}
                levels = ["low", "medium", "high"]
                assert levels.index(h["confidence"]) == levels.index(h["confidence_before_gaps"]) - 1
                assert "depends on evidence gap" in h["confidence_basis"]
            else:
                assert h["confidence"] == h["confidence_before_gaps"]
    assert {g for h in dependent for g in h["depends_on_gaps"]} == set(gaps)

    # No output contains an event id that is not derivable from the raw input files.
    fmt = {"idp_signin": "jsonl", "cloud_audit": "json", "host_auth": "syslog", "resource_access": "csv"}
    derivable = set()
    for batch in BATCH_IDS:
        manifest = json.loads((FIXTURES / "batches" / batch / "batch.json").read_text())
        for src in manifest["sources"]:
            path = FIXTURES / "batches" / batch / src["file"]
            for _, raw, _ in ingest.read_records(path, src["format"]):
                eid = record_event_id(src["name"], fmt[src["name"]], raw)
                if eid:
                    derivable.add(eid)
    quarantined = {q["quarantine_id"] for q in load(full_run, "quarantine.json")["records"]}
    for name in outputs.REQUIRED_FILES:
        assert set(EVENT_ID_RE.findall((full_run / name).read_text())) <= derivable | quarantined, name

    invented = copy_run(full_run, scratch("gate7-invented"))

    def invent(doc):
        fake = dict(doc["events"][0], event_id="ev-1111111111111111")
        doc["events"].append(fake)
        doc["count"] += 1
        return doc

    rewrite(invented, "events.json", invent)
    assert any("no_fabricated_events" in p for p in outputs.validate(invented))
