"""Focused unit tests: parsing, skew, dedup keys, quarantine, each correlation rule, checkpoints, wording."""

import importlib.util
import json
import os
import sqlite3
import tempfile

import pytest

from incidentloom import detect, fixtures, ingest, investigate, outputs, pipeline
from incidentloom.ingest import Quarantine
from incidentloom.util import BATCH_IDS, FIXTURES, MINUTE, ROOT, event_id, iso_ms

from .conftest import FULL, copy_run, load, rewrite, scratch

BASE = 1_792_000_000_000  # 2026-10-14T12:26:40Z


# ---- timestamps and skew --------------------------------------------------------------------------
def test_iso_timestamps_need_an_explicit_zone_and_valid_fields():
    assert iso_ms(ingest.parse_iso("2026-10-15T19:13:29Z")) == "2026-10-15T19:13:29.000Z"
    assert iso_ms(ingest.parse_iso("2026-10-15T21:13:29.250+02:00")) == "2026-10-15T19:13:29.250Z"
    for bad in ("2026-10-16T08:00:00", "yesterday", "2026-10-15T25:61:00Z", "2026-13-01T00:00:00Z", None, 17):
        with pytest.raises(Quarantine) as exc:
            ingest.parse_iso(bad)
        assert exc.value.reason == "invalid_timestamp"


def test_syslog_and_epoch_timestamps():
    tz = ingest.parse_offset("+02:00")
    assert iso_ms(ingest.parse_rfc3164("Oct", "14", "15:40:10", 2026, tz)) == "2026-10-14T13:40:10.000Z"
    assert ingest.parse_offset("-05:30") == -(5 * 3600 + 30 * 60)
    for args in (("Oct", "32", "25:61:00"), ("Okt", "14", "10:00:00")):
        with pytest.raises(Quarantine):
            ingest.parse_rfc3164(*args, 2026, 0)
    assert iso_ms(ingest.parse_epoch_ms("1792051200000")) == "2026-10-15T08:00:00.000Z"
    for bad in ("abc", "", "1792051200", "99999999999999"):
        with pytest.raises(Quarantine):
            ingest.parse_epoch_ms(bad)


def test_skew_correction_uses_the_declared_offset_only_when_on():
    on, off = ingest.new_state("on"), ingest.new_state("off")
    ingest.ingest_batch(on, "2026-10-14")
    ingest.ingest_batch(off, "2026-10-14")
    line = "Accepted password for oren.blackfen from 203.0.113.140"
    a = next(e for e in on["events"].values() if e["source"] == "host_auth" and e["action"] == "host.ssh.login"
             and e["outcome"] == "success" and e["actor"] == "user:oren.blackfen")
    b = off["events"][a["event_id"]]
    assert a["observed_at_raw"] == "Oct 14 15:40:10" and a["observed_at_utc"] == "2026-10-14T13:40:10.000Z"
    assert a["corrected_at_utc"] == "2026-10-14T13:33:10.000Z" and a["skew_applied_seconds"] == -420
    assert b["corrected_at_utc"] == b["observed_at_utc"] and b["skew_applied_seconds"] == 0
    assert line  # the raw line in the fixture carries the skewed local time
    idp = next(e for e in on["events"].values() if e["source"] == "idp_signin")
    assert idp["corrected_at_utc"] == idp["observed_at_utc"]
    stat = next(s for s in on["stats"] if s["source"] == "host_auth")
    assert stat["declared_clock_offset_seconds"] == 420 and stat["skew_applied_seconds"] == -420


# ---- dedup, out-of-order, quarantine --------------------------------------------------------------
def test_dedup_keys_are_stable_and_merge_both_kinds_of_duplicate():
    assert event_id("idp_signin", "idp-000001") == event_id("idp_signin", "idp-000001")
    assert event_id("idp_signin", "idp-000001") != event_id("cloud_audit", "idp-000001")
    rec = '{"id":"idp-1","delivery_id":"dlv-a","ts":"2026-10-13T00:00:00Z","event_type":"signin","user":"u","ip":"192.0.2.1","result":"success"}'
    redelivered = rec.replace("dlv-a", "dlv-b")
    assert ingest.record_event_id("idp_signin", "jsonl", rec) == ingest.record_event_id("idp_signin", "jsonl", redelivered)
    state = ingest.new_state("on")
    for batch in BATCH_IDS:
        ingest.ingest_batch(state, batch)
    dups = [d for e in state["events"].values() for d in e["duplicates"]]
    assert {d["kind"] for d in dups} == {"exact_duplicate", "redelivery"}
    cross = [d for e in state["events"].values() for d in e["duplicates"] if d["batch"] != e["batch"]]
    assert cross and all(d["kind"] == "redelivery" for d in cross)
    for s in state["stats"]:
        assert s["received"] == s["accepted"] + s["duplicates_exact"] + s["duplicates_redelivered"] + sum(
            s["quarantined"].values())
    assert sum(s["out_of_order"] for s in state["stats"]) >= 8
    late = [e for e in state["events"].values() if e["out_of_order"] and e["batch"] == "2026-10-16"
            and e["source"] == "cloud_audit"]
    assert any(e["action"] == "logging.trail.stop" for e in late)  # delivered a day late


def test_malformed_records_are_quarantined_with_reasons_and_redacted():
    state = ingest.new_state("on")
    for batch in BATCH_IDS:
        ingest.ingest_batch(state, batch)
    q = state["quarantine"]
    assert {r["reason"] for r in q} == {"parse_error", "wrong_field_count", "missing_required_field",
                                         "invalid_timestamp"} and {r["reason"] for r in q} <= set(ingest.REASONS)
    by_detail = {r["detail"] for r in q}
    assert "required field user is missing or empty" in by_detail
    assert "required field eventTime is missing or empty" in by_detail
    assert "timestamp is not ISO 8601 with an explicit UTC offset" in by_detail
    token_row = next(r for r in q if "auth_token" in r["excerpt"])
    assert "[REDACTED]" in token_row["excerpt"] and "fake0000placeholder" not in token_row["excerpt"]
    assert all(len(r["excerpt"]) <= 160 and ingest.raw_record(r["raw_ref"]) is not None for r in q)
    assert len({r["quarantine_id"] for r in q}) == len(q)


def test_unreadable_inputs_are_input_errors():
    with pytest.raises(ingest.InputError):
        ingest.load_manifest("2026-10-19")
    bad = scratch("bad-cloud.json")
    bad.write_text("{not json")
    with pytest.raises(ingest.InputError):
        ingest.read_records(bad, "json")


# ---- correlation rules: positive and negative case each -------------------------------------------
_n = [0]


def ev(minute, action, actor="user:alice", outcome="success", ip="192.0.2.21", target=None, source="idp_signin",
       session=None, details=None, parent=None, process=None, request=None):
    _n[0] += 1
    ms = BASE + int(minute * MINUTE)
    return {"event_id": f"ev-{_n[0]:016x}", "source": source, "corrected_ms": ms, "corrected_at_utc": iso_ms(ms),
            "observed_at_utc": iso_ms(ms), "skew_applied_seconds": 0, "actor": actor, "target": target,
            "action": action, "outcome": outcome, "src_ip": ip, "geo": ingest.country_of(ip), "session_id": session,
            "request_id": request, "parent_id": parent, "process_id": process, "details": details or {}}


def fails(n, step, actor="user:alice", ip="203.0.113.77", start=0.0, action="idp.signin"):
    return [ev(start + i * step, action, actor, "failure", ip) for i in range(n)]


def test_password_spray_rule():
    users = [f"user:u{i}" for i in range(5)]
    hit = [ev(i * 3, "idp.signin", u, "failure", "198.51.100.200") for i, u in enumerate(users)]
    assert [d["entity"] for d in detect.password_spray(hit)] == ["ip:198.51.100.200"]
    four = hit[:4]
    assert detect.password_spray(four) == []
    slow = [ev(i * 9, "idp.signin", u, "failure", "203.0.113.30") for i, u in enumerate(users + ["user:u5"])]
    assert detect.password_spray(slow) == []  # never 5 distinct accounts inside 30 minutes


def test_brute_force_success_rule():
    ok = [*fails(6, 1.0), ev(8, "idp.signin", ip="203.0.113.77")]
    (d,) = detect.brute_force_success(ok)
    assert d["measurements"]["failures"] == 6 and d["measurements"]["success_from_failing_address"]
    assert detect.brute_force_success([*fails(5, 1.0), ev(8, "idp.signin")]) == []
    assert detect.brute_force_success([*fails(6, 1.0), ev(5 + 16, "idp.signin")]) == []  # success too late
    host = [*fails(6, 1.0, action="host.ssh.login"), ev(7, "host.ssh.login", source="host_auth", target="host:h")]
    for e in host[:-1]:
        e["source"] = "host_auth"
    assert detect.brute_force_success(host)[0]["measurements"]["source"] == "host_auth"


def test_impossible_travel_rule():
    ca, jp, nl = "192.0.2.21", "203.0.113.80", "198.51.100.130"
    (d,) = detect.impossible_travel([ev(0, "idp.signin", ip=ca), ev(30, "idp.signin", ip=jp)])
    assert d["measurements"]["distance_km"] == 10300 and d["measurements"]["speed_kmh"] > 900
    assert detect.impossible_travel([ev(0, "idp.signin", ip=ca), ev(11 * 60, "idp.signin", ip=nl)]) == []
    assert detect.impossible_travel([ev(0, "idp.signin", ip=ca), ev(1, "idp.signin", ip="192.0.2.99")]) == []


def test_mfa_fatigue_rule():
    pushes = [ev(i * 2, "idp.mfa_push", outcome="failure", ip="198.51.100.140") for i in range(4)]
    ok = [ev(9, "idp.mfa_push", ip="198.51.100.140", session="s-1"), ev(9.2, "idp.signin", ip="198.51.100.140",
                                                                        session="s-1")]
    (d,) = detect.mfa_fatigue(pushes + ok)
    assert d["measurements"]["rejected_pushes"] == 4 and ok[1]["event_id"] in d["event_ids"]
    assert detect.mfa_fatigue(pushes[:3] + ok) == []


def test_privilege_after_anomalous_signin_rule():
    base = [*fails(6, 1.0), ev(7, "idp.signin", ip="203.0.113.77")]
    grant = ev(30, "iam.role.grant", source="cloud_audit", target="user:alice", details={"role": "admin"})
    prior = detect.brute_force_success(base)
    (d,) = detect.privilege_after_anomalous_signin(base + [grant], prior)
    assert d["severity"] == "high" and d["basis_detection_ids"] == [prior[0]["detection_id"]]
    late = ev(7 + 121, "iam.role.grant", source="cloud_audit", target="user:alice")
    assert detect.privilege_after_anomalous_signin(base + [late], prior) == []
    early = ev(6.5, "iam.accesskey.create", source="cloud_audit", target="user:alice")  # before the success
    assert detect.privilege_after_anomalous_signin(base + [early], prior) == []
    history = [ev(-600 + i, "idp.signin") for i in range(3)]
    abroad = ev(0, "idp.signin", ip="198.51.100.80")
    group = ev(15, "iam.group.add_member", source="cloud_audit", target="user:alice")
    (weak,) = detect.privilege_after_anomalous_signin(history + [abroad, group], [])
    assert weak["severity"] == "medium" and weak["measurements"]["anomaly"] == "new_country_signin"
    assert detect.privilege_after_anomalous_signin(history[:2] + [abroad, group], []) == []  # no baseline yet


def test_public_exposure_and_mass_download_rules():
    base = [*fails(6, 1.0), ev(7, "idp.signin", ip="203.0.113.77")]
    prior = detect.brute_force_success(base)
    public = ev(20, "storage.bucket.set_acl", source="cloud_audit", target="resource:bucket/b",
                details={"acl": "public-read"})
    assert len(detect.public_exposure_after_anomaly(base + [public], prior)) == 1
    assert detect.public_exposure_after_anomaly([public], []) == []
    private = ev(20, "storage.bucket.set_acl", source="cloud_audit", target="resource:bucket/b",
                 details={"acl": "private"})
    assert detect.public_exposure_after_anomaly(base + [private], prior) == []
    reads = [ev(25 + i * 0.5, "resource.read", "user:anonymous", ip="203.0.113.200", target="resource:bucket/b",
                source="resource_access", details={"bytes": 1000}) for i in range(40)]
    (d,) = detect.mass_download_after_exposure([public, *reads])
    assert d["measurements"]["reads"] == 40 and d["entity"] == "user:alice"
    assert detect.mass_download_after_exposure([public, *reads[:39]]) == []
    assert detect.mass_download_after_exposure([*reads]) == []  # nothing was exposed
    before = [dict(r, corrected_ms=r["corrected_ms"] - 60 * MINUTE) for r in reads]
    assert detect.mass_download_after_exposure([public, *before]) == []


def test_logging_disabled_rule():
    stop = ev(0, "logging.trail.stop", source="cloud_audit", target="resource:trail/t")
    assert len(detect.logging_disabled([stop])) == 1
    update = ev(0, "logging.trail.update", source="cloud_audit", target="resource:trail/t")
    assert detect.logging_disabled([update]) == []


def test_explicit_links_and_confidence_rule():
    a = ev(0, "host.ssh.login", source="host_auth", process="h:10")
    b = ev(1, "host.sudo", source="host_auth", process="h:11", parent="h:10")
    c = ev(2, "host.sudo", source="host_auth", process="h:12", parent="h:99")
    assert investigate.explicit_link(a, b) == ("parent_id", "h:10")
    assert investigate.explicit_link(a, c) is None
    assert investigate.explicit_link(ev(0, "x", session="s-1"), ev(1, "y", session="s-1")) == ("same_session", "s-1")
    high = investigate.score_confidence(2, 2, False, 0, [])
    gap = investigate.score_confidence(2, 2, False, 0, ["gap-1"])
    assert (high["confidence"], gap["confidence"], gap["confidence_before_gaps"]) == ("high", "medium", "high")
    assert investigate.score_confidence(1, 1, False, 0, ["gap-1"])["confidence"] == "low"
    assert investigate.score_confidence(2, 2, False, 2, [])["confidence"] == "medium"


# ---- checkpoints and requests ---------------------------------------------------------------------
def test_checkpoint_round_trip_and_restart_equivalence(work):
    state = ingest.new_state("on")
    for batch in BATCH_IDS[:2]:
        ingest.ingest_batch(state, batch)
    path = work / "ckpt.json"
    ingest.save_checkpoint(state, [{"after_batch": "x"}], path)
    loaded, history = ingest.load_checkpoint(path, "on")
    assert loaded == state and history == [{"after_batch": "x"}]
    assert ingest.state_digest(loaded) == ingest.state_digest(state)
    with pytest.raises(ingest.InputError):
        ingest.load_checkpoint(path, "off")
    restarted, per_a, info = pipeline.ingest_all(list(BATCH_IDS[:4]), "on", 2, work / "w")
    straight, per_b, _ = pipeline.ingest_all(list(BATCH_IDS[:4]), "on", 0, None)
    assert ingest.state_digest(restarted) == ingest.state_digest(straight) and per_a == per_b
    assert info["stopped_after_batch"] == BATCH_IDS[1] and info["reingest_of_last_batch_was_noop"]


def test_resumed_run_takes_its_history_from_the_checkpoint_file(work, monkeypatch):
    real = ingest.load_checkpoint

    def tampered(path, correction):
        state, per_batch = real(path, correction)
        return state, [{**p, "events_total": -1} for p in per_batch]

    monkeypatch.setattr(pipeline, "load_checkpoint", tampered)
    _, per_batch, _ = pipeline.ingest_all(list(BATCH_IDS[:3]), "on", 2, work / "w")
    assert [p["events_total"] for p in per_batch][:2] == [-1, -1] and per_batch[2]["events_total"] > 0


def test_request_problems():
    assert pipeline.request_problems(FULL) == []
    assert pipeline.request_problems({**FULL, "batches": ["2026-10-13", "2026-10-15"]})
    assert pipeline.request_problems({**FULL, "batches": ["2026-10-14", "2026-10-15"]})
    assert pipeline.request_problems({**FULL, "batches": ["2026-10-14", "2026-10-13"]})
    assert pipeline.request_problems({**FULL, "batches": ["2026-10-13"], "simulate_restart_after": 1})
    assert pipeline.request_problems({**FULL, "batches": list(BATCH_IDS[:2]), "simulate_restart_after": 1}) == []
    assert pipeline.request_errors({**FULL, "clock_skew_correction": "maybe"})
    assert pipeline.request_errors({**FULL, "extra": 1})


# ---- wording ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("text", ["The exposure caused the download", "this led to a grant", "it resulted in loss",
                                  "because the key was new", "Triggered by the login", "due to the spray",
                                  "in order to persist", "consequently the bucket", "causing alarm",
                                  "leads to exposure", "which gave rise to"])
def test_causal_checker_flags_causal_wording(text):
    assert outputs.causal_phrases(text)


@pytest.mark.parametrize("text", ["t03 followed t02 after 4 min 0 s", "preceded the grant", "within 5 minutes of",
                                  "resource:bucket/fh-backups", "the account was later used", "a causal link type",
                                  "results table", "leader to"])
def test_causal_checker_allows_sequence_wording(text):
    assert outputs.causal_phrases(text) == []


def test_narrative_walker_exempts_only_causal_links():
    doc = {"links": [{"link_type": "causal", "text": "the session caused this"},
                     {"link_type": "temporal", "text": "the session caused this"}],
           "details": {"note": "caused by a raw field"}, "statement": "fine"}
    hits = []
    outputs.walk_narrative(doc, "doc", hits)
    assert hits == ["doc/links/1/text: caused"]


def test_no_entity_edge_is_causal(full_run):
    events = {e["event_id"] for e in load(full_run, "events.json")["events"]}
    corr = load(full_run, "correlations.json")
    assert set(corr["link_types"]) == {"causal", "temporal", "attribution"}
    touching = [e for e in corr["edges"] if e["from"] not in events or e["to"] not in events]
    assert touching and all(e["link_type"] == "attribution" for e in touching)
    assert {e["evidence_type"] for e in touching} == {"record_field", "audit_actor_target"}
    causal = [e for e in corr["edges"] if e["link_type"] == "causal"]
    assert causal and all(e["from"] in events and e["to"] in events for e in causal)

    def mutate(kind):
        def edit(doc):
            edge = next(e for e in doc["edges"] if e["evidence_type"] == "record_field")
            if kind == "causal":
                edge["link_type"] = "causal"
            else:
                edge["to"] = "user:nobody.named"
            return doc
        return edit

    checks_order = [c["check"] for c in load(full_run, "checks.json")["checks"]]
    for kind, check in (("causal", "causal_links_verified"), ("wrong-entity", "attribution_edges_name_their_entity")):
        bad = copy_run(full_run, scratch(f"entity-edge-{kind}"))
        rewrite(bad, "correlations.json", mutate(kind))
        assert outputs.validate(bad), kind  # the schema rejects a causal entity edge; the check catches both
        docs = {n: load(bad, n) for n in outputs.EVIDENCE_FILES if n != "checks.json"}
        result = outputs.run_checks(docs, {n: (bad / n).read_bytes() for n in outputs.EVIDENCE_FILES})
        assert [c["check"] for c in result["checks"] if not c["passed"]] == sorted([check, "outputs_rederived"],
                                                                                 key=checks_order.index), kind


# ---- reproducibility, hygiene -------------------------------------------------------------------------
def test_fixture_generator_reproduces_committed_fixtures_byte_for_byte():
    out = scratch("regen-fixtures")
    fixtures.generate(out)
    committed = sorted(p.relative_to(FIXTURES) for p in FIXTURES.rglob("*") if p.is_file())
    regenerated = sorted(p.relative_to(out) for p in out.rglob("*") if p.is_file())
    assert committed == regenerated
    for rel in committed:
        assert (FIXTURES / rel).read_bytes() == (out / rel).read_bytes(), rel
    total = sum((FIXTURES / r).stat().st_size for r in committed)
    labels = json.loads((FIXTURES / "labels" / "scenarios.json").read_text())["scenarios"]
    assert total < 1_500_000 and len(labels) >= 10


def test_fixtures_use_documentation_addresses_only():
    import ipaddress
    import re

    docs = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
    text = "\n".join(p.read_text() for p in (FIXTURES / "batches").rglob("*") if p.is_file())
    v4 = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text))
    v6 = set(re.findall(r"\b2001:db8:[0-9a-f:]+\b", text))
    assert v4 and v6
    for raw in v4 | v6:
        assert any(ipaddress.ip_address(raw) in net for net in docs), raw


def _scan_targets(full_run):
    roots = [ROOT / "src" / "incidentloom", FIXTURES, ROOT / "tests" / "incidentloom", full_run]
    files = [p for r in roots for p in r.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    return files + [ROOT / "schemas" / "event.schema.json", ROOT / "schemas" / "outputs.schema.json"]


def test_secret_scan_and_ascii_over_new_files_and_outputs(full_run):
    spec = importlib.util.spec_from_file_location("secret_scan", ROOT / "scripts" / "secret_scan.py")
    scan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scan)
    findings, non_ascii = [], []
    for path in _scan_targets(full_run):
        data = path.read_bytes()
        findings += scan.scan_text(str(path), data.decode("utf-8", errors="ignore"))
        if any(b > 127 for b in data):
            non_ascii.append(str(path))
    assert findings == [] and non_ascii == []


def test_only_in_memory_sqlite_and_no_database_files(monkeypatch):
    calls = []
    real = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda db, *a, **k: (calls.append(db), real(db, *a, **k))[1])
    before = database_files()
    pipeline.run(FULL, scratch("sqlite-check"))
    assert all(db == ":memory:" for db in calls)
    assert database_files() - before == set()  # other programs' existing files are ignored; new ones fail


def database_files():
    found = set()
    for root in (ROOT, tempfile.gettempdir()):
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            dirnames[:] = [d for d in dirnames if d not in (".git", ".venv", "node_modules")]
            found.update(os.path.join(dirpath, f) for f in filenames if f.endswith((".db", ".sqlite", ".sqlite3")))
    return found


def test_summary_and_report_name_the_gaps(full_run):
    summary = load(full_run, "summary.json")
    for g in load(full_run, "gaps.json")["gaps"]:
        assert g["source"] in summary["statement"] and g["gap_id"] in load(full_run, "report.md")
    assert summary["counts"]["events"] == load(full_run, "events.json")["count"]
    assert sum(summary["incidents_by_severity"].values()) == summary["counts"]["incidents"]
