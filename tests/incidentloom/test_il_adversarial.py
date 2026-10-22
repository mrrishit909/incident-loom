"""Independent adversarial review (Evidence reviewer).

Each confirmed defect is a strict xfail numbered IL-NN in severity order (blocker, major, minor): it fails today
and should pass once the defect is fixed. Every xfail names the exception it expects, so a broken crafted input
cannot pass for a confirmed defect. Tests without xfail are attacks that held ("held"); they stay as regression
guards. Crafted inputs are edited copies of the committed fixtures under tmp_path; nothing here writes into the
repository.

Status: all 23 defects (IL-01..IL-23) were fixed in the engine; their strict-xfail markers were removed and each
reason is kept as a "Fixed (was strict xfail)" comment, so every case is now a plain regression test.
"""

import json
import re
import shutil

import pytest

from incidentloom import evaluate, ingest, investigate, outputs, pipeline, util
from incidentloom.util import BATCH_IDS, HOUR, MINUTE, iso_ms, jbytes, parse_utc, sha256

from .conftest import FULL, load, rewrite

REPO = util.ROOT
DAY = 24 * HOUR
OREN_LOGIN = (
    "Oct 14 15:40:10 fh-bastion-01 sshd[7120]: Accepted password for oren.blackfen from 203.0.113.140 port 40101 ssh2"
)
SEMANTIC_FILES = ["events.json", "quarantine.json", "entities.json", "detections.json", "incidents.json",
                  "correlations.json", "gaps.json", "detector_metrics.json", "summary.json"]
EVIDENCE_ONLY = [n for n in outputs.EVIDENCE_FILES if n != "checks.json"]


# ---- helpers ----------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def base_run(tmp_path_factory):
    """One uninterrupted run over the committed fixtures, written outside the repository."""
    out = tmp_path_factory.mktemp("il-base") / "out"
    pipeline.run(FULL, out)
    return out


@pytest.fixture
def craft(tmp_path, monkeypatch):
    """craft(edit, params): copy the committed fixtures into tmp_path, apply edit(fixtures_dir), point the
    engine's path constants at the copy, run it and return the output directory."""
    runs = []

    def build(edit=None, params=FULL):
        root = (tmp_path / f"root{len(runs)}").resolve()
        shutil.copytree(REPO / "fixtures", root / "fixtures")
        if edit:
            edit(root / "fixtures")
        monkeypatch.setattr(util, "ROOT", root)
        monkeypatch.setattr(ingest, "FIXTURES", root / "fixtures")
        monkeypatch.setattr(pipeline, "FIXTURES", root / "fixtures")
        monkeypatch.setattr(evaluate, "LABELS_PATH", root / "fixtures" / "labels" / "scenarios.json")
        out = root / "out"
        runs.append(out)
        pipeline.run(params, out)
        return out

    return build


def precondition(ok, what):
    """Crafting checks raise a non-assertion error so a broken input never passes for a confirmed defect."""
    if not ok:
        raise RuntimeError(f"crafted input did not set up: {what}")


def batch_file(fx, batch, name):
    return fx / "batches" / batch / name


def append(fx, batch, name, *lines):
    path = batch_file(fx, batch, name)
    text = path.read_text(encoding="utf-8")
    path.write_text(text + ("" if text.endswith("\n") else "\n") + "".join(f"{x}\n" for x in lines), encoding="utf-8")


def edit_line(fx, batch, name, contains, old, new):
    path = batch_file(fx, batch, name)
    lines = path.read_text(encoding="utf-8").split("\n")
    hits = [i for i, x in enumerate(lines) if contains in x and old in x]
    precondition(len(hits) == 1, f"one line with {contains!r} and {old!r}")
    lines[hits[0]] = lines[hits[0]].replace(old, new)
    path.write_text("\n".join(lines), encoding="utf-8")


def edit_json(path, change):
    doc = json.loads(path.read_text(encoding="utf-8"))
    change(doc)
    path.write_text(json.dumps(doc, indent=1), encoding="utf-8")


def manifest(fx, batch, change):
    edit_json(batch_file(fx, batch, "batch.json"), change)


def add_cloud(fx, batch, *records):
    edit_json(batch_file(fx, batch, "cloud_audit.json"), lambda d: d["records"].extend(records))


def drop_source(name):
    return lambda d: d.update(sources=[s for s in d["sources"] if s["name"] != name])


def events_by_id(out):
    return {e["event_id"]: e for e in load(out, "events.json")["events"]}


def incident(out, entity):
    return next(i for i in load(out, "incidents.json")["incidents"] if i["primary_entity"] == entity)


def leaks(out, secrets):
    """[(secret, output file)] for every published output that contains a secret (small, so failures stay fast)."""
    texts = {n: (out / n).read_text(encoding="ascii") for n in outputs.REQUIRED_FILES}
    return [(s, n) for s in secrets for n, text in texts.items() if s in text]


def reseal(out):
    """Recompute checks.json and the replay output hashes exactly as render_evidence does. The stored hashes are
    unkeyed and sit next to the files, so this is what any writer of the files (or a defect upstream) produces."""
    docs = {n: load(out, n) for n in EVIDENCE_ONLY}
    files = {n: (out / n).read_bytes() for n in EVIDENCE_ONLY}
    (out / "checks.json").write_bytes(jbytes(outputs.run_checks(docs, files)))
    replay = load(out, "replay.json")
    replay["output_hashes"] = {n: sha256((out / n).read_bytes()) for n in outputs.EVIDENCE_FILES}
    (out / "replay.json").write_bytes(jbytes(replay))


def tampered(base_run, tmp_path, name, change):
    """Copy the base run, rewrite one output, reseal it and return what validate() reports."""
    bad = tmp_path / "tampered"
    shutil.copytree(base_run, bad)
    rewrite(bad, name, change)
    reseal(bad)
    return outputs.validate(bad)


def cloud_record(event_id, when, principal, operation, target, params, session=None, ip="198.51.100.140"):
    return {"eventId": event_id, "deliveryId": "dlv-" + event_id[3:], "eventTime": when,
            "actor": {"principal": principal, "type": "user", "sessionId": session, "credential": "console"},
            "operation": operation, "target": target,
            "request": {"id": "req-" + event_id[3:], "parentRequestId": None, "params": params},
            "sourceIp": ip, "outcome": "success"}


def grant_by_mira(event_id, role, grantee="mira.quellon", **params):
    return cloud_record(event_id, "2026-10-15T19:24:00Z", "mira.quellon", "iam.role.grant",
                        {"type": "user", "name": grantee}, {"role": role, **params}, session="s-e880cb40")


# ---- blockers ---------------------------------------------------------------------------------------
# Fixed (was strict xfail): IL-01: quarantine excerpts publish secrets written as JSON fields, underscore-prefixed
#   keys (api_key=, client_secret=, access_token=) or Bearer headers
def test_il01_quarantine_excerpts_mask_every_secret_form(craft):
    secrets = ["Hunter2-QX01", "AKIAQXSECRET02", "CS-QX-03", "AT-QX-04", "eyJhbGciOiJIUzI1NiJ9.QX05"]
    out = craft(lambda fx: append(
        fx, "2026-10-13", "idp_signin.jsonl",
        '{"id":"idp-990101","password":"Hunter2-QX01","ts":"2026-10-13T',
        '{"id":"idp-990102","ts":"2026-10-13T12:00:00Z","note":"api_key=AKIAQXSECRET02"}',
        '{"id":"idp-990103","note":"client_secret=CS-QX-03 access_token=AT-QX-04","ts":',
        '{"id":"idp-990104","hdr":"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.QX05","ts":',
    ))
    quarantined = [q for q in load(out, "quarantine.json")["records"] if "idp-9901" in q["excerpt"]]
    precondition(len(quarantined) == 4, "all four crafted records quarantined")
    assert leaks(out, secrets) == []


# Fixed (was strict xfail): IL-02: a placeholder session id ('-') recorded by two unrelated accounts becomes a causal
#   same_session link and pulls the other account's event into the incident
def test_il02_placeholder_ids_never_make_causal_links(craft):
    def edit(fx):
        edit_line(fx, "2026-10-13", "idp_signin.jsonl", "2026-10-13T10:09:20.000Z", '"session_id":null',
                  '"session_id":"-"')
        append(fx, "2026-10-13", "resource_access.csv",
               "rs-990201,dlv-990201,1791886800000,wren.halloway,share/fh-eng-docs/plan.txt,read,1000,192.0.2.29,-,"
               "req-990201,ok")

    out = craft(edit)
    wren = next(e["event_id"] for e in events_by_id(out).values() if e["source_record_id"] == "rs-990201")
    causal = [lk for i in load(out, "incidents.json")["incidents"] for lk in i["links"] if lk["link_type"] == "causal"]
    assert [lk["link_id"] for lk in causal if lk["evidence_value"] == "-"] == []
    assert wren not in incident(out, "user:tobin.harrowgate")["event_ids"]


# Fixed (was strict xfail): IL-03: a source missing from a batch manifest (no file delivered that day) yields no
#   evidence gap; a one-batch run then states 'No evidence gaps found.'
@pytest.mark.parametrize(("removed", "batches"), [("2026-10-15", list(BATCH_IDS)), ("2026-10-13", ["2026-10-13"])],
                         ids=["mid-run-hole", "single-batch"])
def test_il03_missing_source_day_is_an_explicit_gap(craft, removed, batches):
    out = craft(lambda fx: manifest(fx, removed, drop_source("host_auth")), {**FULL, "batches": batches})
    lo = parse_utc(f"{removed}T00:00:00Z")
    gaps = [g for g in load(out, "gaps.json")["gaps"] if g["source"] == "host_auth"
            and parse_utc(g["start_utc"]) < lo + DAY and parse_utc(g["end_utc"]) > lo]
    assert gaps, "host_auth delivered nothing for the whole day but no gap names it"


# ---- major ------------------------------------------------------------------------------------------
# Fixed (was strict xfail): IL-04: a reused pid makes an unrelated later login (another user, hours later) a causal
#   same_process link from the brute-forced SSH session
def test_il04_reused_pid_is_not_causal_evidence(craft):
    out = craft(lambda fx: append(fx, "2026-10-14", "host_auth.log", "Oct 14 19:00:00 fh-bastion-01 sshd[7120]: "
                                  "Accepted publickey for piet.morrow from 192.0.2.33 port 50001 ssh2"))
    ev = events_by_id(out)
    piet = {i for i, e in ev.items() if e["actor"] == "user:piet.morrow" and e["observed_at_raw"] == "Oct 14 19:00:00"}
    precondition(len(piet) == 1, "the reused-pid login was accepted")
    inc = incident(out, "user:oren.blackfen")
    assert [lk["link_id"] for lk in inc["links"] if lk["link_type"] == "causal" and piet & set(lk["event_ids"])] == []


# Fixed (was strict xfail): IL-05: a short declared gap inside a longer silent window suppresses the whole silent gap;
#   about 280 minutes of resource_access silence disappear
def test_il05_declared_gap_does_not_hide_surrounding_silence(craft):
    out = craft(lambda fx: manifest(fx, "2026-10-16", lambda d: d["declared_gaps"].append(
        {"source": "resource_access", "start": "2026-10-16T12:00:00Z", "end": "2026-10-16T12:10:00Z",
         "reason": "export job restarted"})))
    day = parse_utc("2026-10-16T00:00:00Z")
    covered = sum(g["duration_minutes"] for g in load(out, "gaps.json")["gaps"] if g["source"] == "resource_access"
                  and parse_utc(g["start_utc"]) < day + DAY and parse_utc(g["end_utc"]) > day)
    assert covered >= 280, f"only {covered} minutes of the 291-minute resource_access silence are reported"


# Fixed (was strict xfail): IL-06: credential-misuse hypotheses never depend on idp_signin gaps, even a gap lying
#   between the two sign-ins an impossible-travel detection cites
def test_il06_signin_hypothesis_names_identity_provider_gap(craft):
    out = craft(lambda fx: manifest(fx, "2026-10-14", lambda d: d["declared_gaps"].append(
        {"source": "idp_signin", "start": "2026-10-14T17:15:00Z", "end": "2026-10-14T17:40:00Z",
         "reason": "identity provider export lagged"})))
    gap = next(g for g in load(out, "gaps.json")["gaps"] if g["source"] == "idp_signin")
    det = next(d for d in load(out, "detections.json")["detections"]
               if d["detector"] == "impossible_travel" and d["entity"] == "user:sela.vantriss")
    precondition(det["start_utc"] < gap["start_utc"] < gap["end_utc"] < det["end_utc"], "gap between the sign-ins")
    hyp = next(h for h in incident(out, "user:sela.vantriss")["hypotheses"]
               if h["statement"].startswith("Someone other than the owner"))
    assert gap["gap_id"] in hyp["depends_on_gaps"]
    assert gap["gap_id"] in {m["gap_id"] for m in hyp["missing_evidence"]}


# Fixed (was strict xfail): IL-07: the password-spray hypothesis states 'no successful sign-in from that address
#   appears in the ingested batches' while one does (it only searched 30 minutes past the spray)
def test_il07_spray_absence_claim_matches_the_batches(craft):
    out = craft(lambda fx: append(fx, "2026-10-13", "idp_signin.jsonl", json.dumps(
        {"id": "idp-990701", "delivery_id": "dlv-990701", "ts": "2026-10-13T17:00:00.000Z", "event_type": "signin",
         "user": "wren.halloway", "ip": "198.51.100.200", "app": "mail", "result": "success", "session_id": "s-990701"})))
    wins = [e for e in events_by_id(out).values() if e["src_ip"] == "198.51.100.200" and e["outcome"] == "success"]
    precondition(len(wins) == 1, "the later success from the spray address was accepted")
    statement = incident(out, "ip:198.51.100.200")["hypotheses"][0]["statement"]
    assert "no successful sign-in from that address appears in the ingested batches" not in statement


# Fixed (was strict xfail): IL-08: a grouped timeline entry states only its first event's parameters, so a second
#   grant of org-owner reads as role=storage-admin
def test_il08_grouped_timeline_entry_names_every_parameter(craft):
    out = craft(lambda fx: add_cloud(fx, "2026-10-15", grant_by_mira("ca-990801", "org-owner")))
    ev = events_by_id(out)
    entries = [t for t in incident(out, "user:mira.quellon")["timeline"] if t["action"] == "iam.role.grant"]
    precondition("org-owner" in {ev[i]["details"]["role"] for t in entries for i in t["event_ids"]}, "grant ingested")
    for t in entries:
        roles = {ev[i]["details"]["role"] for i in t["event_ids"]}
        assert all(f"role={r}" in t["text"] for r in roles), (t["text"], roles)


# Fixed (was strict xfail): IL-09: brute-force summary says the failures were on the host of the later success
#   (host:fh-db-01) when all of them were on host:fh-web-01
def test_il09_brute_force_summary_names_the_failing_host(craft):
    fails = [f"Oct 16 10:0{m}:00 fh-web-01 sshd[{9000 + m}]: Failed password for lena.marsh from 203.0.113.150 port "
             f"{41000 + m} ssh2" for m in range(7)]
    ok = "Oct 16 10:09:00 fh-db-01 sshd[9100]: Accepted password for lena.marsh from 203.0.113.150 port 41100 ssh2"
    out = craft(lambda fx: append(fx, "2026-10-16", "host_auth.log", *fails, ok))
    ev = events_by_id(out)
    for d in load(out, "detections.json")["detections"]:
        if d["detector"] == "brute_force_success" and d["entity"] == "user:lena.marsh":
            hosts = {ev[i]["target"] for i in d["event_ids"] if ev[i]["outcome"] == "failure"}
            assert all(h in d["summary"] for h in hosts), (d["summary"], hosts)


# Fixed (was strict xfail): IL-10: validate() accepts an event whose outcome, time and app no longer match its raw
#   record; no_fabricated_events only re-derives the id
def test_il10_validator_rederives_event_content(base_run, tmp_path):
    def falsify(doc):
        e = next(x for x in doc["events"] if x["source_record_id"] == "idp-000010")
        e.update(outcome="failure", observed_at_utc="2026-10-13T03:00:00.000Z",
                 corrected_at_utc="2026-10-13T03:00:00.000Z")
        e["details"]["app"] = "vpn"
        return doc

    assert tampered(base_run, tmp_path, "events.json", falsify) != []


def _claim_text(doc, events):
    t = doc["incidents"][0]["timeline"][0]
    t["text"] = t["text"].replace("9 failed", "2 successful").replace("user:tobin.harrowgate", "user:mira.quellon")
    return doc


def _detection_members(doc, events):
    doc["detections"][0]["event_ids"] = [events[0]["event_id"], events[1]["event_id"]]  # midnight, unrelated
    return doc


def _held_out_precision(doc, events):
    doc["held_out"]["overall"]["precision"] = 1.0
    return doc


def _summary_counts(doc, events):
    doc["counts"]["events"] = 1400
    doc["headline"] = doc["headline"].replace("1502", "1400")
    return doc


# Fixed (was strict xfail): IL-11: validate() never re-derives claims from their cited events or rows: false timeline
#   text, a detection citing unrelated events, held-out precision 1.0 (tp 4, fp 1) and a false summary count all pass
@pytest.mark.parametrize(("name", "change"), [
    ("incidents.json", _claim_text), ("detections.json", _detection_members),
    ("detector_metrics.json", _held_out_precision), ("summary.json", _summary_counts),
], ids=["timeline-text", "detection-members", "held-out-precision", "summary-counts"])
def test_il11_validator_rederives_claims(base_run, tmp_path, name, change):
    events = load(base_run, "events.json")["events"]
    assert tampered(base_run, tmp_path, name, lambda doc: change(doc, events)) != []


# Fixed (was strict xfail): IL-12: gaps_lower_confidence only audits the dependencies a hypothesis declares; deleting
#   them (and restoring confidence) passes validate()
def test_il12_validator_recomputes_gap_dependencies(base_run, tmp_path):
    def forget(doc):
        for inc in doc["incidents"]:
            for h in inc["hypotheses"]:
                if h["depends_on_gaps"]:
                    h.update(depends_on_gaps=[], missing_evidence=[], confidence=h["confidence_before_gaps"],
                             statement=h["statement"].split(" This reading depends")[0],
                             confidence_basis=h["confidence_basis"].split("; lowered one level: depends")[0])
        return doc

    assert tampered(base_run, tmp_path, "incidents.json", forget) != []


CLOUD = {"eventId": "ca-990301", "deliveryId": "dlv-990301", "eventTime": "2026-10-13T05:00:00Z",
         "actor": {"principal": "piet.morrow", "type": "user"}, "operation": "compute.instance.resize",
         "target": {"type": "instance", "name": "fh-db-01"}, "sourceIp": "192.0.2.33", "outcome": "success"}


def _crash(marker, exc, edit, why):
    # Fixed (was strict xfail): IL-13, a malformed record aborted the whole run (`why`, raising `exc`) instead of
    # being quarantined.
    return pytest.param(marker, edit, id=marker)


@pytest.mark.parametrize(("marker", "edit"), [
    _crash("ca-990301", AttributeError, lambda fx: add_cloud(fx, "2026-10-13", {**CLOUD, "request": "req-1"}),
           "cloud request is a string"),
    _crash("ca-990302", TypeError, lambda fx: add_cloud(
        fx, "2026-10-13", {**CLOUD, "eventId": "ca-990302", "request": {"id": "r", "params": ["size", "m2"]}}),
        "cloud request params is a list"),
    _crash("ca-990303", TypeError, lambda fx: add_cloud(
        fx, "2026-10-13", {**CLOUD, "eventId": "ca-990303", "target": {"type": ["instance"], "name": "fh-db-01"}}),
        "cloud target type is a list"),
    _crash("rs-990304", ValueError, lambda fx: append(
        fx, "2026-10-13", "resource_access.csv",
        "rs-990304,dlv-990304,1791851261000,mira.quellon,share/fh-eng-docs/x.txt,read,\u00b2,192.0.2.21,,,ok"),
        "CSV bytes is a superscript digit that passes isdigit"),
    _crash("dlv-990305", UnicodeEncodeError, lambda fx: append(
        fx, "2026-10-13", "idp_signin.jsonl",
        '{"id":"\\ud800","delivery_id":"dlv-990305","ts":"2026-10-13T05:00:00Z","event_type":"signin",'
        '"user":"piet.morrow","ip":"192.0.2.33","app":"wiki","result":"success"}'),
        "identity record id is a lone surrogate"),
    _crash("idp-990306", TypeError, lambda fx: append(
        fx, "2026-10-13", "idp_signin.jsonl",
        '{"id":"idp-990306","delivery_id":"dlv-990306","ts":"2026-10-13T10:05:10.000Z","event_type":"signin",'
        '"user":"tobin.harrowgate","ip":"203.0.113.77","app":"mail","result":"failure","session_id":{"sid":"s-1"}}'),
        "session_id is an object"),
])
def test_il13_malformed_record_is_quarantined_not_fatal(craft, marker, edit):
    out = craft(edit)  # the run must finish and account for the record (quarantined, or accepted as data)
    assert marker in (out / "quarantine.json").read_text() + (out / "events.json").read_text()


# Fixed (was strict xfail): IL-14: any non-ASCII character in a record that reaches an incident (here an exe path)
#   crashes report.md rendering, which encodes as ASCII
def test_il14_non_ascii_record_does_not_crash_the_report(craft):
    out = craft(lambda fx: append(fx, "2026-10-14", "host_auth.log",
                                  "Oct 14 15:43:00 fh-bastion-01 proc[7150]: exec user=oren.blackfen ppid=7120 "
                                  "exe=/tmp/na\u00efve"))
    assert outputs.validate(out) == []


# Fixed (was strict xfail): IL-15: a record dated four days after its batch's coverage is accepted with no flag or
#   quarantine, and it lifts the high-water mark so 229 on-time records are flagged out_of_order
def test_il15_record_outside_batch_coverage_is_flagged(craft):
    out = craft(lambda fx: append(fx, "2026-10-13", "idp_signin.jsonl", json.dumps(
        {"id": "idp-990150", "delivery_id": "dlv-990150", "ts": "2026-10-17T12:00:00.000Z", "event_type": "signin",
         "user": "piet.morrow", "ip": "192.0.2.33", "app": "wiki", "result": "success", "session_id": "s-990150"})))
    quarantined = any("idp-990150" in q["excerpt"] for q in load(out, "quarantine.json")["records"])
    future = [e for e in events_by_id(out).values() if e["source_record_id"] == "idp-990150"]
    assert quarantined or future[0]["out_of_order"]


# Fixed (was strict xfail): IL-16: secrets in accepted records (a sudo command line password) are published verbatim
#   in events.json, incidents.json and report.md; redaction covers quarantine excerpts only (the scope SECURITY.md
#   states)
def test_il16_accepted_record_secrets_are_not_published(craft):
    out = craft(lambda fx: append(fx, "2026-10-14", "host_auth.log",
                                  "Oct 14 15:43:30 fh-bastion-01 sudo[7155]: oren.blackfen : PPID=7120 ; USER=root ; "
                                  "COMMAND=/usr/bin/mysql --password=Hunter2Secret -e select"))
    precondition(any(e["details"].get("cmd", "").startswith("/usr/bin/mysql") for e in events_by_id(out).values()),
                 "sudo line accepted")
    assert leaks(out, ["Hunter2Secret"]) == []


# ---- minor ------------------------------------------------------------------------------------------
def _synonyms(doc):
    for inc in doc["incidents"]:
        for lk in inc["links"]:
            if lk["link_type"] == "temporal":
                lk["text"] = (f"{lk['to']} followed {lk['from']} as a direct consequence of it; the exposure enabled "
                              "the download, hence the exfiltration")
                return doc
    raise RuntimeError("no temporal link")


def _link_types(doc):
    doc["link_types"]["temporal"] = "event to event: the earlier event caused the later one"
    return doc


# Fixed (was strict xfail): IL-17: the causal-language check misses synonyms (consequence, enabled, hence) and never
#   scans strings under keys outside NARRATIVE_KEYS
@pytest.mark.parametrize(("name", "change"), [("incidents.json", _synonyms), ("correlations.json", _link_types)],
                         ids=["synonyms-in-temporal-link", "causal-claim-in-link-types"])
def test_il17_causal_language_check_has_no_bypass(base_run, tmp_path, name, change):
    assert tampered(base_run, tmp_path, name, change) != []


# Fixed (was strict xfail): IL-18: simulate_restart_after 3.0 passes the schema as an integer and skips the restart
#   bound (isinstance int); one batch runs uninterrupted while the replay record claims a restart setting of 3
def test_il18_float_restart_after_is_rejected():
    assert pipeline.request_errors({**FULL, "batches": ["2026-10-13"], "simulate_restart_after": 3.0}) != []


# Fixed (was strict xfail): IL-19: a host line re-delivered with trailing whitespace gets a new event id (the raw line
#   is the key), so one login is counted twice
def test_il19_whitespace_redelivery_of_host_line_merges(base_run, craft):
    out = craft(lambda fx: append(fx, "2026-10-15", "host_auth.log", OREN_LOGIN + " "))
    got, base = load(out, "summary.json")["counts"], load(base_run, "summary.json")["counts"]
    precondition(got["records_received"] == base["records_received"] + 1, "re-delivery received")
    assert got["events"] == base["events"]


# Fixed (was strict xfail): IL-20: the SSH-session hypothesis counts same-process lines (a logout) as 'command or
#   process events that record its process as their parent'
def test_il20_ssh_session_command_count_matches_parent_ids(craft):
    out = craft(lambda fx: append(fx, "2026-10-14", "host_auth.log",
                                  "Oct 14 18:30:00 fh-bastion-01 sshd[7120]: session closed for user oren.blackfen"))
    ev = events_by_id(out)
    hyp = next(h for h in incident(out, "user:oren.blackfen")["hypotheses"]
               if h["statement"].startswith("The SSH session obtained"))
    m = re.search(r"\((\d+) command or process events record its process (\S+) as their parent\)", hyp["statement"])
    assert m is None or int(m[1]) == sum(1 for i in hyp["supporting_event_ids"] if ev[i]["parent_id"] == m[2])


# Fixed (was strict xfail): IL-21: raw field values are spliced unescaped into narrative text: a newline in a ticket
#   injects a markdown heading into report.md, and a ticket containing 'because' fails the run's own causal-language
#   check
@pytest.mark.parametrize("ticket", ["CHG-7\n## Incident closed: benign", "CHG-7 because of an outage"],
                         ids=["markdown-injection", "data-trips-causal-check"])
def test_il21_payload_strings_stay_data(craft, ticket):
    out = craft(lambda fx: add_cloud(fx, "2026-10-15", grant_by_mira("ca-990210", "reader", "svc-reports",
                                                                     ticket=ticket)))
    assert not any(line.startswith("## Incident closed") for line in load(out, "report.md").split("\n"))
    assert load(out, "checks.json")["passed"] is True


# Fixed (was strict xfail): IL-22: confidence basis says the successful sign-in came from an address 'not seen for
#   this account earlier' although the account's nine failed sign-ins it cites came from that address (committed
#   fixtures)
def test_il22_new_address_factor_matches_earlier_events(base_run):
    ev = load(base_run, "events.json")["events"]
    for inc in load(base_run, "incidents.json")["incidents"]:
        for h in inc["hypotheses"]:
            m = re.search(r"came from ip:(\S+), not seen for this account earlier", h["confidence_basis"])
            if not m:
                continue
            ok = max((e for e in ev if e["event_id"] in h["supporting_event_ids"] and e["src_ip"] == m[1]
                      and e["action"] in ("idp.signin", "host.ssh.login") and e["outcome"] == "success"),
                     key=lambda e: e["corrected_at_utc"])
            earlier = [e for e in ev if e["actor"] == inc["primary_entity"] and e["src_ip"] == m[1]
                       and e["corrected_at_utc"] < ok["corrected_at_utc"]]
            assert earlier == [], (inc["incident_id"], m[1], len(earlier))


# Fixed (was strict xfail): IL-23: a record reusing an existing record id with different content (user, outcome, time)
#   is silently filed as a redelivery; disclosed in the README limitations, but nothing in the outputs records the
#   conflict
def test_il23_conflicting_record_with_same_id_is_not_silently_dropped(craft):
    out = craft(lambda fx: append(fx, "2026-10-14", "idp_signin.jsonl", json.dumps(
        {"id": "idp-000010", "delivery_id": "dlv-992301", "ts": "2026-10-14T09:00:00.000Z", "event_type": "signin",
         "user": "wren.halloway", "ip": "192.0.2.29", "app": "wiki", "result": "failure", "session_id": None})))
    kept = any(e["actor"] == "user:wren.halloway" and e["corrected_at_utc"] == "2026-10-14T09:00:00.000Z"
               for e in events_by_id(out).values())
    quarantined = any("dlv-992301" in q["excerpt"] for q in load(out, "quarantine.json")["records"])
    assert kept or quarantined


# ---- held: attacks that did not break a guarantee (regression guards) ----------------------------------
def test_held_reseal_helper_is_faithful(base_run, tmp_path):
    clean = tmp_path / "clean"
    shutil.copytree(base_run, clean)
    reseal(clean)
    assert all((clean / n).read_bytes() == (base_run / n).read_bytes() for n in outputs.REQUIRED_FILES)
    assert outputs.validate(clean) == []

    def fabricate(doc):
        doc["incidents"][0]["hypotheses"][0]["alternatives"][0]["event_ids"].append("ev-0000000000000000")
        return doc

    assert any("referential_integrity" in p for p in tampered(base_run, tmp_path, "incidents.json", fabricate))


def test_held_relocated_fixture_copy_is_byte_identical(base_run, craft):
    out = craft()
    assert {n: (out / n).read_bytes() for n in outputs.REQUIRED_FILES} == {
        n: (base_run / n).read_bytes() for n in outputs.REQUIRED_FILES}
    assert outputs.validate(out) == []


def test_held_manifest_source_order_does_not_change_evidence(base_run, craft):
    def reverse(fx):
        for b in BATCH_IDS:
            manifest(fx, b, lambda d: d["sources"].reverse())

    out = craft(reverse)
    for n in SEMANTIC_FILES:
        assert (out / n).read_bytes() == (base_run / n).read_bytes(), n


def test_held_restart_with_crafted_duplicate_and_quarantine(craft):
    def edit(fx):
        append(fx, "2026-10-14", "host_auth.log", "Oct 13 02:35:11 fh-bastion-01 sshd[28795]: Accepted publickey for "
               "piet.morrow from 192.0.2.33 port 58921 ssh2")
        append(fx, "2026-10-15", "idp_signin.jsonl", '{"id": "idp-994001", "ts": ')

    params = {"batches": list(BATCH_IDS[:3]), "clock_skew_correction": "off", "simulate_restart_after": 0}
    straight = craft(edit, params)
    for n in (1, 2):
        out = craft(edit, {**params, "simulate_restart_after": n})
        assert outputs.validate(out) == []
        assert load(out, "replay.json")["comparison"]["identical"] is True
        for name in EVIDENCE_ONLY:
            assert (out / name).read_bytes() == (straight / name).read_bytes(), (n, name)
    counts = load(straight, "summary.json")["counts"]
    precondition(counts["quarantined"] >= 1, "crafted quarantine")
    ev = events_by_id(straight)
    assert [d["kind"] for e in ev.values() for d in e["duplicates"] if d["batch"] == "2026-10-14"
            and e["observed_at_raw"] == "Oct 13 02:35:11"] == ["exact_duplicate"]


def test_held_skew_applied_once_and_off_keeps_raw(base_run, tmp_path):
    offsets = {(s["batch"], s["source"]): s["declared_clock_offset_seconds"]
               for b in load(base_run, "ingest.json")["batches"] for s in b["sources"]}
    assert set(offsets.values()) == {0, 420}
    on = load(base_run, "events.json")["events"]
    for e in on:
        shift = parse_utc(e["corrected_at_utc"]) - parse_utc(e["observed_at_utc"])
        assert shift == -1000 * offsets[(e["batch"], e["source"])] == 1000 * e["skew_applied_seconds"], e["event_id"]
    out = tmp_path / "off"
    pipeline.run({**FULL, "clock_skew_correction": "off"}, out)
    off = load(out, "events.json")["events"]
    assert {e["event_id"] for e in off} == {e["event_id"] for e in on}
    assert all(e["corrected_at_utc"] == e["observed_at_utc"] and e["skew_applied_seconds"] == 0 for e in off)


def test_held_explicit_zones_and_midnight_normalize(craft):
    def rec(rid, ts):
        return json.dumps({"id": rid, "delivery_id": "dlv-" + rid[4:], "ts": ts, "event_type": "signin",
                           "user": "piet.morrow", "ip": "192.0.2.33", "app": "wiki", "result": "success",
                           "session_id": "s-" + rid[4:]})

    def edit(fx):
        append(fx, "2026-10-13", "idp_signin.jsonl", rec("idp-990601", "2026-10-13T17:30:00.250+05:30"),
               rec("idp-990602", "2026-10-13T08:01:00-04:00"), rec("idp-990603", "2026-10-14T01:30:00+02:00"),
               rec("idp-990604", "2026-10-13T12:00:00"), rec("idp-990605", "2026-10-13T23:59:60Z"),
               rec("idp-990606", "2026-10-13T12:00:00.1234567Z"))
        append(fx, "2026-10-13", "host_auth.log", "Oct 14 01:00:30 fh-db-01 sshd[990]: session closed for user "
               "piet.morrow")

    out = craft(edit)
    events = load(out, "events.json")["events"]
    ev = {e["source_record_id"]: e for e in events if e["source_record_id"]}
    assert ev["idp-990601"]["corrected_at_utc"] == "2026-10-13T12:00:00.250Z"
    assert ev["idp-990602"]["corrected_at_utc"] == "2026-10-13T12:01:00.000Z"
    assert ev["idp-990603"]["corrected_at_utc"] == "2026-10-13T23:30:00.000Z"
    host = next(e for e in events if e["observed_at_raw"] == "Oct 14 01:00:30" and e["target"] == "host:fh-db-01")
    assert (host["observed_at_utc"], host["corrected_at_utc"], host["batch"]) == (
        "2026-10-13T23:00:30.000Z", "2026-10-13T22:53:30.000Z", "2026-10-13")
    reasons = {m[1]: q["reason"] for q in load(out, "quarantine.json")["records"]
               if (m := re.search(r'"id": "(idp-99060\d)"', q["excerpt"]))}
    assert reasons == {f"idp-99060{n}": "invalid_timestamp" for n in (4, 5, 6)}


def test_held_key_value_secrets_are_redacted(base_run, craft):
    assert leaks(base_run, ["fake0000placeholder0000"]) == []
    secrets = ["Tk1SECRETvalue", "Pw2SECRETvalue", "Sc3SECRETvalue", "Ak4SECRETvalue"]
    out = craft(lambda fx: append(fx, "2026-10-13", "host_auth.log",
                                  "garbage record token=Tk1SECRETvalue password=Pw2SECRETvalue",
                                  "partial write secret=Sc3SECRETvalue; X-Api-Key=Ak4SECRETvalue \x07" + "x" * 300))
    records = [q for q in load(out, "quarantine.json")["records"] if q["excerpt"].startswith(("garbage", "partial"))]
    precondition(len(records) == 2, "both lines quarantined")
    assert all(len(q["excerpt"]) <= 160 and q["excerpt"].isprintable() and "[REDACTED]" in q["excerpt"]
               for q in records)
    assert leaks(out, secrets) == []


def test_held_quarantine_never_drops_a_record_from_accounting(base_run, craft):
    def edit(fx):
        append(fx, "2026-10-14", "idp_signin.jsonl", "   ", '{"id": ')
        append(fx, "2026-10-14", "resource_access.csv", "rs-994101,dlv-994101,1791930000000,a,b,read,1,ip,s,r,ok,x")
        append(fx, "2026-10-14", "host_auth.log", OREN_LOGIN)

    out = craft(edit)
    ingest_doc = load(out, "ingest.json")
    for b in ingest_doc["batches"]:
        for s in b["sources"]:
            assert s["received"] == (s["accepted"] + s["duplicates_exact"] + s["duplicates_redelivered"]
                                     + sum(s["quarantined"].values())), (s["batch"], s["source"])
    got, base = load(out, "summary.json")["counts"], load(base_run, "summary.json")["counts"]
    assert got["records_received"] - base["records_received"] == 4
    assert (got["quarantined"] - base["quarantined"], got["duplicates_exact"] - base["duplicates_exact"]) == (3, 1)
    assert got["events"] == base["events"]
    assert outputs.validate(out) == []


def test_held_redeliveries_merge_by_record_id(base_run, craft):
    tobin = {"id": "idp-000010", "delivery_id": "dlv-793fd3f1", "ts": "2026-10-13T10:11:05.000Z",
             "event_type": "signin", "user": "tobin.harrowgate", "ip": "203.0.113.77", "app": "mail",
             "result": "success", "failure_reason": None, "mfa": "not_enrolled", "session_id": "s-f49304e1",
             "user_agent": "FernhollowAgent/3.2"}

    def edit(fx):
        append(fx, "2026-10-14", "idp_signin.jsonl",
               json.dumps(dict(reversed(list(tobin.items()))), separators=(" , ", " : ")))
        source = json.loads(batch_file(fx, "2026-10-15", "cloud_audit.json").read_text(encoding="utf-8"))
        key = next(r for r in source["records"] if isinstance(r, dict) and r.get("eventId") == "ca-000010")
        add_cloud(fx, "2026-10-16", {**key, "deliveryId": "dlv-994201"})
        append(fx, "2026-10-15", "host_auth.log", OREN_LOGIN)

    out = craft(edit)
    got, base = load(out, "summary.json")["counts"], load(base_run, "summary.json")["counts"]
    assert got["events"] == base["events"]
    assert got["duplicates_exact"] - base["duplicates_exact"] == 2
    assert got["duplicates_redelivered"] - base["duplicates_redelivered"] == 1
    kinds = {(d["batch"], d["kind"]) for e in events_by_id(out).values() for d in e["duplicates"]
             if e["source_record_id"] in ("idp-000010", "ca-000010") or e["observed_at_raw"] == "Oct 14 15:40:10"}
    assert {("2026-10-14", "exact_duplicate"), ("2026-10-16", "redelivery"), ("2026-10-15", "exact_duplicate")} <= kinds
    assert outputs.validate(out) == []  # every duplicate delivery re-derives its event id from its raw record


def test_held_silence_threshold_and_empty_source_file(craft):
    def gaps_for(silence_ms):
        times = [0, HOUR, HOUR + silence_ms, 2 * HOUR + silence_ms]
        state = {"declared_gaps": [], "coverage": [
            {"batch": "2026-10-13", "source": "s", "start": iso_ms(times[0]), "end": iso_ms(times[-1])}]}
        evs = [{"source": "s", "corrected_ms": t, "event_id": f"ev-{n:016x}", "actor": "user:a", "target": None}
               for n, t in enumerate(times)]
        return investigate.find_gaps(state, evs)

    assert gaps_for(120 * MINUTE) == []
    assert [g["duration_minutes"] for g in gaps_for(120 * MINUTE + 1)] == [120]

    out = craft(lambda fx: batch_file(fx, "2026-10-16", "host_auth.log").write_text("", encoding="utf-8"))
    day = parse_utc("2026-10-16T00:00:00Z")
    assert any(g["source"] == "host_auth" and g["kind"] == "silent" and parse_utc(g["start_utc"]) <= day
               and parse_utc(g["end_utc"]) >= day + DAY for g in load(out, "gaps.json")["gaps"])


BAD_REQUESTS = [
    {**FULL, "batches": ["../2026-10-13"]},
    {**FULL, "batches": ["2026-10-13/../../../etc"]},
    {**FULL, "batches": ["2026-10-13; rm -rf /"]},
    {**FULL, "batches": ["2026-10-19"]},
    {**FULL, "batches": ["2026-10-13", "2026-10-15"]},
    {**FULL, "batches": ["2026-10-14"]},
    {**FULL, "batches": ["2026-10-13", "2026-10-13"]},
    {**FULL, "batches": []},
    {**FULL, "simulate_restart_after": True},
    {**FULL, "simulate_restart_after": -1},
    {**FULL, "simulate_restart_after": 6},
    {**FULL, "batches": ["2026-10-13"], "simulate_restart_after": 1},
    {**FULL, "clock_skew_correction": "ON"},
    {**FULL, "extra": "x"},
    {k: v for k, v in FULL.items() if k != "batches"},
    ["2026-10-13"],
]


def test_held_request_validation_rejects_bad_requests(tmp_path):
    for n, params in enumerate(BAD_REQUESTS):
        assert pipeline.request_errors(params), params
        out = tmp_path / f"out{n}"
        with pytest.raises(pipeline.InputError):
            pipeline.run(params, out)
        assert not out.exists(), params


def test_held_committed_causal_links_join_one_actor(base_run):
    ev = events_by_id(base_run)
    links = [lk for i in load(base_run, "incidents.json")["incidents"] for lk in i["links"]]
    links += load(base_run, "correlations.json")["edges"]
    causal = [lk for lk in links if lk["link_type"] == "causal"]
    assert len(causal) > 20
    for lk in causal:
        a, b = (ev[i] for i in lk["event_ids"])
        assert a["actor"] == b["actor"] and a["event_id"] != b["event_id"], lk
        assert outputs.verify_link(lk, ev) is None and len(lk["evidence_value"]) >= 8, lk


def test_held_metric_arithmetic_and_held_out_headline(base_run):
    m = load(base_run, "detector_metrics.json")
    for split in ("held_out", "development"):
        rows, o = m[split]["scenarios"], m[split]["overall"]
        counts = {k: sum(1 for r in rows if r["outcome"] == k) for k in ("tp", "fp", "fn", "tn")}
        assert {k: o[k] for k in counts} == counts
        assert o["precision"] == round(counts["tp"] / (counts["tp"] + counts["fp"]), 4)
        assert o["recall"] == round(counts["tp"] / (counts["tp"] + counts["fn"]), 4)
        for p in m[split]["per_detector"]:
            touched = [r for r in rows if p["detector"] in r["detected_by"]]
            assert p["tp"] + p["fp"] == len(touched)
    assert load(base_run, "summary.json")["held_out_metrics"] == m["held_out"]["overall"]
