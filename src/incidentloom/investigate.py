"""Investigation: evidence gaps, incidents (timeline, links, hypotheses, alternatives), correlation graph, entities.

Every factual statement carries event ids. Links between timeline entries are `causal` only when an
explicit identifier joins them (same session, request or process id, or a recorded parent id);
everything else is `temporal` and worded as sequence.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .detect import ANOMALOUS_SIGNIN, PRIVILEGE_ACTIONS, hm, is_exposure
from .util import HOUR, MINUTE, data, iso_ms, parse_utc, short_hash

SILENCE_MINUTES = 120
LEVELS = ["low", "medium", "high"]
SEV = ["low", "medium", "high", "critical"]
GROUP_WINDOW = 24 * HOUR
CONTEXT_WINDOW = 6 * HOUR
SESSION_WINDOW = 24 * HOUR  # a shared session or request id links events at most this far apart
PROCESS_WINDOW = 8 * HOUR  # a shared or parent process id links events at most this far apart (pids get reused)
MIN_PIECE_MINUTES = 5
PLACEHOLDER_IDS = {
    "",
    "-",
    "--",
    "0",
    "null",
    "none",
    "nil",
    "n/a",
    "na",
    "unknown",
    "undefined",
    "unset",
    "default",
    "?",
    "empty",
    "missing",
}
ID_FIELDS = ("session_id", "request_id", "process_id", "parent_id")
LABELS = {
    "password_spray": "password spray",
    "brute_force_success": "repeated failed sign-ins then a success",
    "impossible_travel": "impossible travel",
    "mfa_fatigue": "MFA push fatigue",
    "privilege_after_anomalous_signin": "privilege change after an anomalous sign-in",
    "public_exposure_after_anomaly": "public exposure",
    "mass_download_after_exposure": "mass download",
    "logging_disabled": "audit logging stopped",
}


# ---- explicit (causal) evidence -------------------------------------------------------------------
def usable_id(value: Any) -> bool:
    """False for placeholder ids ('-', '0', 'null', 'n/a', 'unknown', ...), including a placeholder pid in host:pid."""
    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    tail = text.rsplit(":", 1)[-1]
    return not (text in PLACEHOLDER_IDS or tail in PLACEHOLDER_IDS or re.fullmatch(r"[-_.?*0 ]*", tail))


def when(e: dict[str, Any]) -> int:
    """Corrected time in ms; published events carry only the ISO string."""
    return e["corrected_ms"] if "corrected_ms" in e else parse_utc(e["corrected_at_utc"])


def explicit_link(a: dict[str, Any], b: dict[str, Any]) -> tuple[str, str] | None:
    """The explicit identifier joining earlier event a to later event b, if any. Both events must name the same
    actor, the id must not be a placeholder, and the two must fall inside the window for that kind of id."""
    if not a["actor"] or a["actor"] != b["actor"] or a["event_id"] == b["event_id"]:
        return None
    apart = abs(when(b) - when(a))
    for field, kind, window in (
        ("session_id", "same_session", SESSION_WINDOW),
        ("request_id", "same_request", SESSION_WINDOW),
        ("process_id", "same_process", PROCESS_WINDOW),
    ):
        if usable_id(a[field]) and a[field] == b[field] and apart <= window:
            return kind, a[field]
    if usable_id(b["parent_id"]) and b["parent_id"] in (a["process_id"], a["request_id"]) and apart <= PROCESS_WINDOW:
        return "parent_id", b["parent_id"]
    return None


def linked(x: dict[str, Any], y: dict[str, Any]) -> bool:
    a, b = sorted((x, y), key=lambda e: (when(e), e["event_id"]))
    return explicit_link(a, b) is not None


def first_link(xs: list[dict[str, Any]], ys: list[dict[str, Any]]) -> tuple[dict, dict, tuple[str, str]] | None:
    for a in xs:
        for b in ys:
            hit = explicit_link(a, b)
            if hit:
                return a, b, hit
    return None


# ---- gaps -----------------------------------------------------------------------------------------
def merge(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1]:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(lo, hi) for lo, hi in out]


def subtract(span: tuple[int, int], holes: list[tuple[int, int]]) -> list[tuple[int, int]]:
    pieces, cur = [], span[0]
    for lo, hi in merge(holes):
        if hi <= cur or lo >= span[1]:
            continue
        if lo > cur:
            pieces.append((cur, lo))
        cur = max(cur, hi)
    if cur < span[1]:
        pieces.append((cur, span[1]))
    return pieces


def find_gaps(
    state: dict[str, Any], events: list[dict[str, Any]], known_sources: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    """Evidence gaps: declared in a manifest; silent (no records longer than the threshold inside a source's
    coverage, minus any declared gap); and uncovered (a known source with no coverage while other sources have it,
    e.g. a source missing from a batch manifest)."""
    by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        by_src[e["source"]].append(e)
    for evs in by_src.values():
        evs.sort(key=lambda e: (e["corrected_ms"], e["event_id"]))
    declared = [(g["source"], parse_utc(g["start"]), parse_utc(g["end"]), g) for g in state["declared_gaps"]]
    cov_batch = {(c["source"], parse_utc(c["start"])): c["batch"] for c in state["coverage"]}
    raw: list[tuple[str, str, int, int, str, str]] = []
    for src, lo, hi, g in declared:
        raw.append(("declared", src, lo, hi, g["batch"], f"Declared in the batch manifest: {data(g['reason'])}"))

    def batch_at(src: str | None, t: int) -> str:
        return max((bt for (s, start), bt in cov_batch.items() if (src is None or s == src) and start <= t), default="")

    run_window = merge([(parse_utc(c["start"]), parse_utc(c["end"])) for c in state["coverage"]])
    for src in sorted(set(known_sources) | {c["source"] for c in state["coverage"]}):
        own = [(parse_utc(c["start"]), parse_utc(c["end"])) for c in state["coverage"] if c["source"] == src]
        for span in run_window:
            for lo, hi in subtract(span, own):
                if hi - lo >= MINUTE:
                    raw.append(
                        (
                            "uncovered",
                            src,
                            lo,
                            hi,
                            batch_at(None, lo),
                            f"No coverage for {data(src)}: the source is missing from the batch manifest for "
                            f"this period while other sources were delivered",
                        )
                    )
    sources = sorted({c["source"] for c in state["coverage"]})
    for src in sources:
        cov = merge([(parse_utc(c["start"]), parse_utc(c["end"])) for c in state["coverage"] if c["source"] == src])
        times = [e["corrected_ms"] for e in by_src.get(src, [])]
        for cs, ce in cov:
            points = [cs] + [t for t in times if cs <= t <= ce] + [ce]
            for a, b in zip(points, points[1:], strict=False):
                if b - a <= SILENCE_MINUTES * MINUTE:
                    continue
                holes = [(dlo, dhi) for s, dlo, dhi, _ in declared if s == src and a < dhi and b > dlo]
                if not holes:
                    raw.append(
                        (
                            "silent",
                            src,
                            a,
                            b,
                            batch_at(src, a),
                            f"No {data(src)} records for {(b - a) // MINUTE} minutes inside the declared coverage "
                            f"(threshold {SILENCE_MINUTES} minutes)",
                        )
                    )
                    continue
                pieces = subtract((a, b), holes)  # report the silence a declared gap does not explain
                if sum(hi - lo for lo, hi in pieces) <= SILENCE_MINUTES * MINUTE:
                    continue
                for lo, hi in pieces:
                    if hi - lo >= MIN_PIECE_MINUTES * MINUTE:
                        raw.append(
                            (
                                "silent",
                                src,
                                lo,
                                hi,
                                batch_at(src, lo),
                                f"No {data(src)} records for {(hi - lo) // MINUTE} minutes outside the declared "
                                f"gap(s), part of a {(b - a) // MINUTE}-minute silence inside the declared coverage "
                                f"(threshold {SILENCE_MINUTES} minutes)",
                            )
                        )
    gaps = []
    for kind, src, lo, hi, batch, reason in sorted(raw, key=lambda r: (r[2], r[1], r[0])):
        evs = by_src.get(src, [])
        before = [e for e in evs if e["corrected_ms"] < lo][-1:]
        after = [e for e in evs if e["corrected_ms"] > hi][:1]
        near = [e for e in evs if lo - 2 * HOUR <= e["corrected_ms"] <= hi + 2 * HOUR]
        affected = sorted({x for e in near for x in (e["actor"], e["target"]) if x})
        gaps.append(
            {
                "gap_id": "gap-" + short_hash(f"{kind}|{src}|{lo}|{hi}", 10),
                "kind": kind,
                "source": src,
                "batch": batch,
                "start_utc": iso_ms(lo),
                "end_utc": iso_ms(hi),
                "_lo": lo,
                "_hi": hi,
                "duration_minutes": (hi - lo) // MINUTE,
                "reason": reason,
                "affected_entities": affected,
                "bounding_event_ids": [e["event_id"] for e in before + after],
                "events_inside_window": sum(1 for e in evs if lo < e["corrected_ms"] < hi),
                "incident_ids": [],
                "hypothesis_refs": [],
            }
        )
    return gaps


# ---- incidents ------------------------------------------------------------------------------------
def group_detections(dets: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    groups: list[list[dict[str, Any]]] = []
    open_by_entity: dict[str, list[dict[str, Any]]] = {}
    for d in dets:
        cur = open_by_entity.get(d["entity"])
        if cur and d["_start"] <= max(x["_end"] for x in cur) + GROUP_WINDOW:
            cur.append(d)
        else:
            cur = [d]
            groups.append(cur)
            open_by_entity[d["entity"]] = cur
    return groups


def expand_context(core: set[str], by_id: dict[str, dict[str, Any]], lo: int, hi: int) -> set[str]:
    """Add events joined to the incident's events by an explicit session, request, process or parent id."""

    def kind(f: str) -> str:
        return "proc" if f in ("process_id", "parent_id") else f

    index: dict[tuple[str, str], list[str]] = defaultdict(list)
    for e in by_id.values():
        if lo - CONTEXT_WINDOW <= e["corrected_ms"] <= hi + CONTEXT_WINDOW:
            for f in ID_FIELDS:
                if usable_id(e[f]):
                    index[(kind(f), e[f])].append(e["event_id"])
    found, frontier = set(core), sorted(core)
    for _ in range(4):
        grow = set()
        for eid in frontier:
            e = by_id[eid]
            for f in ID_FIELDS:
                if usable_id(e[f]):
                    grow.update(c for c in index[(kind(f), e[f])] if c not in found and linked(e, by_id[c]))
        if not grow:
            break
        found |= grow
        frontier = sorted(grow)
    return found


def distinct(evs: list[dict[str, Any]], key: str) -> list[str]:
    """Every distinct value of a detail across a grouped entry, each quoted as data."""
    return sorted({data(x["details"][key]) for x in evs if x["details"].get(key) is not None})


def entry_text(evs: list[dict[str, Any]]) -> str:
    """Timeline text for consecutive events sharing source, action, outcome, actor, target and address. Details that
    differ between the events are all listed, never only the first event's."""
    e, n = evs[0], len(evs)
    span = hm(e["corrected_ms"]) if n == 1 else f"{hm(e['corrected_ms'])}-{hm(evs[-1]['corrected_ms'])}"
    ip = (
        (data(f"ip:{e['src_ip']}") + (f" ({e['geo']})" if e["geo"] else "")) if e["src_ip"] else "an unrecorded address"
    )
    a, actor, target = e["action"], data(e["actor"]), data(e["target"])
    if a == "idp.signin":
        ok = "successful" if e["outcome"] == "success" else "failed"
        text = f"{n} {ok} sign-in(s) for {actor} from {ip} to {', '.join(distinct(evs, 'app')) or 'None'}"
    elif a == "idp.mfa_push":
        text = f"{n} MFA push(es) for {actor} ({', '.join(distinct(evs, 'push_result'))}) for a sign-in from {ip}"
    elif a == "host.ssh.login":
        ok = "accepted" if e["outcome"] == "success" else "failed"
        text = f"{n} {ok} SSH login(s) for {actor} on {target} from {ip}"
    elif a in ("host.sudo", "host.process.exec"):
        what = ", ".join(sorted({data(x["details"].get("cmd") or x["details"].get("exe") or "?") for x in evs}))
        noun = "sudo command" if a == "host.sudo" else "process execution"
        text = f"{n} {noun}(s) by {actor} on {target}: {what}"
    elif a.startswith("resource."):
        mb = sum(x["details"].get("bytes", 0) for x in evs) // 1_000_000
        text = f"{n} {data(a.split('.', 1)[1])}(s) of {target} by {actor} from {ip} ({mb} MB)"
    else:
        keys = ("role", "group", "key_id", "acl", "principal", "permission", "ticket", "credential")
        params = ", ".join(f"{k}={v}" for k in keys for v in distinct(evs, k))
        text = f"{n} x {data(a)} by {actor} on {target} from {ip}" + (f" ({params})" if params else "")
    return f"{text} at {span} UTC"


def link_text(frm: str, to: str, kind: str | None, value: str | None, delta: int) -> str:
    if kind == "same_session":
        return f"{to} carries session id {data(value)}, also recorded in {frm}"
    if kind == "same_request":
        return f"{to} and {frm} carry the same request id {data(value)}"
    if kind == "same_process":
        return f"{to} and {frm} were logged by the same process {data(value)}"
    if kind == "parent_id":
        return f"{to} records parent {data(value)}, the process or request logged in {frm}"
    return (
        f"{to} followed {frm} after {delta // MINUTE} min {(delta // 1000) % 60} s; no shared session, request, "
        f"process or parent id is recorded between them; only the order is asserted"
    )


def build_timeline(evs: list[dict[str, Any]], correction: str, det_of: dict[str, list[str]]) -> tuple[list, list]:
    entries: list[dict[str, Any]] = []
    groups: list[list[dict[str, Any]]] = []
    for e in evs:
        key = (e["source"], e["action"], e["outcome"], e["actor"], e["target"], e["src_ip"])
        if groups and groups[-1][0]["_key"] == key:
            groups[-1].append({**e, "_key": key})
        else:
            groups.append([{**e, "_key": key}])
    for i, g in enumerate(groups, 1):
        ids = [x["event_id"] for x in g]
        entries.append(
            {
                "entry_id": f"t{i:02d}",
                "at_utc": iso_ms(g[0]["corrected_ms"]),
                "end_utc": iso_ms(g[-1]["corrected_ms"]),
                "raw_at_utc": g[0]["observed_at_utc"] if correction == "on" else None,
                "raw_end_utc": g[-1]["observed_at_utc"] if correction == "on" else None,
                "skew_applied_seconds": g[0]["skew_applied_seconds"],
                "source": g[0]["source"],
                "action": g[0]["action"],
                "count": len(g),
                "text": entry_text(g),
                "event_ids": ids,
                "detection_ids": sorted({d for x in ids for d in det_of.get(x, [])}),
            }
        )
    links = []
    for j in range(1, len(groups)):
        prev, cur = groups[j - 1], groups[j]
        hit = first_link(prev, cur)
        delta = cur[0]["corrected_ms"] - prev[-1]["corrected_ms"]
        if hit:
            a, b, (kind, value) = hit
            links.append(link(entries[j - 1], entries[j], "causal", kind, value, [a, b], delta))
        else:
            links.append(link(entries[j - 1], entries[j], "temporal", None, None, [prev[-1], cur[0]], delta))
        for i in range(j - 2, -1, -1):  # nearest earlier non-adjacent entry joined by an explicit id
            hit = first_link(groups[i], cur)
            if hit:
                a, b, (kind, value) = hit
                links.append(
                    link(
                        entries[i],
                        entries[j],
                        "causal",
                        kind,
                        value,
                        [a, b],
                        cur[0]["corrected_ms"] - groups[i][-1]["corrected_ms"],
                    )
                )
                break
    for n, lk in enumerate(links, 1):
        lk["link_id"] = f"l{n:02d}"
    return entries, links


def link(fe: dict, te: dict, ltype: str, kind: str | None, value: str | None, pair: list[dict], delta: int) -> dict:
    return {
        "from": fe["entry_id"],
        "to": te["entry_id"],
        "link_type": ltype,
        "evidence_type": kind,
        "evidence_value": value,
        "event_ids": [pair[0]["event_id"], pair[1]["event_id"]],
        "text": link_text(fe["entry_id"], te["entry_id"], kind, value, delta),
    }


# ---- hypotheses -----------------------------------------------------------------------------------
def score_confidence(
    detections: int, sources: int, explicit: bool, contradicting: int, gap_ids: list[str], factors: tuple[str, ...] = ()
) -> dict[str, str]:
    """Pure confidence rule. Points: one per supporting detection, one for two or more sources, one for an
    explicit identifier joining supporting events, one per named extra factor. 3+ high, 2 medium, else low;
    minus one level for contradicting evidence, minus one more when the hypothesis depends on an evidence gap."""
    points = detections + (1 if sources >= 2 else 0) + (1 if explicit else 0) + len(factors)
    level = (2 if points >= 3 else 1 if points == 2 else 0) - (1 if contradicting else 0)
    before = max(level, 0)
    after = max(before - (1 if gap_ids else 0), 0)
    basis = f"{detections} supporting detection(s) across {sources} source(s); " + (
        "an explicit session, request, process or parent id joins supporting events"
        if explicit
        else "no explicit identifier joins the supporting events"
    )
    for factor in factors:
        basis += f"; {factor}"
    if contradicting:
        basis += f"; lowered one level for {contradicting} contradicting event(s)"
    if gap_ids:
        basis += (
            "; lowered one level: depends on evidence gap(s) "
            if after < before
            else "; already at the lowest level, also depends on evidence gap(s) "
        ) + ", ".join(gap_ids)
    return {"confidence": LEVELS[after], "confidence_before_gaps": LEVELS[before], "confidence_basis": basis}


def hypotheses_for(
    entity: str,
    dets: list[dict[str, Any]],
    by_id: dict[str, dict[str, Any]],
    inc_ids: set[str],
    gaps: list[dict[str, Any]],
    all_events: list[dict[str, Any]],
) -> list[dict]:
    kinds = {d["detector"] for d in dets}
    ev = lambda ids: sorted({i for i in ids}, key=lambda i: (by_id[i]["corrected_ms"], i))  # noqa: E731
    out: list[dict[str, Any]] = []

    def add(
        statement: str,
        support: list[str],
        expected: set[str],
        alternatives: list[dict[str, Any]],
        contradicting: list[str] | None = None,
        factors: tuple[str, ...] = (),
    ) -> None:
        support = ev(support)
        contradicting = ev(contradicting or [])
        evs = [by_id[i] for i in support]
        lo, hi = evs[0]["corrected_ms"], evs[-1]["corrected_ms"] + 2 * HOUR
        deps = [g for g in gaps if g["source"] in expected and g["_lo"] < hi and g["_hi"] > lo]
        explicit = any(explicit_link(a, b) for k, a in enumerate(evs) for b in evs[k + 1 :])
        n_det = sum(1 for d in dets if set(d["event_ids"]) & set(support))
        conf = score_confidence(
            n_det, len({e["source"] for e in evs}), explicit, len(contradicting), [g["gap_id"] for g in deps], factors
        )
        missing = [
            {
                "gap_id": g["gap_id"],
                "source": g["source"],
                "start_utc": g["start_utc"],
                "end_utc": g["end_utc"],
                "description": f"No {data(g['source'])} records between {g['start_utc'][11:16]} and "
                f"{g['end_utc'][11:16]} "
                f"UTC on {g['start_utc'][:10]} ({g['kind']} gap); activity in that window can be "
                f"neither confirmed nor excluded",
            }
            for g in deps
        ]
        if deps:
            statement += (
                " This reading depends on missing evidence: "
                + "; ".join(
                    f"{data(g['source'])} is silent {g['start_utc'][11:16]}-{g['end_utc'][11:16]} UTC ({g['gap_id']})"
                    for g in deps
                )
                + "."
            )
        out.append(
            {
                "hypothesis_id": f"h{len(out) + 1}",
                "statement": statement,
                "supporting_event_ids": support,
                "contradicting_event_ids": contradicting,
                "missing_evidence": missing,
                "depends_on_gaps": [g["gap_id"] for g in deps],
                "expected_sources": sorted(expected),
                **conf,
                "alternatives": alternatives,
            }
        )

    def alt(kind: str, statement: str, ids: list[str], distinguish: str) -> dict[str, Any]:
        return {"kind": kind, "statement": statement, "event_ids": ev(ids), "distinguishing_evidence": distinguish}

    signin_dets = [
        d
        for d in dets
        if d["detector"] in ANOMALOUS_SIGNIN
        or (d["detector"] == "privilege_after_anomalous_signin" and d["severity"] == "medium")
    ]
    if signin_dets:
        support = [i for d in signin_dets for i in d["event_ids"]]
        follow = [
            d
            for d in dets
            if d["detector"] in ("privilege_after_anomalous_signin", "public_exposure_after_anomaly")
            and d not in signin_dets
        ]
        support += [i for d in follow for i in d["event_ids"]]
        ok = [
            by_id[i]
            for d in signin_dets
            for i in d["event_ids"]
            if by_id[i]["outcome"] == "success" and by_id[i]["action"] in ("idp.signin", "host.ssh.login")
        ]
        first_ok = max(ok, key=lambda e: (e["corrected_ms"], e["event_id"])) if ok else None  # the anomalous success
        known = [
            e["event_id"]
            for e in all_events
            if first_ok
            and e["actor"] == entity
            and e["outcome"] == "success"
            and e["action"] == first_ok["action"]
            and e["src_ip"] == first_ok["src_ip"]
            and e["corrected_ms"] < first_ok["corrected_ms"]
            and e["event_id"] not in support
        ][-3:]
        pushes = [
            e
            for e in all_events
            if first_ok
            and e["action"] == "idp.mfa_push"
            and e["actor"] == entity
            and 0 <= first_ok["corrected_ms"] - e["corrected_ms"] <= 15 * MINUTE
        ]
        first_prompt = [p["event_id"] for p in pushes if len(pushes) == 1 and p["outcome"] == "success"]
        prior_success = bool(known)
        factors: tuple[str, ...] = ()
        if first_ok and not prior_success:
            addr = data(f"ip:{first_ok['src_ip']}")
            earlier = [
                e
                for e in all_events
                if e["actor"] == entity
                and e["src_ip"] == first_ok["src_ip"]
                and e["corrected_ms"] < first_ok["corrected_ms"]
            ]
            factors = (
                (f"the successful sign-in came from {addr}, not seen for this account earlier",)
                if not earlier
                else (
                    f"the successful sign-in came from {addr}, an address this account had not signed in from "
                    f"successfully before (it appears earlier only in {len(earlier)} other event(s) such as the "
                    f"failed attempts)",
                )
            )
        known += first_prompt  # the registered device approved the first and only prompt
        host_based = any(d["measurements"].get("source") == "host_auth" for d in signin_dets)
        what = ", ".join(
            sorted(
                LABELS[d["detector"]]
                if d["severity"] != "medium" or d["detector"] in ANOMALOUS_SIGNIN
                else "a first sign-in from a new country"
                for d in signin_dets
            )
        )
        alts = []
        if "brute_force_success" in kinds:
            alts.append(
                alt(
                    "benign",
                    f"The owner of {data(entity)} mistyped or used a stale saved password several times and then "
                    "signed in.",
                    support,
                    f"A password-change or lockout ticket and a success from an address already used by "
                    f"{data(entity)} favour this reading; the success came from "
                    f"{data('ip:' + str(first_ok['src_ip'] if first_ok else '?'))}, which this account "
                    f"{'had' if prior_success else 'had not'} signed in from successfully earlier in the ingested "
                    f"batches.",
                )
            )
        if "impossible_travel" in kinds:
            alts.append(
                alt(
                    "benign",
                    "A VPN exit node, proxy or mobile carrier changed the apparent country without "
                    "the owner travelling.",
                    support,
                    "Device identifiers or VPN assignment records for both sign-ins (not present in these "
                    "sources) would show whether one device made both.",
                )
            )
        if "mfa_fatigue" in kinds:
            alts.append(
                alt(
                    "benign",
                    "The owner dismissed prompts from a stale session on their own device and later "
                    "approved a genuine sign-in.",
                    support,
                    "The approving device and the sign-in address: an approval for a sign-in from an address "
                    "never used by the owner favours the malicious reading.",
                )
            )
        if not alts:
            alts.append(
                alt(
                    "benign",
                    f"The owner of {data(entity)} is travelling and signed in from a new country.",
                    support,
                    "A travel record, the same device identifier as earlier sign-ins, or a change ticket for "
                    "the follow-on activity would support this reading.",
                )
            )
        expected = {"idp_signin", "cloud_audit", "resource_access"} | ({"host_auth"} if host_based else set())
        add(
            f"Someone other than the owner of {data(entity)} may have used the account's credentials ({what}).",
            support,
            expected,
            alts,
            contradicting=known,
            factors=factors,
        )

    for d in dets:
        if d["detector"] == "brute_force_success" and d["measurements"].get("source") == "host_auth":
            ok = by_id[d["event_ids"][-1]]
            cmds = sorted(i for i in inc_ids if explicit_link(ok, by_id[i]) == ("parent_id", ok["process_id"]))
            if cmds:
                add(
                    f"The SSH session obtained on {data(ok['target'])} was used to run commands ({len(cmds)} command "
                    f"or process events record its process {data(ok['process_id'])} as their parent).",
                    [ok["event_id"], *cmds],
                    {"host_auth"},
                    [
                        alt(
                            "benign",
                            f"The owner logged in to {data(ok['target'])} after mistyping and ran routine "
                            "administration.",
                            [ok["event_id"], *cmds],
                            "Whether the commands match the owner's usual work (archiving configuration and copying it "
                            "to an outside address is unusual) and what the session did after its last recorded line.",
                        )
                    ],
                )

    for d in dets:
        if d["detector"] != "privilege_after_anomalous_signin":
            continue
        ps = [by_id[i] for i in d["event_ids"] if by_id[i]["action"] in PRIVILEGE_ACTIONS]
        tickets = sorted({data(p["details"]["ticket"]) for p in ps if p["details"].get("ticket")})
        actions = ", ".join(sorted({data(p["action"]) for p in ps}))
        alts = [
            alt(
                "benign",
                "An authorised administrative change made by the account owner.",
                d["event_ids"],
                "A change ticket in the audit record parameters ("
                + (", ".join(tickets) if tickets else "none recorded")
                + ") and approval by a second administrator.",
            )
        ]
        if any(p["action"] == "iam.accesskey.create" for p in ps):
            alts.append(
                alt(
                    "malicious",
                    "The new access key is persistence for later access rather than for immediate escalation.",
                    d["event_ids"],
                    "Later activity that authenticates with the new key id.",
                )
            )
        add(
            f"Privileges for {', '.join(sorted({data(p['target']) for p in ps}))} were expanded during or shortly "
            f"after the "
            f"anomalous access ({actions}).",
            d["event_ids"],
            {"cloud_audit"},
            alts,
            contradicting=[p["event_id"] for p in ps if p["details"].get("ticket")],
        )

    expo = [d for d in dets if d["detector"] in ("public_exposure_after_anomaly", "mass_download_after_exposure")]
    if expo:
        support = [i for d in expo for i in d["event_ids"]]
        targets = sorted({data(by_id[i]["target"]) for i in support if is_exposure(by_id[i])})
        add(
            f"Data in {', '.join(targets)} may have been exposed to, or copied by, parties outside the organisation.",
            support,
            {"resource_access"},
            [
                alt(
                    "benign",
                    "The resource was published on purpose for public content.",
                    support,
                    "Whether the resource holds public material such as website assets and whether a ticket covers the "
                    "change; reads after the change show who fetched what.",
                ),
                alt(
                    "malicious",
                    "An insider staged the data for collection rather than an outside party.",
                    support,
                    "Whether the reads come from the account owner's usual addresses or from unrelated ones.",
                ),
            ],
        )

    for d in dets:
        if d["detector"] != "logging_disabled":
            continue
        e = by_id[d["event_ids"][0]]
        cred = e["details"].get("credential", "")
        keys = [
            x
            for x in inc_ids
            if by_id[x]["action"] == "iam.accesskey.create"
            and cred == f"access_key:{by_id[x]['details'].get('key_id')}"
        ]
        linked = [x for x in inc_ids if by_id[x]["corrected_ms"] < e["corrected_ms"] and explicit_link(by_id[x], e)]
        add(
            f"Audit logging on {data(e['target'])} was turned off, which may hide later control-plane activity"
            + (
                f"; the request used access key {data(cred.split(':', 1)[1])}, created earlier in this incident."
                if keys
                else "."
            )
            + (
                f" It ran in a session already recorded in {len(linked)} earlier event(s) of this incident."
                if linked
                else ""
            ),
            d["event_ids"] + keys + linked,
            {"cloud_audit"},
            [
                alt(
                    "benign",
                    "Planned logging maintenance or a cost change.",
                    d["event_ids"],
                    "A maintenance ticket and the trail being restarted shortly afterwards.",
                )
            ],
        )

    for d in dets:
        if d["detector"] != "password_spray":
            continue
        m = d["measurements"]
        ip = d["entity"].split(":", 1)[1]
        wins = [
            e for e in all_events if e["action"] == "idp.signin" and e["outcome"] == "success" and e["src_ip"] == ip
        ]
        add(
            f"{data(d['entity'])} attempted password spraying against {m['distinct_accounts']} accounts; "
            + (
                "no successful sign-in from that address appears in the ingested batches."
                if not wins
                else f"{len(wins)} successful sign-in(s) from that address appear in the ingested batches, the first "
                f"at {wins[0]['corrected_at_utc']}."
            ),
            d["event_ids"] + [e["event_id"] for e in wins],
            {"idp_signin"},
            [
                alt(
                    "benign",
                    "A misconfigured client or a shared egress address retrying stale credentials for several users.",
                    d["event_ids"],
                    "User agents and applications of the attempts; a shared address of legitimate users would also "
                    "show successful sign-ins.",
                )
            ],
        )
    return out


def severity_of(dets: list[dict[str, Any]]) -> tuple[str, str]:
    top = max(SEV.index(d["severity"]) for d in dets)
    kinds = sorted({d["detector"] for d in dets})
    level = min(top + (1 if len(kinds) >= 3 else 0), 3)
    basis = f"highest detection severity {SEV[top]}" + (
        f", raised one level for {len(kinds)} distinct detectors" if len(kinds) >= 3 and top < 3 else ""
    )
    return SEV[level], basis


def investigate(
    events: list[dict[str, Any]], dets: list[dict[str, Any]], gaps: list[dict[str, Any]], correction: str
) -> list[dict[str, Any]]:
    by_id = {e["event_id"]: e for e in events}
    det_of: dict[str, list[str]] = defaultdict(list)
    for d in dets:
        for i in d["event_ids"]:
            det_of[i].append(d["detection_id"])
    ordered = sorted(events, key=lambda e: (e["corrected_ms"], e["event_id"]))
    incidents = []
    for group in group_detections(dets):
        core = {i for d in group for i in d["event_ids"]}
        lo, hi = min(d["_start"] for d in group), max(d["_end"] for d in group)
        ids = expand_context(core, by_id, lo, hi)
        evs = sorted((by_id[i] for i in ids), key=lambda e: (e["corrected_ms"], e["event_id"]))
        entries, links = build_timeline(evs, correction, det_of)
        entity = group[0]["entity"]
        hyps = hypotheses_for(entity, group, by_id, ids, gaps, ordered)
        severity, sev_basis = severity_of(group)
        inc_id = "inc-" + short_hash(",".join(sorted(d["detection_id"] for d in group)), 10)
        roles: dict[str, dict[str, Any]] = {}
        for e in evs:
            for role, val in (
                ("actor", e["actor"]),
                ("target", e["target"]),
                ("address", f"ip:{e['src_ip']}" if e["src_ip"] else None),
            ):
                if val:
                    r = roles.setdefault(val, {"entity": val, "roles": set(), "event_ids": []})
                    r["roles"].add(role)
                    r["event_ids"].append(e["event_id"])
        dep_gaps = sorted({g for h in hyps for g in h["depends_on_gaps"]})
        win_gaps = [
            g["gap_id"]
            for g in gaps
            if g["source"] in {e["source"] for e in evs}
            and g["_lo"] < evs[-1]["corrected_ms"] + HOUR
            and g["_hi"] > evs[0]["corrected_ms"] - HOUR
        ]
        kinds = sorted(
            {d["detector"] for d in group}, key=lambda k: min(d["_start"] for d in group if d["detector"] == k)
        )
        incidents.append(
            {
                "incident_id": inc_id,
                "title": f"{data(entity)}: " + ", ".join(LABELS[k] for k in kinds),
                "severity": severity,
                "severity_basis": sev_basis,
                "primary_entity": entity,
                "window": {"start_utc": iso_ms(evs[0]["corrected_ms"]), "end_utc": iso_ms(evs[-1]["corrected_ms"])},
                "detection_ids": [d["detection_id"] for d in group],
                "detectors": kinds,
                "event_ids": [e["event_id"] for e in evs],
                "context_event_ids": [e["event_id"] for e in evs if e["event_id"] not in core],
                "entities": [
                    {"entity": k, "roles": sorted(v["roles"]), "event_ids": v["event_ids"]}
                    for k, v in sorted(roles.items())
                ],
                "timeline": entries,
                "links": links,
                "hypotheses": hyps,
                "gaps": sorted(set(dep_gaps) | set(win_gaps)),
                "gaps_hypotheses_depend_on": dep_gaps,
            }
        )
        for g in gaps:
            if g["gap_id"] in incidents[-1]["gaps"]:
                g["incident_ids"].append(inc_id)
            for h in hyps:
                if g["gap_id"] in h["depends_on_gaps"]:
                    g["hypothesis_refs"].append(f"{inc_id}/{h['hypothesis_id']}")
    return sorted(incidents, key=lambda i: (i["window"]["start_utc"], i["incident_id"]))


# ---- graph and entities ---------------------------------------------------------------------------
def correlations(incidents: list[dict[str, Any]], by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def edge(frm: str, to: str, relation: str, ltype: str, evidence: str, ids: list[str], **extra: Any) -> None:
        eid = "edge-" + short_hash(f"{frm}|{to}|{relation}|{','.join(ids)}", 12)
        edges[eid] = {
            "edge_id": eid,
            "from": frm,
            "to": to,
            "relation": relation,
            "link_type": ltype,
            "evidence_type": evidence,
            "event_ids": ids,
            **extra,
        }

    for inc in incidents:
        for eid in inc["event_ids"]:
            e = by_id[eid]
            nodes[eid] = {
                "id": eid,
                "kind": "event",
                "source": e["source"],
                "action": e["action"],
                "at_utc": e["corrected_at_utc"],
                "incident_ids": sorted(set(nodes.get(eid, {}).get("incident_ids", [])) | {inc["incident_id"]}),
            }
            for rel, val in (
                ("actor", e["actor"]),
                ("target", e["target"]),
                ("address", f"ip:{e['src_ip']}" if e["src_ip"] else None),
            ):
                if val:
                    nodes.setdefault(val, {"id": val, "kind": val.split(":", 1)[0]})
                    edge(eid, val, rel, "attribution", "record_field", [eid])
            if e["source"] == "cloud_audit" and e["actor"] and e["target"] and e["actor"] != e["target"]:
                edge(e["actor"], e["target"], e["action"], "attribution", "audit_actor_target", [eid])
        entries = {t["entry_id"]: t for t in inc["timeline"]}
        for lk in inc["links"]:
            a, b = lk["event_ids"]
            edge(
                a,
                b,
                "sequence" if lk["link_type"] == "temporal" else lk["evidence_type"],
                lk["link_type"],
                lk["evidence_type"] or "time_order",
                [a, b],
                incident_id=inc["incident_id"],
                evidence_value=lk["evidence_value"],
                text=f"{data(entries[lk['from']]['action'])} to {data(entries[lk['to']]['action'])}: {lk['text']}",
            )
    return {
        "nodes": [nodes[k] for k in sorted(nodes)],
        "edges": sorted(edges.values(), key=lambda x: (x["from"], x["to"], x["relation"], x["edge_id"])),
    }


def entities(events: list[dict[str, Any]], incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    inc_of: dict[str, set[str]] = defaultdict(set)
    for inc in incidents:
        for e in inc["entities"]:
            inc_of[e["entity"]].add(inc["incident_id"])
    for e in sorted(events, key=lambda e: (e["corrected_ms"], e["event_id"])):
        for val in (e["actor"], e["target"], f"ip:{e['src_ip']}" if e["src_ip"] else None):
            if not val:
                continue
            r = out.setdefault(
                val,
                {
                    "entity": val,
                    "kind": val.split(":", 1)[0],
                    "events": 0,
                    "sources": set(),
                    "countries": set(),
                    "first_seen_utc": e["corrected_at_utc"],
                },
            )
            r["events"] += 1
            r["sources"].add(e["source"])
            if e["geo"] and (val.startswith("ip:") or val == e["actor"]):
                r["countries"].add(e["geo"])
            r["last_seen_utc"] = e["corrected_at_utc"]
    return [
        {
            **r,
            "sources": sorted(r["sources"]),
            "countries": sorted(r["countries"]),
            "incident_ids": sorted(inc_of.get(k, set())),
        }
        for k, r in sorted(out.items())
    ]
