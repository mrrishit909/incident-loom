"""Correlation rules (detections): a bounded, documented set.

Thresholds were chosen by looking only at the development scenarios (dev-01..dev-07) and the
unlabelled background traffic. This module never opens the labels file; only
`incidentloom.evaluate` does, after detection has finished.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .ingest import distance_km
from .util import MINUTE, data, iso_ms, short_hash

THRESHOLDS: dict[str, dict[str, int]] = {
    "password_spray": {"window_minutes": 30, "min_distinct_users": 5},
    "brute_force_success": {"window_minutes": 20, "min_failures": 6, "success_within_minutes": 15},
    "impossible_travel": {"min_distance_km": 500, "max_plausible_kmh": 900},
    "mfa_fatigue": {"window_minutes": 15, "min_rejected_pushes": 4, "approval_within_minutes": 10},
    "privilege_after_anomalous_signin": {"within_minutes": 120, "new_country_min_prior_signins": 3},
    "public_exposure_after_anomaly": {"within_minutes": 240},
    "mass_download_after_exposure": {
        "start_within_minutes": 120,
        "window_minutes": 30,
        "min_reads": 40,
        "min_bytes": 500_000_000,
    },
    "logging_disabled": {},
}

DETECTORS: list[dict[str, Any]] = [
    {
        "id": "password_spray",
        "title": "Password spray",
        "severity": "medium",
        "sources": ["idp_signin"],
        "description": "Failed sign-ins from one address against many distinct accounts inside a sliding window.",
        "tuning": "dev-02 reaches 8 distinct accounts in 21 minutes; background failures are single typos by one "
        "user. 5 accounts in 30 minutes separates them with margin.",
    },
    {
        "id": "brute_force_success",
        "title": "Repeated failures then a success",
        "severity": "high",
        "sources": ["idp_signin", "host_auth"],
        "description": "At least N failed sign-ins for one account inside a window, then a success for that account "
        "shortly after the last failure (identity provider or SSH, counted per source).",
        "tuning": "dev-01 (9 failures) and dev-07 (8) are attacks; dev-03 maintenance has 3 key failures before a "
        "success. Any value from 4 to 8 separates them; 6 was chosen.",
    },
    {
        "id": "impossible_travel",
        "title": "Impossible travel",
        "severity": "medium",
        "sources": ["idp_signin"],
        "description": "Two consecutive successful sign-ins for one account from countries whose synthetic distance "
        "needs a speed above the plausible limit.",
        "tuning": "dev-04 needs about 15,000 km/h; dev-05 (benign travel) needs about 560 km/h. 900 km/h is airliner "
        "cruising speed.",
    },
    {
        "id": "mfa_fatigue",
        "title": "MFA push fatigue",
        "severity": "high",
        "sources": ["idp_signin"],
        "description": "Several rejected or ignored MFA pushes for one account, then an approval soon after.",
        "tuning": "dev-06 has 5 rejected pushes in 9 minutes; background has at most one dismissed push. 4 in 15 "
        "minutes was chosen.",
    },
    {
        "id": "privilege_after_anomalous_signin",
        "title": "Privilege change after an anomalous sign-in",
        "severity": "high",
        "sources": ["cloud_audit", "idp_signin", "host_auth"],
        "description": "A role grant, access-key creation or group membership change by an account within a window "
        "after that account had an anomalous sign-in (a brute-force, travel or MFA-fatigue detection, "
        "or a first sign-in from a new country once the account has a baseline). Medium severity when "
        "the only anomaly is the new country.",
        "tuning": "dev-07 grants a role 13 minutes after the brute-forced sign-in. 120 minutes is an a-priori "
        "session-length bound; development data contains no new-country-only case.",
    },
    {
        "id": "public_exposure_after_anomaly",
        "title": "Public exposure after an anomaly",
        "severity": "high",
        "sources": ["cloud_audit"],
        "description": "A bucket made public-read or a share opened to everyone by an account within a window after "
        "an anomalous sign-in or privilege-change detection for that account.",
        "tuning": "dev-07 exposes a bucket 21 minutes after the anomalous sign-in; 240 minutes is an a-priori bound.",
    },
    {
        "id": "mass_download_after_exposure",
        "title": "Mass download after exposure",
        "severity": "critical",
        "sources": ["cloud_audit", "resource_access"],
        "description": "Many reads (or many bytes) of a just-exposed resource by one principal and address inside a "
        "sliding window that starts soon after the exposure.",
        "tuning": "dev-07 has 52 reads (about 750 MB) in 19 minutes; background reads are single files. 40 reads or "
        "500 MB in 30 minutes was chosen.",
    },
    {
        "id": "logging_disabled",
        "title": "Audit logging stopped",
        "severity": "critical",
        "sources": ["cloud_audit"],
        "description": "An audit trail stopped or deleted.",
        "tuning": "dev-07 deletes a trail; dev-03 maintenance only updates retention, which does not match.",
    },
]
SEVERITY = {d["id"]: d["severity"] for d in DETECTORS}
PRIVILEGE_ACTIONS = {"iam.role.grant", "iam.accesskey.create", "iam.group.add_member"}
ANOMALOUS_SIGNIN = {"brute_force_success", "impossible_travel", "mfa_fatigue"}


def hm(ms: int) -> str:
    return iso_ms(ms)[11:19]


def is_exposure(e: dict[str, Any]) -> bool:
    d = e["details"]
    return e["outcome"] == "success" and (
        (e["action"] == "storage.bucket.set_acl" and d.get("acl") in ("public-read", "public-read-write"))
        or (e["action"] == "storage.share.set_permission" and d.get("principal") in ("everyone", "anonymous"))
    )


def make(
    detector: str,
    events: list[dict[str, Any]],
    entity: str,
    summary: str,
    measurements: dict[str, Any],
    related: set[str],
    basis: list[str] | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    events = sorted({e["event_id"]: e for e in events}.values(), key=lambda e: (e["corrected_ms"], e["event_id"]))
    ids = [e["event_id"] for e in events]
    return {
        "detection_id": "det-" + short_hash(detector + "|" + ",".join(sorted(ids)), 12),
        "detector": detector,
        "severity": severity or SEVERITY[detector],
        "entity": entity,
        "related_entities": sorted(related - {entity, None}),
        "start_utc": iso_ms(events[0]["corrected_ms"]),
        "end_utc": iso_ms(events[-1]["corrected_ms"]),
        "_start": events[0]["corrected_ms"],
        "_end": events[-1]["corrected_ms"],
        "event_ids": ids,
        "summary": summary,
        "measurements": measurements,
        "sources": sorted({e["source"] for e in events}),
        "basis_detection_ids": sorted(basis or []),
    }


def password_spray(evs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    th = THRESHOLDS["password_spray"]
    win = th["window_minutes"] * MINUTE
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in evs:
        if e["action"] == "idp.signin" and e["outcome"] == "failure" and e["src_ip"]:
            by_ip[e["src_ip"]].append(e)
    out = []
    for ip, fails in sorted(by_ip.items()):
        clusters: list[list[dict[str, Any]]] = []
        for e in fails:
            if clusters and e["corrected_ms"] - clusters[-1][-1]["corrected_ms"] <= win:
                clusters[-1].append(e)
            else:
                clusters.append([e])
        for cl in clusters:
            best, lo = 0, 0
            for hi in range(len(cl)):
                while cl[hi]["corrected_ms"] - cl[lo]["corrected_ms"] > win:
                    lo += 1
                best = max(best, len({x["actor"] for x in cl[lo : hi + 1]}))
            if best < th["min_distinct_users"]:
                continue
            start, end = cl[0]["corrected_ms"], cl[-1]["corrected_ms"]
            wins = [
                e
                for e in evs
                if e["action"] == "idp.signin"
                and e["outcome"] == "success"
                and e["src_ip"] == ip
                and start <= e["corrected_ms"] <= end + win
            ]
            users = {x["actor"] for x in cl}
            summary = (
                f"{len(cl)} failed sign-ins against {len(users)} distinct accounts from {data('ip:' + ip)} between "
                f"{hm(start)} and {hm(end)} UTC; up to {best} distinct accounts inside one "
                f"{th['window_minutes']}-minute window; {len(wins)} successful sign-ins from that address "
                f"in the same period"
            )
            out.append(
                make(
                    "password_spray",
                    cl + wins,
                    f"ip:{ip}",
                    summary,
                    {
                        "attempts": len(cl),
                        "distinct_accounts": len(users),
                        "max_distinct_in_window": best,
                        "successes_from_address": len(wins),
                    },
                    users,
                )
            )
    return out


def burst_then_success(
    evs: list[dict[str, Any]], fail_pred: Any, ok_pred: Any, window: int, within: int, minimum: int, key: Any
) -> list[tuple[list[dict[str, Any]], dict[str, Any]]]:
    """Generic 'N rejections inside a window, then an acceptance soon after the last one' matcher."""
    groups: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for e in evs:
        if fail_pred(e) or ok_pred(e):
            groups[key(e)].append(e)
    hits = []
    for _, items in sorted(groups.items(), key=lambda kv: str(kv[0])):
        pending: list[dict[str, Any]] = []
        for e in items:
            if fail_pred(e):
                pending.append(e)
                continue
            if not pending or e["corrected_ms"] - pending[-1]["corrected_ms"] > within:
                continue
            last = pending[-1]["corrected_ms"]
            burst = [f for f in pending if last - f["corrected_ms"] <= window]
            if len(burst) >= minimum:
                hits.append((burst, e))
                pending = []
    return hits


def brute_force_success(evs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    th = THRESHOLDS["brute_force_success"]
    auth = ("idp.signin", "host.ssh.login")
    hits = burst_then_success(
        evs,
        lambda e: e["action"] in auth and e["outcome"] == "failure",
        lambda e: e["action"] in auth and e["outcome"] == "success",
        th["window_minutes"] * MINUTE,
        th["success_within_minutes"] * MINUTE,
        th["min_failures"],
        key=lambda e: (e["source"], e["actor"]),
    )
    out = []
    for burst, ok in hits:
        ips = {f["src_ip"] for f in burst}
        failed_on = sorted({str(f["target"]) for f in burst})
        where = ", ".join(data(t) for t in failed_on) if ok["source"] == "host_auth" else "the identity provider"
        elsewhere = "" if ok["source"] != "host_auth" or failed_on == [ok["target"]] else f" on {data(ok['target'])}"
        gap = ok["corrected_ms"] - burst[-1]["corrected_ms"]
        summary = (
            f"{len(burst)} failed sign-ins for {data(ok['actor'])} on {where} between {hm(burst[0]['corrected_ms'])} "
            f"and {hm(burst[-1]['corrected_ms'])} UTC, followed {gap // 1000} s after the last failure by a "
            f"successful sign-in{elsewhere} from {data('ip:' + str(ok['src_ip']))}"
            + (" (an address used by the failures)" if ok["src_ip"] in ips else "")
        )
        related = {f"ip:{i}" for i in ips | {ok["src_ip"]}} | ({ok["target"]} if ok["source"] == "host_auth" else set())
        out.append(
            make(
                "brute_force_success",
                burst + [ok],
                ok["actor"],
                summary,
                {
                    "failures": len(burst),
                    "seconds_last_failure_to_success": gap // 1000,
                    "success_from_failing_address": ok["src_ip"] in ips,
                    "source": ok["source"],
                },
                related,
            )
        )
    return out


def mfa_fatigue(evs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    th = THRESHOLDS["mfa_fatigue"]
    hits = burst_then_success(
        evs,
        lambda e: e["action"] == "idp.mfa_push" and e["outcome"] == "failure",
        lambda e: e["action"] == "idp.mfa_push" and e["outcome"] == "success",
        th["window_minutes"] * MINUTE,
        th["approval_within_minutes"] * MINUTE,
        th["min_rejected_pushes"],
        key=lambda e: e["actor"],
    )
    out = []
    for burst, ok in hits:
        signin = [
            e
            for e in evs
            if e["action"] == "idp.signin"
            and e["outcome"] == "success"
            and ok["session_id"]
            and e["session_id"] == ok["session_id"]
        ]
        summary = (
            f"{len(burst)} rejected or unanswered MFA pushes for {data(ok['actor'])} between "
            f"{hm(burst[0]['corrected_ms'])} and {hm(burst[-1]['corrected_ms'])} UTC, then an approved push at "
            f"{hm(ok['corrected_ms'])} UTC for a sign-in from {data('ip:' + str(ok['src_ip']))}"
        )
        out.append(
            make(
                "mfa_fatigue",
                burst + [ok] + signin,
                ok["actor"],
                summary,
                {
                    "rejected_pushes": len(burst),
                    "approved_after_seconds": (ok["corrected_ms"] - burst[-1]["corrected_ms"]) // 1000,
                },
                {f"ip:{e['src_ip']}" for e in burst + [ok]},
            )
        )
    return out


def successes(evs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in evs if e["action"] == "idp.signin" and e["outcome"] == "success" and e["geo"]]


def impossible_travel(evs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    th = THRESHOLDS["impossible_travel"]
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in successes(evs):
        by_user[e["actor"]].append(e)
    out = []
    for user, items in sorted(by_user.items()):
        for a, b in zip(items, items[1:], strict=False):
            if a["geo"] == b["geo"]:
                continue
            km = distance_km(a["geo"], b["geo"])
            dt = b["corrected_ms"] - a["corrected_ms"]
            if km < th["min_distance_km"] or km * 3_600_000 <= th["max_plausible_kmh"] * dt:
                continue
            kmh = km * 3_600_000 // max(dt, 1)
            summary = (
                f"Successful sign-ins for {data(user)} from {a['geo']} ({data('ip:' + a['src_ip'])}) at "
                f"{hm(a['corrected_ms'])} and from {b['geo']} ({data('ip:' + b['src_ip'])}) at {hm(b['corrected_ms'])} "
                f"UTC: {km} km in "
                f"{dt // MINUTE} min, about {kmh} km/h against a plausible limit of "
                f"{th['max_plausible_kmh']} km/h"
            )
            out.append(
                make(
                    "impossible_travel",
                    [a, b],
                    user,
                    summary,
                    {
                        "from_country": a["geo"],
                        "to_country": b["geo"],
                        "distance_km": km,
                        "minutes": dt // MINUTE,
                        "speed_kmh": kmh,
                    },
                    {f"ip:{a['src_ip']}", f"ip:{b['src_ip']}"},
                )
            )
    return out


def new_country_signins(evs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Successful sign-ins from a country the account never used before, once it has a baseline."""
    need = THRESHOLDS["privilege_after_anomalous_signin"]["new_country_min_prior_signins"]
    seen: dict[str, list[str]] = defaultdict(list)
    out = {}
    for e in successes(evs):
        prior = seen[e["actor"]]
        if len(prior) >= need and e["geo"] not in prior:
            out[e["event_id"]] = e
        prior.append(e["geo"])
    return out


def key_event(det: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The last event of a detection: the success sign-in, the approval or the latest privilege change."""
    return (
        by_id[det["event_ids"][-1]]
        if det["detector"] != "mfa_fatigue"
        else max((by_id[i] for i in det["event_ids"]), key=lambda e: (e["corrected_ms"], e["action"] == "idp.signin"))
    )


def privilege_after_anomalous_signin(evs: list[dict[str, Any]], prior: list[dict[str, Any]]) -> list[dict[str, Any]]:
    th = THRESHOLDS["privilege_after_anomalous_signin"]
    within = th["within_minutes"] * MINUTE
    by_id = {e["event_id"]: e for e in evs}
    anomalies: dict[str, list[tuple[int, int, str, dict[str, Any], str | None]]] = defaultdict(list)
    for d in prior:
        if d["detector"] in ANOMALOUS_SIGNIN:
            k = key_event(d, by_id)
            anomalies[d["entity"]].append((k["corrected_ms"], 1, d["detector"], k, d["detection_id"]))
    for e in new_country_signins(evs).values():
        anomalies[e["actor"]].append((e["corrected_ms"], 0, "new_country_signin", e, None))
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    chosen: dict[tuple[str, str], tuple[int, int, str, dict[str, Any], str | None]] = {}
    for p in evs:
        if p["action"] not in PRIVILEGE_ACTIONS or p["outcome"] != "success":
            continue
        cands = [a for a in anomalies.get(p["actor"], []) if a[0] <= p["corrected_ms"] <= a[0] + within]
        if not cands:
            continue
        best = max(cands, key=lambda a: (a[1], a[0], a[3]["event_id"]))
        key = (p["actor"], best[3]["event_id"])
        groups[key].append(p)
        chosen[key] = best
    out = []
    for key in sorted(groups):
        ps = groups[key]
        when, strong, kind, anchor, det_id = chosen[key]
        actions = ", ".join(sorted({data(p["action"]) for p in ps}))
        what = (
            f"a {kind.replace('_', ' ')} detection"
            if strong
            else f"a first sign-in from {anchor['geo']}, a country not seen for this account before"
        )
        summary = (
            f"{len(ps)} privilege change(s) by {data(key[0])} ({actions}) within "
            f"{(ps[-1]['corrected_ms'] - when) // MINUTE} min after {what} at {hm(when)} UTC"
        )
        related = {p["target"] for p in ps} | {f"ip:{anchor['src_ip']}"}
        out.append(
            make(
                "privilege_after_anomalous_signin",
                [anchor] + ps,
                key[0],
                summary,
                {
                    "changes": len(ps),
                    "anomaly": kind,
                    "minutes_after_anomaly": (ps[0]["corrected_ms"] - when) // MINUTE,
                },
                related,
                basis=[det_id] if det_id else [],
                severity=None if strong else "medium",
            )
        )
    return out


def public_exposure_after_anomaly(evs: list[dict[str, Any]], prior: list[dict[str, Any]]) -> list[dict[str, Any]]:
    within = THRESHOLDS["public_exposure_after_anomaly"]["within_minutes"] * MINUTE
    by_id = {e["event_id"]: e for e in evs}
    out = []
    for x in evs:
        if not is_exposure(x):
            continue
        cands = [
            d
            for d in prior
            if d["entity"] == x["actor"]
            and d["detector"] in ANOMALOUS_SIGNIN | {"privilege_after_anomalous_signin"}
            and key_event(d, by_id)["corrected_ms"] <= x["corrected_ms"] <= key_event(d, by_id)["corrected_ms"] + within
        ]
        if not cands:
            continue
        d = max(cands, key=lambda c: (key_event(c, by_id)["corrected_ms"], c["detection_id"]))
        k = key_event(d, by_id)
        summary = (
            f"{data(x['actor'])} opened {data(x['target'])} to the public ({data(x['action'])}) at "
            f"{hm(x['corrected_ms'])} UTC, "
            f"{(x['corrected_ms'] - k['corrected_ms']) // MINUTE} min after the {d['detector'].replace('_', ' ')} "
            f"detection {d['detection_id']}"
        )
        out.append(
            make(
                "public_exposure_after_anomaly",
                [k, x],
                x["actor"],
                summary,
                {"minutes_after_anomaly": (x["corrected_ms"] - k["corrected_ms"]) // MINUTE},
                {x["target"]},
                basis=[d["detection_id"]],
            )
        )
    return out


def mass_download_after_exposure(evs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    th = THRESHOLDS["mass_download_after_exposure"]
    start_within, win = th["start_within_minutes"] * MINUTE, th["window_minutes"] * MINUTE
    out = []
    for x in [e for e in evs if is_exposure(e)]:
        groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for e in evs:
            if (
                e["action"] in ("resource.read", "resource.download")
                and e["outcome"] == "success"
                and e["target"] == x["target"]
                and x["corrected_ms"] <= e["corrected_ms"]
            ):
                groups[(e["actor"], e["src_ip"] or "")].append(e)
        for (who, ip), reads in sorted(groups.items()):
            reads = [r for r in reads if r["corrected_ms"] <= x["corrected_ms"] + start_within + win]
            best_n = best_b = lo = 0
            for hi in range(len(reads)):
                while reads[hi]["corrected_ms"] - reads[lo]["corrected_ms"] > win:
                    lo += 1
                if reads[lo]["corrected_ms"] > x["corrected_ms"] + start_within:
                    continue
                best_n = max(best_n, hi - lo + 1)
                best_b = max(best_b, sum(r["details"].get("bytes", 0) for r in reads[lo : hi + 1]))
            if best_n < th["min_reads"] and best_b < th["min_bytes"]:
                continue
            total = sum(r["details"].get("bytes", 0) for r in reads)
            summary = (
                f"{len(reads)} reads ({total // 1_000_000} MB) of {data(x['target'])} by {data(who)} from "
                f"{data('ip:' + ip)} between "
                f"{hm(reads[0]['corrected_ms'])} and {hm(reads[-1]['corrected_ms'])} UTC, starting "
                f"{(reads[0]['corrected_ms'] - x['corrected_ms']) // MINUTE} min after {data(x['actor'])} made it "
                f"public at {hm(x['corrected_ms'])} UTC"
            )
            out.append(
                make(
                    "mass_download_after_exposure",
                    [x] + reads,
                    x["actor"],
                    summary,
                    {
                        "reads": len(reads),
                        "megabytes": total // 1_000_000,
                        "max_reads_in_window": best_n,
                        "max_megabytes_in_window": best_b // 1_000_000,
                    },
                    {x["target"], who, f"ip:{ip}"},
                )
            )
    return out


def logging_disabled(evs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for e in evs:
        if e["action"] in ("logging.trail.stop", "logging.trail.delete") and e["outcome"] == "success":
            cred = e["details"].get("credential")
            summary = (
                f"{data(e['actor'])} ran {data(e['action'])} on {data(e['target'])} at {hm(e['corrected_ms'])} UTC "
                f"from {data('ip:' + str(e['src_ip']))}" + (f" with credential {data(cred)}" if cred else "")
            )
            out.append(make("logging_disabled", [e], e["actor"], summary, {"action": e["action"]}, {e["target"]}))
    return out


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evs = sorted(events, key=lambda e: (e["corrected_ms"], e["event_id"]))
    first = password_spray(evs) + brute_force_success(evs) + mfa_fatigue(evs) + impossible_travel(evs)
    priv = privilege_after_anomalous_signin(evs, first)
    expo = public_exposure_after_anomaly(evs, first + priv)
    found = first + priv + expo + mass_download_after_exposure(evs) + logging_disabled(evs)
    return sorted(found, key=lambda d: (d["_start"], d["detection_id"]))
