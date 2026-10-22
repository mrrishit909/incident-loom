"""Detector evaluation against labelled scenarios.

This is the ONLY module that reads the labels file. It runs after detection and investigation have
finished and only reads their outputs; nothing it computes flows back into detection.
"""

from __future__ import annotations

import json
from typing import Any

from .detect import DETECTORS, THRESHOLDS
from .util import FIXTURES, SYNTHETIC_DISCLAIMER, rel, sha256

LABELS_PATH = FIXTURES / "labels" / "scenarios.json"
DETECTOR_TECHNIQUES = {
    "password_spray": ["password_spray"],
    "brute_force_success": ["credential_brute_force"],
    "impossible_travel": ["impossible_travel"],
    "mfa_fatigue": ["mfa_fatigue"],
    "privilege_after_anomalous_signin": ["privilege_escalation", "persistence_access_key"],
    "public_exposure_after_anomaly": ["public_exposure"],
    "mass_download_after_exposure": ["mass_download"],
    "logging_disabled": ["logging_disabled"],
}
SCORING = (
    "A scenario counts as detected when any detection shares at least one event id with it. Overall: "
    "tp = incident scenarios detected, fp = benign scenarios detected, fn = incident scenarios not detected, "
    "tn = benign scenarios not detected. Per detector: tp/fp count scenarios that detector touched; recall uses "
    "only incident scenarios whose labelled techniques the detector targets. Scenarios whose events are not "
    "all present in the ingested batches are excluded and listed. Precision or recall is null when its "
    "denominator is zero."
)


def ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def score(split: str, scenarios: dict[str, Any], dets: list[dict[str, Any]], accepted: set[str]) -> dict[str, Any]:
    rows, excluded = [], []
    for sid in sorted(scenarios):
        sc = scenarios[sid]
        if sc["split"] != split:
            continue
        events = set(sc["events"])
        if not events <= accepted:
            excluded.append(
                {
                    "scenario_id": sid,
                    "reason": f"{len(events - accepted)} of {len(events)} labelled events "
                    "are not in the ingested batches",
                }
            )
            continue
        fired = sorted({d["detector"] for d in dets if events & set(d["event_ids"])})
        positive = sc["expected"] == "incident"
        outcome = ("tp" if fired else "fn") if positive else ("fp" if fired else "tn")
        rows.append(
            {
                "scenario_id": sid,
                "kind": sc["kind"],
                "expected": sc["expected"],
                "techniques": sorted(sc["techniques"]),
                "detected_by": fired,
                "outcome": outcome,
            }
        )
    counts = {k: sum(1 for r in rows if r["outcome"] == k) for k in ("tp", "fp", "fn", "tn")}
    overall = {
        **counts,
        "precision": ratio(counts["tp"], counts["tp"] + counts["fp"]),
        "recall": ratio(counts["tp"], counts["tp"] + counts["fn"]),
    }
    per = []
    for det in DETECTORS:
        did = det["id"]
        touched = [r for r in rows if did in r["detected_by"]]
        tp = sum(1 for r in touched if r["expected"] == "incident")
        fp = len(touched) - tp
        relevant = [
            r for r in rows if r["expected"] == "incident" and set(r["techniques"]) & set(DETECTOR_TECHNIQUES[did])
        ]
        hit = sum(1 for r in relevant if did in r["detected_by"])
        tn = sum(1 for r in rows if r["expected"] == "benign" and did not in r["detected_by"])
        per.append(
            {
                "detector": did,
                "tp": tp,
                "fp": fp,
                "fn": len(relevant) - hit,
                "tn": tn,
                "relevant_incident_scenarios": len(relevant),
                "precision": ratio(tp, tp + fp),
                "recall": ratio(hit, len(relevant)),
            }
        )
    return {
        "scenarios_scored": len(rows),
        "overall": overall,
        "per_detector": per,
        "scenarios": rows,
        "excluded": excluded,
    }


def evaluate(dets: list[dict[str, Any]], accepted: set[str]) -> dict[str, Any]:
    base = {
        "synthetic": True,
        "disclaimer": SYNTHETIC_DISCLAIMER,
        "scoring": SCORING,
        "labels_file": rel(LABELS_PATH),
        "thresholds": THRESHOLDS,
        "tuning": {d["id"]: d["tuning"] for d in DETECTORS},
        "detector_techniques": DETECTOR_TECHNIQUES,
    }
    try:
        raw = LABELS_PATH.read_bytes()
        scenarios = json.loads(raw)["scenarios"]
        assert isinstance(scenarios, dict)
    except (OSError, ValueError, KeyError, TypeError, AssertionError):
        return {
            **base,
            "labels_status": "unavailable",
            "labels_sha256": None,
            "held_out": None,
            "development": None,
            "background_detections": None,
        }
    labelled = {e for sc in scenarios.values() for e in sc.get("events", [])}
    background = sorted(d["detection_id"] for d in dets if not labelled & set(d["event_ids"]))
    return {
        **base,
        "labels_status": "loaded",
        "labels_sha256": sha256(raw),
        "held_out": {
            "role": "evaluation: these labels were never used to choose thresholds",
            **score("held_out", scenarios, dets, accepted),
        },
        "development": {
            "role": "tuning data: thresholds were chosen on these scenarios, so these numbers are "
            "not an estimate of anything",
            **score("development", scenarios, dets, accepted),
        },
        "background_detections": {
            "count": len(background),
            "detection_ids": background,
            "note": "Detections that touch no labelled scenario. All background activity "
            "is benign by construction, so each one would be a false positive.",
        },
    }
