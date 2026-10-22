"""Incident Loom hooks for the generic harness (compute, feasibility, validation, headline, memory)."""

from __future__ import annotations

import json
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from harness.core import config
from harness.state import read_json

PUBLIC_FILES = [
    "manifest.json", "ingest.json", "events.json", "quarantine.json", "entities.json", "detections.json",
    "incidents.json", "correlations.json", "gaps.json", "detector_metrics.json", "replay.json", "checkpoint.json",
    "summary.json", "report.md", "checks.json",
]


def compute(params: dict[str, Any], out_dir: Path) -> None:
    """Deterministic investigation run (called by `python -m harness compute` on the read-only compute job)."""
    from incidentloom.pipeline import run

    run(params, out_dir)


def request_problems(params: dict[str, Any]) -> list[str]:
    from incidentloom.pipeline import request_problems as engine_problems

    return list(engine_problems(params))


def validate_outputs(out_dir: Path) -> list[str]:
    from incidentloom.outputs import validate

    return validate(out_dir)


def headline(out_dir: Path) -> str | None:
    return json.loads((out_dir / "summary.json").read_text())["headline"]


def on_publish(root: Path, record: dict[str, Any], out_dir: Path) -> list[str]:
    return []


def memory_candidates(root: Path) -> list[dict[str, Any]]:
    """Lessons backed by at least three completed runs: detectors that keep firing, sources that keep going silent."""
    cfg = config()
    index = read_json(root, "index.json", {"runs": []})
    fired: Counter[str] = Counter()
    fired_runs: dict[str, list[str]] = {}
    silent: Counter[str] = Counter()
    silent_runs: dict[str, list[str]] = {}
    for entry in index["runs"]:
        if entry["status"] != "completed":
            continue
        rid = entry["run_id"]
        detections = read_json(root, f"runs/{rid}/detections.json")
        gaps = read_json(root, f"runs/{rid}/gaps.json")
        if not detections or not gaps:
            continue
        for det in sorted({d["detector"] for d in _list(detections, "detections")}):
            fired[det] += 1
            fired_runs.setdefault(det, []).append(rid)
        for src in sorted({g["source"] for g in _list(gaps, "gaps")}):
            silent[src] += 1
            silent_runs.setdefault(src, []).append(rid)
    base = f"https://github.com/{cfg['owner']}/{cfg['repo']}/blob/{cfg['state_branch']}"
    expires = (date.today() + timedelta(days=90)).isoformat()
    out = []
    for det, count in sorted(fired.items()):
        if count >= 3:
            runs = sorted(set(fired_runs[det]))[:20]
            out.append({
                "topic": f"Detector {det} fires repeatedly",
                "finding": f"Detector {det} produced at least one detection in {count} completed runs "
                           "on the synthetic batches.",
                "supporting_run_ids": runs,
                "evidence_links": [f"{base}/runs/{r}/detections.json" for r in runs[:5]],
                "scope": "data-quality",
                "confidence": "medium" if count >= 6 else "low",
                "revalidate_when": "after a fixture, threshold or detector change",
                "expires_on": expires,
            })
    for src, count in sorted(silent.items()):
        if count >= 3:
            runs = sorted(set(silent_runs[src]))[:20]
            out.append({
                "topic": f"Source {src} has evidence gaps",
                "finding": f"Source {src} had a declared or silent gap in {count} completed runs; "
                           "hypotheses depending on it carry lowered confidence.",
                "supporting_run_ids": runs,
                "evidence_links": [f"{base}/runs/{r}/gaps.json" for r in runs[:5]],
                "scope": "data-quality",
                "confidence": "medium" if count >= 6 else "low",
                "revalidate_when": "after the fixtures change or the silence threshold changes",
                "expires_on": expires,
            })
    return out


def _list(doc: Any, key: str) -> list[dict[str, Any]]:
    """The list under `key`; an unrecognised shape is an error, never silently empty."""
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict) and isinstance(doc.get(key), list):
        return doc[key]
    raise ValueError(f"expected a list under {key!r}")
