"""Real hooks against real engine output (the fake-hook tests cannot catch contract drift)."""

import json
import re
import shutil
from pathlib import Path

import project_hooks
from harness.memory import screen

ALL = ["2026-10-13", "2026-10-14", "2026-10-15", "2026-10-16", "2026-10-17", "2026-10-18"]
REQUEST = {"batches": ALL, "clock_skew_correction": "on", "simulate_restart_after": 0}


def test_hooks_on_real_outputs(tmp_path: Path):
    out = tmp_path / "out"
    project_hooks.compute(REQUEST, out)
    assert project_hooks.validate_outputs(out) == []
    # The harness copies this into the run record, whose schema requires the sha256: prefix.
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", json.loads((out / "manifest.json").read_text())["input_manifest_hash"])
    summary = json.loads((out / "summary.json").read_text())
    assert project_hooks.headline(out) == summary["headline"] and summary["headline"]

    state = tmp_path / "state"
    runs = []
    for i in range(3):
        rid = f"incident-loom-2026102{i}T000000Z-abcdef12-a1"
        shutil.copytree(out, state / "runs" / rid)
        runs.append({"run_id": rid, "status": "completed", "created_at": f"2026-10-2{i}T00:00:00Z"})
    (state / "index.json").write_text(json.dumps({"runs": runs}))
    candidates = project_hooks.memory_candidates(state)
    topics = {c["topic"] for c in candidates}
    assert any(t.endswith("fires repeatedly") for t in topics)
    assert any(t.endswith("has evidence gaps") for t in topics)
    for c in candidates:
        entry = {**c, "id": "mem-0123456789", "status": "active", "date": "2026-10-21", "supersedes": []}
        assert screen(entry) == [], (c["topic"], screen(entry))


def test_request_problems_contiguous_batches_and_restart_bound():
    assert project_hooks.request_problems(REQUEST) == []
    assert project_hooks.request_problems({**REQUEST, "batches": ["2026-10-14", "2026-10-15"]})
    assert project_hooks.request_problems({**REQUEST, "batches": ALL[:2], "simulate_restart_after": 2})
