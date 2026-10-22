"""Shared fixtures. Scratch output goes to <repo>/.tmp/tests (gitignored), never the system temp dir."""

import json
import re
import shutil
from pathlib import Path

import pytest

from incidentloom import pipeline
from incidentloom.util import BATCH_IDS, ROOT

FULL = {"batches": list(BATCH_IDS), "clock_skew_correction": "on", "simulate_restart_after": 0}
SCRATCH = ROOT / ".tmp" / "tests"


def scratch(name: str) -> Path:
    path = SCRATCH / re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    shutil.rmtree(path, ignore_errors=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture
def work(request: pytest.FixtureRequest) -> Path:
    path = scratch(request.node.name)
    path.mkdir()
    return path


@pytest.fixture(scope="session")
def full_run() -> Path:
    out = scratch("session-full-run")
    pipeline.run(FULL, out)
    return out


def load(out: Path, name: str):
    text = (out / name).read_text(encoding="ascii")
    return text if name.endswith(".md") else json.loads(text)


def copy_run(src: Path, dest: Path) -> Path:
    shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(src, dest)
    return dest


def rewrite(out: Path, name: str, mutate) -> None:
    doc = load(out, name)
    doc = mutate(doc)
    data = doc if isinstance(doc, str) else json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n"
    (out / name).write_text(data, encoding="ascii")
