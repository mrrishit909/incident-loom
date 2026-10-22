"""CLI contract: exit 0 on success, 2 on an invalid request or bad input, 1 on invalid outputs."""

import json
import subprocess
import sys

from incidentloom import __main__ as cli
from incidentloom import outputs

from .conftest import FULL, load


def run_cli(work, params, out_name="out", raw=None):
    req = work / "request.json"
    req.write_text(raw if raw is not None else json.dumps(params))
    return cli.main(["run", "--request", str(req), "--out", str(work / out_name)])


def test_cli_success_writes_valid_outputs(work, full_run, capsys):
    assert run_cli(work, {**FULL, "batches": FULL["batches"][:2]}) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["batches"] == FULL["batches"][:2] and outputs.validate(work / "out") == []


def test_cli_rejects_bad_requests_with_exit_2(work, full_run):
    assert run_cli(work, {**FULL, "batches": ["2026-10-13", "2026-10-15"]}) == 2
    assert run_cli(work, {**FULL, "batches": ["2026-10-14"]}) == 2
    assert run_cli(work, {**FULL, "simulate_restart_after": 6}) == 2
    assert run_cli(work, {**FULL, "batches": ["2026-10-13"], "simulate_restart_after": 1}) == 2
    assert run_cli(work, {**FULL, "clock_skew_correction": "sometimes"}) == 2
    assert run_cli(work, None, raw="{not json") == 2
    (work / "busy").mkdir()
    (work / "busy" / "keep.txt").write_text("x")
    assert run_cli(work, FULL, out_name="busy") == 2


def test_cli_exit_1_when_outputs_fail_validation(work, monkeypatch):
    monkeypatch.setattr(outputs, "validate", lambda out: ["injected problem"])
    assert run_cli(work, {**FULL, "batches": FULL["batches"][:1]}) == 1


def test_module_entry_point_and_fixture_command(work, full_run):
    proc = subprocess.run([sys.executable, "-m", "incidentloom", "--help"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0 and "fixtures" in proc.stdout
    assert load(full_run, "manifest.json")["input_manifest_hash"].startswith("sha256:")
