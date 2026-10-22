"""Run entry points for the harness: `run(params, out_dir)` and `request_problems(params)`."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from . import __version__
from .ingest import InputError, ingest_batch, load_checkpoint, new_state, save_checkpoint, state_digest
from .outputs import EVIDENCE_FILES, render_evidence
from .util import BATCH_IDS, FIXTURES, SCHEMAS, dumps, jbytes, sha256

__all__ = ["InputError", "compute", "request_errors", "request_problems", "run"]


def request_problems(params: dict[str, Any]) -> list[str]:
    """Feasibility rules beyond the JSON schema: contiguous batches from the first, and the restart bound."""
    batches = list(params.get("batches") or [])
    problems = []
    if batches != list(BATCH_IDS[: len(batches)]):
        problems.append(
            f"batches must be a contiguous run starting at {BATCH_IDS[0]}, in order (for example {list(BATCH_IDS[:2])})"
        )
    restart = params.get("simulate_restart_after", 0)
    if isinstance(restart, int) and restart and restart >= len(batches):
        problems.append(
            f"simulate_restart_after must be less than the number of batches ({len(batches)}) when non-zero"
        )
    return problems


def request_errors(params: Any) -> list[str]:
    request_schema = json.loads((SCHEMAS / "request.schema.json").read_text(encoding="utf-8"))
    errors = [
        f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message[:160]}"
        for e in Draft202012Validator(request_schema).iter_errors(params)
    ]
    return errors or request_problems(params)


def ingest_all(
    batches: list[str], correction: str, restart_after: int, workdir: Path | None
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any] | None]:
    """Ingest batches in order, writing a checkpoint after each. With restart_after=N, stop after batch N,
    drop every in-memory structure, reload the checkpoint from disk and continue with the rest."""
    state = new_state(correction)
    per_batch, restart = [], None
    for n, batch in enumerate(batches, 1):
        ingest_batch(state, batch)
        digest = state_digest(state)
        per_batch.append(
            {
                "after_batch": batch,
                "events_total": len(state["events"]),
                "quarantined_total": len(state["quarantine"]),
                "state_sha256": digest,
            }
        )
        ckpt_sha = save_checkpoint(state, per_batch, workdir / "checkpoint.json") if workdir else None
        if n == restart_after:
            assert workdir is not None
            del state, per_batch  # the restart: nothing ingested so far survives except the checkpoint file
            state, per_batch = load_checkpoint(workdir / "checkpoint.json", correction)
            resumed = state_digest(state)
            noop = ingest_batch(state, batch) is False and state_digest(state) == resumed
            restart = {
                "stopped_after_batch": batch,
                "checkpoint_sha256": ckpt_sha,
                "state_sha256_before_stop": digest,
                "state_sha256_after_reload": resumed,
                "state_matches_checkpoint": resumed == digest,
                "reingest_of_last_batch_was_noop": noop,
                "batches_after_resume": batches[n:],
            }
    return state, per_batch, restart


def compute(params: dict[str, Any], workdir: Path) -> dict[str, bytes]:
    batches, correction = list(params["batches"]), params["clock_skew_correction"]
    restart_after = int(params["simulate_restart_after"])
    state, per_batch, restart = ingest_all(batches, correction, restart_after, workdir)
    evidence = render_evidence(state, params, per_batch)
    comparison = None
    if restart is not None:
        ref_state, ref_batches, _ = ingest_all(batches, correction, 0, None)
        reference = render_evidence(ref_state, params, ref_batches)
        differing = sorted(n for n in EVIDENCE_FILES if evidence[n] != reference[n])
        comparison = {
            "against": "an internal uninterrupted run of the same request, computed in memory",
            "identical": not differing
            and restart["state_matches_checkpoint"]
            and restart["reingest_of_last_batch_was_noop"],
            "differing_files": differing,
            "uninterrupted_output_hashes": {n: sha256(reference[n]) for n in EVIDENCE_FILES},
        }
    inputs = {k: v for k, v in sorted(state["inputs"].items())}
    hash_basis = {"params": params, "batch_file_sha256": inputs, "package_version": __version__}
    labels = evidence["detector_metrics.json"]
    manifest = {
        "package": "incidentloom",
        "version": __version__,
        "params": params,
        "input_manifest_hash": sha256(dumps(hash_basis).encode("ascii")),
        "input_manifest_hash_basis": "sha256 of canonical JSON {params, batch_file_sha256, package_version}",
        "inputs": inputs,
        "labels_sha256": json.loads(labels)["labels_sha256"],
        "reference_files": {"fixtures/reference/geo.json": sha256((FIXTURES / "reference" / "geo.json").read_bytes())},
        "outputs": sorted([*EVIDENCE_FILES, "manifest.json", "replay.json"]),
        "synthetic": True,
    }
    manifest_bytes = jbytes(manifest)
    replay = {
        "simulate_restart_after": restart_after,
        "mode": "restart" if restart else "uninterrupted",
        "restart": restart,
        "comparison": comparison,
        "output_hashes": {n: sha256(evidence[n]) for n in EVIDENCE_FILES},
        "manifest_sha256": sha256(manifest_bytes),
        "note": "output_hashes cover every evidence file and are what the restart comparison uses; manifest.json "
        "(hashed separately) and this file are the only outputs that record the restart setting.",
    }
    return {**evidence, "replay.json": jbytes(replay), "manifest.json": manifest_bytes}


def run(params: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Validate the request, compute every output and write them to out_dir (which must be absent or empty)."""
    errors = request_errors(params)
    if errors:
        raise InputError("; ".join(errors))
    out_dir = Path(out_dir)
    if out_dir.exists() and (not out_dir.is_dir() or any(out_dir.iterdir())):
        raise InputError(f"output directory {out_dir.name} exists and is not empty")
    out_dir.mkdir(parents=True, exist_ok=True)
    work = out_dir / ".work"
    try:
        files = compute(params, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for name, data in sorted(files.items()):
        (out_dir / name).write_bytes(data)
    return json.loads(files["summary.json"])
