"""CLI: `python -m incidentloom run --request REQUEST.json --out OUT_DIR` and `fixtures --out DIR`.

Exit codes for `run`: 0 success, 1 outputs failed validation, 2 invalid request or bad input.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="incidentloom")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run_p = sub.add_parser("run", help="ingest, correlate and investigate the requested batches")
    run_p.add_argument("--request", required=True)
    run_p.add_argument("--out", required=True)
    fix_p = sub.add_parser("fixtures", help="regenerate the synthetic fixtures byte-for-byte")
    fix_p.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    if args.cmd == "fixtures":
        from .fixtures import generate

        print(json.dumps(generate(Path(args.out)), sort_keys=True))
        return 0

    from .outputs import validate
    from .pipeline import InputError, run

    try:
        params = json.loads(Path(args.request).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"invalid request file: {type(exc).__name__}", file=sys.stderr)
        return 2
    out = Path(args.out)
    try:
        summary = run(params, out)
    except InputError as exc:
        print(f"invalid request or input: {exc}", file=sys.stderr)
        return 2
    problems = validate(out)
    if problems:
        for problem in problems[:20]:
            print(f"output problem: {problem}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
