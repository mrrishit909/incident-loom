"""Small shared helpers: paths, canonical JSON, hashing, integer-millisecond UTC time."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
SCHEMAS = ROOT / "schemas"
BATCH_IDS = ("2026-10-13", "2026-10-14", "2026-10-15", "2026-10-16", "2026-10-17", "2026-10-18")
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
MINUTE = 60_000
HOUR = 60 * MINUTE
SYNTHETIC_DISCLAIMER = (
    "Synthetic data: every event, entity and label was generated for a fictional organisation. "
    "Detector metrics measure agreement with synthetic labels and do not estimate real-world performance."
)
EVENT_ID_RE = re.compile(r"\b(?:ev|q)-[0-9a-f]{16}\b")


def dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def jbytes(obj: Any) -> bytes:
    return (dumps(obj) + "\n").encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def short_hash(text: str, n: int = 16) -> str:
    return sha256_hex(text.encode("utf-8"))[:n]


def event_id(source: str, key: str) -> str:
    """Stable event id from the source name and its record id (or the raw record text when it has none)."""
    return "ev-" + short_hash(f"{source}|{key}")


def rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def ms_from_dt(dt: datetime) -> int:
    delta = dt.astimezone(UTC) - EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1000 + delta.microseconds // 1000


def dt_from_ms(ms: int) -> datetime:
    return EPOCH + timedelta(milliseconds=ms)


def iso_ms(ms: int) -> str:
    dt = dt_from_ms(ms)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{ms % 1000:03d}Z"


def parse_utc(text: str) -> int:
    """Parse our own output format (or a plain ...Z timestamp) back to milliseconds."""
    return ms_from_dt(datetime.fromisoformat(text))


def fmt_minutes(ms: int) -> str:
    minutes, seconds = divmod(abs(ms) // 1000, 60)
    return f"{minutes} min {seconds} s"
