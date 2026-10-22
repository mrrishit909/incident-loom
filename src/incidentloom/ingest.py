"""Ingestion: per-source parsers, normalization, dedup, skew correction, quarantine and checkpoints.

The whole ingest state is one JSON-safe dict (lists, dicts, str, int, bool, None). A checkpoint is
that dict written as canonical JSON, so restart identity is "the state survives a JSON round-trip".
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from functools import cache
from pathlib import Path
from typing import Any

from .util import FIXTURES, HOUR, dumps, event_id, iso_ms, ms_from_dt, rel, sha256, short_hash

STATE_VERSION = 1
REASONS = (
    "parse_error",
    "wrong_field_count",
    "missing_required_field",
    "invalid_timestamp",
    "invalid_field",
    "outside_batch_window",
    "conflicting_redelivery",
)
KNOWN_SOURCES = ("idp_signin", "cloud_audit", "host_auth", "resource_access")
LATE_TOLERANCE_HOURS = 72  # a record may arrive up to this long after its time (late delivery)
EARLY_TOLERANCE_MINUTES = 30  # and may be dated this far past its batch's coverage end (plus the declared offset)
CONTENT_FIELDS = (
    "observed",
    "action",
    "outcome",
    "actor",
    "target",
    "src_ip",
    "session_id",
    "request_id",
    "parent_id",
    "process_id",
    "details",
)
RESOURCE_COLUMNS = [
    "record_id",
    "delivery_id",
    "epoch_ms",
    "principal",
    "resource",
    "operation",
    "bytes",
    "src_ip",
    "session_id",
    "request_id",
    "status",
]
MONTHS = {
    m: i + 1 for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"))
}
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$")
TZ_RE = re.compile(r"^([+-])(\d{2}):(\d{2})$")
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Za-z]{3}) +(?P<day>\d{1,2}) (?P<hms>\d{2}:\d{2}:\d{2}) (?P<host>[A-Za-z0-9.-]+) "
    r"(?P<prog>[A-Za-z_-]+)\[(?P<pid>\d+)\]: (?P<msg>.+)$"
)
HOST_MESSAGES = [
    (
        "host.ssh.login",
        "failure",
        re.compile(
            r"^Failed (?P<method>password|publickey) for (?:invalid user )?"
            r"(?P<user>\S+) from (?P<ip>\S+) port \d+"
        ),
    ),
    (
        "host.ssh.login",
        "success",
        re.compile(
            r"^Accepted (?P<method>password|publickey) for (?P<user>\S+) from "
            r"(?P<ip>\S+) port \d+"
        ),
    ),
    ("host.ssh.logout", "success", re.compile(r"^session closed for user (?P<user>\S+)$")),
    (
        "host.sudo",
        "success",
        re.compile(r"^(?P<user>\S+) : PPID=(?P<ppid>\d+) ; USER=(?P<as>\S+) ; COMMAND=(?P<cmd>.+)$"),
    ),
    (
        "host.process.exec",
        "success",
        re.compile(
            r"^exec user=(?P<user>\S+) ppid=(?P<ppid>\d+) exe=(?P<exe>\S+)"
            r'(?: args="(?P<args>.*)")?$'
        ),
    ),
    ("host.cron", "success", re.compile(r"^\((?P<user>\S+)\) CMD \((?P<cmd>.*)\)$")),
]
SENSITIVE_NAME = r"[A-Za-z0-9_.-]*?(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key|auth)"
SENSITIVE_NAME_RE = re.compile(rf"(?i)^-*{SENSITIVE_NAME}[A-Za-z0-9_.-]*$")
SECRET_PATTERNS = [
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 [REDACTED]"),
    (
        re.compile(
            rf"(?i)(?<![A-Za-z0-9])({SENSITIVE_NAME}[A-Za-z0-9_.-]*)(\s*=\s*|\"\s*:\s*\"?|\s*:\s+)([^\s,;\"'&}}]+)"
        ),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9._-]+"), "[REDACTED]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b"), "[REDACTED]"),
]


class InputError(ValueError):
    """The request or the committed input cannot be processed (CLI exit 2)."""


class Quarantine(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(reason)
        self.reason, self.detail = reason, detail


# ---- reference data -------------------------------------------------------------------------------
@cache
def geo_table() -> tuple[list[tuple[Any, str]], dict[str, int]]:
    doc = json.loads((FIXTURES / "reference" / "geo.json").read_text(encoding="ascii"))
    nets = [(ipaddress.ip_network(n["cidr"]), n["country"]) for n in doc["networks"]]
    return nets, doc["distances_km"]


def country_of(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, country in geo_table()[0]:
        if addr.version == net.version and addr in net:
            return country
    return None


def distance_km(a: str, b: str) -> int:
    if a == b:
        return 0
    return geo_table()[1]["|".join(sorted((a, b)))]


# ---- timestamp parsing ----------------------------------------------------------------------------
def parse_iso(text: Any) -> int:
    if not isinstance(text, str) or not ISO_RE.match(text):
        raise Quarantine("invalid_timestamp", "timestamp is not ISO 8601 with an explicit UTC offset")
    try:
        return ms_from_dt(datetime.fromisoformat(text))
    except ValueError:
        raise Quarantine("invalid_timestamp", "timestamp has a date or time field out of range") from None


def parse_offset(text: str) -> int:
    m = TZ_RE.match(text)
    if not m:
        raise InputError(f"timezone {text!r} is not +HH:MM")
    seconds = int(m.group(2)) * 3600 + int(m.group(3)) * 60
    return -seconds if m.group(1) == "-" else seconds


def parse_rfc3164(mon: str, day: str, hms: str, year: int, tz_seconds: int) -> int:
    """Syslog timestamps carry no year or zone: the year comes from the batch id, the zone from the manifest."""
    if mon not in MONTHS:
        raise Quarantine("invalid_timestamp", "unknown month name")
    try:
        h, m, s = (int(x) for x in hms.split(":"))
        dt = datetime(year, MONTHS[mon], int(day), h, m, s, tzinfo=timezone(timedelta(seconds=tz_seconds)))
    except ValueError:
        raise Quarantine("invalid_timestamp", "timestamp has a date or time field out of range") from None
    return ms_from_dt(dt)


def parse_epoch_ms(text: str) -> int:
    if not re.fullmatch(r"\d{12,13}", text or ""):
        raise Quarantine("invalid_timestamp", "epoch_ms is not a 12-13 digit integer")
    ms = int(text)
    if not 946_684_800_000 <= ms < 4_102_444_800_000:
        raise Quarantine("invalid_timestamp", "epoch_ms outside 2000-2100")
    return ms


# ---- per-source normalizers -----------------------------------------------------------------------
def field(obj: Any, dotted: str, kinds: tuple[type, ...] = (str,), required: bool = False) -> Any:
    """A typed field: None when absent (or a missing_required_field quarantine), invalid_field on a wrong type."""
    node: Any = obj
    for part in dotted.split("."):
        node = node.get(part) if isinstance(node, dict) else None
    if node is None or node == "":
        if required:
            raise Quarantine("missing_required_field", f"required field {dotted} is missing or empty")
        return None
    if isinstance(node, bool) or not isinstance(node, kinds):
        names = "/".join(k.__name__ for k in kinds)
        raise Quarantine("invalid_field", f"field {dotted} is a {type(node).__name__}, expected {names}")
    return node


def need(obj: Any, dotted: str, kinds: tuple[type, ...] = (str,)) -> Any:
    return field(obj, dotted, kinds, required=True)


def ent(kind: str, name: str | None) -> str | None:
    return f"{kind}:{name}" if name else None


def norm_idp(obj: Any, ctx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise Quarantine("parse_error", "record is not a JSON object")
    rid = need(obj, "id", (str, int))
    ts = need(obj, "ts")
    for f in ("event_type", "user", "ip", "result"):
        need(obj, f)
    observed = parse_iso(ts)
    push = obj["event_type"] == "mfa_push"
    details = {k: field(obj, k) for k in ("app", "mfa", "failure_reason") if field(obj, k) is not None}
    if push:
        details["push_result"] = obj["result"]
    return {
        "key": str(rid),
        "delivery_id": field(obj, "delivery_id"),
        "raw_time": ts,
        "observed": observed,
        "action": "idp.mfa_push" if push else "idp.signin",
        "outcome": "success" if obj["result"] in ("success", "approved") else "failure",
        "actor": ent("user", obj["user"]),
        "target": ent("resource", f"app/{field(obj, 'app')}"),
        "src_ip": obj["ip"],
        "session_id": field(obj, "session_id"),
        "request_id": None,
        "parent_id": None,
        "process_id": None,
        "details": details,
    }


def norm_cloud(obj: Any, ctx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise Quarantine("parse_error", "record is not a JSON object")
    rid = need(obj, "eventId", (str, int))
    ts = need(obj, "eventTime")
    for f in ("actor.principal", "operation", "target.type", "target.name", "outcome"):
        need(obj, f)
    observed = parse_iso(ts)
    ttype, tname = obj["target"]["type"], obj["target"]["name"]
    target = {"user": ent("user", tname), "instance": ent("host", tname)}.get(ttype) or ent(
        "resource", f"{ttype}/{tname}"
    )
    req = field(obj, "request", (dict,)) or {}
    details = {
        "credential": field(obj, "actor.credential"),
        "principal_type": field(obj, "actor.type"),
        **(field(req, "params", (dict,)) or {}),
    }
    return {
        "key": str(rid),
        "delivery_id": field(obj, "deliveryId"),
        "raw_time": ts,
        "observed": observed,
        "action": obj["operation"],
        "outcome": obj["outcome"],
        "actor": ent("user", obj["actor"]["principal"]),
        "target": target,
        "src_ip": field(obj, "sourceIp"),
        "session_id": field(obj, "actor.sessionId"),
        "request_id": field(req, "id"),
        "parent_id": field(req, "parentRequestId"),
        "process_id": None,
        "details": {k: v for k, v in details.items() if v is not None},
    }


def norm_host(line: Any, ctx: dict[str, Any]) -> dict[str, Any]:
    line = line.rstrip()  # a re-delivery with trailing whitespace or CR is the same record
    m = SYSLOG_RE.match(line)
    if not m:
        raise Quarantine("parse_error", "line does not match 'Mon DD HH:MM:SS host prog[pid]: message'")
    observed = parse_rfc3164(m["mon"], m["day"], m["hms"], ctx["year"], ctx["tz_seconds"])
    host, pid, msg = m["host"], m["pid"], m["msg"]
    action, outcome, fields = "host.log", "unknown", {}
    for act, out, pat in HOST_MESSAGES:
        hit = pat.match(msg)
        if hit:
            action, outcome, fields = act, out, {k: v for k, v in hit.groupdict().items() if v is not None}
            break
    details = {"program": m["prog"]} if fields else {"program": m["prog"], "message": msg[:200]}
    for k in ("method", "cmd", "exe", "args", "as"):
        if k in fields:
            details[k] = fields[k]
    return {
        "key": line,
        "delivery_id": None,
        "raw_time": f"{m['mon']} {m['day']} {m['hms']}",
        "observed": observed,
        "action": action,
        "outcome": outcome,
        "actor": ent("user", fields.get("user")),
        "target": ent("host", host),
        "src_ip": fields.get("ip"),
        "session_id": None,
        "request_id": None,
        "parent_id": f"{host}:{fields['ppid']}" if "ppid" in fields else None,
        "process_id": f"{host}:{pid}",
        "details": details,
    }


def norm_resource(row: Any, ctx: dict[str, Any]) -> dict[str, Any]:
    if len(row) != len(RESOURCE_COLUMNS):
        raise Quarantine("wrong_field_count", f"expected {len(RESOURCE_COLUMNS)} fields, found {len(row)}")
    obj = dict(zip(RESOURCE_COLUMNS, row, strict=True))
    for f in ("record_id", "epoch_ms", "principal", "resource", "operation", "status"):
        need(obj, f)
    observed = parse_epoch_ms(obj["epoch_ms"])
    if not re.fullmatch(r"[0-9]{1,15}", obj["bytes"]):
        raise Quarantine("invalid_field", "bytes is not a non-negative ASCII integer")
    parts = obj["resource"].split("/")
    return {
        "key": obj["record_id"],
        "delivery_id": obj["delivery_id"] or None,
        "raw_time": obj["epoch_ms"],
        "observed": observed,
        "action": f"resource.{obj['operation']}",
        "outcome": "success" if obj["status"] == "ok" else "failure",
        "actor": ent("user", obj["principal"]),
        "target": ent("resource", "/".join(parts[:2])),
        "src_ip": obj["src_ip"] or None,
        "session_id": obj["session_id"] or None,
        "request_id": obj["request_id"] or None,
        "parent_id": None,
        "process_id": None,
        "details": {"object": "/".join(parts[2:]) or None, "bytes": int(obj["bytes"])},
    }


NORMALIZERS = {"jsonl": norm_idp, "json": norm_cloud, "syslog": norm_host, "csv": norm_resource}


def redact_text(text: str) -> str:
    for pat, sub in SECRET_PATTERNS:
        text = pat.sub(sub, text)
    return text


def redact_value(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {k: redact_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(key, v) for v in value]
    if isinstance(value, str):
        return "[REDACTED]" if SENSITIVE_NAME_RE.match(key) else redact_text(value)
    return value


def strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [*value.keys(), *(s for v in value.values() for s in strings(v))]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return [value] if isinstance(value, str) else []


def normalize(fmt: str, parsed: Any, ctx: dict[str, Any]) -> dict[str, Any]:
    """Normalize one parsed record. Every per-record failure becomes a Quarantine with a reason code; free-text
    detail values are redacted (the event id is derived from the raw key, before redaction)."""
    if isinstance(parsed, Quarantine):
        raise parsed
    try:
        norm = NORMALIZERS[fmt](parsed, ctx)
    except Quarantine:
        raise
    except Exception as exc:  # malformed input must never abort the run
        raise Quarantine("invalid_field", f"record could not be normalized ({type(exc).__name__})") from None
    if any("\ud800" <= c <= "\udfff" for text in strings(norm) for c in text):
        raise Quarantine("invalid_field", "a text field contains an unpaired surrogate")
    redacted = redact_value("details", norm["details"])
    norm["redacted_fields"] = sorted(f"details.{k}" for k in norm["details"] if redacted[k] != norm["details"][k])
    norm["details"] = redacted
    return norm


def parse_raw(fmt: str, raw_text: str) -> Any:
    if fmt in ("jsonl", "json"):
        try:
            return json.loads(raw_text)
        except ValueError:
            return Quarantine("parse_error", "line is not valid JSON")
    if fmt == "csv":
        return next(csv.reader(io.StringIO(raw_text)), [])
    return raw_text


def content(norm_or_event: dict[str, Any]) -> dict[str, Any]:
    return {k: norm_or_event.get(k) for k in CONTENT_FIELDS}


# ---- raw record readers ---------------------------------------------------------------------------
def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def read_records(path: Path, fmt: str) -> list[tuple[dict[str, Any], str, Any]]:
    """[(raw_ref, raw_text, parsed)] where parsed is an exception instance for unreadable records."""
    text = read_text(path)
    ref = rel(path)
    out: list[tuple[dict[str, Any], str, Any]] = []
    if fmt == "json":
        try:
            doc = json.loads(text)
            records = doc["records"]
            assert isinstance(records, list)
        except (ValueError, KeyError, TypeError, AssertionError):
            raise InputError(f"{ref} is not a JSON document with a records array") from None
        for i, rec in enumerate(records):
            out.append(({"file": ref, "pointer": f"/records/{i}"}, json.dumps(rec, separators=(",", ":")), rec))
        return out
    lines = text.split("\n")
    if fmt == "csv":
        header = next(csv.reader([lines[0]]), [])
        if header != RESOURCE_COLUMNS:
            raise InputError(f"{ref} header does not match the resource-access columns")
    for no, line in enumerate(lines, 1):
        if not line or (fmt == "csv" and no == 1):
            continue
        out.append(({"file": ref, "line": no}, line, parse_raw(fmt, line)))
    return out


def raw_record(raw_ref: dict[str, Any]) -> str | None:
    """Re-read one raw record by reference (used by validation to prove no event id was invented)."""
    from .util import ROOT

    path = ROOT / raw_ref["file"]
    if not path.is_file() or not raw_ref["file"].startswith("fixtures/batches/"):
        return None
    if "pointer" in raw_ref:
        records = json.loads(read_text(path))["records"]
        i = int(raw_ref["pointer"].rsplit("/", 1)[1])
        return json.dumps(records[i], separators=(",", ":")) if i < len(records) else None
    lines = read_text(path).split("\n")
    no = raw_ref["line"]
    return lines[no - 1] if 0 < no <= len(lines) else None


def record_event_id(source: str, fmt: str, raw_text: str) -> str | None:
    """The event id a raw record would get, or None when it does not normalize."""
    try:
        key = normalize(fmt, parse_raw(fmt, raw_text), {"year": 2026, "tz_seconds": 0})["key"]
        return event_id(source, key)
    except (Quarantine, UnicodeError):
        return None


def redact(raw: str) -> str:
    """Quarantine excerpt: printable ASCII only, secrets masked, at most 160 characters."""
    clean = "".join(c if 32 <= ord(c) < 127 else "?" for c in raw)
    return redact_text(clean)[:160]


# ---- state, batches, checkpoints ------------------------------------------------------------------
def new_state(correction: str) -> dict[str, Any]:
    return {
        "version": STATE_VERSION,
        "clock_skew_correction": correction,
        "batches_ingested": [],
        "events": {},
        "quarantine": [],
        "stats": [],
        "high_water": {},
        "coverage": [],
        "declared_gaps": [],
        "inputs": {},
    }


def load_manifest(batch: str) -> tuple[Path, dict[str, Any]]:
    bdir = FIXTURES / "batches" / batch
    path = bdir / "batch.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        assert manifest["batch"] == batch and isinstance(manifest["sources"], list)
        for src in manifest["sources"]:
            assert {"name", "file", "format", "declared_clock_offset_seconds", "coverage"} <= set(src)
            assert src["format"] in NORMALIZERS and (bdir / src["file"]).is_file()
    except (OSError, ValueError, KeyError, TypeError, AssertionError):
        raise InputError(f"batch {batch}: missing or malformed batch.json or source file") from None
    return path, manifest


def batch_summary(state: dict[str, Any], batch: str) -> dict[str, Any]:
    return {
        "after_batch": batch,
        "events_total": len(state["events"]),
        "quarantined_total": len(state["quarantine"]),
        "state_sha256": state_digest(state),
    }


def ingest_batch(state: dict[str, Any], batch: str) -> bool:
    """Append one batch. Returns False (and changes nothing) when the batch is already in the state."""
    if batch in state["batches_ingested"]:
        return False
    manifest_path, manifest = load_manifest(batch)
    state["inputs"][rel(manifest_path)] = sha256(manifest_path.read_bytes())
    correct = state["clock_skew_correction"] == "on"
    year = int(batch[:4])
    for src in manifest["sources"]:
        name, fmt = src["name"], src["format"]
        path = manifest_path.parent / src["file"]
        state["inputs"][rel(path)] = sha256(path.read_bytes())
        offset = int(src["declared_clock_offset_seconds"])
        skew_ms = -offset * 1000 if correct else 0
        cov_start, cov_end = (parse_iso(c) for c in src["coverage"])
        window = (
            cov_start - LATE_TOLERANCE_HOURS * HOUR,
            cov_end + (EARLY_TOLERANCE_MINUTES * 60 + abs(offset)) * 1000,
        )
        state["coverage"].append({"batch": batch, "source": name, "start": iso_ms(cov_start), "end": iso_ms(cov_end)})
        ctx = {"year": year, "tz_seconds": parse_offset(src.get("timezone", "+00:00"))}
        stat = {
            "batch": batch,
            "source": name,
            "file": rel(path),
            "file_sha256": state["inputs"][rel(path)],
            "format": fmt,
            "timestamp_format": src.get("timestamp_format"),
            "timezone": src.get("timezone"),
            "declared_clock_offset_seconds": offset,
            "skew_applied_seconds": skew_ms // 1000,
            "received": 0,
            "accepted": 0,
            "duplicates_exact": 0,
            "duplicates_redelivered": 0,
            "out_of_order": 0,
            "quarantined": {},
        }

        def quarantine(
            raw_ref: dict[str, Any], raw_text: str, q: Quarantine, name: str = name, stat: dict = stat, **extra: Any
        ) -> None:
            loc = raw_ref.get("pointer") or raw_ref.get("line")
            state["quarantine"].append(
                {
                    "quarantine_id": "q-" + short_hash(f"{name}|{batch}|{raw_ref['file']}|{loc}"),
                    "batch": batch,
                    "source": name,
                    "raw_ref": raw_ref,
                    "reason": q.reason,
                    "detail": q.detail,
                    "excerpt": redact(raw_text),
                    **extra,
                }
            )
            stat["quarantined"][q.reason] = stat["quarantined"].get(q.reason, 0) + 1

        for raw_ref, raw_text, parsed in read_records(path, fmt):
            stat["received"] += 1
            try:
                norm = normalize(fmt, parsed, ctx)
                eid = event_id(name, norm["key"])
            except Quarantine as q:
                quarantine(raw_ref, raw_text, q)
                continue
            delivery = {"batch": batch, "delivery_id": norm["delivery_id"], "raw_ref": raw_ref}
            existing = state["events"].get(eid)
            if existing is not None:
                mine = {**content(norm), "observed": iso_ms(norm["observed"])}
                theirs = {**content(existing), "observed": existing["observed_at_utc"]}
                differ = sorted(k for k in CONTENT_FIELDS if mine[k] != theirs[k])
                if differ:  # same record id, different content: keep the first, quarantine this delivery visibly
                    quarantine(
                        raw_ref,
                        raw_text,
                        Quarantine(
                            "conflicting_redelivery", f"record id already ingested with different {', '.join(differ)}"
                        ),
                        conflicts_with=eid,
                        conflicting_fields=differ,
                    )
                    continue
                same = existing["delivery_id"] == norm["delivery_id"]
                delivery["kind"] = "exact_duplicate" if same else "redelivery"
                existing["duplicates"].append(delivery)
                stat["duplicates_exact" if same else "duplicates_redelivered"] += 1
                continue
            t = norm["observed"] + skew_ms
            if not window[0] <= t <= window[1]:
                quarantine(
                    raw_ref,
                    raw_text,
                    Quarantine(
                        "outside_batch_window",
                        f"event time {iso_ms(t)} is outside batch {batch} coverage "
                        f"{iso_ms(cov_start)} to {iso_ms(cov_end)} (late tolerance {LATE_TOLERANCE_HOURS} h, early "
                        f"tolerance {EARLY_TOLERANCE_MINUTES} min plus the declared offset)",
                    ),
                )
                continue
            late = t < cov_start or t < state["high_water"].get(name, t)
            state["high_water"][name] = max(t, state["high_water"].get(name, t))
            stat["accepted"] += 1
            stat["out_of_order"] += int(late)
            event = {
                "event_id": eid,
                "source": name,
                "source_record_id": None if fmt == "syslog" else norm["key"],
                "batch": batch,
                "observed_at_raw": norm["raw_time"],
                "observed_at_utc": iso_ms(norm["observed"]),
                "corrected_at_utc": iso_ms(t),
                "corrected_ms": t,
                "skew_applied_seconds": skew_ms // 1000,
                "actor": norm["actor"],
                "target": norm["target"],
                "action": norm["action"],
                "outcome": norm["outcome"],
                "src_ip": norm["src_ip"],
                "geo": country_of(norm["src_ip"]),
                "session_id": norm["session_id"],
                "request_id": norm["request_id"],
                "parent_id": norm["parent_id"],
                "process_id": norm["process_id"],
                "details": norm["details"],
                "delivery_id": norm["delivery_id"],
                "raw_ref": raw_ref,
                "duplicates": [],
                "out_of_order": late,
            }
            if norm["redacted_fields"]:
                event["redacted_fields"] = norm["redacted_fields"]
            state["events"][eid] = event
        state["stats"].append(stat)
    for gap in manifest.get("declared_gaps", []):
        state["declared_gaps"].append({**gap, "batch": batch})
    state["batches_ingested"].append(batch)
    return True


def state_digest(state: dict[str, Any]) -> str:
    return sha256(dumps(state).encode("ascii"))


def save_checkpoint(state: dict[str, Any], per_batch: list[dict[str, Any]], path: Path) -> str:
    """Write the complete ingest state plus the per-batch history; everything a resumed run needs."""
    data = dumps({"state": state, "per_batch": per_batch}).encode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return sha256(data)


def load_checkpoint(path: Path, correction: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    doc = json.loads(path.read_text(encoding="ascii"))
    state = doc.get("state") or {}
    if state.get("version") != STATE_VERSION or state.get("clock_skew_correction") != correction:
        raise InputError("checkpoint does not match this request (version or clock-skew setting)")
    return state, doc["per_batch"]
