"""Scan history in SQLite.

One row per device per scan. The whole point of keeping history is that the
inventory is the artifact, not any single scan: you want to ask "when did this
thing first show up" months later.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .scan import Device

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    started   TEXT NOT NULL,
    subnet    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    mac       TEXT NOT NULL,
    ip        TEXT NOT NULL,
    vendor    TEXT NOT NULL DEFAULT '',
    hostname  TEXT NOT NULL DEFAULT '',
    ports     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, mac)
);
CREATE INDEX IF NOT EXISTS observations_mac ON observations(mac);
CREATE TABLE IF NOT EXISTS findings (
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule      TEXT NOT NULL,
    severity  TEXT NOT NULL,
    device    TEXT NOT NULL,
    title     TEXT NOT NULL,
    evidence  TEXT NOT NULL,
    PRIMARY KEY (scan_id, rule, device, title)
);
"""

DEFAULT_PATH = Path.home() / ".netdiff" / "history.db"


def connect(path=DEFAULT_PATH) -> sqlite3.Connection:
    path = Path(path)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def _ports_to_text(ports) -> str:
    return ",".join(str(p) for p in ports)


def _ports_from_text(text: str) -> tuple[int, ...]:
    if not text:
        return ()
    return tuple(int(p) for p in text.split(",") if p)


def record_scan(conn: sqlite3.Connection, subnet: str, devices) -> int:
    """Persist one scan; returns its id."""
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with conn:
        cursor = conn.execute(
            "INSERT INTO scans (started, subnet) VALUES (?, ?)", (started, subnet)
        )
        scan_id = cursor.lastrowid
        conn.executemany(
            "INSERT INTO observations (scan_id, mac, ip, vendor, hostname, ports)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            [
                (scan_id, d.mac, d.ip, d.vendor, d.hostname, _ports_to_text(d.ports))
                for d in devices
            ],
        )
    return scan_id


def load_scan(conn: sqlite3.Connection, scan_id: int) -> list[Device]:
    rows = conn.execute(
        "SELECT mac, ip, vendor, hostname, ports FROM observations WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()
    return [
        Device(
            mac=r["mac"],
            ip=r["ip"],
            vendor=r["vendor"],
            hostname=r["hostname"],
            ports=_ports_from_text(r["ports"]),
        )
        for r in rows
    ]


def record_findings(conn: sqlite3.Connection, scan_id: int, findings) -> None:
    """Persist the findings of one audit.

    Only what varies is stored. The teaching text lives in `audit.RULES` and is
    looked up by rule id at render time, so improving an explanation improves it
    everywhere including in reports already on disk.
    """
    with conn:
        conn.executemany(
            "INSERT OR REPLACE INTO findings"
            " (scan_id, rule, severity, device, title, evidence)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            [
                (scan_id, f.rule, f.severity, f.device, f.title, f.evidence)
                for f in findings
            ],
        )


def finding_keys(conn: sqlite3.Connection, scan_id: int) -> set:
    """Identity of each finding in a scan, for spotting what is new."""
    rows = conn.execute(
        "SELECT rule, device, title FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    return {(r["rule"], r["device"], r["title"]) for r in rows}


def last_audited_scan_id(conn: sqlite3.Connection, before_scan_id: int):
    """The most recent earlier scan that actually recorded findings.

    Plain `netdiff scan` writes no findings, so stepping back one scan would
    often compare against an empty set and call everything new.

    ponytail: an audit that found literally nothing is indistinguishable from a
    plain scan here, so a finding that clears and later returns is not marked
    NEW. Reaching that needs a network with no open ports and no gateway, since
    `open-ports-noted` fires otherwise. Add an `audits(scan_id)` table if it
    ever matters.
    """
    row = conn.execute(
        "SELECT DISTINCT scan_id FROM findings WHERE scan_id < ?"
        " ORDER BY scan_id DESC LIMIT 1",
        (before_scan_id,),
    ).fetchone()
    return row["scan_id"] if row else None


def recent_scan_ids(conn: sqlite3.Connection, limit: int = 2) -> list[int]:
    """Most recent scan ids, newest first."""
    rows = conn.execute(
        "SELECT id FROM scans ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [r["id"] for r in rows]


def previous_devices(conn: sqlite3.Connection, before_scan_id: int) -> list[Device]:
    """The scan immediately preceding `before_scan_id`, or [] if it was the first."""
    row = conn.execute(
        "SELECT id FROM scans WHERE id < ? ORDER BY id DESC LIMIT 1", (before_scan_id,)
    ).fetchone()
    return load_scan(conn, row["id"]) if row else []


def first_seen(conn: sqlite3.Connection, mac: str) -> str | None:
    row = conn.execute(
        "SELECT s.started FROM scans s JOIN observations o ON o.scan_id = s.id"
        " WHERE o.mac = ? ORDER BY s.id ASC LIMIT 1",
        (mac,),
    ).fetchone()
    return row["started"] if row else None


def inventory(conn: sqlite3.Connection) -> list[dict]:
    """Every device ever seen, with first/last sighting and its latest details."""
    rows = conn.execute(
        """
        SELECT o.mac AS mac,
               MIN(s.started) AS first_seen,
               MAX(s.started) AS last_seen,
               COUNT(*)       AS times_seen
        FROM observations o JOIN scans s ON s.id = o.scan_id
        GROUP BY o.mac
        ORDER BY last_seen DESC, mac
        """
    ).fetchall()
    out = []
    for row in rows:
        latest = conn.execute(
            "SELECT ip, vendor, hostname, ports FROM observations o"
            " JOIN scans s ON s.id = o.scan_id WHERE o.mac = ?"
            " ORDER BY s.id DESC LIMIT 1",
            (row["mac"],),
        ).fetchone()
        out.append(
            {
                "mac": row["mac"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "times_seen": row["times_seen"],
                "ip": latest["ip"],
                "vendor": latest["vendor"],
                "hostname": latest["hostname"],
                "ports": _ports_from_text(latest["ports"]),
            }
        )
    return out
