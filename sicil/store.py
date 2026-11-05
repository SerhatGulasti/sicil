"""Sicil's own state: runs, findings and the last known AUR data."""

import json
import os
import sqlite3
from dataclasses import dataclass, field

from .rules import AUR, EVENT_KEYS, AurState, Finding, OpenEvent

SCHEMA_VERSION = 3

ENRICHMENT_TABLES = """
CREATE TABLE cve_cache (
    cve TEXT PRIMARY KEY,
    raw TEXT,
    fetched_at INTEGER NOT NULL
);
CREATE TABLE enrich_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

SCHEMA = """
CREATE TABLE runs (
    id INTEGER PRIMARY KEY,
    started_at INTEGER NOT NULL,
    finished_at INTEGER NOT NULL,
    repo_ok INTEGER NOT NULL,
    aur_ok INTEGER NOT NULL,
    yoklama_ok INTEGER NOT NULL,
    warnings TEXT NOT NULL,
    kernel_ok INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    strip TEXT NOT NULL,
    package TEXT NOT NULL,
    key TEXT NOT NULL,
    level TEXT NOT NULL,
    detail TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    closed_at INTEGER,
    first_run INTEGER NOT NULL REFERENCES runs(id),
    level_run INTEGER NOT NULL REFERENCES runs(id),
    closed_run INTEGER REFERENCES runs(id),
    last_used INTEGER,
    leaves TEXT,
    suggest_removal INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX findings_open
    ON findings (strip, package, key) WHERE closed_at IS NULL;
CREATE TABLE aur_state (
    name TEXT PRIMARY KEY,
    maintainer TEXT,
    found INTEGER NOT NULL,
    ever_found INTEGER NOT NULL,
    version TEXT,
    out_of_date INTEGER,
    last_modified INTEGER,
    co_maintainers TEXT
);
""" + ENRICHMENT_TABLES

# Existing rows keep NULL: the current co-maintainers become the baseline on the next
# run, rather than all being reported as newly added.
MIGRATE_1_TO_2 = "ALTER TABLE aur_state ADD COLUMN co_maintainers TEXT;"

# Each entry brings a database of that version up to the next one.
MIGRATIONS = {
    1: MIGRATE_1_TO_2,
    2: ENRICHMENT_TABLES
    + "ALTER TABLE runs ADD COLUMN kernel_ok INTEGER NOT NULL DEFAULT 1;",
}


@dataclass
class Diff:
    new: list[tuple[str, str, str]] = field(default_factory=list)
    closed: list[tuple[str, str, str]] = field(default_factory=list)
    changed: list[tuple[str, str, str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class OpenFinding:
    id: int
    strip: str
    package: str
    key: str
    level: str


class Store:
    def __init__(self, path: str):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA foreign_keys = ON")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            steps = SCHEMA
        else:
            steps = "".join(MIGRATIONS[v] for v in range(version, SCHEMA_VERSION))
        if version != SCHEMA_VERSION:
            self.db.executescript(
                f"BEGIN; {steps} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;"
            )

    def cached_cves(self, cves: list[str]) -> dict[str, tuple[str | None, int]]:
        marks = ",".join("?" for _ in cves)
        rows = self.db.execute(
            f"SELECT cve, raw, fetched_at FROM cve_cache WHERE cve IN ({marks})", cves
        ).fetchall()
        return {cve: (raw, fetched_at) for cve, raw, fetched_at in rows}

    def put_cve(self, cve: str, raw: str | None, now: int) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO cve_cache (cve, raw, fetched_at) VALUES (?, ?, ?)",
            (cve, raw, now),
        )

    def meta(self, key: str) -> str | None:
        row = self.db.execute(
            "SELECT value FROM enrich_meta WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else None

    def put_meta(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO enrich_meta (key, value) VALUES (?, ?)", (key, value)
        )

    def close(self) -> None:
        self.db.close()

    def __enter__(self):
        """One transaction: a run is recorded whole or not at all."""
        self.db.__enter__()
        return self

    def __exit__(self, *exc):
        return self.db.__exit__(*exc)

    def add_run(
        self,
        started_at: int,
        finished_at: int,
        repo_ok: bool,
        aur_ok: bool,
        yoklama_ok: bool,
        kernel_ok: bool,
        warnings: list[str],
    ) -> int:
        cursor = self.db.execute(
            "INSERT INTO runs (started_at, finished_at, repo_ok, aur_ok, yoklama_ok,"
            " kernel_ok, warnings) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                started_at,
                finished_at,
                repo_ok,
                aur_ok,
                yoklama_ok,
                kernel_ok,
                json.dumps(warnings),
            ),
        )
        return cursor.lastrowid

    def set_run_warnings(self, run: int, warnings: list[str]) -> None:
        self.db.execute(
            "UPDATE runs SET warnings = ? WHERE id = ?", (json.dumps(warnings), run)
        )

    def open_aur_events(self) -> list[OpenEvent]:
        marks = ",".join("?" for _ in EVENT_KEYS)
        rows = self.db.execute(
            "SELECT package, key, level, detail, first_seen FROM findings"
            f" WHERE strip = ? AND closed_at IS NULL AND key IN ({marks})",
            (AUR, *sorted(EVENT_KEYS)),
        ).fetchall()
        return [
            OpenEvent(package, key, level, json.loads(detail), first_seen)
            for package, key, level, detail, first_seen in rows
        ]

    def sync_strip(
        self,
        strip: str,
        findings: list[Finding],
        run: int,
        now: int,
        renew: set[tuple[str, str]] = frozenset(),
    ) -> Diff:
        """Bring one strip's open findings in line with this run's.

        A finding in `renew` is a new occurrence: an open one of the same kind closes
        and a new one opens, with its own first-seen date.
        """
        diff = Diff()
        current = {(f.package, f.key): f for f in findings}
        rows = self.db.execute(
            "SELECT id, package, key, level FROM findings"
            " WHERE strip = ? AND closed_at IS NULL",
            (strip,),
        ).fetchall()
        known = set()
        for row_id, package, key, level in rows:
            finding = current.get((package, key))
            if finding is None or (package, key) in renew:
                self.db.execute(
                    "UPDATE findings SET closed_at = ?, closed_run = ? WHERE id = ?",
                    (now, run, row_id),
                )
                diff.closed.append((package, key, level))
                continue
            known.add((package, key))
            if finding.level != level:
                self.db.execute(
                    "UPDATE findings SET level = ?, level_run = ? WHERE id = ?",
                    (finding.level, run, row_id),
                )
                diff.changed.append((package, key, level, finding.level))
            self.db.execute(
                "UPDATE findings SET detail = ?, last_seen = ? WHERE id = ?",
                (json.dumps(finding.detail), now, row_id),
            )
        for (package, key), finding in current.items():
            if (package, key) in known:
                continue
            self.db.execute(
                "INSERT INTO findings (strip, package, key, level, detail, first_seen,"
                " last_seen, first_run, level_run) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    strip,
                    package,
                    key,
                    finding.level,
                    json.dumps(finding.detail),
                    now,
                    now,
                    run,
                    run,
                ),
            )
            diff.new.append((package, key, finding.level))
        return diff

    def open_findings(self) -> list[OpenFinding]:
        rows = self.db.execute(
            "SELECT id, strip, package, key, level FROM findings"
            " WHERE closed_at IS NULL ORDER BY strip, package, key"
        ).fetchall()
        return [OpenFinding(*row) for row in rows]

    def annotate(
        self, finding_id: int, leaves: list[str] | None, suggest_removal: bool
    ) -> None:
        self.db.execute(
            "UPDATE findings SET leaves = ?, suggest_removal = ? WHERE id = ?",
            (
                None if leaves is None else json.dumps(leaves),
                suggest_removal,
                finding_id,
            ),
        )

    def set_last_used(self, finding_id: int, last_used: int | None) -> None:
        self.db.execute(
            "UPDATE findings SET last_used = ? WHERE id = ?", (last_used, finding_id)
        )

    def aur_state(self) -> dict[str, AurState]:
        rows = self.db.execute(
            "SELECT name, maintainer, found, ever_found, version, out_of_date,"
            " last_modified, co_maintainers FROM aur_state"
        ).fetchall()
        return {
            row[0]: AurState(
                row[0],
                row[1],
                bool(row[2]),
                bool(row[3]),
                row[4],
                row[5],
                row[6],
                None if row[7] is None else tuple(json.loads(row[7])),
            )
            for row in rows
        }

    def replace_aur_state(self, states: list[AurState]) -> None:
        self.db.execute("DELETE FROM aur_state")
        self.db.executemany(
            "INSERT INTO aur_state (name, maintainer, found, ever_found, version,"
            " out_of_date, last_modified, co_maintainers)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    s.name,
                    s.maintainer,
                    s.found,
                    s.ever_found,
                    s.version,
                    s.out_of_date,
                    s.last_modified,
                    None if s.co_maintainers is None else json.dumps(s.co_maintainers),
                )
                for s in states
            ],
        )
