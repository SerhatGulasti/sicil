"""`sicil report`: reads the database only, never the network or the system."""

import json
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass

from . import rules

STALE_HOURS = 36
MAX_CVES_SHOWN = 3
MAX_LEAVES_SHOWN = 5

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


class ReportError(Exception):
    pass


@dataclass
class Report:
    generated_at: int
    all_findings: bool
    last_run: dict
    warnings: list[str]
    red: list[dict]
    yellow: list[dict]
    removal: list[dict]
    unverified: list[dict]
    not_found: list[dict]
    closed: list[dict]


def _row(row: sqlite3.Row) -> dict:
    return {
        "strip": row["strip"],
        "package": row["package"],
        "key": row["key"],
        "level": row["level"],
        "detail": json.loads(row["detail"]),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "closed_at": row["closed_at"],
        "last_used": row["last_used"],
        "leaves": None if row["leaves"] is None else json.loads(row["leaves"]),
        "suggest_removal": bool(row["suggest_removal"]),
    }


def _sort_key(finding: dict) -> tuple:
    severity = finding["detail"].get("severity")
    return (
        finding["strip"],
        SEVERITY_ORDER.get(severity, len(SEVERITY_ORDER)),
        finding["package"],
        finding["key"],
    )


def _removal(findings: list[dict]) -> list[dict]:
    """One row per package: its leaves are the same whatever the finding."""
    packages: dict[str, dict] = {}
    for finding in findings:
        if not finding["suggest_removal"]:
            continue
        entry = packages.setdefault(
            finding["package"],
            {
                "package": finding["package"],
                "remove": finding["leaves"],
                "signals": [],
                "last_used": finding["last_used"],
            },
        )
        entry["signals"].append(_signal(finding))
    return sorted(packages.values(), key=lambda entry: entry["package"])


def load(path: str, now: int | None = None, all_findings: bool = False) -> Report:
    now = int(time.time()) if now is None else now
    uri = f"file:{urllib.parse.quote(path)}?mode=ro"
    try:
        db = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as e:
        raise ReportError(f"{path}: {e}; try `sicil run` first") from e
    db.row_factory = sqlite3.Row
    try:
        run = db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        if run is None:
            raise ReportError("no run recorded yet; try `sicil run` first")
        rows = db.execute(
            "SELECT * FROM findings WHERE closed_at IS NULL"
            + ("" if not all_findings else " OR closed_at IS NOT NULL")
        ).fetchall()
    except sqlite3.Error as e:
        raise ReportError(f"{path}: {e}") from e
    finally:
        db.close()

    findings = sorted((_row(row) for row in rows), key=_sort_key)
    current = [f for f in findings if f["closed_at"] is None]
    by_level = lambda level: [f for f in current if f["level"] == level]

    age_hours = (now - run["finished_at"]) / 3600
    stale = age_hours > STALE_HOURS
    warnings = json.loads(run["warnings"])
    if stale:
        warnings.insert(0, f"The last run is {age_hours:.0f} hours old.")

    return Report(
        generated_at=now,
        all_findings=all_findings,
        last_run={
            "id": run["id"],
            "finished_at": run["finished_at"],
            "repo_ok": bool(run["repo_ok"]),
            "aur_ok": bool(run["aur_ok"]),
            "yoklama_ok": bool(run["yoklama_ok"]),
            "age_hours": round(age_hours, 1),
            "stale": stale,
        },
        warnings=warnings,
        red=by_level(rules.RED),
        yellow=by_level(rules.YELLOW),
        removal=_removal(current),
        unverified=by_level(rules.UNVERIFIED),
        not_found=by_level(rules.NOT_FOUND),
        closed=sorted(
            (f for f in findings if f["closed_at"] is not None),
            key=lambda f: (-f["closed_at"], f["package"], f["key"]),
        ),
    )


def _date(timestamp: int | None) -> str:
    if timestamp is None:
        return "-"
    return time.strftime("%Y-%m-%d", time.localtime(timestamp))


def _shorten(items: list[str] | None, limit: int) -> str:
    if not items:
        return "-"
    shown = ", ".join(items[:limit])
    extra = len(items) - limit
    return f"{shown} +{extra} more" if extra > 0 else shown


def _signal(finding: dict) -> str:
    detail = finding["detail"]
    match finding["key"]:
        case "maintainer_changed":
            return f"maintainer {detail['from'] or 'none'} -> {detail['to']}"
        case "co_maintainer_added":
            return f"new co-maintainer {', '.join(detail['added'])}"
        case "removed":
            return "removed from AUR"
        case "orphan":
            return "orphan"
        case "out_of_date":
            return "flagged out of date"
    if finding["strip"] == rules.REPO:
        return f"{detail['severity']} {finding['key']}"
    return finding["key"]


def _changed_at(finding: dict) -> int:
    since = finding["detail"].get("since") if finding["key"] == "out_of_date" else None
    return since or finding["first_seen"]


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    widths = [
        max(len(line[column]) for line in [headers, *rows])
        for column in range(len(headers))
    ]
    return [
        "  " + "  ".join(cell.ljust(width) for cell, width in zip(line, widths)).rstrip()
        for line in [headers, *rows]
    ]


def _finding_tables(findings: list[dict]) -> list[str]:
    lines: list[str] = []
    repo = [f for f in findings if f["strip"] == rules.REPO]
    aur = [f for f in findings if f["strip"] == rules.AUR]
    if repo:
        lines += _table(
            ["PACKAGE", "SEVERITY", "CVES", "FIXED IN", "LAST USED", "PULLED BY"],
            [
                [
                    f["package"],
                    f["detail"]["severity"],
                    _shorten(f["detail"]["cves"], MAX_CVES_SHOWN),
                    f["detail"]["fixed"] or "-",
                    _date(f["last_used"]),
                    _shorten(f["leaves"], MAX_LEAVES_SHOWN),
                ]
                for f in repo
            ],
        )
    if aur:
        lines += _table(
            ["PACKAGE", "SIGNAL", "CHANGED", "LAST USED", "PULLED BY"],
            [
                [
                    f["package"],
                    _signal(f),
                    _date(_changed_at(f)),
                    _date(f["last_used"]),
                    _shorten(f["leaves"], MAX_LEAVES_SHOWN),
                ]
                for f in aur
            ],
        )
    return lines


def _section(title: str, lines: list[str]) -> list[str]:
    return ["", title if lines else f"{title}: none", *lines]


def format_text(report: Report) -> str:
    run = report.last_run
    status = lambda ok: "ok" if ok else "FAILED"
    finished = time.strftime("%Y-%m-%d %H:%M", time.localtime(run["finished_at"]))
    lines = [
        f"Last run: {finished} (repo {status(run['repo_ok'])},"
        f" aur {status(run['aur_ok'])}, yoklama {status(run['yoklama_ok'])})"
    ]
    lines += [f"Warning: {warning}" for warning in report.warnings]

    lines += _section("Red", _finding_tables(report.red))
    lines += _section("Yellow", _finding_tables(report.yellow))
    lines += _section(
        "Removal suggestions",
        _table(
            ["PACKAGE", "REMOVE", "BECAUSE", "LAST USED"],
            [
                [
                    entry["package"],
                    ", ".join(entry["remove"]),
                    "; ".join(entry["signals"]),
                    _date(entry["last_used"]),
                ]
                for entry in report.removal
            ],
        )
        if report.removal
        else [],
    )
    lines += _section(
        "Unverified (no fix recorded, installed version is newer than the record)",
        _table(
            ["PACKAGE", "SEVERITY", "CVES", "INSTALLED", "RECORD", "LAST USED"],
            [
                [
                    f["package"],
                    f["detail"]["severity"],
                    _shorten(f["detail"]["cves"], MAX_CVES_SHOWN),
                    f["detail"]["installed"],
                    f["detail"]["affected"],
                    _date(f["last_used"]),
                ]
                for f in report.unverified
            ],
        )
        if report.unverified
        else [],
    )
    lines += _section(
        "Not found in AUR",
        ["  " + f["package"] for f in report.not_found],
    )
    if report.all_findings:
        lines += _section(
            "Closed",
            _table(
                ["PACKAGE", "SIGNAL", "WAS", "OPENED", "CLOSED"],
                [
                    [
                        f["package"],
                        _signal(f),
                        f["level"],
                        _date(f["first_seen"]),
                        _date(f["closed_at"]),
                    ]
                    for f in report.closed
                ],
            )
            if report.closed
            else [],
        )
    return "\n".join(lines)


def format_json(report: Report) -> str:
    data = {
        "generated_at": report.generated_at,
        "last_run": report.last_run,
        "warnings": report.warnings,
        "red": report.red,
        "yellow": report.yellow,
        "removal_suggestions": report.removal,
        "unverified": report.unverified,
        "not_found": report.not_found,
    }
    if report.all_findings:
        data["closed"] = report.closed
    return json.dumps(data, indent=2, ensure_ascii=False)
