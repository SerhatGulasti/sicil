"""`sicil report`: reads the database only, never the network or the system."""

import json
import re
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass

from . import rules

STALE_HOURS = 36
MAX_LEAVES_SHOWN = 5
MAX_DESCRIPTION_SHOWN = 70

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
    looks_closed: list[dict]
    kernels: list[dict]
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
            # A database not yet migrated by `sicil run` has no such column.
            "kernel_ok": bool(run["kernel_ok"]) if "kernel_ok" in run.keys() else True,
            "age_hours": round(age_hours, 1),
            "stale": stale,
        },
        warnings=warnings,
        red=by_level(rules.RED),
        yellow=by_level(rules.YELLOW),
        removal=_removal(current),
        unverified=by_level(rules.UNVERIFIED),
        looks_closed=by_level(rules.LOOKS_CLOSED),
        kernels=by_level(rules.INFO),
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


def _description(text: str | None) -> str:
    """One line of someone else's text, with nothing a terminal would act on."""
    if not text:
        return "-"
    clean = " ".join(re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", text).split())
    if len(clean) > MAX_DESCRIPTION_SHOWN:
        return clean[: MAX_DESCRIPTION_SHOWN - 3].rstrip() + "..."
    return clean


def _cve_cells(finding: dict, cve: str) -> dict[str, str]:
    known = finding["detail"].get("enrichment", {}).get(cve, {})
    cvss = known.get("cvss")
    epss = known.get("epss")
    version = known.get("version", "unknown")
    return {
        "cve": cve,
        "cvss": f"{cvss} {known.get('cvss_source')}" if cvss is not None else "-",
        "epss": f"{epss:.3f}" if epss is not None else "-",
        "version": f"{version} KEV" if known.get("kev") else version,
        "description": _description(known.get("description")),
    }


def _repo_table(findings: list[dict], extra: list[str], cells) -> list[str]:
    """One row per CVE, so that every CVE shows its description."""
    return _table(
        ["PACKAGE", "SEVERITY", "CVE", "CVSS", "EPSS", "VERSION", *extra, "DESCRIPTION"],
        [
            [
                f["package"],
                f["detail"]["severity"],
                row["cve"],
                row["cvss"],
                row["epss"],
                row["version"],
                *cells(f),
                row["description"],
            ]
            for f in findings
            for row in (_cve_cells(f, cve) for cve in f["detail"]["cves"])
        ],
    )


def _record_table(findings: list[dict]) -> list[str]:
    """For findings the tracker has no fix for: what the record and the system say."""
    if not findings:
        return []
    return _repo_table(
        findings,
        ["INSTALLED", "RECORD", "LAST USED"],
        lambda f: [
            f["detail"]["installed"],
            f["detail"]["affected"] or "-",
            _date(f["last_used"]),
        ],
    )


def _kernel_summary(finding: dict) -> str:
    """One line. "Cover" rather than "open": neither the build's configuration nor its
    own patches are known here, so a record is not proof of a hole in this kernel.
    """
    d = finding["detail"]
    parts = [f"{d['version']} (running)" if d["running"] else d["version"]]
    if d["behind"]:
        parts.append(f"branch latest {d['latest']}, {d['behind']} behind")
    elif d["behind"] == 0:
        parts.append("latest in its branch")
    if d["repo_newer"]:
        parts.append(f"update available: {d['repo_version']}")
    elif d["behind"] and d["repo_version"]:
        parts.append(f"repo still has {d['repo_version']}")
    if d["eol"]:
        parts.append("branch is end of life")
    count = d["covered_count"]
    parts.append(
        "1 record covers this version"
        if count == 1
        else f"{count} records cover this version"
    )
    if d["behind"] and d["remaining_count"] is not None:
        fixed = d["covered_count"] - d["remaining_count"]
        parts.append(
            f"{d['latest']} fixes {fixed} of them, {d['remaining_count']} remain"
        )
    if d["kev"]:
        parts.append(f"in KEV: {_shorten(d['kev'], MAX_LEAVES_SHOWN)}")
    if d["reboot_pending"]:
        parts.append(f"reboot pending: running {d['running_version']}")
    return "; ".join(parts)


def _kernel_table(findings: list[dict]) -> list[str]:
    if not findings:
        return []
    return _table(
        ["PACKAGE", "SUMMARY"],
        [[f["package"], _kernel_summary(f)] for f in findings],
    )


def _finding_tables(findings: list[dict]) -> list[str]:
    lines: list[str] = []
    repo = [f for f in findings if f["strip"] == rules.REPO]
    aur = [f for f in findings if f["strip"] == rules.AUR]
    lines += _kernel_table([f for f in findings if f["strip"] == rules.KERNEL])
    if repo:
        lines += _repo_table(
            repo,
            ["FIXED IN", "LAST USED", "PULLED BY"],
            lambda f: [
                f["detail"]["fixed"] or "-",
                _date(f["last_used"]),
                _shorten(f["leaves"], MAX_LEAVES_SHOWN),
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
        f" aur {status(run['aur_ok'])}, kernel {status(run['kernel_ok'])},"
        f" yoklama {status(run['yoklama_ok'])})"
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
        _record_table(report.unverified),
    )
    lines += _section(
        "Looks closed (installed version is outside every CVE's affected range)",
        _record_table(report.looks_closed),
    )
    lines += _section(
        "Kernels (for information, nothing to do now)",
        _kernel_table(report.kernels),
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
        "looks_closed": report.looks_closed,
        "kernels": report.kernels,
        "not_found": report.not_found,
    }
    if report.all_findings:
        data["closed"] = report.closed
    return json.dumps(data, indent=2, ensure_ascii=False)
