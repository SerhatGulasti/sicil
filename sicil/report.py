"""`sicil report`: reads the database, never the network.

The only programs it may run are `vercmp`, for the version filters asked for.
"""

import json
import re
import shutil
import sqlite3
import textwrap
import time
import unicodedata
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from . import filters as filters_module
from . import rules
from .filters import Filters, Record
from .store import SCHEMA_VERSION, newer_schema_message

STALE_HOURS = 36
MAX_LEAVES_SHOWN = 5
MAX_CVES_SHOWN = 3
MAX_KERNEL_IDS_SHOWN = 10
MIN_WIDTH = 20

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

YOKLAMA_NOT_FOUND = "Yoklama not found, no usage data"
YOKLAMA_SINCE_INSTALLED = "Yoklama was not there at the last run; `sicil run` will use it"

# What a reader calls each level. The labels themselves stay in the JSON.
LEVEL_WORDS = {
    rules.RED: "red",
    rules.YELLOW: "yellow",
    rules.UNVERIFIED: "can't verify",
    rules.LOOKS_CLOSED: "looks closed",
    rules.NOT_FOUND: "not found in AUR",
    rules.INFO: "kernel note",
}
RANGE_WORDS = {"open": "inside", "closed": "outside", "unknown": "unknown"}


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
    # False when `yoklama` is not installed: no last-used column, no removal section.
    usage: bool = True
    # False until `sicil run` migrates the database: --unused can't trust it yet.
    knows_unmeasurable: bool = True
    filtered: bool = False
    shown: int = 0
    total: int = 0
    hidden: dict[str, int] = field(default_factory=dict)


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
        # A database not yet migrated by `sicil run` has no such column.
        "unmeasurable": "unmeasurable" in row.keys() and bool(row["unmeasurable"]),
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


def _connect(path: str) -> sqlite3.Connection:
    uri = f"file:{urllib.parse.quote(path)}?mode=ro"
    try:
        return sqlite3.connect(uri, uri=True)
    except sqlite3.Error as e:
        raise ReportError(f"{path}: {e}; try `sicil run` first") from e


def yoklama_installed() -> bool:
    return shutil.which("yoklama") is not None


def cached_record(path: str, cve: str) -> str | None:
    """The CVE record `sicil run` saved, if any. An older database has no such table."""
    db = _connect(path)
    try:
        row = db.execute("SELECT raw FROM cve_cache WHERE cve = ?", (cve,)).fetchone()
    except sqlite3.Error:
        return None
    finally:
        db.close()
    return row[0] if row else None


def load(
    path: str,
    now: int | None = None,
    all_findings: bool = False,
    usage: bool | None = None,
) -> Report:
    now = int(time.time()) if now is None else now
    usage = yoklama_installed() if usage is None else usage
    db = _connect(path)
    db.row_factory = sqlite3.Row
    try:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise ReportError(f"{path}: {newer_schema_message(version)}")
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
    if not usage and YOKLAMA_NOT_FOUND not in warnings:
        warnings.insert(0, YOKLAMA_NOT_FOUND)
    if usage and YOKLAMA_NOT_FOUND in warnings:
        warnings[warnings.index(YOKLAMA_NOT_FOUND)] = YOKLAMA_SINCE_INSTALLED
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
        usage=usage,
        knows_unmeasurable=version >= 4,
    )


def format_date(timestamp: int | None) -> str:
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
        case "not_found":
            return "not found in AUR"
    if finding["strip"] == rules.REPO:
        return f"{detail['severity']}: {_shorten(detail['cves'], MAX_CVES_SHOWN)}"
    if finding["strip"] == rules.KERNEL:
        return "kernel summary"
    return finding["key"]


def _changed_at(finding: dict) -> int:
    since = finding["detail"].get("since") if finding["key"] == "out_of_date" else None
    return since or finding["first_seen"]


def clean(text: str | None) -> str:
    """One line of someone else's text, with nothing a terminal would act on."""
    if not text:
        return ""
    return " ".join(re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", text).split())


def _shown_width(text: str) -> int:
    return sum(
        0
        if unicodedata.combining(c)
        else 2
        if unicodedata.east_asian_width(c) in "WF"
        else 1
        for c in text
    )


def _crop(text: str, width: int | None) -> str:
    if width is None or _shown_width(text) <= width:
        return text
    room = max(width - 3, 0)
    used = 0
    kept = []
    for c in text:
        used += _shown_width(c)
        if used > room:
            break
        kept.append(c)
    return "".join(kept).rstrip() + "..."


def wrap(text: str, width: int | None, indent: str = "") -> list[str]:
    """Lines that fit the width; everything stays, unlike a cropped description."""
    if width is None:
        return [indent + text]
    return textwrap.wrap(
        text,
        width=max(width, MIN_WIDTH),
        initial_indent=indent,
        subsequent_indent=indent,
        break_on_hyphens=False,
    ) or [indent]


@dataclass(frozen=True)
class Column:
    header: str
    # Which goes first when the terminal is too narrow; None never goes.
    drop: int | None = None
    # The section title already says what a constant value of this column would.
    implied: bool = False


@dataclass
class Row:
    cells: list[str]
    full: list[str] = field(default_factory=list)  # wrapped under the row
    cropped: list[str] = field(default_factory=list)  # one line each under the row


def _table(columns: list[Column], rows: list[Row], width: int | None) -> list[str]:
    """A table that fits the width, without the columns that say nothing.

    A value shared by every row moves out of the columns, so that hiding it loses
    nothing. One row is exempt: there every value is shared, and it reads as a row.
    """
    if not rows:
        return []
    keep = list(range(len(columns)))
    notes = []
    for i, column in enumerate(columns):
        if column.drop is None:
            continue
        values = {row.cells[i] for row in rows}
        if values == {"-"}:
            keep.remove(i)
        elif len(rows) > 1 and len(values) == 1:
            keep.remove(i)
            if not column.implied:
                notes.append(f"{column.header} {values.pop()}")

    def table_width(indices: list[int]) -> int:
        return (
            2
            + sum(
                max(
                    _shown_width(columns[i].header),
                    *(_shown_width(row.cells[i]) for row in rows),
                )
                for i in indices
            )
            + 2 * (len(indices) - 1)
        )

    dropped = []
    if width is not None:
        for i in sorted(
            (i for i in keep if columns[i].drop is not None),
            key=lambda i: columns[i].drop,
        ):
            if table_width(keep) <= width:
                break
            keep.remove(i)
            dropped.append(columns[i].header)

    lines = wrap(f"All rows: {', '.join(notes)}.", width, "  ") if notes else []
    if dropped:
        lines += wrap(
            f"Not shown at this width: {', '.join(dropped)}.", width, "  "
        )
    widths = {
        i: max(
            _shown_width(columns[i].header),
            *(_shown_width(row.cells[i]) for row in rows),
        )
        for i in keep
    }

    def line(cells: list[str]) -> str:
        padded = [
            cells[i] + " " * (widths[i] - _shown_width(cells[i])) for i in keep
        ]
        return "  " + "  ".join(padded).rstrip()

    # Whatever still does not fit is cropped, never the first column: it may be an ID
    # someone copies, and a broken line is the one thing this layout must not produce.
    def fit(text: str) -> str:
        return _crop(text, None if width is None else max(width, widths[keep[0]] + 2))

    lines.append(fit(line([c.header for c in columns])))
    for row in rows:
        lines.append(fit(line(row.cells)))
        for text in row.full:
            lines += wrap(text, width, "    ")
        for text in row.cropped:
            lines.append(_crop("    " + text, width))
    return lines


def _cve_cells(finding: dict, cve: str) -> dict[str, str]:
    known = finding["detail"].get("enrichment", {}).get(cve, {})
    cvss = known.get("cvss")
    epss = known.get("epss")
    return {
        "cvss": f"{cvss} {known.get('cvss_source')}" if cvss is not None else "-",
        "epss": f"{epss:.3f}" if epss is not None else "-",
        "range": RANGE_WORDS.get(known.get("version", "unknown"), "unknown"),
        "kev": "yes" if known.get("kev") else "-",
        "description": clean(known.get("description")),
    }


def finding_id(package: str, cve: str) -> str:
    return f"{package}:{cve}"


def _repo_rows(findings: list[dict], extra, pulled_by: bool) -> list[Row]:
    """One row per CVE, so that every CVE shows its description and its ID."""
    rows = []
    seen = set()
    for f in findings:
        first = True
        for cve in f["detail"]["cves"]:
            record_id = finding_id(f["package"], cve)
            if record_id in seen:
                continue
            seen.add(record_id)
            cells = _cve_cells(f, cve)
            rows.append(
                Row(
                    [
                        record_id,
                        f["detail"]["severity"],
                        cells["cvss"],
                        cells["epss"],
                        cells["range"],
                        cells["kev"],
                        *extra(f),
                    ],
                    full=[f"pulled by: {_shorten(f['leaves'], MAX_LEAVES_SHOWN)}"]
                    if pulled_by and first and f["leaves"]
                    else [],
                    cropped=[cells["description"]] if cells["description"] else [],
                )
            )
            first = False
    return rows


REPO_COLUMNS = [
    Column("ID"),
    Column("SEVERITY", 70),
    Column("CVSS", 50),
    Column("EPSS", 10),
    Column("RANGE", 40, implied=True),
    Column("KEV", 90),
]
LAST_USED = Column("LAST USED", 20)


def _last_used(finding: dict, usage: bool) -> list[str]:
    return [format_date(finding["last_used"]) if usage else "-"]


def _record_table(findings: list[dict], usage: bool, width: int | None) -> list[str]:
    """For findings the tracker has no fix for: what the record and the system say."""
    return _table(
        [
            *REPO_COLUMNS,
            Column("INSTALLED", 60),
            Column("RECORD", 30),
            LAST_USED,
        ],
        _repo_rows(
            findings,
            lambda f: [
                f["detail"]["installed"],
                f["detail"]["affected"] or "-",
                *_last_used(f, usage),
            ],
            pulled_by=False,
        ),
        width,
    )


def kernel_parts(d: dict) -> list[str]:
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
    if d["kev"]:
        parts.append(f"in KEV: {_shorten(d['kev'], MAX_LEAVES_SHOWN)}")
    if d["reboot_pending"]:
        parts.append(f"reboot pending: running {d['running_version']}")
    return parts


def _kernel_summary(finding: dict) -> str:
    """The whole line. It says "cover" rather than "open": neither the build's
    configuration nor its own patches are known here, so a record is not proof of a hole.
    """
    d = finding["detail"]
    parts = kernel_parts(d)
    count = d["covered_count"]
    covering = (
        "1 record covers this version"
        if count == 1
        else f"{count} records cover this version"
    )
    if d["behind"] and d["remaining_count"] is not None:
        fixed = d["covered_count"] - d["remaining_count"]
        covering += f"; {d['latest']} fixes {fixed} of them, {d['remaining_count']} remain"
    parts.insert(len(parts) - bool(d["reboot_pending"]) - bool(d["kev"]), covering)
    return "; ".join(parts)


def _kernel_lines(findings: list[dict], width: int | None) -> list[str]:
    lines = []
    for f in findings:
        lines.append(f"  {f['package']}")
        lines += wrap(_kernel_summary(f), width, "    ")
        # Present only when a CVE filter narrowed the list down to what it asked for.
        matched = f.get("matched_cves") or []
        for entry in matched[:MAX_KERNEL_IDS_SHOWN]:
            fixed = f"  fixed in {entry['fixed_in']}" if entry["fixed_in"] else ""
            lines.append(_crop(f"    {finding_id(f['package'], entry['cve'])}{fixed}", width))
        if len(matched) > MAX_KERNEL_IDS_SHOWN:
            extra = len(matched) - MAX_KERNEL_IDS_SHOWN
            lines.append(_crop(f"    +{extra} more, see --json", width))
    return lines


def _finding_tables(findings: list[dict], usage: bool, width: int | None) -> list[str]:
    lines: list[str] = _kernel_lines(
        [f for f in findings if f["strip"] == rules.KERNEL], width
    )
    repo = [f for f in findings if f["strip"] == rules.REPO]
    aur = [f for f in findings if f["strip"] == rules.AUR]
    lines += _table(
        [*REPO_COLUMNS, Column("FIXED IN", 80), LAST_USED],
        _repo_rows(
            repo,
            lambda f: [f["detail"]["fixed"] or "-", *_last_used(f, usage)],
            pulled_by=True,
        ),
        width,
    )
    lines += _table(
        [Column("PACKAGE"), Column("SIGNAL"), Column("CHANGED", 30), LAST_USED],
        [
            Row(
                [
                    f["package"],
                    _signal(f),
                    format_date(_changed_at(f)),
                    *_last_used(f, usage),
                ],
                full=[f"pulled by: {_shorten(f['leaves'], MAX_LEAVES_SHOWN)}"]
                if f["leaves"]
                else [],
            )
            for f in aur
        ],
        width,
    )
    return lines


def _removal_table(report: Report, width: int | None) -> list[str]:
    # The list of what to remove is never shortened: part of it would be wrong advice.
    return _table(
        [Column("PACKAGE"), LAST_USED],
        [
            Row(
                [entry["package"], format_date(entry["last_used"])],
                full=[
                    f"remove: {', '.join(entry['remove'])}",
                    f"because: {'; '.join(entry['signals'])}",
                ],
            )
            for entry in report.removal
        ],
        width,
    )


def _closed_table(report: Report, width: int | None) -> list[str]:
    rows = []
    for f in report.closed:
        opened, closed = format_date(f["first_seen"]), format_date(f["closed_at"])
        was = LEVEL_WORDS.get(f["level"], f["level"])
        if f["strip"] == rules.REPO:
            rows += [
                Row(
                    [finding_id(f["package"], cve), f["detail"]["severity"], was, opened, closed]
                )
                for cve in f["detail"]["cves"]
            ]
        else:
            rows.append(Row([f["package"], _signal(f), was, opened, closed]))
    return _table(
        [
            Column("ID OR PACKAGE"),
            Column("SIGNAL", 40),
            Column("WAS", 30),
            Column("OPENED", 10),
            Column("CLOSED", 20),
        ],
        rows,
        width,
    )


def _section(
    name: str, meaning: str, lines: list[str], width: int | None
) -> list[str]:
    if not lines:
        return ["", f"{name}: none"]
    return ["", *wrap(f"{name}: {meaning}" if meaning else name, width), *lines]


def header_status(run: dict, warnings: list[str]) -> str:
    status = lambda ok: "ok" if ok else "FAILED"
    parts = [
        f"repo {status(run['repo_ok'])}",
        f"aur {status(run['aur_ok'])}",
        f"kernel {status(run['kernel_ok'])}",
    ]
    # Not having Yoklama is a choice rather than a failure.
    if YOKLAMA_NOT_FOUND not in warnings and YOKLAMA_SINCE_INSTALLED not in warnings:
        parts.append(f"yoklama {status(run['yoklama_ok'])}")
    return ", ".join(parts)


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def format_text(report: Report, width: int | None = None) -> str:
    run = report.last_run
    finished = time.strftime("%Y-%m-%d %H:%M", time.localtime(run["finished_at"]))
    lines = wrap(
        f"Last run: {finished} ({header_status(run, report.warnings)})", width
    )
    for warning in report.warnings:
        label = (
            "Note"
            if warning in (YOKLAMA_NOT_FOUND, YOKLAMA_SINCE_INSTALLED)
            else "Warning"
        )
        lines += wrap(f"{label}: {warning}", width)
    if report.filtered:
        lines += wrap(
            f"Filtered: showing {report.shown} of {_plural(report.total, 'record')}.",
            width,
        )

    usage = report.usage
    lines += _section(
        "Red", "act on these", _finding_tables(report.red, usage, width), width
    )
    lines += _section(
        "Yellow", "worth a look", _finding_tables(report.yellow, usage, width), width
    )
    if usage:
        lines += _section(
            "Removal suggestions",
            "removing these takes the vulnerable package off the system",
            _removal_table(report, width),
            width,
        )
    lines += _section(
        "Can't verify",
        "record is old, installed version is newer",
        _record_table(report.unverified, usage, width),
        width,
    )
    lines += _section(
        "Looks closed",
        "installed version is outside every CVE's affected range",
        _record_table(report.looks_closed, usage, width),
        width,
    )
    lines += _section(
        "Kernels",
        "for information, nothing to do now",
        _kernel_lines(report.kernels, width),
        width,
    )
    lines += _section(
        "Not found in AUR",
        "not there since Sicil first looked",
        ["  " + f["package"] for f in report.not_found],
        width,
    )
    if report.all_findings:
        lines += _section("Closed", "", _closed_table(report, width), width)
    if report.hidden:
        lines.append("")
        for reason, count in sorted(report.hidden.items()):
            lines += wrap(f"{_plural(count, 'record')} hidden: {reason}", width)
    return "\n".join(lines)


def _with_ids(finding: dict) -> dict:
    if finding["strip"] == rules.REPO:
        return {
            **finding,
            "ids": [finding_id(finding["package"], c) for c in finding["detail"]["cves"]],
        }
    if finding["strip"] == rules.KERNEL:
        detail = finding["detail"]
        covered = [
            {**entry, "id": finding_id(finding["package"], entry["cve"])}
            for entry in detail["covered"]
        ]
        return {**finding, "detail": {**detail, "covered": covered}}
    return finding


def format_json(report: Report) -> str:
    listed = lambda findings: [_with_ids(f) for f in findings]
    data = {
        "generated_at": report.generated_at,
        "last_run": report.last_run,
        "warnings": report.warnings,
        "yoklama_found": report.usage,
        "red": listed(report.red),
        "yellow": listed(report.yellow),
        "removal_suggestions": report.removal,
        "unverified": listed(report.unverified),
        "looks_closed": listed(report.looks_closed),
        "kernels": listed(report.kernels),
        "not_found": report.not_found,
    }
    if report.filtered:
        data["filtered"] = {
            "shown": report.shown,
            "total": report.total,
            "hidden": report.hidden,
        }
    if report.all_findings:
        data["closed"] = listed(report.closed)
    return json.dumps(data, indent=2, ensure_ascii=False)


def _status(finding: dict) -> str | None:
    # Asking for a status never asks for a closed finding, and that is no empty field.
    if finding["closed_at"] is not None:
        return "closed"
    match finding["level"]:
        case rules.RED | rules.YELLOW:
            return "open"
        case rules.UNVERIFIED:
            return "unverified"
        case rules.LOOKS_CLOSED:
            return "looks-closed"
    return None


def _records(finding: dict) -> list[Record]:
    detail = finding["detail"]
    common = {
        "package": finding["package"],
        "last_used": finding["last_used"],
        # A kernel's use is not a package's: Sicil records none for it.
        "has_usage": finding["strip"] != rules.KERNEL and not finding["unmeasurable"],
        "status": _status(finding),
    }
    if finding["strip"] == rules.REPO:
        return [
            Record(
                cves=(cve,),
                severity=detail["severity"],
                cvss=detail.get("enrichment", {}).get(cve, {}).get("cvss"),
                installed=detail["installed"],
                record=detail["affected"],
                **common,
            )
            for cve in detail["cves"]
        ]
    if finding["strip"] == rules.KERNEL:
        return [
            Record(
                cves=tuple(entry["cve"] for entry in detail["covered"]),
                installed=detail["installed"],
                **common,
            )
        ]
    return [Record(**common)]


def _narrowed(finding: dict, cves: list[str], wanted: list[str]) -> dict:
    detail = finding["detail"]
    if finding["strip"] == rules.REPO:
        return {
            **finding,
            "detail": {
                **detail,
                "cves": cves,
                "enrichment": {
                    cve: known
                    for cve, known in detail.get("enrichment", {}).items()
                    if cve in cves
                },
            },
        }
    if finding["strip"] == rules.KERNEL and wanted:
        kept = set(filters_module.matching_cves(tuple(cves), wanted))
        matched = [entry for entry in detail["covered"] if entry["cve"] in kept]
        return {**finding, "matched_cves": matched, "detail": {**detail, "covered": matched}}
    return finding


def apply_filters(
    report: Report, filters: Filters, vercmp: Callable[[str, str], int]
) -> Report:
    """The same report with only the records asked for. Vercmp runs only if needed."""
    if not filters.active():
        return report
    hidden: dict[str, set] = {}
    counts = {"shown": 0, "total": 0}

    def keep(findings: list[dict]) -> list[dict]:
        kept = []
        for finding in findings:
            cves: list[str] = []
            any_shown = False
            for number, record in enumerate(_records(finding)):
                counts["total"] += 1
                shown, empty = filters_module.evaluate(
                    record, filters, report.generated_at, vercmp
                )
                identity = (finding["strip"], finding["package"], finding["key"], number)
                for reason in empty:
                    hidden.setdefault(reason, set()).add(identity)
                if shown:
                    any_shown = True
                    counts["shown"] += 1
                    cves += record.cves or ()
            if any_shown:
                kept.append(_narrowed(finding, cves, filters.cve))
        return kept

    red = keep(report.red)
    yellow = keep(report.yellow)
    unverified = keep(report.unverified)
    looks_closed = keep(report.looks_closed)
    kernels = keep(report.kernels)
    not_found = keep(report.not_found)
    closed = keep(report.closed) if report.all_findings else []
    return replace(
        report,
        red=red,
        yellow=yellow,
        removal=_removal([*red, *yellow]),
        unverified=unverified,
        looks_closed=looks_closed,
        kernels=kernels,
        not_found=not_found,
        closed=closed,
        filtered=True,
        shown=counts["shown"],
        total=counts["total"],
        hidden={reason: len(items) for reason, items in hidden.items()},
    )
