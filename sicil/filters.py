"""The filters of `sicil report`. Pure functions: no I/O, no clock.

Different filters are ANDed and a repeated one is ORed. A record dropped because the
filtered field is empty is not the same as one that fails the filter, so it is counted
instead of disappearing.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITY_CHOICES = (*SEVERITY_RANK, "unknown")
STATUS_CHOICES = ("open", "unverified", "looks-closed")
DAY = 86400

NO_CVE = "no CVE"
NO_SEVERITY = "no severity"
UNKNOWN_SEVERITY = "severity unknown"
NO_CVSS = "no CVSS"
NO_LAST_USED = "no last-used date"
NO_INSTALLED = "no installed version"
NO_RECORD = "no record version"
NO_STATUS = "no such status"


@dataclass
class Filters:
    package: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    severity: list[str] = field(default_factory=list)
    min_cvss: list[float] = field(default_factory=list)
    unused: list[int] = field(default_factory=list)
    used: list[int] = field(default_factory=list)
    installed_min: list[str] = field(default_factory=list)
    installed_max: list[str] = field(default_factory=list)
    record_min: list[str] = field(default_factory=list)
    record_max: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)

    def active(self) -> bool:
        return any(vars(self).values())

    def needs_usage(self) -> bool:
        return bool(self.unused or self.used)


@dataclass(frozen=True)
class Record:
    """One row a filter can look at. None means the field is empty for this record."""

    package: str
    # A kernel carries every CVE covering it, a repo row one, an AUR event none.
    cves: tuple[str, ...] | None = None
    severity: str | None = None
    cvss: float | None = None
    # None with has_usage is a package never seen in use, which is a value.
    last_used: int | None = None
    has_usage: bool = True
    installed: str | None = None
    record: str | None = None
    status: str | None = None


def matching_cves(cves: tuple[str, ...], patterns: list[str]) -> list[str]:
    wanted = [pattern.upper() for pattern in patterns]
    return [cve for cve in cves if any(fnmatchcase(cve, w) for w in wanted)]


def _severity(value: str | None, wanted: list[str]) -> bool | str:
    if value is None:
        return NO_SEVERITY
    name = value.lower()
    ranks = [SEVERITY_RANK[w] for w in wanted if w != "unknown"]
    if name not in SEVERITY_RANK:
        return True if "unknown" in wanted else UNKNOWN_SEVERITY
    return bool(ranks) and SEVERITY_RANK[name] >= min(ranks)


def _bounded(
    value: str | None,
    lowest: list[str],
    highest: list[str],
    vercmp: Callable[[str, str], int],
    empty: str,
) -> list[bool | str]:
    results: list[bool | str] = []
    if lowest:
        results.append(
            empty if value is None else any(vercmp(value, v) >= 0 for v in lowest)
        )
    if highest:
        results.append(
            empty if value is None else any(vercmp(value, v) <= 0 for v in highest)
        )
    return results


def evaluate(
    record: Record, filters: Filters, now: int, vercmp: Callable[[str, str], int]
) -> tuple[bool, list[str]]:
    """Whether the record is shown and, if it is hidden only by empty fields, which."""
    results: list[bool | str] = []
    if filters.package:
        results.append(any(fnmatchcase(record.package, p) for p in filters.package))
    if filters.cve:
        results.append(
            NO_CVE
            if record.cves is None
            else bool(matching_cves(record.cves, filters.cve))
        )
    if filters.severity:
        results.append(_severity(record.severity, filters.severity))
    if filters.min_cvss:
        results.append(
            NO_CVSS
            if record.cvss is None
            else any(record.cvss >= score for score in filters.min_cvss)
        )
    if filters.unused:
        if not record.has_usage:
            results.append(NO_LAST_USED)
        elif record.last_used is None:
            results.append(True)
        else:
            results.append(any(now - record.last_used >= d * DAY for d in filters.unused))
    if filters.used:
        if not record.has_usage:
            results.append(NO_LAST_USED)
        elif record.last_used is None:
            results.append(False)
        else:
            results.append(any(now - record.last_used <= d * DAY for d in filters.used))
    results += _bounded(
        record.installed,
        filters.installed_min,
        filters.installed_max,
        vercmp,
        NO_INSTALLED,
    )
    results += _bounded(
        record.record, filters.record_min, filters.record_max, vercmp, NO_RECORD
    )
    if filters.status:
        results.append(
            NO_STATUS if record.status is None else record.status in filters.status
        )
    # Failing any filter is a plain no: an empty field then hid nothing.
    if any(result is False for result in results):
        return False, []
    empty = [result for result in results if isinstance(result, str)]
    return not empty, empty
