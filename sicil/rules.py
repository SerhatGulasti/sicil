"""The decision rules. Pure functions: no I/O, no clock."""

from collections.abc import Callable
from dataclasses import dataclass

from . import cve as cve_module
from .cve import CLOSED, UNKNOWN, Enrichment
from .sources import Advisory

RED = "red"
YELLOW = "yellow"
UNVERIFIED = "unverified"
LOOKS_CLOSED = "looks_closed"
NOT_FOUND = "not_found"
INFO = "info"

REPO = "repo"
AUR = "aur"
KERNEL = "kernel"

# Removal is only ever suggested after this much observation.
OBSERVATION_DAYS = 60

RED_SEVERITIES = {"High", "Critical"}

# Signals that fire once, in the run that notices the change, rather than describing
# a lasting state. They stay open this long so a report read later still shows them.
EVENT_KEYS = {"maintainer_changed", "removed", "co_maintainer_added"}
EVENT_WINDOW_SECONDS = 7 * 86400

MAX_PACKAGES_NOTIFIED = 5


@dataclass(frozen=True)
class Finding:
    strip: str
    package: str
    key: str
    level: str
    detail: dict


@dataclass(frozen=True)
class OpenEvent:
    package: str
    key: str
    level: str
    detail: dict
    first_seen: int


@dataclass(frozen=True)
class AurState:
    name: str
    maintainer: str | None
    found: bool
    ever_found: bool
    version: str | None = None
    out_of_date: int | None = None
    last_modified: int | None = None
    # None: not known yet, as after a migration. Empty: known to have none.
    co_maintainers: tuple[str, ...] | None = None


def repo_level(advisory: Advisory, vercmp: Callable[[str, str], int]) -> str:
    # With no fixed version the tracker gives no upper bound: arch-audit reports
    # every newer version too, so the record may simply never have been closed.
    if (
        not advisory.fixed
        and advisory.affected
        and vercmp(advisory.installed, advisory.affected) > 0
    ):
        return UNVERIFIED
    return RED if advisory.severity in RED_SEVERITIES else YELLOW


def enrich_advisory(
    advisory: Advisory, enrichment: Enrichment, vercmp: Callable[[str, str], int]
) -> dict[str, dict]:
    """What is known about each of the advisory's CVEs, for this installed version."""
    result = {}
    for cve in advisory.cves:
        facts = enrichment.facts.get(cve)
        result[cve] = {
            "description": facts.description if facts else None,
            "cvss": facts.cvss if facts else None,
            "cvss_source": facts.cvss_source if facts else None,
            # A score, not a level: it knows nothing about the installed version.
            "epss": enrichment.epss.get(cve),
            "kev": cve in enrichment.kev,
            "version": (
                cve_module.decide(facts, advisory.package, advisory.installed, vercmp)
                if facts
                else UNKNOWN
            ),
        }
    return result


def enriched_level(level: str, cves: dict[str, dict]) -> str:
    if any(c["kev"] and c["version"] != CLOSED for c in cves.values()):
        return RED
    if level == UNVERIFIED and cves and all(c["version"] == CLOSED for c in cves.values()):
        return LOOKS_CLOSED
    return level


def classify_repo(
    advisories: list[Advisory],
    vercmp: Callable[[str, str], int],
    enrichment: Enrichment | None = None,
) -> list[Finding]:
    enrichment = enrichment or Enrichment()
    findings = []
    for a in advisories:
        cves = enrich_advisory(a, enrichment, vercmp)
        findings.append(
            Finding(
                REPO,
                a.package,
                a.avg,
                enriched_level(repo_level(a, vercmp), cves),
                {
                    "severity": a.severity,
                    "status": a.status,
                    "type": a.type,
                    "cves": list(a.cves),
                    "fixed": a.fixed,
                    "affected": a.affected,
                    "installed": a.installed,
                    "enrichment": cves,
                },
            )
        )
    return findings


def classify_aur(
    names: list[str], info: dict[str, dict], previous: dict[str, AurState]
) -> tuple[list[Finding], list[AurState]]:
    """Findings and the new state for every installed foreign package."""
    findings = []
    states = []
    for name in names:
        before = previous.get(name)
        result = info.get(name)

        if result is None:
            if before and before.found:
                findings.append(
                    Finding(AUR, name, "removed", RED, {"maintainer": before.maintainer})
                )
            else:
                # Possibly built locally: not alarming unless it was there before.
                findings.append(Finding(AUR, name, "not_found", NOT_FOUND, {}))
            states.append(
                AurState(
                    name,
                    before.maintainer if before else None,
                    found=False,
                    ever_found=bool(before and before.ever_found),
                    co_maintainers=before.co_maintainers if before else None,
                )
            )
            continue

        maintainer = result.get("Maintainer")
        out_of_date = result.get("OutOfDate")
        co_maintainers = tuple(sorted(result.get("CoMaintainers") or []))
        # Losing a maintainer is the orphan signal below. Gaining a different one,
        # by a handover or by adopting an orphan, is the takeover this rule looks for.
        if (
            before
            and before.ever_found
            and maintainer is not None
            and maintainer != before.maintainer
        ):
            findings.append(
                Finding(
                    AUR,
                    name,
                    "maintainer_changed",
                    RED,
                    {"from": before.maintainer, "to": maintainer},
                )
            )
        if before and before.co_maintainers is not None:
            added = set(co_maintainers) - set(before.co_maintainers)
            if added:
                findings.append(
                    Finding(
                        AUR,
                        name,
                        "co_maintainer_added",
                        YELLOW,
                        {"added": sorted(added)},
                    )
                )
        if maintainer is None:
            findings.append(Finding(AUR, name, "orphan", YELLOW, {}))
        if out_of_date:
            findings.append(
                Finding(AUR, name, "out_of_date", YELLOW, {"since": out_of_date})
            )
        states.append(
            AurState(
                name,
                maintainer,
                found=True,
                ever_found=True,
                version=result.get("Version"),
                out_of_date=out_of_date,
                last_modified=result.get("LastModified"),
                co_maintainers=co_maintainers,
            )
        )
    return findings, states


def fresh_events(findings: list[Finding]) -> set[tuple[str, str]]:
    """The events this run noticed. classify_aur only emits one when it happens."""
    return {(f.package, f.key) for f in findings if f.key in EVENT_KEYS}


def carry_events(
    findings: list[Finding], events: list[OpenEvent], names: list[str], now: int
) -> list[Finding]:
    """Keep earlier events open for their window, while the package is installed."""
    current = {(f.package, f.key) for f in findings}
    installed = set(names)
    carried = [
        Finding(AUR, e.package, e.key, e.level, e.detail)
        for e in events
        if (e.package, e.key) not in current
        and e.package in installed
        and now - e.first_seen < EVENT_WINDOW_SECONDS
    ]
    # A package shown as just removed is not also listed as never found.
    removed = {f.package for f in carried if f.key == "removed"}
    kept = [f for f in findings if not (f.key == "not_found" and f.package in removed)]
    return kept + carried


def notification(reds: list[tuple[str, str]]) -> tuple[str, str]:
    """Title and body for (package, key) pairs: always one notification."""
    if len(reds) == 1:
        package, key = reds[0]
        return "Sicil: new red finding", f"{package}: {key}\nSee: sicil report"
    packages = sorted({package for package, _ in reds})
    shown = ", ".join(packages[:MAX_PACKAGES_NOTIFIED])
    extra = len(packages) - MAX_PACKAGES_NOTIFIED
    if extra > 0:
        shown += f" +{extra} more"
    return f"Sicil: {len(reds)} new red findings", f"{shown}\nSee: sicil report"


def suggests_removal(
    leaves: frozenset[str], idle: frozenset[str], observed_days: float
) -> bool:
    """Removing the leaves must take the vulnerable package off the system.

    Yoklama's sections are exclusive, so a protected or unmeasurable leaf is never
    in `idle` and blocks the suggestion like a used one does. No leaves: no suggestion.
    """
    return observed_days >= OBSERVATION_DAYS and bool(leaves) and leaves <= idle
