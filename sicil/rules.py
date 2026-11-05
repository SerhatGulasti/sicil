"""The decision rules. Pure functions: no I/O, no clock."""

from collections.abc import Callable
from dataclasses import dataclass

from .sources import Advisory

RED = "red"
YELLOW = "yellow"
UNVERIFIED = "unverified"
NOT_FOUND = "not_found"

REPO = "repo"
AUR = "aur"

# Removal is only ever suggested after this much observation.
OBSERVATION_DAYS = 60

RED_SEVERITIES = {"High", "Critical"}


@dataclass(frozen=True)
class Finding:
    strip: str
    package: str
    key: str
    level: str
    detail: dict


@dataclass(frozen=True)
class AurState:
    name: str
    maintainer: str | None
    found: bool
    ever_found: bool
    version: str | None = None
    out_of_date: int | None = None
    last_modified: int | None = None


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


def classify_repo(
    advisories: list[Advisory], vercmp: Callable[[str, str], int]
) -> list[Finding]:
    return [
        Finding(
            REPO,
            a.package,
            a.avg,
            repo_level(a, vercmp),
            {
                "severity": a.severity,
                "status": a.status,
                "type": a.type,
                "cves": list(a.cves),
                "fixed": a.fixed,
                "affected": a.affected,
                "installed": a.installed,
            },
        )
        for a in advisories
    ]


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
                )
            )
            continue

        maintainer = result.get("Maintainer")
        out_of_date = result.get("OutOfDate")
        # Losing a maintainer is the orphan signal below. Gaining a different one,
        # adoption of an orphan included, is the takeover this rule looks for.
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
            )
        )
    return findings, states


def suggests_removal(
    leaves: frozenset[str], idle: frozenset[str], observed_days: float
) -> bool:
    """Removing the leaves must take the vulnerable package off the system.

    Yoklama's sections are exclusive, so a protected or unmeasurable leaf is never
    in `idle` and blocks the suggestion like a used one does. No leaves: no suggestion.
    """
    return observed_days >= OBSERVATION_DAYS and bool(leaves) and leaves <= idle
