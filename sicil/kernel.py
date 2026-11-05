"""The kernel strip. Pure functions: no I/O, no clock.

The kernel CNA opens a CVE for nearly every fix, so a kernel behind its branch is
covered by hundreds of records with nothing to tell them apart. What helps is one
line per kernel, and the level depends on whether there is anything to do about it.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from .cve import upstream_version
from .rules import INFO, KERNEL, RED, YELLOW, Finding
from .sources import KernelRecord, KernelRelease, SourceError

KERNEL_PACKAGES = ("linux-cachyos", "linux-cachyos-lts")

Version = tuple[int, ...]


@dataclass(frozen=True)
class InstalledKernel:
    package: str
    installed: str
    repo_version: str | None


def version_key(text: str | None) -> Version | None:
    """Comparable form of 6.18.55 or 7.4-rc1. An rc sorts before its release."""
    match = re.fullmatch(r"(\d+(?:\.\d+)*)(-rc\d+)?", text or "")
    if match is None:
        return None
    parts = tuple(int(part) for part in match.group(1).split("."))
    parts += (0,) * (3 - len(parts))
    return parts + (-1 if match.group(2) else 0,)


def _in_range(version: Version, entry: dict) -> bool | None:
    start = version_key(entry.get("version"))
    if start is None:
        return None
    below = entry.get("lessThan")
    through = entry.get("lessThanOrEqual")
    if below:
        end = version_key(below)
        return None if end is None else start <= version < end
    if through == "*":
        return version >= start
    if through:
        branch = re.fullmatch(r"(\d+)\.(\d+)\.\*", through)
        if branch:
            same = (int(branch[1]), int(branch[2])) == version[:2]
            return same and version >= start
        end = version_key(through)
        return None if end is None else start <= version <= end
    return None


def covers(rows: tuple[dict, ...], version: Version) -> bool:
    """Does any row of the record say this version is affected?

    Rows with a default of "affected" list what is safe, the others what is not. Git
    hashes cannot be compared with a version.
    """
    for row in rows:
        default = row.get("defaultStatus")
        if default not in ("affected", "unaffected"):
            continue
        usable = False
        hits = {"affected": False, "unaffected": False}
        for entry in row.get("versions") or []:
            if entry.get("versionType") == "git":
                continue
            inside = _in_range(version, entry)
            if inside is None:
                continue
            usable = True
            if inside and entry.get("status") in hits:
                hits[entry["status"]] = True
        if not usable:
            continue
        if not hits["unaffected"] if default == "affected" else hits["affected"]:
            return True
    return False


def fixed_in_branch(rows: tuple[dict, ...], branch: Version) -> str | None:
    bound = f"{branch[0]}.{branch[1]}.*"
    found = [
        entry["version"]
        for row in rows
        for entry in row.get("versions") or []
        if entry.get("status") == "unaffected"
        and entry.get("lessThanOrEqual") == bound
        and version_key(entry.get("version"))
    ]
    return min(found, key=version_key) if found else None


def running_version(package: str, release: str) -> str | None:
    """The version this package would be running at, if this release is its kernel.

    `uname -r` gives 6.18.55-2-cachyos-lts. The modules directory holding the package
    name is gone once the package is upgraded, which is the case that matters here.
    """
    match = re.fullmatch(r"(.+?)-(cachyos(?:-lts)?)", release)
    if match is None or f"linux-{match.group(2)}" != package:
        return None
    return match.group(1)


def _level(kev: list[str], eol: bool, repo_newer: bool) -> str:
    if kev:
        return RED
    # Being behind the branch alone asks for nothing: the repo may not have it yet.
    return YELLOW if eol or repo_newer else INFO


def classify(
    kernels: list[InstalledKernel],
    records: list[KernelRecord],
    releases: dict[str, KernelRelease],
    kev: frozenset[str],
    vercmp: Callable[[str, str], int],
    running_release: str,
) -> list[Finding]:
    findings = []
    for kernel in kernels:
        text = upstream_version(kernel.installed)
        version = version_key(text)
        if version is None:
            raise SourceError(f"{kernel.package}: unreadable version {kernel.installed}")
        name = f"{version[0]}.{version[1]}"
        release = releases.get(name)
        # kernel.org drops a branch from its list some time after it ends.
        eol = release is None or release.eol
        latest = None if release is None else release.version
        latest_key = version_key(latest)
        behind = None
        if latest_key and latest_key[:2] == version[:2]:
            behind = max(latest_key[2] - version[2], 0)

        covered = [r for r in records if covers(r.rows, version)]
        remaining = None
        if latest_key:
            remaining = sum(covers(r.rows, latest_key) for r in covered)
        kev_hits = sorted(r.cve for r in covered if r.cve in kev)
        repo_newer = bool(
            kernel.repo_version and vercmp(kernel.repo_version, kernel.installed) > 0
        )
        running = running_version(kernel.package, running_release)
        findings.append(
            Finding(
                KERNEL,
                kernel.package,
                "kernel",
                _level(kev_hits, eol, repo_newer),
                {
                    "version": text,
                    "installed": kernel.installed,
                    "branch": name,
                    "latest": latest,
                    "behind": behind,
                    "eol": eol,
                    "repo_version": kernel.repo_version,
                    "repo_newer": repo_newer,
                    "running": running is not None,
                    "running_version": running,
                    "reboot_pending": running is not None
                    and running != kernel.installed,
                    "covered_count": len(covered),
                    "remaining_count": remaining,
                    "kev": kev_hits,
                    "covered": [
                        {
                            "cve": r.cve,
                            "fixed_in": fixed_in_branch(r.rows, version[:2]),
                        }
                        for r in sorted(covered, key=lambda r: r.cve)
                    ],
                },
            )
        )
    return findings
