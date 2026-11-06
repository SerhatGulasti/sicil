"""`sicil show`: one record, judged against what is installed right now.

An ID names a package and a CVE, never a version: the version is read when the question
is asked, so one ID means the same on every machine. Not having a finding is reported as
exactly that, because "not found" must not read as "not affected".
"""

import json
import re
from dataclasses import dataclass, field

from . import cve as cve_module
from . import kernel, report, rules
from .report import Report, clean, finding_id, wrap
from .sources import Sources, kernel_rows

CVE_FORM = re.compile(r"CVE-\d{4}-\d{4,}")
CVE_PAGE = "https://www.cve.org/CVERecord?id={cve}"
TRACKER_PAGE = "https://security.archlinux.org/{cve}"

FIELDS = (
    "desc",
    "installed",
    "status",
    "severity",
    "cvss",
    "epss",
    "kev",
    "range",
    "record",
    "fixed",
    "last-used",
    "url",
)


class ShowError(Exception):
    """The question has no answer here: exit 1, unlike an empty field."""


@dataclass
class Shown:
    id: str
    package: str
    cve: str
    installed: str | None
    status: str
    known: bool = False
    fields: dict[str, str] = field(default_factory=dict)


def parse_id(text: str) -> tuple[str | None, str]:
    """(package, CVE), or (None, CVE) for a bare CVE. Raises ValueError otherwise."""
    package, separator, cve = text.rpartition(":")
    cve = cve.upper()
    if not CVE_FORM.fullmatch(cve) or (separator and not package):
        raise ValueError(f"{text!r} is not an ID: expected package:CVE-... or CVE-...")
    return (package or None), cve


def _sections(loaded: Report) -> list[dict]:
    """Every finding, the one that matters most first."""
    return [
        *loaded.red,
        *loaded.yellow,
        *loaded.unverified,
        *loaded.looks_closed,
        *loaded.kernels,
        *loaded.closed,
    ]


def _has_cve(finding: dict, cve: str) -> bool:
    detail = finding["detail"]
    if finding["strip"] == rules.REPO:
        return cve in detail["cves"]
    if finding["strip"] == rules.KERNEL:
        return any(entry["cve"] == cve for entry in detail["covered"])
    return False


def _word(finding: dict) -> str:
    if finding["closed_at"] is not None:
        return f"closed on {report.format_date(finding['closed_at'])}"
    match finding["level"]:
        case rules.RED:
            return "open, act on this (red)"
        case rules.YELLOW:
            return "open, worth a look (yellow)"
    return report.LEVEL_WORDS[finding["level"]]


def _not_listed(loaded: Report) -> str:
    finished = report.format_date(loaded.last_run["finished_at"])
    return (
        f"not among this machine's findings at the last run ({finished});"
        " that does not prove it is unaffected"
    )


def _range_word(facts: cve_module.CveFacts, package: str, installed: str, sources) -> str:
    return report.RANGE_WORDS[
        cve_module.decide(facts, package, installed, sources.vercmp)
    ]


def _kernel_shown(
    shown: Shown, finding: dict | None, sources: Sources, cve: str
) -> None:
    """A kernel's record lives in the checkout, not in the findings: they would be huge."""
    raw = sources.kernel_record(cve)
    facts = None
    if raw is not None:
        try:
            facts = cve_module.parse_record(raw)
        except ValueError:
            pass
    fields = shown.fields
    if facts is not None:
        shown.known = True
        fields["desc"] = clean(facts.description)
        if facts.cvss is not None:
            fields["cvss"] = str(facts.cvss)
            fields["cvss_source"] = facts.cvss_source or ""
    if finding is not None:
        shown.known = True
        fields["kev"] = "yes" if cve in finding["detail"]["kev"] else "no"
        for entry in finding["detail"]["covered"]:
            if entry["cve"] == cve and entry["fixed_in"]:
                fields["fixed"] = entry["fixed_in"]
    if shown.installed is None:
        return
    version = kernel.version_key(cve_module.upstream_version(shown.installed))
    if raw is None or version is None:
        return
    try:
        rows = kernel_rows(raw)
    except (KeyError, TypeError, AttributeError):
        return
    covered = kernel.covers(rows, version)
    shown.status = (
        "record covers this version" if covered else "record does not cover this version"
    )
    fixed = kernel.fixed_in_branch(rows, version[:2])
    if fixed:
        fields["fixed"] = fixed


def _repo_shown(
    shown: Shown, finding: dict | None, path: str, sources: Sources, cve: str
) -> None:
    fields = shown.fields
    facts = None
    raw = report.cached_record(path, cve)
    if raw:
        try:
            facts = cve_module.parse_record(json.loads(raw))
        except ValueError:
            pass
    known = {} if finding is None else finding["detail"].get("enrichment", {}).get(cve, {})
    description = known.get("description") or (facts.description if facts else None)
    if description:
        fields["desc"] = clean(description)
    cvss = known.get("cvss", facts.cvss if facts else None)
    if cvss is not None:
        fields["cvss"] = str(cvss)
        fields["cvss_source"] = known.get(
            "cvss_source", facts.cvss_source if facts else ""
        ) or ""
    if known.get("epss") is not None:
        fields["epss"] = f"{known['epss']:.3f}"
    if finding is not None:
        shown.known = True
        detail = finding["detail"]
        fields["severity"] = detail["severity"]
        fields["kev"] = "yes" if known.get("kev") else "no"
        if detail["affected"]:
            fields["record"] = detail["affected"]
        if detail["fixed"]:
            fields["fixed"] = detail["fixed"]
        if finding["leaves"]:
            fields["pulled_by"] = ", ".join(finding["leaves"])
        fields["tracker"] = TRACKER_PAGE.format(cve=cve)
    if facts is not None:
        shown.known = True
    if shown.installed is None:
        return
    # The range is judged on the version installed now, even if the run saw another.
    if facts is not None:
        fields["range"] = _range_word(facts, shown.package, shown.installed, sources)
    elif known.get("version"):
        fields["range"] = report.RANGE_WORDS.get(known["version"], "unknown")
    if finding is not None and detail["installed"] != shown.installed:
        shown.status = f"last run saw {detail['installed']}; run `sicil run` to judge it again"


def lookup(
    loaded: Report, path: str, sources: Sources, package: str, cve: str
) -> Shown:
    installed = sources.installed_version(package)
    finding = next(
        (
            f
            for f in _sections(loaded)
            if f["package"] == package and _has_cve(f, cve)
        ),
        None,
    )
    if installed is None:
        status = "not installed"
    elif finding is not None:
        status = _word(finding)
    else:
        status = _not_listed(loaded)
    shown = Shown(finding_id(package, cve), package, cve, installed, status)
    fields = shown.fields
    fields["url"] = CVE_PAGE.format(cve=cve)
    is_kernel = package in kernel.KERNEL_PACKAGES or (
        finding is not None and finding["strip"] == rules.KERNEL
    )
    if is_kernel:
        _kernel_shown(shown, finding, sources, cve)
    else:
        _repo_shown(shown, finding, path, sources, cve)
    if finding is not None and loaded.usage and not is_kernel:
        fields["last-used"] = report.format_date(finding["last_used"])
    return shown


def packages_with(loaded: Report, cve: str) -> list[str]:
    names: list[str] = []
    for finding in _sections(loaded):
        if _has_cve(finding, cve) and finding["package"] not in names:
            names.append(finding["package"])
    return names


def state_line(shown: Shown) -> str:
    if shown.installed is None:
        return shown.status.capitalize()
    return f"Installed {shown.installed} · {shown.status}"


def format_shown(shown: Shown, width: int | None) -> str:
    fields = shown.fields
    lines = [shown.id, *wrap(state_line(shown), width)]
    if fields.get("desc"):
        lines += ["", *wrap(fields["desc"], width)]
    cvss = fields.get("cvss")
    if cvss and fields.get("cvss_source"):
        cvss = f"{cvss} ({fields['cvss_source']})"
    rows = [
        ("Severity", fields.get("severity")),
        ("CVSS", cvss),
        ("EPSS", fields.get("epss")),
        ("KEV", fields.get("kev")),
        ("Range", fields.get("range")),
        ("Record", fields.get("record")),
        ("Fixed in", fields.get("fixed")),
        ("Last used", fields.get("last-used")),
        ("Pulled by", fields.get("pulled_by")),
        ("Tracker", fields.get("tracker")),
        ("Source", fields.get("url")),
    ]
    present = [(label, value) for label, value in rows if value]
    lines.append("")
    for label, value in present:
        indent = " " * 11
        body = wrap(value, width, indent)
        lines.append(f"{label:<9}  {body[0].strip()}")
        lines += body[1:]
    return "\n".join(lines)


def field_value(shown: Shown, name: str) -> str:
    """One field, bare, for scripts. An empty one prints an empty line."""
    match name:
        case "installed":
            return shown.installed or ""
        case "status":
            return shown.status
    return shown.fields.get(name, "")


def format_listing(
    loaded: Report, path: str, sources: Sources, cve: str, width: int | None
) -> str:
    names = packages_with(loaded, cve)
    if not names:
        return "\n".join(
            wrap(f"{cve}: {_not_listed(loaded)}.", width)
        )
    lines = [cve]
    for package in names:
        shown = lookup(loaded, path, sources, package, cve)
        lines.append(f"  {shown.id}")
        lines += wrap(state_line(shown), width, "    ")
    return "\n".join(lines)
