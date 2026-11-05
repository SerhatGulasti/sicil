"""Reading cvelistV5 records and deciding what they say. Pure: no I/O, no clock."""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

CLOSED = "closed"
OPEN = "open"
UNKNOWN = "unknown"

# A distribution's own builds say nothing about the upstream version installed here.
DISTRO_VENDORS = (
    "red hat",
    "suse",
    "debian",
    "ubuntu",
    "canonical",
    "fedora",
    "oracle",
    "amazon",
    "alpine",
)
# Versions of these types cannot be compared with an upstream version.
UNUSABLE_VERSION_TYPES = {"rpm", "deb", "apk", "git"}
METRICS_NEWEST_FIRST = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
CISA_ADP = "CISA-ADP"


@dataclass(frozen=True)
class ProductRow:
    vendor: str
    names: tuple[str, ...]
    default_status: str | None
    versions: tuple[dict, ...]


@dataclass(frozen=True)
class CveFacts:
    cve: str
    description: str | None
    cvss: float | None
    cvss_source: str | None
    rows: tuple[ProductRow, ...]


@dataclass
class Enrichment:
    facts: dict[str, CveFacts] = field(default_factory=dict)
    kev: frozenset[str] = frozenset()
    epss: dict[str, float] = field(default_factory=dict)


def _score(container: dict) -> float | None:
    metrics = container.get("metrics") or []
    for name in METRICS_NEWEST_FIRST:
        for metric in metrics:
            score = (metric.get(name) or {}).get("baseScore")
            if score is not None:
                return score
    return None


def parse_record(raw: dict) -> CveFacts:
    """Raises ValueError on a record of an unexpected shape."""
    try:
        containers = raw["containers"]
        cna = containers["cna"]
        descriptions = cna.get("descriptions") or []
        english = [d["value"] for d in descriptions if d.get("lang", "").startswith("en")]
        cvss = _score(cna)
        source = "CNA" if cvss is not None else None
        if cvss is None:
            for adp in containers.get("adp") or []:
                if (adp.get("providerMetadata") or {}).get("shortName") != CISA_ADP:
                    continue
                cvss = _score(adp)
                source = CISA_ADP if cvss is not None else None
        rows = tuple(
            ProductRow(
                vendor=row.get("vendor") or "",
                names=tuple(
                    name for name in (row.get("product"), row.get("packageName")) if name
                ),
                default_status=row.get("defaultStatus"),
                versions=tuple(row.get("versions") or []),
            )
            for row in cna.get("affected") or []
        )
        return CveFacts(
            cve=raw["cveMetadata"]["cveId"],
            description=(english or [None])[0],
            cvss=cvss,
            cvss_source=source,
            rows=rows,
        )
    except (KeyError, TypeError, AttributeError) as e:
        raise ValueError(f"unexpected CVE record: {e!r}") from e


def _squash(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def row_matches(package: str, row: ProductRow) -> bool:
    """Does this row describe the package itself rather than someone's build of it?"""
    vendor = row.vendor.lower()
    if any(distro in vendor for distro in DISTRO_VENDORS):
        return False
    base = re.sub(r"\d+$", "", package)
    for name in row.names:
        words = re.split(r"[^a-z0-9]+", name.lower())
        if _squash(name) in (_squash(package), _squash(base)) or base.lower() in words:
            return True
    return False


def _version_like(text: str | None) -> bool:
    return bool(text) and bool(re.fullmatch(r"\d[\w.+~-]*", text))


def upstream_version(installed: str) -> str:
    """Drop the epoch and pkgrel, which upstream ranges know nothing about."""
    return installed.split(":")[-1].rsplit("-", 1)[0]


def decide(
    facts: CveFacts,
    package: str,
    installed: str,
    vercmp: Callable[[str, str], int],
) -> str:
    """Whether the installed version falls in this CVE's affected range.

    Only machine-readable ranges on a row naming the package count, and free text is
    never parsed: a wrong "closed" is worse than none. A version outside the ranges
    counts as closed only if the row says everything unlisted is unaffected.
    """
    version = upstream_version(installed)
    has_range = False
    can_close = True
    for row in facts.rows:
        if not row_matches(package, row):
            continue
        if row.default_status != "unaffected":
            can_close = False
        for entry in row.versions:
            if entry.get("status") != "affected":
                continue
            if entry.get("versionType") in UNUSABLE_VERSION_TYPES:
                continue
            start = entry.get("version")
            below = entry.get("lessThan")
            through = entry.get("lessThanOrEqual")
            if not _version_like(start):
                continue
            if below or through:
                if not _version_like(below or through):
                    continue
                has_range = True
                above_start = start == "0" or vercmp(version, start) >= 0
                under_end = (
                    vercmp(version, below) < 0
                    if below
                    else vercmp(version, through) <= 0
                )
                if above_start and under_end:
                    return OPEN
            elif vercmp(version, start) == 0:
                return OPEN
    return CLOSED if has_range and can_close else UNKNOWN
