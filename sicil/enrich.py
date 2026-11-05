"""Collect CVE records, KEV and EPSS. A failure here never fails the repo strip."""

import json
from dataclasses import dataclass, field

from . import cve as cve_module
from .cve import CLOSED, CveFacts, Enrichment
from .sources import Advisory, SourceError, Sources
from .store import Store

REFRESH_SECONDS = 7 * 86400


@dataclass
class Gathered:
    enrichment: Enrichment
    records: list[tuple[str, str | None]] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)


def _parse(cve: str, text: str | None, warnings: list[str]) -> CveFacts | None:
    if text is None:
        return None
    try:
        return cve_module.parse_record(json.loads(text))
    except ValueError as e:
        warnings.append(f"{cve}: {e}")
        return None


def _due(
    cve: str,
    cached: tuple[str | None, int] | None,
    facts: CveFacts | None,
    packages: list[Advisory],
    sources: Sources,
    now: int,
) -> bool:
    if cached is None:
        return True
    if now - cached[1] < REFRESH_SECONDS:
        return False
    # Only a record that has not settled the question is worth asking about again.
    if facts is None:
        return True
    return any(
        cve_module.decide(facts, a.package, a.installed, sources.vercmp) != CLOSED
        for a in packages
    )


def gather(
    sources: Sources,
    store: Store,
    advisories: list[Advisory],
    now: int,
    warnings: list[str],
) -> Gathered:
    by_cve: dict[str, list[Advisory]] = {}
    for advisory in advisories:
        for cve in advisory.cves:
            by_cve.setdefault(cve, []).append(advisory)

    gathered = Gathered(Enrichment())
    cached = store.cached_cves(sorted(by_cve))
    reachable = True
    for cve, packages in sorted(by_cve.items()):
        entry = cached.get(cve)
        text = entry[0] if entry else None
        facts = _parse(cve, text, warnings)
        if reachable and _due(cve, entry, facts, packages, sources, now):
            try:
                text = sources.cve_record(cve)
                gathered.records.append((cve, text))
                facts = _parse(cve, text, warnings)
            except SourceError as e:
                # Most likely the network: do not wait out a timeout for every CVE.
                reachable = False
                warnings.append(f"CVE records incomplete: {e}")
        if facts is not None:
            gathered.enrichment.facts[cve] = facts

    kev_text = store.meta("kev")
    try:
        kev_text = json.dumps(sorted(sources.kev()))
        gathered.meta["kev"] = kev_text
    except SourceError as e:
        warnings.append(f"KEV not updated: {e}")
    gathered.enrichment.kev = frozenset(json.loads(kev_text or "[]"))

    known = json.loads(store.meta("epss") or "{}")
    try:
        known.update(sources.epss(set(by_cve)))
        gathered.meta["epss"] = json.dumps(known)
    except SourceError as e:
        warnings.append(f"EPSS not updated: {e}")
    gathered.enrichment.epss = known
    return gathered
