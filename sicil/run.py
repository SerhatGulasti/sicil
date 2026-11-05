"""One `sicil run`: read the sources, then record the result in one transaction."""

import time
from dataclasses import dataclass, field

from . import rules
from .rules import AUR, REPO, Finding
from .sources import SourceError, Sources, YoklamaView
from .store import Diff, Store


@dataclass
class RunResult:
    run_id: int
    repo_ok: bool
    aur_ok: bool
    yoklama_ok: bool
    warnings: list[str]
    diff: Diff
    levels: dict[str, int] = field(default_factory=dict)
    removal_suggestions: int = 0
    notified: int = 0


def _gather_repo(sources: Sources) -> list[Finding]:
    advisories = sources.advisories(sources.installed())
    return rules.classify_repo(advisories, sources.vercmp)


def _gather_aur(sources: Sources, store: Store):
    names = sources.foreign_packages()
    findings, states = rules.classify_aur(
        names, sources.aur_info(names), store.aur_state()
    )
    return names, findings, states


def _annotate(
    store: Store,
    sources: Sources,
    view: YoklamaView | None,
    warnings: list[str],
) -> int:
    """Attach last use, leaves and removal suggestions to the open findings."""
    try:
        leaves = sources.leaves()
    except SourceError as e:
        warnings.append(f"no removal suggestions: {e}")
        leaves = None

    chains: dict[str, frozenset[str] | None] = {}
    suggestions = 0
    for finding in store.open_findings():
        if view is not None:
            store.set_last_used(finding.id, view.last_seen.get(finding.package))
        if finding.level not in (rules.RED, rules.YELLOW) or leaves is None:
            store.annotate(finding.id, None, False)
            continue
        if finding.package not in chains:
            try:
                chains[finding.package] = sources.chain(finding.package)
            except SourceError as e:
                warnings.append(f"no dependency chain for {finding.package}: {e}")
                chains[finding.package] = None
        chain = chains[finding.package]
        if chain is None:
            store.annotate(finding.id, None, False)
            continue
        top = chain & leaves
        suggest = view is not None and rules.suggests_removal(
            top, view.idle, view.observed_days
        )
        store.annotate(finding.id, sorted(top), suggest)
        suggestions += suggest
    return suggestions


def execute(store: Store, sources: Sources, clock=time.time) -> RunResult:
    started = int(clock())
    warnings: list[str] = []

    # The network is read before the transaction, so no lock is held during it. A
    # strip that fails keeps its previous state: nothing of it is closed or changed.
    repo_findings = aur_names = aur_findings = aur_states = None
    try:
        repo_findings = _gather_repo(sources)
    except SourceError as e:
        warnings.append(f"this run is incomplete: repo strip skipped: {e}")
    try:
        aur_names, aur_findings, aur_states = _gather_aur(sources, store)
    except SourceError as e:
        warnings.append(f"this run is incomplete: AUR strip skipped: {e}")
    view = None
    try:
        view = sources.yoklama()
        warnings.extend(view.warnings)
    except SourceError as e:
        warnings.append(f"no usage data, no removal suggestions: {e}")

    now = int(clock())
    with store:
        run_id = store.add_run(
            started,
            now,
            repo_findings is not None,
            aur_findings is not None,
            view is not None,
            [],
        )
        diff = Diff()
        if repo_findings is not None:
            _merge(diff, store.sync_strip(REPO, repo_findings, run_id, now))
        if aur_findings is not None:
            merged = rules.carry_events(
                aur_findings, store.open_aur_events(), aur_names, now
            )
            renew = rules.fresh_events(aur_findings)
            _merge(diff, store.sync_strip(AUR, merged, run_id, now, renew))
            store.replace_aur_state(aur_states)
        suggestions = _annotate(store, sources, view, warnings)
        store.set_run_warnings(run_id, warnings)

        levels: dict[str, int] = {}
        for finding in store.open_findings():
            levels[finding.level] = levels.get(finding.level, 0) + 1

    # Only after the commit: these findings are no longer new, so they alert once,
    # and a run that failed to record alerts nobody.
    reds = _new_reds(diff)
    notified = 0
    if reds:
        try:
            sources.notify(*rules.notification(reds))
            notified = len(reds)
        except SourceError as e:
            warnings.append(f"could not send the notification: {e}")
            with store:
                store.set_run_warnings(run_id, warnings)

    return RunResult(
        run_id,
        repo_findings is not None,
        aur_findings is not None,
        view is not None,
        warnings,
        diff,
        levels,
        suggestions,
        notified,
    )


def _new_reds(diff: Diff) -> list[tuple[str, str]]:
    """Findings that became red in this run, whether newly opened or raised."""
    opened = [(package, key) for package, key, level in diff.new if level == rules.RED]
    raised = [
        (package, key) for package, key, _, level in diff.changed if level == rules.RED
    ]
    return opened + raised


def _merge(into: Diff, other: Diff) -> None:
    into.new.extend(other.new)
    into.closed.extend(other.closed)
    into.changed.extend(other.changed)
