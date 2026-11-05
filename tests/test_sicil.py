"""Tests. They never touch the network: AUR and tracker data come from fixtures."""

import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
import urllib.error
from unittest import mock

from sicil import rules, sources
from sicil.__main__ import format_result
from sicil.rules import AurState
from sicil.run import execute
from sicil.sources import (
    Advisory,
    SourceError,
    YoklamaView,
    parse_advisories,
    parse_aur_info,
    parse_yoklama,
)
from sicil.store import Store

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(name):
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return f.read()


def vercmp(a, b):
    return int(subprocess.check_output(["vercmp", a, b], text=True))


def advisory(**overrides):
    values = dict(
        package="pam",
        avg="AVG-1",
        severity="High",
        status="Vulnerable",
        type="unknown",
        fixed=None,
        affected=None,
        installed="1.0-1",
        cves=("CVE-1",),
    )
    values.update(overrides)
    return Advisory(**values)


def aur(name, maintainer="alice", out_of_date=None):
    return {
        "Name": name,
        "Maintainer": maintainer,
        "OutOfDate": out_of_date,
        "Version": "1-1",
        "LastModified": 100,
    }


class FixtureData(unittest.TestCase):
    """The real responses saved in Phase 0."""

    def test_all_phase0_advisories_are_unverified(self):
        installed = json.loads(fixture("installed-subset.json"))
        advisories = parse_advisories(
            json.loads(fixture("arch-audit.json")),
            json.loads(fixture("tracker-subset.json")),
            installed,
        )
        self.assertEqual(len(advisories), 21)
        self.assertEqual(len({a.package for a in advisories}), 17)
        findings = rules.classify_repo(advisories, vercmp)
        self.assertEqual({f.level for f in findings}, {rules.UNVERIFIED})

    def test_advisory_for_a_package_not_installed_is_dropped(self):
        audit = [
            {
                "name": "AVG-1",
                "packages": ["a", "b"],
                "status": "Vulnerable",
                "type": "x",
                "severity": "Low",
                "fixed": None,
                "issues": [],
            }
        ]
        found = parse_advisories(audit, [], {"a": "1-1"})
        self.assertEqual([a.package for a in found], ["a"])

    def test_aur_fixture(self):
        info = parse_aur_info(fixture("aur-info.json"))
        self.assertEqual(len(info), 41)
        findings, states = rules.classify_aur(sorted(info), info, {})
        self.assertEqual(findings, [])
        self.assertTrue(all(s.found for s in states))

    def test_orphan_fixture(self):
        info = parse_aur_info(fixture("aur-orphan.json"))
        findings, _ = rules.classify_aur(
            ["cbatticon-gtk2", "sicil-olmayan-paket"], info, {}
        )
        self.assertEqual(
            {(f.package, f.key, f.level) for f in findings},
            {
                ("cbatticon-gtk2", "orphan", rules.YELLOW),
                ("cbatticon-gtk2", "out_of_date", rules.YELLOW),
                ("sicil-olmayan-paket", "not_found", rules.NOT_FOUND),
            },
        )


class RepoLevels(unittest.TestCase):
    def level(self, **overrides):
        return rules.repo_level(advisory(**overrides), vercmp)

    def test_severities(self):
        self.assertEqual(self.level(severity="Critical"), rules.RED)
        self.assertEqual(self.level(severity="High"), rules.RED)
        self.assertEqual(self.level(severity="Medium"), rules.YELLOW)
        self.assertEqual(self.level(severity="Low"), rules.YELLOW)
        self.assertEqual(self.level(severity="Unknown"), rules.YELLOW)

    def test_no_fix_and_newer_than_affected_is_unverified(self):
        self.assertEqual(
            self.level(installed="1.1-1", affected="1.0-1"), rules.UNVERIFIED
        )

    def test_no_fix_and_same_as_affected_keeps_its_severity(self):
        self.assertEqual(self.level(installed="1.0-1", affected="1.0-1"), rules.RED)

    def test_cachyos_suffix_counts_as_newer(self):
        self.assertEqual(
            self.level(installed="1.0-1.1", affected="1.0-1"), rules.UNVERIFIED
        )

    def test_known_fix_is_not_unverified(self):
        self.assertEqual(
            self.level(installed="1.1-1", affected="1.0-1", fixed="2.0-1"), rules.RED
        )

    def test_missing_affected_keeps_its_severity(self):
        self.assertEqual(self.level(installed="1.1-1", affected=None), rules.RED)


class AurSignals(unittest.TestCase):
    def keys(self, names, info, previous):
        findings, states = rules.classify_aur(names, info, previous)
        return {(f.package, f.key, f.level) for f in findings}, {
            s.name: s for s in states
        }

    def test_not_found_on_first_run_is_not_red(self):
        found, states = self.keys(["a"], {}, {})
        self.assertEqual(found, {("a", "not_found", rules.NOT_FOUND)})
        self.assertFalse(states["a"].ever_found)

    def test_disappearing_is_red_once_then_not_found(self):
        before = {"a": AurState("a", "alice", True, True)}
        found, states = self.keys(["a"], {}, before)
        self.assertEqual(found, {("a", "removed", rules.RED)})
        found, _ = self.keys(["a"], {}, states)
        self.assertEqual(found, {("a", "not_found", rules.NOT_FOUND)})

    def test_maintainer_change_is_red(self):
        before = {"a": AurState("a", "alice", True, True)}
        found, _ = self.keys(["a"], {"a": aur("a", "mallory")}, before)
        self.assertEqual(found, {("a", "maintainer_changed", rules.RED)})

    def test_adopting_an_orphan_is_red(self):
        before = {"a": AurState("a", None, True, True)}
        found, _ = self.keys(["a"], {"a": aur("a", "mallory")}, before)
        self.assertEqual(found, {("a", "maintainer_changed", rules.RED)})

    def test_losing_the_maintainer_is_only_yellow(self):
        before = {"a": AurState("a", "alice", True, True)}
        found, _ = self.keys(["a"], {"a": aur("a", None)}, before)
        self.assertEqual(found, {("a", "orphan", rules.YELLOW)})

    def test_change_across_a_disappearance_is_still_seen(self):
        before = {"a": AurState("a", "alice", False, True)}
        found, _ = self.keys(["a"], {"a": aur("a", "mallory")}, before)
        self.assertEqual(found, {("a", "maintainer_changed", rules.RED)})

    def test_first_sight_of_a_maintainer_is_not_a_change(self):
        found, _ = self.keys(["a"], {"a": aur("a")}, {})
        self.assertEqual(found, set())


class RemovalRule(unittest.TestCase):
    def suggests(self, leaves, idle, days=60):
        return rules.suggests_removal(frozenset(leaves), frozenset(idle), days)

    def test_all_leaves_idle(self):
        self.assertTrue(self.suggests({"a", "b"}, {"a", "b", "c"}))

    def test_one_used_leaf_blocks(self):
        self.assertFalse(self.suggests({"a", "b"}, {"a"}))

    def test_no_leaves_means_no_suggestion(self):
        self.assertFalse(self.suggests(set(), {"a"}))

    def test_short_observation_blocks(self):
        self.assertFalse(self.suggests({"a"}, {"a"}, days=59.9))


class YoklamaParsing(unittest.TestCase):
    def test_threshold_comes_from_the_default_report(self):
        row = lambda name, seen=None: {"name": name, "last_seen": seen}
        view = parse_yoklama(
            {
                "observed_days": 61,
                "idle": [row("old")],
                "protected": [],
                "unmeasurable": [],
                "warnings": ["w"],
            },
            {
                "idle": [row("old", 5), row("recent", 9)],
                "protected": [row("base")],
                "unmeasurable": [row("theme")],
            },
        )
        self.assertEqual(view.idle, {"old"})
        self.assertEqual(view.last_seen["recent"], 9)
        self.assertIn("theme", view.last_seen)
        self.assertEqual(view.warnings, ("w",))

    def test_changed_shape_is_a_source_error(self):
        with self.assertRaises(SourceError):
            parse_yoklama({}, {})


class RealSourcesFailCleanly(unittest.TestCase):
    def test_network_failure_is_a_source_error(self):
        with mock.patch(
            "urllib.request.urlopen", side_effect=urllib.error.URLError("down")
        ):
            with self.assertRaises(SourceError):
                sources.Sources().aur_info(["a"])
            with self.assertRaises(SourceError):
                sources.Sources().advisories({})

    def test_aur_error_reply_is_a_source_error(self):
        with self.assertRaises(SourceError):
            parse_aur_info(b'{"type": "error", "error": "Too many package results."}')
        with self.assertRaises(SourceError):
            parse_aur_info(b"<html>")

    def test_empty_pacman_query_is_not_an_error(self):
        result = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch("subprocess.run", return_value=result):
            self.assertEqual(sources.Sources().foreign_packages(), [])

    def test_pacman_failure_is_an_error(self):
        result = subprocess.CompletedProcess([], 1, "", "error: db locked\n")
        with mock.patch("subprocess.run", return_value=result):
            with self.assertRaises(SourceError):
                sources.Sources().foreign_packages()

    def test_missing_program_is_an_error(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError("arch-audit")):
            with self.assertRaises(SourceError):
                sources.Sources().installed()


class FakeSources:
    def __init__(self):
        self.packages = {"pam": "1.0-1", "foo": "1-1"}
        self.adv = [advisory(package="pam", installed="1.0-1")]
        self.names = ["foo"]
        self.info = {"foo": aur("foo")}
        self.leaf_set = frozenset({"app"})
        self.chains = {
            "pam": frozenset({"pam", "app"}),
            "foo": frozenset({"foo"}),
        }
        self.view = YoklamaView(0.2, frozenset(), {"pam": 7}, ("too early",))
        self.fail = set()

    def _maybe_fail(self, name):
        if name in self.fail:
            raise SourceError(f"{name} down")

    def installed(self):
        return self.packages

    def advisories(self, installed):
        self._maybe_fail("repo")
        return self.adv

    def vercmp(self, a, b):
        return vercmp(a, b)

    def foreign_packages(self):
        return self.names

    def aur_info(self, names):
        self._maybe_fail("aur")
        return self.info

    def yoklama(self):
        self._maybe_fail("yoklama")
        return self.view

    def leaves(self):
        self._maybe_fail("leaves")
        return self.leaf_set

    def chain(self, package):
        self._maybe_fail("chain")
        return self.chains[package]


class Runs(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "state", "sicil.db")
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.fake = FakeSources()
        self.now = 1000

    def run_once(self):
        self.now += 100
        return execute(self.store, self.fake, clock=lambda: self.now)

    def rows(self, sql, *args):
        return self.store.db.execute(sql, args).fetchall()

    def test_first_run_opens_a_finding(self):
        result = self.run_once()
        self.assertEqual(result.diff.new, [("pam", "AVG-1", rules.RED)])
        self.assertEqual(result.levels, {rules.RED: 1})
        self.assertIn("too early", result.warnings)
        first, last, used = self.rows(
            "SELECT first_seen, last_seen, last_used FROM findings"
        )[0]
        self.assertEqual((first, last, used), (1100, 1100, 7))

    def test_second_run_keeps_first_seen(self):
        self.run_once()
        result = self.run_once()
        self.assertEqual(result.diff.new, [])
        self.assertEqual(
            self.rows("SELECT first_seen, last_seen FROM findings"), [(1100, 1200)]
        )

    def test_finding_that_goes_away_closes_and_can_reopen(self):
        self.run_once()
        kept = self.fake.adv
        self.fake.adv = []
        result = self.run_once()
        self.assertEqual(result.diff.closed, [("pam", "AVG-1", rules.RED)])
        self.assertEqual(self.store.open_findings(), [])
        self.fake.adv = kept
        result = self.run_once()
        self.assertEqual(result.diff.new, [("pam", "AVG-1", rules.RED)])
        self.assertEqual(self.rows("SELECT count(*) FROM findings"), [(2,)])

    def test_level_change_is_reported(self):
        self.run_once()
        self.fake.adv = [advisory(installed="2.0-1", affected="1.0-1")]
        result = self.run_once()
        self.assertEqual(
            result.diff.changed, [("pam", "AVG-1", rules.RED, rules.UNVERIFIED)]
        )

    def test_failed_repo_strip_keeps_its_state(self):
        self.run_once()
        self.fake.fail = {"repo"}
        self.fake.adv = []
        result = self.run_once()
        self.assertFalse(result.repo_ok)
        self.assertTrue(result.aur_ok)
        self.assertEqual(result.diff.closed, [])
        self.assertEqual(len(self.store.open_findings()), 1)
        self.assertTrue(any("incomplete" in w for w in result.warnings))

    def test_failed_aur_strip_keeps_its_state(self):
        self.fake.names = ["foo"]
        self.fake.info = {"foo": aur("foo", None)}
        self.run_once()
        self.fake.fail = {"aur"}
        self.fake.info = {}
        result = self.run_once()
        self.assertFalse(result.aur_ok)
        self.assertEqual(result.diff.closed, [])
        self.assertEqual(self.store.aur_state()["foo"].found, True)
        self.assertEqual(
            [f.key for f in self.store.open_findings() if f.strip == "aur"], ["orphan"]
        )

    def test_network_outage_does_not_make_aur_packages_look_removed(self):
        self.run_once()
        self.fake.fail = {"aur"}
        self.run_once()
        self.fake.fail = set()
        result = self.run_once()
        self.assertEqual(result.levels.get(rules.RED), 1)  # only the repo finding
        self.assertEqual(result.diff.new, [])

    def test_both_strips_down_still_records_the_run(self):
        self.fake.fail = {"repo", "aur", "yoklama"}
        result = self.run_once()
        self.assertEqual(
            (result.repo_ok, result.aur_ok, result.yoklama_ok), (False, False, False)
        )
        warnings = json.loads(self.rows("SELECT warnings FROM runs")[0][0])
        self.assertEqual(len(warnings), 3)

    def test_uninstalled_aur_package_is_not_removed_red(self):
        self.run_once()
        self.fake.names = []
        self.fake.info = {}
        result = self.run_once()
        self.assertEqual(result.diff.new, [])
        self.assertEqual(self.store.aur_state(), {})

    def test_removal_suggested_only_when_every_leaf_is_idle(self):
        self.fake.view = YoklamaView(61, frozenset({"app"}), {}, ())
        result = self.run_once()
        self.assertEqual(result.removal_suggestions, 1)
        self.assertEqual(
            self.rows("SELECT leaves, suggest_removal FROM findings"),
            [('["app"]', 1)],
        )

    def test_no_suggestion_before_sixty_days(self):
        self.fake.view = YoklamaView(59, frozenset({"app"}), {}, ())
        self.assertEqual(self.run_once().removal_suggestions, 0)
        self.assertEqual(
            self.rows("SELECT leaves, suggest_removal FROM findings"),
            [('["app"]', 0)],
        )

    def test_unverified_never_suggests_removal(self):
        self.fake.adv = [advisory(installed="2.0-1", affected="1.0-1")]
        self.fake.view = YoklamaView(61, frozenset({"app"}), {}, ())
        self.assertEqual(self.run_once().removal_suggestions, 0)
        self.assertEqual(
            self.rows("SELECT leaves, suggest_removal FROM findings"), [(None, 0)]
        )

    def test_yoklama_down_keeps_last_use_and_withdraws_suggestion(self):
        self.fake.view = YoklamaView(61, frozenset({"app"}), {"pam": 7}, ())
        self.assertEqual(self.run_once().removal_suggestions, 1)
        self.fake.fail = {"yoklama"}
        result = self.run_once()
        self.assertEqual(result.removal_suggestions, 0)
        self.assertEqual(
            self.rows("SELECT last_used, suggest_removal FROM findings"), [(7, 0)]
        )

    def test_missing_pactree_warns_and_does_not_fail_the_run(self):
        self.fake.view = YoklamaView(61, frozenset({"app"}), {}, ())
        self.fake.fail = {"chain"}
        result = self.run_once()
        self.assertEqual(result.removal_suggestions, 0)
        self.assertTrue(any("dependency chain" in w for w in result.warnings))

    def test_state_survives_reopening_the_database(self):
        self.run_once()
        self.store.close()
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.assertEqual(len(self.store.open_findings()), 1)
        self.assertEqual(self.store.aur_state()["foo"].maintainer, "alice")

    def test_failed_run_leaves_nothing_behind(self):
        with mock.patch.object(
            self.store, "replace_aur_state", side_effect=sqlite3.OperationalError("x")
        ):
            with self.assertRaises(sqlite3.OperationalError):
                self.run_once()
        self.assertEqual(self.rows("SELECT count(*) FROM runs"), [(0,)])
        self.assertEqual(self.rows("SELECT count(*) FROM findings"), [(0,)])

    def test_summary_names_failures(self):
        self.fake.fail = {"repo"}
        text = format_result(self.run_once())
        self.assertIn("repo FAILED", text)
        self.assertIn("incomplete", text)


if __name__ == "__main__":
    unittest.main()
