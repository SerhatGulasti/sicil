"""Tests. They never touch the network: AUR and tracker data come from fixtures."""

import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
import urllib.error
from unittest import mock

from sicil import report, rules, sources
from sicil.__main__ import format_result, main
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

    def test_new_co_maintainer_is_yellow(self):
        before = {"a": AurState("a", "alice", True, True, co_maintainers=("bob",))}
        info = {"a": dict(aur("a"), CoMaintainers=["bob", "mallory"])}
        findings, _ = rules.classify_aur(["a"], info, before)
        self.assertEqual(
            [(f.key, f.level, f.detail) for f in findings],
            [("co_maintainer_added", rules.YELLOW, {"added": ["mallory"]})],
        )

    def test_co_maintainer_leaving_is_not_a_signal(self):
        before = {"a": AurState("a", "alice", True, True, co_maintainers=("bob",))}
        found, _ = self.keys(["a"], {"a": aur("a")}, before)
        self.assertEqual(found, set())

    def test_unknown_co_maintainers_become_the_baseline(self):
        before = {"a": AurState("a", "alice", True, True, co_maintainers=None)}
        info = {"a": dict(aur("a"), CoMaintainers=["bob"])}
        found, states = self.keys(["a"], info, before)
        self.assertEqual(found, set())
        self.assertEqual(states["a"].co_maintainers, ("bob",))

    def test_first_sight_of_co_maintainers_is_not_an_addition(self):
        info = {"a": dict(aur("a"), CoMaintainers=["bob"])}
        found, _ = self.keys(["a"], info, {})
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
        self.sent = []
        self.records = {}
        self.fetched = []
        self.cve_attempts = 0
        self.kev_set = frozenset()
        self.epss_map = {}

    def notify(self, title, body):
        self._maybe_fail("notify")
        self.sent.append((title, body))

    def cve_record(self, cve):
        self.cve_attempts += 1
        self._maybe_fail("cve")
        self.fetched.append(cve)
        return self.records.get(cve)

    def kev(self):
        self._maybe_fail("kev")
        return self.kev_set

    def epss(self, wanted):
        self._maybe_fail("epss")
        return {cve: score for cve, score in self.epss_map.items() if cve in wanted}

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


class RunCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "state", "sicil.db")
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.fake = FakeSources()
        self.now = 1000
        # Whether this machine has Yoklama must not decide what a test sees.
        found = mock.patch("sicil.report.yoklama_installed", return_value=True)
        found.start()
        self.addCleanup(found.stop)

    def run_once(self):
        self.now += 100
        return execute(self.store, self.fake, clock=lambda: self.now)

    def rows(self, sql, *args):
        return self.store.db.execute(sql, args).fetchall()


class Runs(RunCase):
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
        self.assertIn("Not checked this run: official packages.", text)
        self.assertIn("incomplete", text)

    def open_aur(self):
        return sorted(
            (f.package, f.key) for f in self.store.open_findings() if f.strip == "aur"
        )

    def days(self, count):
        self.now += count * 86400

    def test_maintainer_change_stays_open_for_seven_days(self):
        self.run_once()
        self.fake.info = {"foo": aur("foo", "mallory")}
        result = self.run_once()
        self.assertEqual(
            [r for r in result.diff.new if r[0] == "foo"],
            [("foo", "maintainer_changed", rules.RED)],
        )
        self.days(6)
        result = self.run_once()
        self.assertEqual(self.open_aur(), [("foo", "maintainer_changed")])
        self.assertEqual(result.diff.new, [])  # not new again: one notification only
        self.days(1)
        result = self.run_once()
        self.assertEqual(self.open_aur(), [])
        self.assertEqual(
            result.diff.closed, [("foo", "maintainer_changed", rules.RED)]
        )

    def test_second_change_restarts_the_window(self):
        self.run_once()
        self.fake.info = {"foo": aur("foo", "mallory")}
        self.run_once()
        self.days(6)
        self.fake.info = {"foo": aur("foo", "eve")}
        result = self.run_once()
        self.assertIn(("foo", "maintainer_changed", rules.RED), result.diff.new)
        self.assertIn(("foo", "maintainer_changed", rules.RED), result.diff.closed)
        self.days(6)
        self.run_once()
        self.assertEqual(self.open_aur(), [("foo", "maintainer_changed")])

    def test_removed_stays_red_then_becomes_not_found(self):
        self.run_once()
        self.fake.info = {}
        self.run_once()
        self.assertEqual(self.open_aur(), [("foo", "removed")])
        self.days(3)
        self.run_once()
        self.assertEqual(self.open_aur(), [("foo", "removed")])
        self.days(5)
        self.run_once()
        self.assertEqual(self.open_aur(), [("foo", "not_found")])

    def test_uninstalling_closes_an_open_event(self):
        self.run_once()
        self.fake.info = {"foo": aur("foo", "mallory")}
        self.run_once()
        self.fake.names = []
        self.fake.info = {}
        self.run_once()
        self.assertEqual(self.open_aur(), [])

    def test_new_co_maintainer_stays_open_for_seven_days(self):
        self.run_once()
        self.fake.info = {"foo": dict(aur("foo"), CoMaintainers=["mallory"])}
        self.run_once()
        self.days(6)
        self.run_once()
        self.assertEqual(self.open_aur(), [("foo", "co_maintainer_added")])
        self.days(1)
        self.run_once()
        self.assertEqual(self.open_aur(), [])

    def test_outage_during_the_window_keeps_the_event(self):
        self.run_once()
        self.fake.info = {"foo": aur("foo", "mallory")}
        self.run_once()
        self.fake.fail = {"aur"}
        self.days(8)
        self.run_once()
        self.assertEqual(self.open_aur(), [("foo", "maintainer_changed")])

    def test_version_1_database_migrates_without_false_alarms(self):
        self.fake.info = {"foo": dict(aur("foo"), CoMaintainers=["bob"])}
        self.run_once()
        self.store.db.executescript(
            "DROP TABLE cve_cache; DROP TABLE enrich_meta;"
            " ALTER TABLE runs DROP COLUMN kernel_ok;"
            " ALTER TABLE aur_state DROP COLUMN co_maintainers;"
            " PRAGMA user_version = 1;"
        )
        self.store.close()
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        version = self.rows("PRAGMA user_version")[0][0]
        self.assertEqual(version, 3)
        self.assertIsNone(self.store.aur_state()["foo"].co_maintainers)
        self.run_once()
        self.assertEqual(self.open_aur(), [])
        self.assertEqual(self.store.aur_state()["foo"].co_maintainers, ("bob",))


class Notifications(RunCase):
    def test_new_red_alerts_once(self):
        self.assertEqual(self.run_once().notified, 1)
        self.assertEqual(self.run_once().notified, 0)
        self.assertEqual(len(self.fake.sent), 1)
        title, body = self.fake.sent[0]
        self.assertIn("new red finding", title)
        self.assertIn("pam: known vulnerability", body)
        self.assertNotIn("AVG", body)

    def test_several_reds_make_one_summary(self):
        self.fake.adv = [
            advisory(package=f"pkg{i}", avg=f"AVG-{i}") for i in range(7)
        ]
        self.fake.chains.update({f"pkg{i}": frozenset() for i in range(7)})
        self.assertEqual(self.run_once().notified, 7)
        self.assertEqual(len(self.fake.sent), 1)
        title, body = self.fake.sent[0]
        self.assertIn("7 new red findings", title)
        self.assertIn("+2 more", body)

    def test_yellow_and_unverified_do_not_alert(self):
        self.fake.adv = [
            advisory(severity="Low"),
            advisory(avg="AVG-2", installed="2.0-1", affected="1.0-1"),
        ]
        self.fake.info = {"foo": aur("foo", None)}
        self.assertEqual(self.run_once().notified, 0)
        self.assertEqual(self.fake.sent, [])

    def test_raised_to_red_alerts(self):
        self.fake.adv = [advisory(severity="Low")]
        self.run_once()
        self.fake.adv = [advisory(severity="High")]
        self.assertEqual(self.run_once().notified, 1)

    def test_aur_event_alerts_on_its_first_day_only(self):
        self.fake.adv = []
        self.run_once()
        self.fake.info = {"foo": aur("foo", "mallory")}
        self.assertEqual(self.run_once().notified, 1)
        self.now += 86400
        self.assertEqual(self.run_once().notified, 0)
        self.assertEqual(len(self.fake.sent), 1)

    def test_outage_does_not_alert_again(self):
        self.run_once()
        self.fake.fail = {"repo", "aur"}
        self.run_once()
        self.fake.fail = set()
        self.assertEqual(self.run_once().notified, 0)
        self.assertEqual(len(self.fake.sent), 1)

    def test_failed_notification_is_a_recorded_warning(self):
        self.fake.fail = {"notify"}
        result = self.run_once()
        self.assertEqual(result.notified, 0)
        warnings = json.loads(self.rows("SELECT warnings FROM runs")[0][0])
        self.assertTrue(any("notification" in w for w in warnings))
        self.assertEqual(len(self.store.open_findings()), 1)

    def test_run_that_failed_to_record_does_not_alert(self):
        with mock.patch.object(
            self.store, "replace_aur_state", side_effect=sqlite3.OperationalError("x")
        ):
            with self.assertRaises(sqlite3.OperationalError):
                self.run_once()
        self.assertEqual(self.fake.sent, [])

    def test_real_command_line(self):
        result = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch("subprocess.run", return_value=result) as run:
            sources.Sources().notify("title", "body")
        command = run.call_args.args[0]
        self.assertEqual(command[0], "notify-send")
        self.assertIn("--urgency=critical", command)
        self.assertEqual(command[-2:], ["title", "body"])


class Reports(RunCase):
    """Every report test reads a database written by a real run."""

    def load(self, **kwargs):
        kwargs.setdefault("now", self.now)
        self.store.db.commit()
        return report.load(self.path, **kwargs)

    def test_sections(self):
        self.fake.names = ["foo", "gone"]
        self.fake.info = {"foo": aur("foo", None)}
        self.fake.adv = [
            advisory(package="pam", avg="AVG-1", severity="High"),
            advisory(package="lib", avg="AVG-2", severity="Low", installed="1.0-1"),
            advisory(
                package="old",
                avg="AVG-3",
                severity="High",
                installed="2.0-1",
                affected="1.0-1",
            ),
        ]
        self.fake.chains.update(lib=frozenset({"lib"}), gone=frozenset({"gone"}))
        self.run_once()
        loaded = self.load()
        self.assertEqual([f["package"] for f in loaded.red], ["pam"])
        self.assertEqual([f["package"] for f in loaded.yellow], ["foo", "lib"])
        self.assertEqual([f["package"] for f in loaded.unverified], ["old"])
        self.assertEqual([f["package"] for f in loaded.not_found], ["gone"])
        self.assertEqual(loaded.closed, [])

    def test_removal_section_has_one_row_per_package(self):
        self.fake.adv = [
            advisory(avg="AVG-1"),
            advisory(avg="AVG-2", severity="Low"),
        ]
        self.fake.view = YoklamaView(61, frozenset({"app"}), {}, ())
        self.run_once()
        loaded = self.load()
        self.assertEqual(len(loaded.removal), 1)
        self.assertEqual(loaded.removal[0]["remove"], ["app"])
        self.assertEqual(len(loaded.removal[0]["signals"]), 2)
        self.assertIn("app", report.format_text(loaded))

    def test_blocked_suggestion_still_shows_what_pulls_the_package(self):
        self.run_once()
        loaded = self.load()
        self.assertEqual(loaded.removal, [])
        self.assertEqual(loaded.red[0]["leaves"], ["app"])
        self.assertIn("app", report.format_text(loaded))

    def test_closed_only_with_all(self):
        self.run_once()
        self.fake.adv = []
        self.run_once()
        self.assertEqual(self.load().closed, [])
        self.assertNotIn("Closed", report.format_text(self.load()))
        closed = self.load(all_findings=True)
        self.assertEqual([f["package"] for f in closed.closed], ["pam"])
        self.assertIn("Closed", report.format_text(closed))
        self.assertIn("closed", json.loads(report.format_json(closed)))
        self.assertNotIn("closed", json.loads(report.format_json(self.load())))

    def test_stale_run_warns_after_36_hours(self):
        self.run_once()
        fresh = self.load(now=self.now + 36 * 3600)
        self.assertFalse(fresh.last_run["stale"])
        stale = self.load(now=self.now + 36 * 3600 + 1)
        self.assertTrue(stale.last_run["stale"])
        self.assertIn("hours old", report.format_text(stale))

    def test_yoklama_warning_and_incomplete_run_are_carried(self):
        self.fake.fail = {"aur"}
        self.run_once()
        text = report.format_text(self.load())
        self.assertIn("too early", text)
        self.assertIn("incomplete", text)
        self.assertIn("aur FAILED", text)

    def test_long_leaf_list_is_shortened_in_text_but_not_in_json(self):
        leaves = frozenset(f"leaf{i}" for i in range(9))
        self.fake.leaf_set = leaves
        self.fake.chains["pam"] = leaves
        self.run_once()
        loaded = self.load()
        self.assertIn("+4 more", report.format_text(loaded))
        data = json.loads(report.format_json(loaded))
        self.assertEqual(len(data["red"][0]["leaves"]), 9)

    def test_empty_sections_say_so(self):
        self.fake.adv = []
        self.run_once()
        text = report.format_text(self.load())
        for title in ("Red: none", "Yellow: none", "Removal suggestions: none"):
            self.assertIn(title, text)

    def test_signals_are_readable(self):
        self.run_once()
        self.fake.adv = []
        self.fake.info = {
            "foo": dict(
                aur("foo", "mallory", out_of_date=500), CoMaintainers=["eve"]
            )
        }
        self.store.db.execute(
            "UPDATE aur_state SET co_maintainers = '[]' WHERE name = 'foo'"
        )
        self.store.db.commit()
        self.run_once()
        text = report.format_text(self.load())
        self.assertIn("maintainer alice -> mallory", text)
        self.assertIn("new co-maintainer eve", text)
        self.assertIn("flagged out of date", text)

    def test_report_writes_nothing_and_uses_no_network_or_programs(self):
        self.run_once()
        self.store.db.commit()
        before = os.stat(self.path).st_mtime_ns
        forbidden = AssertionError("report must not leave the database")
        with (
            mock.patch("urllib.request.urlopen", side_effect=forbidden),
            mock.patch("subprocess.run", side_effect=forbidden),
            mock.patch("builtins.print"),
        ):
            self.assertEqual(main(["report", "--db", self.path]), 0)
            self.assertEqual(main(["report", "--all", "--json", "--db", self.path]), 0)
        self.assertEqual(os.stat(self.path).st_mtime_ns, before)

    def test_report_cannot_write_through_its_connection(self):
        self.run_once()
        self.store.db.commit()
        db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        self.addCleanup(db.close)
        with self.assertRaises(sqlite3.OperationalError):
            db.execute("DELETE FROM runs")

    def test_missing_database_is_a_clean_error(self):
        path = os.path.join(self.dir.name, "nothing.db")
        with self.assertRaises(report.ReportError):
            report.load(path)
        self.assertFalse(os.path.exists(path))
        with mock.patch("sys.stderr"):
            self.assertEqual(main(["report", "--db", path]), 1)

    def test_database_with_no_runs_is_a_clean_error(self):
        with self.assertRaises(report.ReportError):
            self.load()


if __name__ == "__main__":
    unittest.main()
