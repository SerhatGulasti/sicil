"""Faz 5: what a person reads. Every test reads a database written by a real run."""

import contextlib
import io
import json
import os
import shlex
import shutil
import sqlite3
import tempfile
import unittest
import unicodedata
from unittest import mock

from sicil import report, rules, show, sources
from sicil.__main__ import build_parser, format_result, main, terminal_width
from sicil.filters import Filters
from sicil.sources import SourceError, YoklamaView
from sicil.store import SCHEMA_VERSION, NewerSchema, Store

from test_enrich import real_record
from test_kernel import REAL, KernelSources
from test_sicil import RunCase, advisory, aur, vercmp

DAY = 86400
LONG = "A flaw " * 60


def enriched(cvss=None, epss=None, version="unknown", kev=False, description=LONG):
    return {
        "cvss": cvss,
        "cvss_source": "CNA" if cvss is not None else None,
        "epss": epss,
        "version": version,
        "kev": kev,
        "description": description,
    }


class PresentationCase(RunCase):
    def setUp(self):
        super().setUp()
        self.now = 100 * DAY

    def load(self, **kwargs):
        self.store.db.commit()
        kwargs.setdefault("now", self.now)
        return report.load(self.path, **kwargs)

    def filtered(self, **filters):
        return report.apply_filters(self.load(), Filters(**filters), vercmp)

    def cli(self, *arguments):
        self.store.db.commit()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*arguments, "--db", self.path])
        return code, out.getvalue(), err.getvalue()

    def set_enrichment(self, package, cves):
        """The run's enrichment comes from records, whose parsing has its own tests."""
        row = self.store.db.execute(
            "SELECT id, detail FROM findings WHERE package = ? AND closed_at IS NULL",
            (package,),
        ).fetchone()
        detail = json.loads(row[1])
        detail["enrichment"] = cves
        self.store.db.execute(
            "UPDATE findings SET detail = ? WHERE id = ?", (json.dumps(detail), row[0])
        )


def ids(findings):
    return [i for f in findings for i in (f"{f['package']}:{c}" for c in f["detail"]["cves"])]


class Filtering(PresentationCase):
    def setUp(self):
        super().setUp()
        self.fake.names = []
        self.fake.adv = [
            advisory(package="pam", avg="AVG-1", severity="High", cves=("CVE-2025-1",)),
            advisory(
                package="libxml2",
                avg="AVG-2",
                severity="Medium",
                installed="5.10-1",
                affected="5.9-1",
                fixed="5.11-1",
                cves=("CVE-2021-2", "CVE-2021-3"),
            ),
            advisory(package="libtiff", avg="AVG-3", severity="Unknown", cves=("CVE-2021-4",)),
        ]
        self.fake.chains.update(
            libxml2=frozenset({"libxml2"}), libtiff=frozenset({"libtiff"})
        )
        self.fake.view = YoklamaView(
            90,
            frozenset(),
            {"pam": self.now - 40 * DAY, "libxml2": self.now - 2 * DAY},
            (),
        )
        self.run_once()
        self.set_enrichment("pam", {"CVE-2025-1": enriched(cvss=7.8)})
        self.set_enrichment(
            "libxml2",
            {"CVE-2021-2": enriched(cvss=9.1), "CVE-2021-3": enriched(cvss=5.0)},
        )
        self.set_enrichment("libtiff", {"CVE-2021-4": enriched()})

    def test_no_filter_returns_the_same_report(self):
        loaded = self.load()
        self.assertIs(report.apply_filters(loaded, Filters(), vercmp), loaded)
        self.assertNotIn("Filtered", report.format_text(loaded))

    def test_different_filters_and_repeats_or(self):
        result = self.filtered(package=["pam", "libxml2"], min_cvss=[7])
        self.assertEqual(ids(result.red), ["pam:CVE-2025-1"])
        self.assertEqual(ids(result.yellow), ["libxml2:CVE-2021-2"])

    def test_a_filter_narrows_a_group_to_its_matching_cve(self):
        result = self.filtered(min_cvss=[9])
        self.assertEqual(result.yellow[0]["detail"]["cves"], ["CVE-2021-2"])
        self.assertEqual(list(result.yellow[0]["detail"]["enrichment"]), ["CVE-2021-2"])

    def test_wildcards(self):
        self.assertEqual(
            ids(self.filtered(package=["libx*"]).yellow),
            ["libxml2:CVE-2021-2", "libxml2:CVE-2021-3"],
        )
        result = self.filtered(cve=["cve-2021-*"])
        self.assertEqual(result.red, [])
        self.assertIn("libxml2:CVE-2021-3", ids(result.yellow))
        self.assertIn("libtiff:CVE-2021-4", ids(result.yellow))

    def test_severity_is_this_and_above(self):
        result = self.filtered(severity=["medium"])
        self.assertEqual(
            [f["package"] for f in result.red + result.yellow], ["pam", "libxml2"]
        )
        self.assertEqual(ids(self.filtered(severity=["high"]).yellow), [])

    def test_unknown_severity_needs_asking_and_is_counted_otherwise(self):
        hidden = self.filtered(severity=["low"])
        self.assertEqual(hidden.hidden, {"severity unknown": 1})
        self.assertIn(
            "1 record hidden: severity unknown", report.format_text(hidden)
        )
        asked = self.filtered(severity=["unknown"])
        self.assertEqual(
            [f["package"] for f in asked.red + asked.yellow], ["libtiff"]
        )
        both = self.filtered(severity=["unknown", "high"])
        self.assertEqual(
            sorted(f["package"] for f in both.red + both.yellow), ["libtiff", "pam"]
        )

    def test_empty_field_is_counted_not_lost(self):
        result = self.filtered(min_cvss=[1])
        self.assertEqual(result.hidden, {"no CVSS": 1})
        self.assertIn("1 record hidden: no CVSS", report.format_text(result))

    def test_a_record_another_filter_rejects_is_not_counted_as_hidden(self):
        result = self.filtered(package=["pam"], min_cvss=[1])
        self.assertEqual(result.hidden, {})

    def test_filtered_view_says_so_so_red_none_is_not_read_as_all_clear(self):
        result = self.filtered(package=["nothing"])
        text = report.format_text(result)
        self.assertIn("Filtered: showing 0 of 4 records.", text)
        self.assertIn("Red: none", text)

    def test_unused_counts_a_package_never_used(self):
        result = self.filtered(unused=[30])
        self.assertEqual(
            sorted(f["package"] for f in result.red + result.yellow), ["libtiff", "pam"]
        )

    def mark_unmeasurable(self, last_seen):
        self.fake.view = YoklamaView(
            90,
            frozenset(),
            {"pam": last_seen, "libxml2": self.now - 2 * DAY},
            (),
            frozenset({"pam"}),
        )
        self.run_once()

    def test_unused_does_not_list_an_unmeasurable_package_and_counts_it(self):
        self.mark_unmeasurable(None)
        result = self.filtered(unused=[30])
        self.assertEqual(
            sorted(f["package"] for f in result.red + result.yellow), ["libtiff"]
        )
        self.assertEqual(result.hidden, {"no last-used date": 1})
        self.assertIn("1 record hidden: no last-used date", report.format_text(result))

    def test_used_does_not_list_an_unmeasurable_package_and_counts_it(self):
        self.mark_unmeasurable(self.now - DAY)
        result = self.filtered(used=[7])
        self.assertEqual([f["package"] for f in result.yellow], ["libxml2"])
        self.assertEqual(result.red, [])
        self.assertEqual(result.hidden, {"no last-used date": 1})

    def test_a_date_on_an_unmeasurable_package_is_not_kept(self):
        self.mark_unmeasurable(self.now - DAY)
        pam = next(f for f in self.load().red + self.load().yellow if f["package"] == "pam")
        self.assertIsNone(pam["last_used"])
        self.assertTrue(pam["unmeasurable"])

    def test_a_package_measurable_again_loses_the_mark(self):
        self.mark_unmeasurable(None)
        self.fake.view = YoklamaView(90, frozenset(), {"pam": self.now - DAY}, ())
        self.run_once()
        result = self.filtered(used=[7])
        self.assertIn("pam", [f["package"] for f in result.red + result.yellow])
        self.assertEqual(result.hidden, {})

    def test_used(self):
        result = self.filtered(used=[7])
        self.assertEqual([f["package"] for f in result.yellow], ["libxml2"])
        self.assertEqual(result.red, [])

    def test_versions_compare_with_vercmp_not_as_text(self):
        # As text, 5.10 sorts before 5.9.
        name = {"package": ["libxml2"]}
        self.assertEqual(
            len(ids(self.filtered(installed_min=["5.9"], **name).yellow)), 2
        )
        self.assertEqual(ids(self.filtered(installed_max=["5.9"], **name).yellow), [])
        self.assertEqual(len(ids(self.filtered(record_min=["5.9"], **name).yellow)), 2)
        self.assertEqual(ids(self.filtered(record_max=["5.8"], **name).yellow), [])

    def test_epoch_beats_a_bigger_version(self):
        self.assertGreater(vercmp("1:1.0", "9.0"), 0)
        self.fake.adv = [advisory(package="pam", installed="1:1.0-1")]
        self.run_once()
        self.assertEqual(len(self.filtered(installed_min=["9.0"]).red), 1)

    def test_no_record_version_is_counted(self):
        result = self.filtered(record_min=["1"], package=["pam"])
        self.assertEqual(result.hidden, {"no record version": 1})

    def test_status(self):
        self.fake.adv = [
            advisory(package="pam", avg="AVG-1"),
            advisory(package="old", avg="AVG-2", installed="2-1", affected="1-1"),
        ]
        self.fake.chains["old"] = frozenset({"old"})
        self.run_once()
        self.assertEqual(
            [f["package"] for f in self.filtered(status=["unverified"]).unverified],
            ["old"],
        )
        self.assertEqual(self.filtered(status=["open"]).unverified, [])
        both = self.filtered(status=["open", "unverified"])
        self.assertEqual(len(both.red) + len(both.unverified), 2)

    def test_closed_is_filtered_and_status_excludes_it_without_counting(self):
        self.fake.adv = []
        self.run_once()
        self.store.db.commit()
        loaded = report.load(self.path, now=self.now, all_findings=True)
        by_name = report.apply_filters(loaded, Filters(package=["pam"]), vercmp)
        self.assertEqual([f["package"] for f in by_name.closed], ["pam"])
        by_status = report.apply_filters(loaded, Filters(status=["open"]), vercmp)
        self.assertEqual(by_status.closed, [])
        self.assertEqual(by_status.hidden, {})

    def test_json_carries_the_same_view(self):
        code, out, _ = self.cli("report", "--json", "-p", "pam", "-c", "7")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["red"][0]["ids"], ["pam:CVE-2025-1"])
        self.assertEqual(data["yellow"], [])
        self.assertEqual(data["filtered"], {"shown": 1, "total": 4, "hidden": {}})

    def test_json_says_what_was_hidden(self):
        _, out, _ = self.cli("report", "--json", "-c", "1")
        self.assertEqual(json.loads(out)["filtered"]["hidden"], {"no CVSS": 1})

    def test_filters_without_versions_run_no_program(self):
        forbidden = AssertionError("no program for this filter")
        with mock.patch("subprocess.run", side_effect=forbidden):
            code, _, _ = self.cli("report", "-p", "pam", "-c", "1", "-s", "low")
        self.assertEqual(code, 0)

    def test_bad_values_are_refused(self):
        for arguments in (
            ("-s", "severe"),
            ("-c", "high"),
            ("--unused", "-1"),
            ("--status", "closed"),
        ):
            with self.subTest(arguments), self.assertRaises(SystemExit) as caught:
                self.cli("report", *arguments)
            self.assertEqual(caught.exception.code, 2)


class KernelFiltering(PresentationCase):
    def setUp(self):
        super().setUp()
        self.fake = KernelSources()
        self.fake.names = []
        self.run_once()

    def filtered(self, **filters):
        return report.apply_filters(self.load(), Filters(**filters), vercmp)

    def test_a_kernel_has_no_severity_cvss_or_last_use_to_filter_on(self):
        self.assertEqual(self.filtered(severity=["low"]).hidden, {"no severity": 2})
        self.assertEqual(self.filtered(min_cvss=[1]).hidden, {"no CVSS": 2})
        self.assertEqual(self.filtered(unused=[1]).hidden, {"no last-used date": 2})

    def test_cve_filter_lists_the_ids_it_found(self):
        result = self.filtered(cve=["CVE-2026-*"])
        self.assertEqual([k["package"] for k in result.kernels], ["linux-cachyos-lts"])
        text = report.format_text(result)
        self.assertIn("linux-cachyos-lts:CVE-2026-99999  fixed in 6.18.57", text)

    def test_cve_filter_with_no_match_hides_nothing(self):
        result = self.filtered(cve=["CVE-1999-*"])
        self.assertEqual(result.kernels, [])
        self.assertEqual(result.hidden, {})

    def test_installed_version_filter_reaches_kernels(self):
        result = self.filtered(installed_min=["7.0"])
        self.assertEqual([k["package"] for k in result.kernels], ["linux-cachyos"])

    def test_json_covered_entries_have_ids(self):
        data = json.loads(report.format_json(self.load()))
        lts = {k["package"]: k for k in data["kernels"]}["linux-cachyos-lts"]
        self.assertEqual(
            lts["detail"]["covered"][0]["id"], "linux-cachyos-lts:CVE-2026-99999"
        )


def display_width(text):
    return sum(
        0
        if unicodedata.combining(c)
        else 2
        if unicodedata.east_asian_width(c) in "WF"
        else 1
        for c in text
    )


class Layout(PresentationCase):
    def full_report(self):
        """Everything at once, with the longest values seen in real data."""
        self.fake = KernelSources()
        self.fake.release = "6.18.55-2-cachyos-lts"
        self.fake.names = ["foo", "bar", "gone"]
        self.fake.info = {"foo": aur("foo", "alice"), "bar": aur("bar", None)}
        self.fake.chains.update(
            bar=frozenset({"bar"}),
            gone=frozenset({"gone"}),
            xdg=frozenset({"xdg", "app"}),
            old=frozenset({"old"}),
            shut=frozenset({"shut"}),
        )
        self.fake.leaf_set = frozenset(
            {"app", "linux-cachyos-lts", "linux-cachyos", *(f"leaf{i}" for i in range(30))}
        )
        self.fake.chains["pam"] = self.fake.leaf_set
        self.fake.adv = [
            advisory(package="pam", avg="AVG-1", cves=("CVE-2025-6020", "CVE-2025-6021")),
            advisory(
                package="xdg",
                avg="AVG-2",
                severity="Low",
                installed="1.2.1-2",
                fixed="1.2.2-1",
                cves=("CVE-2020-27748",),
            ),
            advisory(
                package="old",
                avg="AVG-3",
                installed="2-1",
                affected="1.1.3+19+g9816ebb-1",
                cves=("CVE-2021-1", "CVE-2021-2"),
            ),
        ]
        self.fake.view = YoklamaView(
            90, frozenset(self.fake.leaf_set), {"pam": 7, "xdg": 8}, ("too early",)
        )
        self.run_once()
        self.fake.info = {"foo": aur("foo", "mallory"), "bar": aur("bar", None)}
        self.run_once()
        wide = "漏洞 " * 60 + "combining é " * 30
        self.set_enrichment(
            "pam",
            {
                "CVE-2025-6020": enriched(cvss=7.8, epss=0.1, kev=True, description=wide),
                "CVE-2025-6021": enriched(cvss=9.8, epss=0.964),
            },
        )
        self.store.db.execute("UPDATE findings SET first_seen = 86400")

    def test_no_line_is_wider_than_the_terminal(self):
        self.full_report()
        self.store.db.commit()
        loaded = report.load(self.path, now=self.now, all_findings=True)
        for width in (50, 60, 80, 100, 120, 200):
            with self.subTest(width=width):
                for line in report.format_text(loaded, width).split("\n"):
                    self.assertLessEqual(display_width(line), width, line)

    def test_a_pipe_gets_every_line_whole(self):
        self.full_report()
        self.assertIn(LONG.strip(), report.format_text(self.load()))

    def test_no_internal_label_is_visible(self):
        self.full_report()
        self.store.db.commit()
        loaded = report.load(self.path, now=self.now, all_findings=True)
        for width in (None, 80):
            text = report.format_text(loaded, width)
            for label in ("AVG-", "looks_closed", "kernel info", "not_found", "maintainer_changed"):
                self.assertNotIn(label, text)

    def test_every_repo_row_shows_its_id_first(self):
        self.full_report()
        text = report.format_text(self.load(), 80)
        self.assertRegex(text, r"(?m)^  pam:CVE-2025-6020\b")
        self.assertRegex(text, r"(?m)^  pam:CVE-2025-6021\b")

    def test_description_sits_below_the_row_indented_and_cropped(self):
        self.full_report()
        lines = report.format_text(self.load(), 80).split("\n")
        at = next(i for i, l in enumerate(lines) if l.startswith("  pam:CVE-2025-6021"))
        below = lines[at + 1]
        self.assertTrue(below.startswith("    A flaw A flaw"))
        self.assertTrue(below.endswith("..."))
        self.assertEqual(display_width(below), 80)

    def test_narrow_terminal_says_which_columns_it_dropped(self):
        self.full_report()
        text = report.format_text(self.load(), 50)
        self.assertIn("Not shown at this width:", text)
        self.assertNotIn("Not shown at this width:", report.format_text(self.load()))

    def test_kernel_summary_wraps_and_loses_nothing(self):
        self.full_report()
        text = report.format_text(self.load(), 50)
        kernels = " ".join(text.split("Kernels:")[-1].split())
        for part in ("6.18.55 (running)", "5 behind", "repo still has 6.18.55-2"):
            self.assertIn(part, kernels)

    def test_removal_list_is_never_shortened(self):
        self.full_report()
        self.store.db.commit()
        text = report.format_text(self.load(), 60)
        section = " ".join(
            text.split("Removal suggestions")[1].split("Can't verify")[0].split()
        )
        for i in range(30):
            self.assertIn(f"leaf{i}", section)

    def test_wrapping_stays_a_wrap_in_show_too(self):
        self.assertEqual(
            report.wrap("one two three four five six seven", 20, "  "),
            ["  one two three four", "  five six seven"],
        )


class ColumnHiding(PresentationCase):
    def table(self, rows, width=None):
        columns = [
            report.Column("ID"),
            report.Column("SEVERITY", 2),
            report.Column("RANGE", 1, implied=True),
            report.Column("EMPTY", 3),
        ]
        return "\n".join(report._table(columns, rows, width))

    def test_a_column_always_empty_is_hidden(self):
        text = self.table(
            [report.Row(["a", "High", "inside", "-"]), report.Row(["b", "Low", "outside", "-"])]
        )
        self.assertNotIn("EMPTY", text)

    def test_a_shared_value_moves_out_of_the_columns_and_stays_said(self):
        text = self.table(
            [report.Row(["a", "High", "inside", "x"]), report.Row(["b", "High", "outside", "y"])]
        )
        self.assertIn("All rows: SEVERITY High.", text)
        self.assertNotIn("  SEVERITY", text.split("\n")[1])

    def test_an_implied_shared_value_just_goes(self):
        text = self.table(
            [report.Row(["a", "High", "unknown", "x"]), report.Row(["b", "Low", "unknown", "y"])]
        )
        self.assertNotIn("RANGE", text)
        self.assertNotIn("unknown", text)

    def test_one_row_keeps_its_values(self):
        text = self.table([report.Row(["a", "High", "inside", "-"])])
        self.assertIn("SEVERITY", text)
        self.assertIn("High", text)
        self.assertNotIn("All rows", text)

    def test_real_report_hides_range_when_every_row_says_the_same(self):
        self.fake.adv = [
            advisory(package="old", avg="AVG-1", installed="2-1", affected="1-1", cves=("CVE-1", "CVE-2")),
        ]
        self.fake.chains["old"] = frozenset({"old"})
        self.run_once()
        self.assertNotIn("RANGE", report.format_text(self.load()))


class StatusNames(PresentationCase):
    def test_names_explain_themselves(self):
        self.fake.adv = [
            advisory(package="old", avg="AVG-1", installed="2-1", affected="1-1"),
        ]
        self.fake.chains["old"] = frozenset({"old"})
        self.run_once()
        text = report.format_text(self.load())
        self.assertIn("Can't verify: record is old, installed version is newer", text)
        self.assertNotIn("Unverified", text)


class Terminal(unittest.TestCase):
    def test_columns_variable_is_honoured(self):
        with mock.patch.dict(os.environ, {"COLUMNS": "93"}):
            self.assertEqual(terminal_width(), 93)

    def test_a_pipe_has_no_width(self):
        env = {k: v for k, v in os.environ.items() if k != "COLUMNS"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("os.get_terminal_size", side_effect=OSError),
        ):
            self.assertIsNone(terminal_width())


class RunSentences(PresentationCase):
    def test_quiet_run(self):
        self.fake.adv = []
        self.fake.names = []
        self.fake.view = YoklamaView(90, frozenset(), {}, ())
        text = format_result(self.run_once())
        self.assertEqual(text, "No new problems.\nNothing is listed.\nDetails: sicil report")

    def test_new_problems_name_their_packages(self):
        self.fake.adv = [
            advisory(package="pam", avg="AVG-1"),
            advisory(package="lib", avg="AVG-2", severity="Low"),
        ]
        self.fake.chains["lib"] = frozenset({"lib"})
        text = format_result(self.run_once())
        self.assertIn("New problems: act on pam; worth a look: lib.", text)
        self.assertIn("Standing: 1 to act on, 1 worth a look.", text)
        self.assertNotIn("AVG", text)

    def test_second_run_has_no_new_problems(self):
        self.run_once()
        self.assertIn("No new problems.", format_result(self.run_once()))

    def test_closed_is_named(self):
        self.run_once()
        self.fake.adv = []
        self.assertIn("No longer reported: pam.", format_result(self.run_once()))

    def test_level_change_is_named_in_words(self):
        self.run_once()
        self.fake.adv = [advisory(package="pam", installed="2-1", affected="1-1")]
        self.assertIn("Now can't verify: pam.", format_result(self.run_once()))

    def test_unverified_is_listed_as_nothing_to_act_on(self):
        self.fake.adv = [advisory(package="old", installed="2-1", affected="1-1")]
        self.fake.chains["old"] = frozenset({"old"})
        text = format_result(self.run_once())
        self.assertIn("No new problems.", text)
        self.assertIn("Newly listed, nothing to act on: old.", text)
        self.assertIn("1 can't be verified", text)

    def test_long_name_lists_are_shortened(self):
        self.fake.adv = [
            advisory(package=f"p{i}", avg=f"AVG-{i}", installed="2-1", affected="1-1")
            for i in range(11)
        ]
        self.fake.chains.update({f"p{i}": frozenset({f"p{i}"}) for i in range(11)})
        self.assertIn("+3 more", format_result(self.run_once()))

    def test_kernel_summary_is_a_sentence(self):
        self.fake = KernelSources()
        self.fake.names = []
        text = format_result(self.run_once())
        self.assertIn(
            "linux-cachyos-lts: 6.18.55 (running); branch latest 6.18.60, 5 behind;",
            text,
        )
        self.assertNotIn("kernel info", text)
        self.assertNotIn("New problems", text)

    def test_notification_and_warning_are_said(self):
        text = format_result(self.run_once())
        self.assertIn("Sent a desktop notification.", text)
        self.assertIn("Warning: too early", text)
        self.assertTrue(text.endswith("Details: sicil report"))

    def test_notification_has_no_internal_label(self):
        self.assertEqual(
            rules.notification([("foo", "maintainer_changed")])[1],
            "foo: maintainer changed\nSee: sicil report",
        )


class WithoutYoklama(PresentationCase):
    """Whoever downloads Sicil does not have Yoklama. PATH really has no such command."""

    def setUp(self):
        super().setUp()
        self.empty = tempfile.TemporaryDirectory()
        self.addCleanup(self.empty.cleanup)
        # The rest of Sicil's tools stay: only Yoklama is absent.
        os.symlink(
            shutil.which("vercmp"), os.path.join(self.empty.name, "vercmp")
        )
        path = mock.patch.dict(os.environ, {"PATH": self.empty.name})
        path.start()
        self.addCleanup(path.stop)
        self.fake.yoklama = sources.Sources().yoklama
        real = mock.patch(
            "sicil.report.yoklama_installed",
            side_effect=lambda: report.shutil.which("yoklama") is not None,
        )
        real.start()
        self.addCleanup(real.stop)

    def test_real_source_says_it_is_missing_not_failing(self):
        with self.assertRaises(sources.YoklamaMissing):
            sources.Sources().yoklama()

    def test_run_works_with_one_note_and_no_error(self):
        result = self.run_once()
        self.assertEqual(result.warnings, ["Yoklama not found, no usage data"])
        self.assertIn("Note: Yoklama not found, no usage data", format_result(result))

    def test_report_hides_last_use_and_removal_and_keeps_the_rest(self):
        self.fake.adv = [advisory(package="old", installed="2-1", affected="1-1")]
        self.fake.chains["old"] = frozenset({"old"})
        self.run_once()
        code, out, _ = self.cli("report")
        self.assertEqual(code, 0)
        self.assertEqual(out.count("Yoklama not found, no usage data"), 1)
        self.assertIn("Note: Yoklama not found", out)
        self.assertNotIn("LAST USED", out)
        self.assertNotIn("Removal suggestions", out)
        self.assertNotIn("yoklama FAILED", out)
        self.assertIn("old:CVE-1", out)

    def test_a_failure_of_yoklama_is_still_a_failure(self):
        self.fake.yoklama = lambda: (_ for _ in ()).throw(SourceError("crashed"))
        result = self.run_once()
        self.assertTrue(any("no usage data" in w for w in result.warnings))
        self.assertNotIn("Yoklama not found, no usage data", result.warnings)

    def test_usage_filters_refuse_rather_than_return_an_empty_list(self):
        self.run_once()
        for flag in ("--unused", "--used"):
            code, out, err = self.cli("report", flag, "30")
            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("Yoklama not found, this filter can't run", err)

    def test_other_filters_still_work(self):
        self.run_once()
        code, out, _ = self.cli("report", "-p", "pam")
        self.assertEqual(code, 0)
        self.assertIn("pam:CVE-1", out)

    def test_installing_yoklama_after_the_run_does_not_read_as_a_failure(self):
        self.run_once()
        with mock.patch("sicil.report.yoklama_installed", return_value=True):
            _, out, _ = self.cli("report")
        self.assertIn("Note: Yoklama was not there at the last run", out)
        self.assertNotIn("Yoklama not found", out)
        self.assertNotIn("yoklama FAILED", out)

    def test_json_says_so(self):
        self.run_once()
        _, out, _ = self.cli("report", "--json")
        self.assertFalse(json.loads(out)["yoklama_found"])

    def test_show_leaves_out_last_use(self):
        self.run_once()
        fake = ShowSources(self.fake)
        with mock.patch("sicil.__main__.Sources", return_value=fake):
            _, out, _ = self.cli("show", "pam:CVE-1")
        self.assertNotIn("Last used", out)


class YoklamaBrokenAtRun(PresentationCase):
    def test_usage_filter_refuses_when_the_last_run_got_no_data(self):
        self.fake.fail = {"yoklama"}
        self.run_once()
        code, _, err = self.cli("report", "--unused", "30")
        self.assertEqual(code, 1)
        self.assertIn("got no usage data", err)


class DatabaseBeforeTheUnmeasurableList(PresentationCase):
    def setUp(self):
        super().setUp()
        self.fake.adv = [advisory()]
        self.fake.view = YoklamaView(90, frozenset(), {}, ())
        self.run_once()
        self.store.db.executescript(
            "ALTER TABLE findings DROP COLUMN unmeasurable; PRAGMA user_version = 3;"
        )

    def test_usage_filters_refuse_until_the_next_run(self):
        for flag in ("--unused", "--used"):
            code, out, err = self.cli("report", flag, "30")
            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("`sicil run` will add it", err)

    def test_the_report_and_other_filters_still_work(self):
        self.assertIn("pam:CVE-", self.cli("report")[1])
        self.assertIn("pam:CVE-", self.cli("report", "-p", "pam")[1])


class DatabaseFromANewerSicil(PresentationCase):
    MESSAGE = f"database schema 99 is newer than this sicil ({SCHEMA_VERSION}); update sicil"

    def setUp(self):
        super().setUp()
        self.fake.adv = [advisory()]
        self.run_once()
        self.store.db.execute("PRAGMA user_version = 99")

    def state(self):
        self.store.db.commit()
        db = sqlite3.connect(self.path)
        try:
            return (
                db.execute("PRAGMA user_version").fetchone()[0],
                db.execute("SELECT count(*) FROM runs").fetchone()[0],
            )
        finally:
            db.close()

    def test_opening_it_to_write_fails_and_changes_nothing(self):
        before = self.state()
        with self.assertRaises(NewerSchema) as caught:
            Store(self.path)
        self.assertEqual(str(caught.exception), self.MESSAGE)
        self.assertEqual(self.state(), before)

    def test_every_command_exits_with_the_message_and_changes_nothing(self):
        before = self.state()
        for command in (["run"], ["report"], ["report", "-p", "pam"], ["show", "pam:CVE-2021-1234"]):
            code, out, err = self.cli(*command)
            self.assertEqual(code, 1, command)
            self.assertEqual(out, "", command)
            self.assertIn(self.MESSAGE, err, command)
        self.assertEqual(self.state(), before)

    def test_the_current_schema_still_opens(self):
        self.store.db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self.store.db.commit()
        Store(self.path).close()
        self.assertEqual(self.state()[0], SCHEMA_VERSION)


class ShowSources:
    """What `sicil show` reads besides the database: the system, right now."""

    def __init__(self, fake, installed=None, kernel_records=None):
        self.versions = dict(fake.packages if installed is None else installed)
        self.kernel_records = kernel_records or {}

    def installed_version(self, package):
        return self.versions.get(package)

    def vercmp(self, a, b):
        return vercmp(a, b)

    def kernel_record(self, cve):
        return self.kernel_records.get(cve)


class Ids(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(show.parse_id("pam:CVE-2025-6020"), ("pam", "CVE-2025-6020"))
        self.assertEqual(show.parse_id("CVE-2025-6020"), (None, "CVE-2025-6020"))
        self.assertEqual(show.parse_id("pam:cve-2025-6020"), ("pam", "CVE-2025-6020"))

    def test_anything_else_is_refused(self):
        for text in ("pam", "pam:", ":CVE-2025-6020", "pam:AVG-1", "../x:CVE-1-1", "CVE-2025"):
            with self.subTest(text), self.assertRaises(ValueError):
                show.parse_id(text)


class Showing(PresentationCase):
    def setUp(self):
        super().setUp()
        self.fake.adv = [
            advisory(
                package="pam",
                avg="AVG-2901",
                installed="1.7.3-1.1",
                affected="1.7.0-2",
                cves=("CVE-2025-6020",),
            )
        ]
        self.fake.records = {"CVE-2025-6020": real_record("CVE-2025-6020")}
        self.fake.packages = {"pam": "1.7.3-1.1", "foo": "1-1"}
        self.fake.epss_map = {"CVE-2025-6020": 0.005}
        self.fake.view = YoklamaView(90, frozenset(), {"pam": self.now}, ())
        self.run_once()
        self.system = ShowSources(self.fake)

    def show(self, *arguments):
        with mock.patch("sicil.__main__.Sources", return_value=self.system):
            return self.cli("show", *arguments)

    def test_full_record(self):
        code, out, _ = self.show("pam:CVE-2025-6020")
        self.assertEqual(code, 0)
        lines = out.split("\n")
        self.assertEqual(lines[0], "pam:CVE-2025-6020")
        self.assertEqual(lines[1], "Installed 1.7.3-1.1 · looks closed")
        self.assertIn("multiple symlink attacks and race conditions", " ".join(out.split()))
        for expected in ("7.8 (CNA)", "0.005", "outside", "1.7.0-2", "cve.org"):
            self.assertIn(expected, out)
        self.assertNotIn("AVG", out)

    def test_not_installed(self):
        self.system.versions = {}
        code, out, _ = self.show("pam:CVE-2025-6020")
        self.assertEqual(code, 0)
        self.assertIn("Not installed", out)

    def test_version_changed_since_the_run_is_judged_again(self):
        self.system.versions["pam"] = "1.6.0-1"
        _, out, _ = self.show("pam:CVE-2025-6020")
        self.assertIn("Installed 1.6.0-1", out)
        self.assertIn("last run saw 1.7.3-1.1", out)
        self.assertRegex(out, r"Range\s+inside")

    def test_id_from_another_machine_never_reads_as_safe(self):
        _, out, _ = self.show("foo:CVE-2025-6020")
        self.assertIn("Installed 1-1", out)
        self.assertIn("that does not prove it is unaffected", " ".join(out.split()))

    def test_closed_finding_says_when(self):
        self.fake.adv = []
        self.run_once()
        _, out, _ = self.show("pam:CVE-2025-6020")
        self.assertIn("closed on", out)

    def test_one_field_is_bare(self):
        for name, expected in (
            ("cvss", "7.8"),
            ("epss", "0.005"),
            ("severity", "High"),
            ("installed", "1.7.3-1.1"),
            ("status", "looks closed"),
            ("range", "outside"),
            ("kev", "no"),
        ):
            code, out, _ = self.show("pam:CVE-2025-6020", "-f", name)
            self.assertEqual((code, out), (0, expected + "\n"), name)
        _, out, _ = self.show("pam:CVE-2025-6020", "-f", "desc")
        self.assertEqual(out.count("\n"), 1)
        self.assertTrue(out.startswith("A flaw was found in linux-pam"))

    def test_empty_field_prints_an_empty_line_and_succeeds(self):
        code, out, _ = self.show("pam:CVE-2025-6020", "-f", "fixed")
        self.assertEqual((code, out), (0, "\n"))

    def test_field_of_something_never_recorded_fails(self):
        code, out, err = self.show("foo:CVE-1999-1111", "-f", "cvss")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("nothing recorded", err)

    def test_status_of_something_never_recorded_is_still_answered(self):
        code, out, _ = self.show("foo:CVE-1999-1111", "-f", "status")
        self.assertEqual(code, 0)
        self.assertIn("not among this machine's findings", out)

    def test_bare_cve_lists_packages(self):
        code, out, _ = self.show("CVE-2025-6020")
        self.assertEqual(code, 0)
        self.assertIn("pam:CVE-2025-6020", out)
        self.assertIn("Installed 1.7.3-1.1 · looks closed", out)

    def test_bare_cve_nowhere_does_not_read_as_safe(self):
        _, out, _ = self.show("CVE-1999-1111")
        self.assertIn("does not prove", " ".join(out.split()))

    def test_bare_cve_with_a_field_is_refused(self):
        code, _, err = self.show("CVE-2025-6020", "-f", "desc")
        self.assertEqual(code, 2)
        self.assertIn("package:CVE-2025-6020", err)

    def test_not_an_id(self):
        code, _, err = self.show("pam")
        self.assertEqual(code, 2)
        self.assertIn("not an ID", err)

    def test_description_is_cleaned(self):
        raw = json.loads(real_record("CVE-2025-6020"))
        raw["containers"]["cna"]["descriptions"][0]["value"] = "bad \x1b[2Jtext\nnext"
        self.fake.records = {"CVE-2025-6020": json.dumps(raw)}
        self.store.db.execute("DELETE FROM cve_cache")
        self.store.db.commit()
        self.run_once()
        _, out, _ = self.show("pam:CVE-2025-6020", "-f", "desc")
        self.assertNotIn("\x1b", out)
        self.assertEqual(out, "bad [2Jtext next\n")

    def test_no_run_yet_is_a_clean_error(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["show", "pam:CVE-2025-6020", "--db", "/nonexistent/x.db"])
        self.assertEqual(code, 1)
        self.assertIn("sicil run", err.getvalue())


KERNEL_RAW = {
    "cveMetadata": {"cveId": "CVE-2026-99999"},
    "containers": {
        "cna": {
            "descriptions": [{"lang": "en", "value": "In the Linux kernel, a fix."}],
            "affected": list(REAL),
        }
    },
}


class ShowingKernels(PresentationCase):
    def setUp(self):
        super().setUp()
        self.fake = KernelSources()
        self.fake.names = []
        self.run_once()
        self.system = ShowSources(
            self.fake, kernel_records={"CVE-2026-99999": KERNEL_RAW}
        )

    def show(self, *arguments):
        with mock.patch("sicil.__main__.Sources", return_value=self.system):
            return self.cli("show", *arguments)

    def test_record_is_read_from_the_checkout_and_judged_now(self):
        _, out, _ = self.show("linux-cachyos-lts:CVE-2026-99999")
        self.assertIn("Installed 6.18.55-2 · record covers this version", out)
        self.assertIn("In the Linux kernel, a fix.", out)
        self.assertRegex(out, r"Fixed in\s+6\.18\.57")
        self.assertNotIn("Last used", out)

    def test_upgraded_kernel_is_no_longer_covered(self):
        self.system.versions["linux-cachyos-lts"] = "6.18.60-1"
        _, out, _ = self.show("linux-cachyos-lts:CVE-2026-99999")
        self.assertIn("Installed 6.18.60-1 · record does not cover this version", out)

    def test_bare_cve_finds_the_kernel(self):
        _, out, _ = self.show("CVE-2026-99999")
        self.assertIn("linux-cachyos-lts:CVE-2026-99999", out)

    def test_missing_checkout_still_answers_from_the_findings(self):
        self.system.kernel_records = {}
        code, out, _ = self.show("linux-cachyos-lts:CVE-2026-99999")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"Fixed in\s+6\.18\.57")


class HelpText(unittest.TestCase):
    def help_of(self, *arguments, columns="80"):
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"COLUMNS": columns, "NO_COLOR": "1"}),
            contextlib.redirect_stdout(out),
            self.assertRaises(SystemExit) as caught,
        ):
            main(list(arguments))
        self.assertEqual(caught.exception.code, 0)
        return out.getvalue()

    def report_flags(self):
        _, report_parser = build_parser()
        group = next(
            g for g in report_parser._action_groups if g.title == "filters"
        )
        return [flag for action in group._group_actions for flag in action.option_strings]

    def test_top_help_lists_the_commands(self):
        text = self.help_of("-h")
        self.assertTrue(text.startswith("usage: sicil [-h] COMMAND ...\n"))
        for command in ("run", "report", "show"):
            self.assertRegex(text, rf"(?m)^  {command} ")
        self.assertNotIn("positional arguments", text)

    def test_top_help_lists_every_filter(self):
        text = self.help_of("-h")
        for flag in self.report_flags():
            self.assertIn(flag, text)

    def test_report_help_explains_every_filter_and_how_they_combine(self):
        text = " ".join(self.help_of("report", "-h").split())
        for flag in self.report_flags():
            self.assertIn(flag, text)
        self.assertIn("must all match", text)
        self.assertIn("a repeated filter may match any value", text)
        self.assertIn("counted at the end", text)
        self.assertIn("Needs Yoklama", text)
        self.assertIn("-p pam -p libxml2 -c 7", text)

    def test_report_usage_is_short(self):
        usage = self.help_of("report", "-h").split("\n\n")[0]
        self.assertEqual(
            usage, "usage: sicil report [-h] [--all] [--json] [--db PATH] [filters]"
        )

    def test_flag_before_the_command_asks_the_same(self):
        self.assertEqual(self.help_of("-h", "report"), self.help_of("report", "-h"))
        self.assertEqual(self.help_of("--help", "show"), self.help_of("show", "--help"))

    def test_help_fits_eighty_columns(self):
        for arguments in (("-h",), ("report", "-h"), ("run", "-h"), ("show", "-h")):
            for line in self.help_of(*arguments).split("\n"):
                self.assertLessEqual(len(line), 80, line)

    def test_help_examples_really_parse(self):
        text = self.help_of("-h") + self.help_of("report", "-h")
        parser, _ = build_parser()
        examples = [
            line.strip()
            for line in text.split("\n")
            if line.startswith("  sicil ")
        ]
        self.assertGreaterEqual(len(examples), 8)
        for line in examples:
            # What follows two spaces is the example's explanation.
            words = shlex.split(line.split("  ")[0])[1:]
            with self.subTest(line):
                parser.parse_args(words)


class RealSources(unittest.TestCase):
    def test_installed_version_reads_pacman(self):
        result = mock.Mock(returncode=0, stdout="pam 1.7.3-1.1\n", stderr="")
        with mock.patch("subprocess.run", return_value=result) as run:
            self.assertEqual(sources.Sources().installed_version("pam"), "1.7.3-1.1")
        self.assertEqual(run.call_args.args[0], ["pacman", "-Q", "pam"])

    def test_package_not_installed_is_none_not_an_error(self):
        result = mock.Mock(
            returncode=1, stdout="", stderr="error: package 'x' was not found\n"
        )
        with mock.patch("subprocess.run", return_value=result):
            self.assertIsNone(sources.Sources().installed_version("x"))

    def test_pacman_failing_is_an_error(self):
        result = mock.Mock(returncode=1, stdout="", stderr="error: database is broken\n")
        with mock.patch("subprocess.run", return_value=result):
            with self.assertRaises(SourceError):
                sources.Sources().installed_version("x")

    def test_kernel_record_comes_from_the_checkout_only(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = os.path.join(directory, "cve", "published", "2026")
            os.makedirs(folder)
            with open(os.path.join(folder, "CVE-2026-1.json"), "w") as f:
                json.dump(KERNEL_RAW, f)
            found = sources.Sources(kernel_dir=directory)
            self.assertEqual(found.kernel_record("CVE-2026-1"), KERNEL_RAW)
            self.assertIsNone(found.kernel_record("CVE-2026-2"))
        self.assertIsNone(sources.Sources().kernel_record("CVE-2026-1"))


if __name__ == "__main__":
    unittest.main()
