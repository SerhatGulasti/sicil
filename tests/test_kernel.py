"""The kernel strip. No network: the git tests use a repository in a temporary folder."""

import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from sicil import kernel, report, rules, sources
from sicil.kernel import InstalledKernel, covers, fixed_in_branch, version_key
from sicil.sources import (
    KernelRecord,
    KernelRelease,
    SourceError,
    parse_kernel_releases,
    read_kernel_records,
)

from test_sicil import FakeSources, RunCase, advisory, vercmp

# The shape of a real record: CVE-2026-99999, fixed in 6.18.57, 7.2.11 and 7.3.
FIXED_ROW = {
    "vendor": "Linux",
    "product": "Linux",
    "defaultStatus": "affected",
    "versions": [
        {"version": "2.6.27", "status": "affected"},
        {
            "version": "0",
            "lessThan": "2.6.27",
            "status": "unaffected",
            "versionType": "semver",
        },
        {
            "version": "6.18.57",
            "lessThanOrEqual": "6.18.*",
            "status": "unaffected",
            "versionType": "semver",
        },
        {
            "version": "7.2.11",
            "lessThanOrEqual": "7.2.*",
            "status": "unaffected",
            "versionType": "semver",
        },
        {
            "version": "7.3",
            "lessThanOrEqual": "*",
            "status": "unaffected",
            "versionType": "original_commit_for_fix",
        },
    ],
}
GIT_ROW = {
    "vendor": "Linux",
    "product": "Linux",
    "defaultStatus": "unaffected",
    "versions": [
        {
            "version": "f43798c27684",
            "lessThan": "a464d950f31c",
            "status": "affected",
            "versionType": "git",
        }
    ],
}
REAL = (GIT_ROW, FIXED_ROW)
# Came into the branch with 6.18.57 and left with 6.18.59.
LATE_ROW = {
    "defaultStatus": "unaffected",
    "versions": [
        {
            "version": "6.18.57",
            "lessThan": "6.18.59",
            "status": "affected",
            "versionType": "semver",
        }
    ],
}
RELEASES = {
    "6.18": KernelRelease("6.18.60", False),
    "7.3": KernelRelease("7.3.1", False),
    "7.2": KernelRelease("7.2.15", True),
}


def v(text):
    return version_key(text)


class Versions(unittest.TestCase):
    def test_order(self):
        self.assertLess(v("6.18.9"), v("6.18.10"))
        self.assertLess(v("6.18"), v("6.18.1"))
        self.assertLess(v("7.4-rc1"), v("7.4"))

    def test_not_a_version(self):
        self.assertIsNone(v("f43798c27684"))
        self.assertIsNone(v(None))


class Coverage(unittest.TestCase):
    def test_before_the_fix_in_its_branch(self):
        self.assertTrue(covers(REAL, v("6.18.55")))

    def test_at_and_after_the_fix(self):
        self.assertFalse(covers(REAL, v("6.18.57")))
        self.assertFalse(covers(REAL, v("6.18.60")))

    def test_each_branch_has_its_own_fix(self):
        self.assertTrue(covers(REAL, v("7.2.10")))
        self.assertFalse(covers(REAL, v("7.2.11")))

    def test_a_fix_in_another_branch_does_not_count(self):
        # 6.18.57 is greater than 6.12.100 and says nothing about that branch.
        self.assertTrue(covers(REAL, v("6.12.100")))

    def test_mainline_fix_covers_everything_after_it(self):
        self.assertFalse(covers(REAL, v("7.3.1")))
        self.assertFalse(covers(REAL, v("7.4.5")))

    def test_older_than_the_bug(self):
        self.assertFalse(covers(REAL, v("2.6.20")))

    def test_bug_that_entered_after_this_version(self):
        self.assertFalse(covers((LATE_ROW,), v("6.18.55")))
        self.assertTrue(covers((LATE_ROW,), v("6.18.58")))
        self.assertFalse(covers((LATE_ROW,), v("6.18.59")))

    def test_git_rows_alone_say_nothing(self):
        self.assertFalse(covers((GIT_ROW,), v("6.18.55")))

    def test_unknown_default_says_nothing(self):
        row = dict(FIXED_ROW, defaultStatus="unknown")
        self.assertFalse(covers((row,), v("6.18.55")))

    def test_lowest_fix_in_the_branch(self):
        self.assertEqual(fixed_in_branch(REAL, v("6.18.55")[:2]), "6.18.57")
        self.assertIsNone(fixed_in_branch(REAL, v("6.12.1")[:2]))


class RunningKernel(unittest.TestCase):
    def test_suffix_names_the_package(self):
        release = "6.18.55-2-cachyos-lts"
        self.assertEqual(
            kernel.running_version("linux-cachyos-lts", release), "6.18.55-2"
        )
        self.assertIsNone(kernel.running_version("linux-cachyos", release))

    def test_main_kernel(self):
        self.assertEqual(
            kernel.running_version("linux-cachyos", "7.3.1-1-cachyos"), "7.3.1-1"
        )
        self.assertIsNone(
            kernel.running_version("linux-cachyos-lts", "7.3.1-1-cachyos")
        )

    def test_some_other_kernel(self):
        self.assertIsNone(kernel.running_version("linux-cachyos", "6.1.0-arch1-1"))


def classify(
    installed="6.18.55-2",
    repo="6.18.55-2",
    package="linux-cachyos-lts",
    records=None,
    releases=RELEASES,
    kev=frozenset(),
    running="6.18.55-2-cachyos-lts",
):
    records = [KernelRecord("CVE-2026-99999", REAL)] if records is None else records
    return kernel.classify(
        [InstalledKernel(package, installed, repo)],
        records,
        releases,
        kev,
        vercmp,
        running,
    )[0]


class Levels(unittest.TestCase):
    def test_behind_with_nothing_to_install_is_information(self):
        found = classify()
        self.assertEqual(found.level, rules.INFO)
        self.assertEqual(found.detail["behind"], 5)
        self.assertEqual(found.detail["covered_count"], 1)
        self.assertEqual(found.detail["remaining_count"], 0)

    def test_newer_in_the_repo_is_yellow(self):
        found = classify(repo="6.18.60-1")
        self.assertEqual(found.level, rules.YELLOW)
        self.assertTrue(found.detail["repo_newer"])

    def test_end_of_life_is_yellow(self):
        found = classify(installed="7.2.15-1", repo="7.2.15-1")
        self.assertEqual(found.level, rules.YELLOW)
        self.assertTrue(found.detail["eol"])

    def test_branch_gone_from_the_list_is_end_of_life(self):
        found = classify(installed="6.17.3-1", repo="6.17.3-1")
        self.assertEqual(found.level, rules.YELLOW)
        self.assertTrue(found.detail["eol"])
        self.assertIsNone(found.detail["behind"])

    def test_latest_in_its_branch_is_information(self):
        found = classify(installed="7.3.1-1", repo="7.3.1-1", package="linux-cachyos")
        self.assertEqual(found.level, rules.INFO)
        self.assertEqual(found.detail["behind"], 0)

    def test_unknown_repo_version_is_no_reason_for_yellow(self):
        self.assertEqual(classify(repo=None).level, rules.INFO)

    def test_kev_on_a_covered_record_is_red(self):
        found = classify(kev=frozenset({"CVE-2026-99999"}))
        self.assertEqual(found.level, rules.RED)
        self.assertEqual(found.detail["kev"], ["CVE-2026-99999"])

    def test_kev_on_a_fixed_record_does_not_apply(self):
        found = classify(installed="6.18.57-1", kev=frozenset({"CVE-2026-99999"}))
        self.assertEqual(found.level, rules.INFO)

    def test_records_that_stay_at_the_latest_are_counted(self):
        unfixed = dict(
            FIXED_ROW,
            versions=[{"version": "6.1", "status": "affected"}, FIXED_ROW["versions"][1]],
        )
        found = classify(
            records=[KernelRecord("CVE-1", (unfixed,)), KernelRecord("CVE-2", REAL)]
        )
        self.assertEqual(found.detail["covered_count"], 2)
        self.assertEqual(found.detail["remaining_count"], 1)
        self.assertEqual(
            found.detail["covered"],
            [
                {"cve": "CVE-1", "fixed_in": None},
                {"cve": "CVE-2", "fixed_in": "6.18.57"},
            ],
        )

    def test_reboot_pending(self):
        found = classify(installed="6.18.60-1", repo="6.18.60-1")
        self.assertTrue(found.detail["reboot_pending"])
        self.assertEqual(found.detail["running_version"], "6.18.55-2")

    def test_no_reboot_note_for_the_kernel_not_running(self):
        found = classify(installed="7.3.1-1", repo="7.3.1-1", package="linux-cachyos")
        self.assertFalse(found.detail["reboot_pending"])
        self.assertFalse(found.detail["running"])

    def test_unreadable_version_skips_the_strip(self):
        with self.assertRaises(SourceError):
            classify(installed="7.3.rc1-1")


class Parsing(unittest.TestCase):
    def test_releases(self):
        body = json.dumps(
            {
                "releases": [
                    {"moniker": "mainline", "version": "7.4-rc1", "iseol": False},
                    {"moniker": "stable", "version": "7.2.15", "iseol": True},
                    {"moniker": "longterm", "version": "6.18.60", "iseol": False},
                    {"moniker": "linux-next", "version": "next-1", "iseol": False},
                ]
            }
        ).encode()
        releases = parse_kernel_releases(body)
        self.assertEqual(set(releases), {"7.4", "7.2", "6.18"})
        self.assertTrue(releases["7.2"].eol)
        self.assertEqual(releases["6.18"].version, "6.18.60")

    def test_bad_releases_are_a_source_error(self):
        for body in (b"<html>", b"{}", b'{"releases": []}'):
            with self.assertRaises(SourceError):
                parse_kernel_releases(body)

    def test_repo_version_follows_pacmans_answer(self):
        done = subprocess.CompletedProcess([], 0, "linux-cachyos-lts 6.18.55-2\n", "")
        with mock.patch("subprocess.run", return_value=done) as run:
            self.assertEqual(
                sources.Sources().repo_version("linux-cachyos-lts"), "6.18.55-2"
            )
        self.assertEqual(run.call_args.args[0][:2], ["pacman", "-Sp"])

    def test_repo_version_failure_is_none(self):
        failed = subprocess.CompletedProcess([], 1, "", "error: target not found: x\n")
        with mock.patch("subprocess.run", return_value=failed):
            self.assertIsNone(sources.Sources().repo_version("x"))

    def test_no_directory_is_a_source_error(self):
        with self.assertRaises(SourceError):
            sources.Sources().update_kernel_cves()
        with self.assertRaises(SourceError):
            sources.Sources().kernel_records()


def record_text(cve="CVE-2026-1"):
    return json.dumps(
        {
            "cveMetadata": {"cveId": cve},
            "containers": {"cna": {"affected": [FIXED_ROW]}},
        }
    )


class RealGit(unittest.TestCase):
    """The clone and update against a repository in a temporary folder."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.origin = os.path.join(self.dir.name, "origin")
        self.target = os.path.join(self.dir.name, "state", "kernel-vulns")
        self.git("init", "--quiet", "--initial-branch=master", self.origin)
        self.commit("CVE-2026-1", record_text("CVE-2026-1"))
        self.sources = sources.Sources(self.target, "file://" + self.origin)

    def git(self, *args):
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                *args,
            ],
            check=True,
            capture_output=True,
        )

    def commit(self, name, text):
        folder = os.path.join(self.origin, "cve", "published", "2026")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, f"{name}.json"), "w") as f:
            f.write(text)
        with open(os.path.join(folder, f"{name}.mbox"), "w") as f:
            f.write("mail")
        self.git("-C", self.origin, "add", ".")
        self.git("-C", self.origin, "commit", "--quiet", "-m", name)

    def names(self):
        records, _ = self.sources.kernel_records()
        return sorted(r.cve for r in records)

    def test_first_run_clones_only_the_records(self):
        self.sources.update_kernel_cves()
        self.assertEqual(self.names(), ["CVE-2026-1"])
        folder = os.path.join(self.target, "cve", "published", "2026")
        self.assertEqual(os.listdir(folder), ["CVE-2026-1.json"])
        self.assertFalse(os.path.exists(self.target + ".new"))

    def test_update_brings_new_records(self):
        self.sources.update_kernel_cves()
        self.commit("CVE-2026-2", record_text("CVE-2026-2"))
        self.sources.update_kernel_cves()
        self.assertEqual(self.names(), ["CVE-2026-1", "CVE-2026-2"])

    def test_update_with_nothing_new_changes_nothing(self):
        self.sources.update_kernel_cves()
        self.sources.update_kernel_cves()
        self.assertEqual(self.names(), ["CVE-2026-1"])

    def test_failed_update_keeps_the_old_records(self):
        self.sources.update_kernel_cves()
        broken = sources.Sources(self.target)
        with mock.patch.object(broken, "_git", side_effect=SourceError("down")):
            with self.assertRaises(SourceError):
                broken.update_kernel_cves()
        self.assertEqual(self.names(), ["CVE-2026-1"])

    def test_failed_clone_leaves_no_half_checkout(self):
        missing = sources.Sources(self.target, "file:///nonexistent/repo")
        with self.assertRaises(SourceError):
            missing.update_kernel_cves()
        self.assertFalse(os.path.exists(self.target))
        with self.assertRaises(SourceError):
            missing.kernel_records()

    def test_unreadable_record_is_counted_not_fatal(self):
        self.commit("CVE-2026-3", "not json")
        self.sources.update_kernel_cves()
        records, unreadable = self.sources.kernel_records()
        self.assertEqual([r.cve for r in records], ["CVE-2026-1"])
        self.assertEqual(unreadable, 1)

    def test_rows_of_other_products_are_left_out(self):
        other = json.loads(record_text("CVE-2026-4"))
        other["containers"]["cna"]["affected"][0] = dict(FIXED_ROW, product="other")
        self.commit("CVE-2026-4", json.dumps(other))
        self.sources.update_kernel_cves()
        by_cve = {r.cve: r for r in read_kernel_records(self.target)[0]}
        self.assertEqual(by_cve["CVE-2026-4"].rows, ())


class KernelSources(FakeSources):
    def __init__(self):
        super().__init__()
        self.adv = []
        self.packages = {
            "foo": "1-1",
            "linux-cachyos-lts": "6.18.55-2",
            "linux-cachyos": "7.3.1-1",
        }
        self.records_list = [KernelRecord("CVE-2026-99999", REAL)]
        self.unreadable = 0
        self.releases = RELEASES
        self.repo = {"linux-cachyos-lts": "6.18.55-2", "linux-cachyos": "7.3.1-1"}
        self.release = "6.18.55-2-cachyos-lts"
        self.chains.update(
            {
                "linux-cachyos-lts": frozenset({"linux-cachyos-lts"}),
                "linux-cachyos": frozenset({"linux-cachyos"}),
            }
        )
        self.leaf_set = frozenset({"linux-cachyos-lts", "linux-cachyos", "app"})

    def update_kernel_cves(self):
        self._maybe_fail("kernel-git")

    def kernel_records(self):
        self._maybe_fail("kernel-records")
        return self.records_list, self.unreadable

    def kernel_releases(self):
        self._maybe_fail("kernel-releases")
        return self.releases

    def repo_version(self, package):
        return self.repo.get(package)

    def running_kernel(self):
        return self.release


class KernelRuns(RunCase):
    def setUp(self):
        super().setUp()
        self.fake = KernelSources()

    def findings(self):
        return {f.package: f for f in self.store.open_findings() if f.strip == "kernel"}

    def text(self):
        self.store.db.commit()
        return report.format_text(report.load(self.path, now=self.now))

    def test_one_finding_per_kernel(self):
        result = self.run_once()
        self.assertTrue(result.kernel_ok)
        self.assertEqual(set(self.findings()), {"linux-cachyos", "linux-cachyos-lts"})
        self.assertEqual(result.levels[rules.INFO], 2)
        self.assertEqual(result.notified, 0)

    def test_no_kernel_package_needs_no_source(self):
        self.fake.packages = {"foo": "1-1"}
        self.fake.fail = {"kernel-git", "kernel-records", "kernel-releases"}
        result = self.run_once()
        self.assertTrue(result.kernel_ok)
        self.assertEqual(self.findings(), {})

    def test_kernel_is_never_a_removal_candidate(self):
        self.fake.repo["linux-cachyos-lts"] = "6.18.60-1"
        self.fake.view = sources.YoklamaView(
            61, frozenset({"linux-cachyos-lts", "linux-cachyos"}), {}, ()
        )
        result = self.run_once()
        self.assertEqual(self.findings()["linux-cachyos-lts"].level, rules.YELLOW)
        self.assertEqual(result.removal_suggestions, 0)
        self.assertEqual(
            self.rows("SELECT leaves, suggest_removal FROM findings"),
            [(None, 0), (None, 0)],
        )

    def test_repo_catching_up_turns_it_yellow_without_an_alert(self):
        self.run_once()
        self.fake.repo["linux-cachyos-lts"] = "6.18.60-1"
        result = self.run_once()
        self.assertEqual(
            result.diff.changed,
            [("linux-cachyos-lts", "kernel", rules.INFO, rules.YELLOW)],
        )
        self.assertEqual(result.notified, 0)

    def test_kev_alerts_once(self):
        self.run_once()
        self.fake.kev_set = frozenset({"CVE-2026-99999"})
        self.assertEqual(self.run_once().notified, 1)
        self.assertEqual(self.findings()["linux-cachyos-lts"].level, rules.RED)
        self.assertEqual(self.run_once().notified, 0)

    def test_kev_from_the_last_run_when_the_repo_strip_is_down(self):
        self.fake.kev_set = frozenset({"CVE-2026-99999"})
        self.run_once()
        self.fake.fail = {"repo"}
        self.run_once()
        self.assertEqual(self.findings()["linux-cachyos-lts"].level, rules.RED)

    def test_failed_releases_keep_the_previous_state(self):
        self.run_once()
        self.fake.fail = {"kernel-releases"}
        self.fake.repo["linux-cachyos-lts"] = "6.18.60-1"
        result = self.run_once()
        self.assertFalse(result.kernel_ok)
        self.assertEqual(self.findings()["linux-cachyos-lts"].level, rules.INFO)
        self.assertTrue(any("kernel strip skipped" in w for w in result.warnings))
        self.assertTrue(result.repo_ok)

    def test_failed_update_still_reads_the_old_list(self):
        self.fake.fail = {"kernel-git"}
        result = self.run_once()
        self.assertTrue(result.kernel_ok)
        self.assertTrue(any("not updated" in w for w in result.warnings))
        self.assertEqual(len(self.findings()), 2)

    def test_no_list_at_all_skips_the_strip(self):
        self.fake.fail = {"kernel-git", "kernel-records"}
        result = self.run_once()
        self.assertFalse(result.kernel_ok)
        self.assertEqual(self.findings(), {})

    def test_unreadable_records_are_a_warning(self):
        self.fake.unreadable = 3
        result = self.run_once()
        self.assertTrue(any("3 kernel CVE records" in w for w in result.warnings))

    def test_uninstalled_kernel_closes(self):
        self.run_once()
        del self.fake.packages["linux-cachyos"]
        result = self.run_once()
        self.assertEqual(
            result.diff.closed, [("linux-cachyos", "kernel", rules.INFO)]
        )

    def test_report_is_a_summary_in_the_agreed_words(self):
        self.run_once()
        text = self.text()
        self.assertIn("Kernels (for information", text)
        self.assertIn("6.18.55 (running)", text)
        self.assertIn("branch latest 6.18.60, 5 behind", text)
        self.assertIn("repo still has 6.18.55-2", text)
        self.assertIn("1 record covers this version", text)
        self.assertIn("6.18.60 fixes 1 of them, 0 remain", text)
        self.assertNotIn("CVE-2026-99999", text)
        self.assertNotIn(" open", text.split("Kernels")[1])

    def test_full_list_is_only_in_json(self):
        self.run_once()
        self.store.db.commit()
        data = json.loads(report.format_json(report.load(self.path, now=self.now)))
        kernels = {k["package"]: k for k in data["kernels"]}
        self.assertEqual(
            kernels["linux-cachyos-lts"]["detail"]["covered"],
            [{"cve": "CVE-2026-99999", "fixed_in": "6.18.57"}],
        )

    def test_yellow_kernel_shows_in_yellow_with_the_update(self):
        self.fake.repo["linux-cachyos-lts"] = "6.18.60-1"
        self.run_once()
        yellow = self.text().split("Removal suggestions")[0]
        self.assertIn("linux-cachyos-lts", yellow)
        self.assertIn("update available: 6.18.60-1", yellow)

    def test_reboot_note(self):
        self.fake.packages["linux-cachyos-lts"] = "6.18.60-1"
        self.fake.repo["linux-cachyos-lts"] = "6.18.60-1"
        self.run_once()
        self.assertIn("reboot pending: running 6.18.55-2", self.text())

    def test_failed_strip_shows_in_the_header(self):
        self.fake.fail = {"kernel-releases"}
        self.run_once()
        self.assertIn("kernel FAILED", self.text())

    def test_repo_strip_is_not_disturbed(self):
        self.fake.adv = [advisory()]
        result = self.run_once()
        self.assertEqual(result.levels[rules.RED], 1)
        self.assertEqual(result.levels[rules.INFO], 2)


if __name__ == "__main__":
    unittest.main()
