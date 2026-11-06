"""Faz 4: CVE records, KEV and EPSS. Fixtures are the real records of 2026-11-05."""

import glob
import gzip
import json
import os
import sqlite3
import unittest
import urllib.error
from unittest import mock

from sicil import cve as cve_module
from sicil import report, rules, sources
from sicil.cve import CLOSED, OPEN, UNKNOWN, CveFacts, Enrichment, ProductRow
from sicil.sources import SourceError, parse_advisories, parse_epss, parse_kev
from sicil.store import Store

from test_sicil import RunCase, advisory, fixture, vercmp

CVE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "cve")


def real_record(cve):
    with open(os.path.join(CVE_DIR, f"{cve}.json")) as f:
        return f.read()


def row(*versions, name="foo", vendor="foo", default="unaffected"):
    return ProductRow(vendor, (name,), default, tuple(versions))


def affected(start="0", below=None, through=None, kind="semver"):
    return {
        "version": start,
        "status": "affected",
        "lessThan": below,
        "lessThanOrEqual": through,
        "versionType": kind,
    }


def facts(*rows):
    return CveFacts("CVE-2026-0001", "text", None, None, tuple(rows))


def decide(*rows, package="foo", installed="2.0-1"):
    return cve_module.decide(facts(*rows), package, installed, vercmp)


class Decisions(unittest.TestCase):
    def test_outside_every_range_is_closed(self):
        self.assertEqual(decide(row(affected(below="1.5"))), CLOSED)

    def test_inside_a_range_is_open(self):
        self.assertEqual(decide(row(affected(below="2.1"))), OPEN)

    def test_range_start_counts(self):
        self.assertEqual(decide(row(affected("3.0", below="4.0"))), CLOSED)

    def test_upper_bound_is_exclusive_or_inclusive_as_written(self):
        self.assertEqual(decide(row(affected(below="2.0"))), CLOSED)
        self.assertEqual(decide(row(affected(through="2.0"))), OPEN)

    def test_second_range_can_hold_the_version(self):
        rows = row(affected(below="1.0"), affected("1.9", below="2.5"))
        self.assertEqual(decide(rows), OPEN)

    def test_epoch_and_pkgrel_are_ignored(self):
        self.assertEqual(
            decide(row(affected(below="1.5")), installed="1:2.0-1.1"), CLOSED
        )

    def test_exact_listed_version_is_open(self):
        rows = row(affected(below="1.0"), affected("2.0"))
        self.assertEqual(decide(rows), OPEN)

    def test_free_text_is_never_parsed(self):
        for text in ("<=1.5", "=1.5", "Fixed in foo 1.5", "1.5 and prior", "n/a"):
            with self.subTest(text):
                self.assertEqual(decide(row(affected(text))), UNKNOWN)

    def test_unreadable_upper_bound_settles_nothing(self):
        self.assertEqual(decide(row(affected(below="*"))), UNKNOWN)

    def test_exact_versions_alone_are_no_range(self):
        self.assertEqual(decide(row(affected("1.5"))), UNKNOWN)

    def test_outside_a_range_needs_unaffected_as_the_default(self):
        for default in ("affected", "unknown", None):
            with self.subTest(default):
                rows = row(affected(below="1.5"), default=default)
                self.assertEqual(decide(rows), UNKNOWN)

    def test_inside_a_range_is_open_whatever_the_default(self):
        self.assertEqual(decide(row(affected(below="2.1"), default=None)), OPEN)

    def test_a_vague_second_row_blocks_closing(self):
        rows = (row(affected(below="1.5")), row(affected("n/a"), default="unknown"))
        self.assertEqual(decide(*rows), UNKNOWN)

    def test_distribution_rows_are_ignored(self):
        rows = row(affected(below="1.5"), name="foo", vendor="Red Hat")
        self.assertEqual(decide(rows), UNKNOWN)

    def test_rpm_versions_are_ignored(self):
        self.assertEqual(decide(row(affected(below="1.5", kind="rpm"))), UNKNOWN)

    def test_git_hashes_are_ignored(self):
        self.assertEqual(decide(row(affected("abc123", below="def456", kind="git"))), UNKNOWN)

    def test_other_products_are_ignored(self):
        self.assertEqual(decide(row(affected(below="1.5"), name="bar")), UNKNOWN)

    def test_no_data_is_unknown(self):
        self.assertEqual(decide(), UNKNOWN)


class NameMatching(unittest.TestCase):
    def matches(self, package, name, vendor="x"):
        return cve_module.row_matches(package, ProductRow(vendor, (name,), None, ()))

    def test_real_pairs(self):
        for package, name in (
            ("pam", "linux-pam"),
            ("libxml2", "libxml2"),
            ("systemd", "systemd-coredump"),
            ("openjpeg2", "OpenJPEG"),
            ("openssl", "OpenSSL"),
        ):
            with self.subTest(package):
                self.assertTrue(self.matches(package, name))

    def test_no_guessing(self):
        for package, name in (
            ("openvpn", "kernel"),
            ("ruby-bundler", "rubygems"),
            ("cpio", "n/a"),
            ("perl", "superlatives"),
            ("pam", "spam-filter"),
        ):
            with self.subTest(package):
                self.assertFalse(self.matches(package, name))


class Records(unittest.TestCase):
    def test_description_and_cna_score(self):
        parsed = cve_module.parse_record(json.loads(real_record("CVE-2025-6020")))
        self.assertIn("linux-pam", parsed.description)
        self.assertEqual((parsed.cvss, parsed.cvss_source), (7.8, "CNA"))

    def test_adp_score_when_the_cna_has_none(self):
        parsed = cve_module.parse_record(json.loads(real_record("CVE-2021-38185")))
        self.assertEqual((parsed.cvss, parsed.cvss_source), (7.8, "CISA-ADP"))

    def test_no_score_at_all(self):
        parsed = cve_module.parse_record(json.loads(real_record("CVE-2021-31879")))
        self.assertEqual((parsed.cvss, parsed.cvss_source), (None, None))
        self.assertTrue(parsed.description)

    def test_other_adp_providers_do_not_count(self):
        raw = {
            "cveMetadata": {"cveId": "CVE-1"},
            "containers": {
                "cna": {},
                "adp": [
                    {
                        "providerMetadata": {"shortName": "other"},
                        "metrics": [{"cvssV3_1": {"baseScore": 1.0}}],
                    }
                ],
            },
        }
        self.assertIsNone(cve_module.parse_record(raw).cvss)

    def test_wrong_shape_is_a_value_error(self):
        with self.assertRaises(ValueError):
            cve_module.parse_record({"containers": []})


class RealRecords(unittest.TestCase):
    """The discovery's result, held in place."""

    def setUp(self):
        self.advisories = parse_advisories(
            json.loads(fixture("arch-audit.json")),
            json.loads(fixture("tracker-subset.json")),
            json.loads(fixture("installed-subset.json")),
        )
        facts = {}
        for path in glob.glob(os.path.join(CVE_DIR, "*.json")):
            with open(path) as f:
                parsed = cve_module.parse_record(json.load(f))
            facts[parsed.cve] = parsed
        self.assertEqual(len(facts), 44)
        self.enrichment = Enrichment(facts=facts)

    def levels(self, enrichment=None):
        found = rules.classify_repo(
            self.advisories, vercmp, enrichment or self.enrichment
        )
        return {(f.package, f.key): f for f in found}

    def closed_records(self):
        return {
            key for key, f in self.levels().items() if f.level == rules.LOOKS_CLOSED
        }

    def test_the_six_records_that_close(self):
        self.assertEqual(
            self.closed_records(),
            {
                ("pam", "AVG-2901"),
                ("libxml2", "AVG-2898"),
                ("coreutils", "AVG-2885"),
                ("systemd", "AVG-2893"),
                ("openssl", "AVG-2882"),
                ("perl", "AVG-2890"),
            },
        )

    def test_the_rest_stays_unverified(self):
        levels = [f.level for f in self.levels().values()]
        self.assertEqual(levels.count(rules.UNVERIFIED), 15)
        self.assertNotIn(rules.RED, levels)

    def test_free_text_records_do_not_close(self):
        # The discovery closed these only by reading free text.
        for key in (
            ("openjpeg2", "AVG-2850"),
            ("openssl", "AVG-2765"),
            ("ruby-bundler", "AVG-2615"),
        ):
            self.assertEqual(self.levels()[key].level, rules.UNVERIFIED)

    def test_no_cve_is_open(self):
        versions = [
            c["version"]
            for f in self.levels().values()
            for c in f.detail["enrichment"].values()
        ]
        self.assertNotIn(OPEN, versions)

    def test_high_epss_changes_nothing(self):
        self.enrichment.epss = {"CVE-2022-2068": 0.96391}
        found = self.levels()[("openssl", "AVG-2765")]
        self.assertEqual(found.level, rules.UNVERIFIED)
        self.assertEqual(
            found.detail["enrichment"]["CVE-2022-2068"]["epss"], 0.96391
        )

    def test_kev_on_an_unsettled_cve_is_red(self):
        self.enrichment.kev = frozenset({"CVE-2021-31879"})
        self.assertEqual(self.levels()[("wget", "AVG-1892")].level, rules.RED)

    def test_kev_outside_the_range_does_not_apply(self):
        self.enrichment.kev = frozenset({"CVE-2025-6020"})
        self.assertEqual(self.levels()[("pam", "AVG-2901")].level, rules.LOOKS_CLOSED)

    def test_every_cve_has_a_description(self):
        missing = [
            cve
            for f in self.levels().values()
            for cve, c in f.detail["enrichment"].items()
            if not c["description"]
        ]
        self.assertEqual(missing, [])


class KnownFixIsKept(unittest.TestCase):
    def test_closed_cves_do_not_quiet_a_known_fix(self):
        # A fix newer than the installed version is the tracker's firm word.
        record = facts(row(affected(below="0.5"), name="pam"))
        found = rules.classify_repo(
            [advisory(fixed="2.0-1", cves=("CVE-2026-0001",))],
            vercmp,
            Enrichment(facts={"CVE-2026-0001": record}),
        )
        self.assertEqual(found[0].level, rules.RED)


class Parsers(unittest.TestCase):
    def test_epss_skips_the_comment_and_keeps_only_what_is_wanted(self):
        body = gzip.compress(
            b"#model_version:v1,score_date:x\ncve,epss,percentile\n"
            b"CVE-1,0.5,0.9\nCVE-2,0.1,0.2\n"
        )
        self.assertEqual(parse_epss(body, {"CVE-1"}), {"CVE-1": 0.5})

    def test_bad_epss_is_a_source_error(self):
        for body in (b"not gzip", gzip.compress(b"#c\ncve,other\nCVE-1,1\n")):
            with self.assertRaises(SourceError):
                parse_epss(body, {"CVE-1"})

    def test_kev(self):
        body = json.dumps({"vulnerabilities": [{"cveID": "CVE-1"}]}).encode()
        self.assertEqual(parse_kev(body), {"CVE-1"})
        with self.assertRaises(SourceError):
            parse_kev(b"{}")

    def test_record_address(self):
        self.assertTrue(
            sources.cve_record_url("CVE-2025-49794").endswith(
                "/cves/2025/49xxx/CVE-2025-49794.json"
            )
        )
        self.assertTrue(
            sources.cve_record_url("CVE-2021-3575").endswith(
                "/cves/2021/3xxx/CVE-2021-3575.json"
            )
        )

    def test_odd_id_never_reaches_the_address(self):
        with self.assertRaises(SourceError):
            sources.cve_record_url("CVE-2025-1/../../secret")

    def test_missing_record_is_none_but_an_outage_is_an_error(self):
        missing = urllib.error.HTTPError("u", 404, "not found", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=missing):
            self.assertIsNone(sources.Sources().cve_record("CVE-2026-0001"))
        down = urllib.error.HTTPError("u", 503, "busy", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=down):
            with self.assertRaises(SourceError):
                sources.Sources().cve_record("CVE-2026-0001")


class EnrichCase(RunCase):
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
        self.fake.chains["pam"] = frozenset({"pam", "app"})

    def level(self):
        return [f.level for f in self.store.open_findings() if f.strip == "repo"]

    def days(self, count):
        self.now += count * 86400


class Enriching(EnrichCase):
    def test_record_is_downloaded_once_and_cached(self):
        self.run_once()
        self.run_once()
        self.assertEqual(self.fake.fetched, ["CVE-2025-6020"])
        self.assertEqual(self.level(), [rules.LOOKS_CLOSED])

    def test_closed_record_is_not_refreshed(self):
        self.run_once()
        self.days(8)
        self.run_once()
        self.assertEqual(self.fake.fetched, ["CVE-2025-6020"])

    def test_unsettled_record_is_refreshed_after_a_week_only(self):
        self.fake.adv = [
            advisory(
                package="wget",
                avg="AVG-1892",
                installed="1.25.0-6.1",
                affected="1.21.3-1",
                cves=("CVE-2021-31879",),
            )
        ]
        self.fake.chains["wget"] = frozenset({"wget"})
        self.fake.records = {"CVE-2021-31879": real_record("CVE-2021-31879")}
        self.run_once()
        self.days(6)
        self.run_once()
        self.assertEqual(len(self.fake.fetched), 1)
        self.days(2)
        self.run_once()
        self.assertEqual(len(self.fake.fetched), 2)

    def test_record_not_yet_published_is_asked_again_after_a_week(self):
        self.fake.records = {}
        self.run_once()
        self.assertEqual(self.level(), [rules.UNVERIFIED])
        self.days(1)
        self.run_once()
        self.assertEqual(len(self.fake.fetched), 1)
        self.days(7)
        self.fake.records = {"CVE-2025-6020": real_record("CVE-2025-6020")}
        self.run_once()
        self.assertEqual(self.level(), [rules.LOOKS_CLOSED])

    def test_looks_closed_never_alerts_or_suggests_removal(self):
        self.fake.view = sources.YoklamaView(61, frozenset({"app"}), {}, ())
        result = self.run_once()
        self.assertEqual((result.notified, result.removal_suggestions), (0, 0))
        self.assertEqual(self.fake.sent, [])

    def test_kev_raises_an_unsettled_finding_and_alerts_once(self):
        self.fake.adv = [
            advisory(
                package="wget",
                avg="AVG-1892",
                installed="1.25.0-6.1",
                affected="1.21.3-1",
                cves=("CVE-2021-31879",),
            )
        ]
        self.fake.chains["wget"] = frozenset({"wget"})
        self.fake.records = {"CVE-2021-31879": real_record("CVE-2021-31879")}
        self.run_once()
        self.assertEqual(self.level(), [rules.UNVERIFIED])
        self.fake.kev_set = frozenset({"CVE-2021-31879"})
        self.assertEqual(self.run_once().notified, 1)
        self.assertEqual(self.level(), [rules.RED])
        self.assertEqual(self.run_once().notified, 0)

    def test_cve_outage_stops_asking_and_keeps_the_strip(self):
        self.fake.adv = [
            advisory(avg=f"AVG-{i}", cves=(f"CVE-2026-000{i}",)) for i in range(3)
        ]
        self.fake.fail = {"cve"}
        result = self.run_once()
        self.assertTrue(result.repo_ok)
        self.assertEqual(self.fake.cve_attempts, 1)
        self.assertEqual(sum("CVE records incomplete" in w for w in result.warnings), 1)
        self.assertEqual(len(self.store.open_findings()), 3)

    def test_kev_outage_keeps_the_last_catalog(self):
        self.fake.kev_set = frozenset({"CVE-2025-6020"})
        self.run_once()
        self.fake.kev_set = frozenset()
        self.fake.fail = {"kev"}
        result = self.run_once()
        self.assertTrue(any("KEV not updated" in w for w in result.warnings))
        self.assertEqual(json.loads(self.store.meta("kev")), ["CVE-2025-6020"])

    def test_epss_outage_keeps_the_last_scores(self):
        self.fake.epss_map = {"CVE-2025-6020": 0.25}
        self.run_once()
        self.fake.fail = {"epss"}
        result = self.run_once()
        self.assertTrue(any("EPSS not updated" in w for w in result.warnings))
        detail = json.loads(self.rows("SELECT detail FROM findings")[0][0])
        self.assertEqual(detail["enrichment"]["CVE-2025-6020"]["epss"], 0.25)

    def test_failed_repo_strip_stores_no_enrichment(self):
        self.fake.fail = {"repo"}
        self.run_once()
        self.assertEqual(self.rows("SELECT count(*) FROM cve_cache"), [(0,)])

    def test_malformed_record_is_a_warning_not_a_failure(self):
        self.fake.records = {"CVE-2025-6020": '{"containers": []}'}
        result = self.run_once()
        self.assertTrue(result.repo_ok)
        self.assertTrue(any("CVE-2025-6020" in w for w in result.warnings))
        self.assertEqual(self.level(), [rules.UNVERIFIED])

    def test_version_2_database_migrates_keeping_its_findings(self):
        self.run_once()
        self.store.db.executescript(
            "DROP TABLE cve_cache; DROP TABLE enrich_meta;"
            " ALTER TABLE runs DROP COLUMN kernel_ok; PRAGMA user_version = 2;"
        )
        self.store.close()
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.assertEqual(self.rows("PRAGMA user_version"), [(3,)])
        self.assertEqual(len(self.store.open_findings()), 1)
        self.run_once()

    def test_version_1_database_migrates_all_the_way(self):
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
        self.assertEqual(self.rows("PRAGMA user_version"), [(3,)])
        self.run_once()


class Reporting(EnrichCase):
    def text(self):
        self.store.db.commit()
        return report.format_text(report.load(self.path, now=self.now))

    def test_looks_closed_has_its_own_section(self):
        self.run_once()
        text = self.text()
        self.assertIn("Looks closed", text)
        self.assertIn("Can't verify: none", text)
        self.assertIn("7.8 CNA", text)
        self.assertIn("A flaw was found in linux-pam", text)
        data = json.loads(
            report.format_json(report.load(self.path, now=self.now))
        )
        self.assertEqual(len(data["looks_closed"]), 1)

    def test_every_cve_of_a_record_has_its_row(self):
        cves = tuple(f"CVE-2026-000{i}" for i in range(4))
        self.fake.adv = [advisory(cves=cves)]
        self.run_once()
        text = self.text()
        for cve in cves:
            self.assertIn(cve, text)

    def test_epss_and_kev_are_shown(self):
        self.fake.adv = [advisory(cves=("CVE-2026-0001",))]
        self.fake.epss_map = {"CVE-2026-0001": 0.123456}
        self.fake.kev_set = frozenset({"CVE-2026-0001"})
        self.run_once()
        text = self.text()
        self.assertIn("0.123", text)
        self.assertIn("KEV", text)

    def test_description_cannot_steer_the_terminal(self):
        raw = json.loads(real_record("CVE-2025-6020"))
        raw["containers"]["cna"]["descriptions"][0]["value"] = "bad\x1b[2Jtext\nnext"
        self.fake.records = {"CVE-2025-6020": json.dumps(raw)}
        self.run_once()
        text = self.text()
        self.assertNotIn("\x1b", text)
        self.assertIn("bad [2Jtext next", text)

    def test_long_description_is_cut_in_text_but_not_in_json(self):
        raw = json.loads(real_record("CVE-2025-6020"))
        long = "word " * 40
        raw["containers"]["cna"]["descriptions"][0]["value"] = long
        self.fake.records = {"CVE-2025-6020": json.dumps(raw)}
        self.run_once()
        self.store.db.commit()
        narrow = report.format_text(report.load(self.path, now=self.now), width=80)
        self.assertNotIn(long.strip(), narrow)
        self.assertIn(long.strip(), self.text())  # nothing to fit in a pipe
        data = json.loads(report.format_json(report.load(self.path, now=self.now)))
        self.assertEqual(
            data["looks_closed"][0]["detail"]["enrichment"]["CVE-2025-6020"][
                "description"
            ],
            long,
        )

    def test_findings_from_before_enrichment_still_print(self):
        self.run_once()
        self.store.db.execute(
            "UPDATE findings SET detail = json_remove(detail, '$.enrichment')"
        )
        self.store.db.commit()
        self.assertIn("CVE-2025-6020", self.text())


if __name__ == "__main__":
    unittest.main()
