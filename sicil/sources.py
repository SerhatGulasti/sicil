"""Everything Sicil reads from outside its own database."""

import csv
import glob
import gzip
import http.client
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

# all.json answers with a redirect to this address.
TRACKER_URL = "https://security.archlinux.org/issues/all.json"
AUR_INFO_URL = "https://aur.archlinux.org/rpc/v5/info"
CVE_RECORD_URL = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
    "/{year}/{bucket}xxx/{cve}.json"
)
# cisa.gov refuses automated clients; this is CISA's own copy of the catalog.
KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KERNEL_VULNS_URL = "https://git.kernel.org/pub/scm/linux/security/vulns.git"
KERNEL_RELEASES_URL = "https://www.kernel.org/releases.json"
USER_AGENT = "sicil/0.1"
NETWORK_TIMEOUT = 30
COMMAND_TIMEOUT = 60
GIT_TIMEOUT = 180


class SourceError(Exception):
    """A source could not be read; the strip that needs it is skipped this run."""


class NotFound(SourceError):
    """The server answered, and has no such thing."""


class YoklamaMissing(SourceError):
    """The `yoklama` command does not exist here, which is a normal way to run Sicil."""


@dataclass(frozen=True)
class Advisory:
    package: str
    avg: str
    severity: str
    status: str
    type: str
    fixed: str | None
    affected: str | None
    installed: str
    cves: tuple[str, ...]


@dataclass(frozen=True)
class YoklamaView:
    observed_days: float
    idle: frozenset[str]
    last_seen: dict[str, int | None]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class KernelRelease:
    version: str
    eol: bool


@dataclass(frozen=True)
class KernelRecord:
    cve: str
    rows: tuple[dict, ...]


def _run(
    command: list[str], empty_ok: bool = False, timeout: int = COMMAND_TIMEOUT
) -> str:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise SourceError(f"{command[0]}: {e}") from e
    stderr = result.stderr.strip()
    # pacman exits 1 with no message when a query simply matches nothing.
    if empty_ok and result.returncode == 1 and not stderr:
        return ""
    if result.returncode != 0:
        detail = stderr.splitlines()[-1] if stderr else "no message"
        raise SourceError(f"{command[0]} exited {result.returncode}: {detail}")
    return result.stdout


def _fetch(request: urllib.request.Request) -> bytes:
    try:
        with urllib.request.urlopen(request, timeout=NETWORK_TIMEOUT) as response:
            return response.read()
    except urllib.error.HTTPError as e:
        kind = NotFound if e.code == 404 else SourceError
        raise kind(f"{request.full_url}: {e}") from e
    except (OSError, http.client.HTTPException) as e:
        # URLError and timeouts are both OSError.
        raise SourceError(f"{request.full_url}: {e}") from e


def _json(text: str | bytes, source: str):
    try:
        return json.loads(text)
    except ValueError as e:
        raise SourceError(f"{source}: not JSON: {e}") from e


def parse_advisories(
    audit: list[dict], tracker: list[dict], installed: dict[str, str]
) -> list[Advisory]:
    """Join arch-audit's findings with what only the tracker knows.

    arch-audit decides what is affected but does not report `affected`, which the
    stale-record rule needs, nor the installed version.
    """
    affected = {group.get("name"): group.get("affected") for group in tracker}
    advisories = []
    try:
        for group in audit:
            for package in group["packages"]:
                if package not in installed:
                    continue
                advisories.append(
                    Advisory(
                        package=package,
                        avg=group["name"],
                        severity=group["severity"],
                        status=group["status"],
                        type=group["type"],
                        fixed=group["fixed"],
                        affected=affected.get(group["name"]),
                        installed=installed[package],
                        cves=tuple(group["issues"]),
                    )
                )
    except (KeyError, TypeError) as e:
        raise SourceError(f"arch-audit: unexpected JSON: {e!r}") from e
    return advisories


def parse_aur_info(body: bytes) -> dict[str, dict]:
    """Results by name. A name the AUR does not know is simply absent."""
    data = _json(body, "AUR RPC")
    if not isinstance(data, dict) or data.get("type") != "multiinfo":
        message = data.get("error") if isinstance(data, dict) else None
        raise SourceError(f"AUR RPC: unexpected reply: {message or 'no results'}")
    try:
        return {result["Name"]: result for result in data["results"]}
    except (KeyError, TypeError) as e:
        raise SourceError(f"AUR RPC: unexpected JSON: {e!r}") from e


def cve_record_url(cve: str) -> str:
    match = re.fullmatch(r"CVE-(\d{4})-(\d{4,})", cve)
    if match is None:
        raise SourceError(f"not a CVE id: {cve!r}")
    year, number = match.groups()
    return CVE_RECORD_URL.format(year=year, bucket=int(number) // 1000, cve=cve)


def parse_kev(body: bytes) -> frozenset[str]:
    data = _json(body, "KEV")
    try:
        return frozenset(entry["cveID"] for entry in data["vulnerabilities"])
    except (KeyError, TypeError) as e:
        raise SourceError(f"KEV: unexpected JSON: {e!r}") from e


def parse_epss(body: bytes, wanted: set[str]) -> dict[str, float]:
    """Scores for the wanted CVEs. The file starts with a comment line."""
    try:
        text = gzip.decompress(body).decode()
        lines = io.StringIO(text)
        lines.readline()
        return {
            row["cve"]: float(row["epss"])
            for row in csv.DictReader(lines)
            if row["cve"] in wanted
        }
    except (OSError, EOFError, ValueError, KeyError, TypeError) as e:
        raise SourceError(f"EPSS: unexpected file: {e!r}") from e


def parse_yoklama(default_report: dict, full_report: dict) -> YoklamaView:
    """Combine the two reports.

    The idle list comes from Yoklama's own threshold, so that rule lives in one
    place. Only `--days 0` lists every package, which the last-used column needs.
    """
    try:
        last_seen = {
            row["name"]: row["last_seen"]
            for section in ("idle", "protected", "unmeasurable")
            for row in full_report[section]
        }
        return YoklamaView(
            observed_days=float(default_report["observed_days"]),
            idle=frozenset(row["name"] for row in default_report["idle"]),
            last_seen=last_seen,
            warnings=tuple(default_report["warnings"]),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise SourceError(f"yoklama: unexpected JSON: {e!r}") from e


def parse_kernel_releases(body: bytes) -> dict[str, KernelRelease]:
    """Newest release and end-of-life flag by branch, such as "6.18"."""
    data = _json(body, "kernel releases")
    releases: dict[str, KernelRelease] = {}
    try:
        for entry in data["releases"]:
            if entry["moniker"] not in ("mainline", "stable", "longterm"):
                continue
            match = re.match(r"\d+\.\d+", entry["version"])
            if match:
                releases.setdefault(
                    match.group(0),
                    KernelRelease(entry["version"], bool(entry["iseol"])),
                )
    except (KeyError, TypeError) as e:
        raise SourceError(f"kernel releases: unexpected JSON: {e!r}") from e
    if not releases:
        raise SourceError("kernel releases: no branches listed")
    return releases


def kernel_rows(data: dict) -> tuple[dict, ...]:
    return tuple(
        row
        for row in data["containers"]["cna"]["affected"]
        if (row.get("vendor") or "").lower() == "linux"
        and (row.get("product") or "").lower() == "linux"
    )


def read_kernel_records(directory: str) -> tuple[list[KernelRecord], int]:
    """The published records in a checkout, and how many could not be read.

    Only the JSON is ever read. Nothing in the repository is run.
    """
    paths = glob.glob(os.path.join(directory, "cve", "published", "*", "*.json"))
    if not paths:
        raise SourceError("the kernel CVE list is empty")
    records = []
    unreadable = 0
    for path in paths:
        if os.path.islink(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            records.append(KernelRecord(data["cveMetadata"]["cveId"], kernel_rows(data)))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            unreadable += 1
    return records, unreadable


class Sources:
    """The real sources. Tests replace this class, so they never touch the network."""

    def __init__(
        self, kernel_dir: str | None = None, kernel_url: str = KERNEL_VULNS_URL
    ):
        self.kernel_dir = kernel_dir
        self.kernel_url = kernel_url

    def _git(self, *arguments: str, directory: str | None = None) -> str:
        command = ["git", "-c", "core.hooksPath=/dev/null"]
        if directory:
            command += ["-C", directory]
        return _run(command + list(arguments), timeout=GIT_TIMEOUT)

    def update_kernel_cves(self) -> None:
        """Keep a shallow checkout of the records' JSON files, and nothing else."""
        if not self.kernel_dir:
            raise SourceError("no directory for the kernel CVE list")
        if os.path.isdir(os.path.join(self.kernel_dir, ".git")):
            here = self.kernel_dir
            before = self._git("rev-parse", "HEAD", directory=here).strip()
            self._git("fetch", "--quiet", "--depth", "1", "origin", "master", directory=here)
            after = self._git("rev-parse", "FETCH_HEAD", directory=here).strip()
            if after != before:
                self._git("reset", "--quiet", "--hard", "FETCH_HEAD", directory=here)
                # Without this every day's snapshot stays in .git.
                self._git("reflog", "expire", "--expire=now", "--all", directory=here)
                self._git("gc", "--quiet", "--prune=now", directory=here)
            return
        # Built aside, so an interrupted clone never looks like a finished one.
        fresh = self.kernel_dir + ".new"
        try:
            shutil.rmtree(fresh, ignore_errors=True)
            os.makedirs(os.path.dirname(fresh), exist_ok=True)
            self._git(
                "clone",
                "--quiet",
                "--depth",
                "1",
                "--single-branch",
                "--no-checkout",
                self.kernel_url,
                fresh,
            )
            self._git(
                "sparse-checkout",
                "set",
                "--no-cone",
                "/cve/published/*/*.json",
                directory=fresh,
            )
            self._git("checkout", "--quiet", "master", directory=fresh)
            os.replace(fresh, self.kernel_dir)
        except OSError as e:
            raise SourceError(f"kernel CVE list: {e}") from e

    def kernel_records(self) -> tuple[list[KernelRecord], int]:
        if not self.kernel_dir:
            raise SourceError("no directory for the kernel CVE list")
        return read_kernel_records(self.kernel_dir)

    def kernel_record(self, cve: str) -> dict | None:
        """One record's JSON from the local checkout. The CVE's form is the caller's."""
        if self.kernel_dir is None:
            return None
        paths = glob.glob(
            os.path.join(self.kernel_dir, "cve", "published", "*", f"{cve}.json")
        )
        for path in paths:
            if os.path.islink(path):
                continue
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, ValueError):
                return None
        return None

    def kernel_releases(self) -> dict[str, KernelRelease]:
        return parse_kernel_releases(self._get(KERNEL_RELEASES_URL))

    def repo_version(self, package: str) -> str | None:
        """What an upgrade would install, by pacman's own repo order.

        Reads the sync database as it stands, last refreshed by `pacman -Sy`. Any failure
        counts as no newer version, which only keeps a finding from turning yellow.
        """
        try:
            output = _run(["pacman", "-Sp", "--print-format", "%n %v", package])
        except SourceError:
            return None
        for line in output.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == package:
                return parts[1]
        return None

    def running_kernel(self) -> str:
        return os.uname().release

    def installed(self) -> dict[str, str]:
        lines = _run(["pacman", "-Q"]).splitlines()
        return dict(line.split()[:2] for line in lines if line.strip())

    def installed_version(self, package: str) -> str | None:
        """The version installed right now, or None if the package is not installed."""
        try:
            output = _run(["pacman", "-Q", package], empty_ok=True)
        except SourceError as e:
            if "was not found" in str(e):
                return None
            raise
        fields = output.split()
        return fields[1] if len(fields) >= 2 else None

    def foreign_packages(self) -> list[str]:
        return _run(["pacman", "-Qqm"], empty_ok=True).split()

    def leaves(self) -> frozenset[str]:
        # -tt: a package only optionally required by others can still be removed.
        return frozenset(_run(["pacman", "-Qqtt"], empty_ok=True).split())

    def chain(self, package: str) -> frozenset[str]:
        """The package and everything that needs it. pactree follows hard deps only."""
        return frozenset(_run(["pactree", "-ru", package]).split())

    def vercmp(self, a: str, b: str) -> int:
        try:
            return int(_run(["vercmp", a, b]))
        except ValueError as e:
            raise SourceError(f"vercmp: {e}") from e

    def advisories(self, installed: dict[str, str]) -> list[Advisory]:
        request = urllib.request.Request(
            TRACKER_URL, headers={"User-Agent": USER_AGENT}
        )
        body = _fetch(request)
        tracker = _json(body, "tracker")
        # One download, so arch-audit and `affected` describe the same snapshot.
        with tempfile.NamedTemporaryFile(suffix=".json") as copy:
            copy.write(body)
            copy.flush()
            audit = _json(
                _run(["arch-audit", "--json", "--source", copy.name]), "arch-audit"
            )
        return parse_advisories(audit, tracker, installed)

    def aur_info(self, names: list[str]) -> dict[str, dict]:
        if not names:
            return {}
        request = urllib.request.Request(
            AUR_INFO_URL,
            data=urllib.parse.urlencode([("arg[]", n) for n in names]).encode(),
            headers={"User-Agent": USER_AGENT},
        )
        return parse_aur_info(_fetch(request))

    def _get(self, url: str) -> bytes:
        return _fetch(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}))

    def cve_record(self, cve: str) -> str | None:
        """The record's JSON text, or None if cvelistV5 has no such CVE."""
        try:
            return self._get(cve_record_url(cve)).decode()
        except NotFound:
            return None
        except UnicodeDecodeError as e:
            raise SourceError(f"{cve}: {e}") from e

    def kev(self) -> frozenset[str]:
        return parse_kev(self._get(KEV_URL))

    def epss(self, wanted: set[str]) -> dict[str, float]:
        return parse_epss(self._get(EPSS_URL), wanted)

    def notify(self, title: str, body: str) -> None:
        _run(["notify-send", "--app-name=Sicil", "--urgency=critical", title, body])

    def yoklama(self) -> YoklamaView:
        if shutil.which("yoklama") is None:
            raise YoklamaMissing("yoklama is not installed")
        base = ["yoklama", "report", "--all", "--json"]
        return parse_yoklama(
            _json(_run(base), "yoklama"),
            _json(_run(base + ["--days", "0"]), "yoklama"),
        )
