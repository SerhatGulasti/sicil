**EN** | [TR](README_TR.md)

# Sicil

A small tool for CachyOS that checks once a day whether the installed packages have
known security problems. It combines what it finds with how recently [Yoklama](https://github.com/SerhatGulasti/yoklama), a separate
package usage recorder, saw each package used, and sorts the result by what is worth your
attention.

Sicil only reads and reports. It never installs, updates or removes a package, needs no
root, and writes nothing to [Yoklama](https://github.com/SerhatGulasti/yoklama). If Sicil breaks, [Yoklama](https://github.com/SerhatGulasti/yoklama) is not affected.

## Requirements

- CachyOS or another pacman-based system, with systemd for the daily run
- Python 3.10 or newer (standard library only)
- `arch-audit`, `git`, `pactree` (from `pacman-contrib`), `notify-send`
- Optional: [Yoklama](https://github.com/SerhatGulasti/yoklama), for last-used dates and removal
  suggestions. Without it Sicil works the same with one note, no last-used column and no
  removal section, and `--unused` and `--used` refuse to run.
- About 300 MB of disk for the kernel CVE records

## Installation

Sicil runs from its source tree, and the service expects that tree at `~/.daemons/sicil`.

```sh
systemctl --user link ~/.daemons/sicil/systemd/sicil.service ~/.daemons/sicil/systemd/sicil.timer
systemctl --user enable --now sicil.timer
ln -s ~/.daemons/sicil/bin/sicil ~/.local/bin/sicil    # to call it as `sicil`
```

The timer runs around 10:00 every day, once `nm-online` reports a connection or after
two minutes. A run missed while the computer was off happens at the next start. User
timers only run while you are logged in, which is also when a notification can be seen.

The first run takes about a minute, because it clones the kernel CVE records.

## Usage

```sh
sicil run                # check the sources and record what changed
sicil report             # show the open findings; no network, read-only
sicil report --all       # closed findings too
sicil report --json      # JSON output, with the complete lists
sicil show <id>          # one record, judged against the version installed now
```

`sicil run` says in a few sentences whether there is a new problem, what changed, and where the
kernels stand:

```text
No new problems.
Standing: 15 can't be verified, 6 look closed.
linux-cachyos: 7.3.1; latest in its branch.
linux-cachyos-lts: 6.18.55 (running); branch latest 6.18.60, 5 behind; repo still has 6.18.55-2.
Details: sicil report
```

`sicil report` fits the terminal. A table too wide for it drops its least important columns and
says which; in a pipe nothing is shortened.

```text
Last run: 2026-11-06 09:44 (repo ok, aur ok, kernel ok, yoklama ok)

Red: none

Yellow: none

Removal suggestions: none

Can't verify: record is old, installed version is newer
  ID                   SEVERITY  EPSS   RANGE    INSTALLED   RECORD
  wget:CVE-2021-31879  Medium    0.011  unknown  1.25.0-6.1  1.21.3-1
    GNU Wget through 1.21.1 does not omit the Authorization header upon a redirect to a different...

Looks closed: installed version is outside every CVE's affected range
  ID                 SEVERITY  CVSS     EPSS   RANGE    INSTALLED  RECORD   LAST USED
  pam:CVE-2025-6020  High      7.8 CNA  0.005  outside  1.7.3-1.1  1.7.0-2  2026-11-06
    A flaw was found in linux-pam. The module pam_namespace may use access user-controlled paths...

Kernels: for information, nothing to do now
  linux-cachyos-lts
    6.18.55 (running); branch latest 6.18.60, 5 behind; repo still has 6.18.55-2; 873 records cover
    this version; 6.18.60 fixes 737 of them, 136 remain

Not found in AUR: none
```

Each row starts with an ID you can copy, and its description sits below it. A column that is empty
in every row is left out, and a value shared by every row moves above the table.

The header warns if the last run is more than 36 hours old or was incomplete, and carries
Yoklama's warning about a short observation period.

### Filters

Filters work on `sicil report`, also with `--json`. Different filters must all match and a
repeated one may match any: `-p pam -p libxml2 -c 7` means "pam or libxml2, with CVSS 7 or above".

| What | Flag | Rule |
| --- | --- | --- |
| Package | `-p`, `--package <name>` | Wildcards work: `'lib*'` |
| CVE | `--cve <id>` | Wildcards work: `'CVE-2021-*'`. On a kernel it lists the matching IDs |
| Severity | `-s`, `--severity <level>` | This level and above: `-s medium` is medium, high and critical. Unknown only with `-s unknown` |
| CVSS | `-c`, `--min-cvss <score>` | This score and above; the CNA's, or else CISA-ADP's |
| Last use | `--unused <days>`, `--used <days>` | A package never seen in use counts as unused. A package Yoklama cannot measure is not listed and is counted as `no last-used date`. Without Yoklama this is an error, not an empty list |
| Installed version | `--installed-min`, `--installed-max` | Compared by pacman's `vercmp`, not as text |
| Record version | `--record-min`, `--record-max` | The same |
| Status | `--status <status>` | `open`, `unverified`, `looks-closed` |

A record dropped because the filtered field is empty does not vanish: the end of the report counts
it per field, as in `3 records hidden: no CVSS`. A filtered report says so at the top, so that
`Red: none` is not read as an all-clear. Only the version filters run a program, `vercmp`.

### IDs and `sicil show`

An ID is `package:CVE`, such as `pam:CVE-2025-6020`, so two machines reach the same ID without
seeing each other. It carries no version: `sicil show` reads the installed version when you ask.
AUR findings are events and have no ID.

```text
pam:CVE-2025-6020
Installed 1.7.3-1.1 · looks closed

A flaw was found in linux-pam. The module pam_namespace may use access user-controlled paths without
proper protection, allowing local users to elevate their privileges to root via multiple symlink
attacks and race conditions.

Severity   High
CVSS       7.8 (CNA)
EPSS       0.005
KEV        no
Range      outside
Record     1.7.0-2
Last used  2026-11-06
Tracker    https://security.archlinux.org/CVE-2025-6020
Source     https://www.cve.org/CVERecord?id=CVE-2025-6020
```

- `sicil show CVE-2025-6020` lists every package on this machine with that CVE.
- `-f`, `--field <field>` prints one field bare for scripts: `desc`, `installed`, `status`,
  `severity`, `cvss`, `epss`, `kev`, `range`, `record`, `fixed`, `last-used`, `url`.
- An installed package with no finding is reported as exactly that, because not having a finding
  does not prove it is unaffected. A package that is not installed says `Not installed`.
- `show` opens the database read-only and asks pacman for the version; it uses no network. For a
  kernel it also reads the record from the local checkout.

## What the sections mean

| Section | Official packages | AUR packages | Kernels |
| --- | --- | --- | --- |
| Red | Severity High or Critical, or a CVE in KEV that the version range does not rule out | Maintainer changed hands, an orphan was adopted, or the package left the AUR | A CVE covering this version is in KEV |
| Yellow | Severity Low, Medium or Unknown | Orphan, flagged out of date, or a new co-maintainer | The repo has a newer version, or the branch is end of life |
| Removal suggestions | See below | See below | Never |
| Can't verify | The tracker has no fix, and the installed version is newer than its record | | |
| Looks closed | As Can't verify, but every CVE's affected range excludes the installed version | | |
| Kernels | | | Behind or not, with nothing to do right now |
| Not found in AUR | | Not on the AUR since the first time Sicil looked | |

A new red finding raises one desktop notification, a single summary if there are several.
Nothing else notifies, and the same finding does not notify twice.

One-off AUR events stay open for 7 days and then close by themselves, so a report read
later still shows them. Lasting states such as an orphan stay open as long as they last.

**Why Can't verify exists.** When the Arch tracker has no fixed version, `arch-audit` reports
every newer version too, so an old record may simply never have been closed. Sicil keeps
these out of the alarms but still shows them.

**How Looks closed is decided.** A CVE counts as closed only if its record has a
machine-readable version range on a row naming the package itself, that row says everything
unlisted is unaffected, and the installed version is outside the range. Rows from
distributions are ignored and free text is never parsed: a wrong "closed" is worse than none.

**Removal suggestions** are made only if removing the packages would really take the
vulnerable one off the system. Sicil walks up the dependency chain with `pactree -ru`
to the packages nothing requires (`pacman -Qqtt`). All of them must have gone unused for 60
days by Yoklama's count, and none may be protected or unmeasurable. Otherwise the report only
shows what pulls the package in. No suggestions are made until Yoklama has observed for 60
days. Can't verify findings, Looks closed findings and kernels never get one.

**CVSS and EPSS never change a level.** EPSS knows nothing about the installed version:
the highest score in one real report belonged to a CVE fixed long before that version.

## Kernels

The kernel's CVE team opens a record for nearly every fix, so a kernel behind its branch is
covered by hundreds of records with little to tell them apart. Sicil therefore prints one line
per kernel instead of a list; the complete list is in `--json`. Only `linux-cachyos` and
`linux-cachyos-lts` are checked. If the package was upgraded but the machine still runs
the old kernel, the line says a reboot is pending.

## How it works

Each run reads its sources first, then records the result in one transaction. A source that
fails only skips its own strip: that strip's previous state is kept, nothing of it is closed,
and the report says the run was incomplete.

| Source | Used for | When |
| --- | --- | --- |
| `arch-audit`, with [security.archlinux.org](https://security.archlinux.org/) data | Findings on official packages | Every run |
| [AUR RPC](https://aur.archlinux.org/rpc/) | Maintainer and out-of-date state | Every run |
| [cvelistV5](https://github.com/CVEProject/cvelistV5) | Description, CVSS, version ranges | New CVEs; unsettled ones again after a week |
| [EPSS](https://www.first.org/epss/) | Score shown in the report | Every run |
| [CISA KEV](https://github.com/cisagov/kev-data) | Known exploited CVEs | Every run |
| [Kernel CVE records](https://git.kernel.org/pub/scm/linux/security/vulns.git) | Records covering each kernel | Every run, shallow fetch of the JSON files |
| [kernel.org](https://www.kernel.org/releases.json) | Latest version and end of life per branch | Every run |
| `yoklama report` | Last use, idle packages, observation time | Every run |

State lives in `~/.local/state/sicil/`: `sicil.db` and the `kernel-vulns` checkout.

| Module | Purpose |
| --- | --- |
| `sicil/sources.py` | Everything read from outside |
| `sicil/rules.py` | Levels for official and AUR packages, removal rule |
| `sicil/cve.py` | Reading CVE records, the version decision |
| `sicil/enrich.py` | CVE cache, KEV and EPSS |
| `sicil/kernel.py` | The kernel strip |
| `sicil/store.py` | SQLite storage and migrations |
| `sicil/run.py` | One `sicil run` |
| `sicil/report.py` | The `report` command and its layout |
| `sicil/filters.py` | The filters of `report` |
| `sicil/show.py` | The `show` command |

## Limitations

The report is a hint, not a verdict.

- **"Looks closed" is about upstream versions.** It trusts the ranges in the CVE record.
- **Many records cannot be decided.** Plenty of CVE records carry no usable version range; those
  stay in Can't verify. Their package name may not match the product named in the record either.
- **Kernel numbers look only at the version.** CachyOS's own patches and the kernel's
  configuration are not considered, so a record may concern a module that is not even built.
  That is why the report says records "cover" a version, not that it has that many holes. The
  count of fixes missed is a lower bound, since CVEs are often opened after the fix.
- **"The repo has a newer version" uses pacman's last sync.** Sicil needs no root, so it does not
  refresh the package lists itself.
- **Packages only in the CachyOS repos are not covered,** apart from the two kernels. The Arch
  tracker does not know them.
- **AUR packages get no CVE check.** AUR names do not reliably match upstream projects, so only
  trust signals are collected for them.
- **`--unused` and `--used` say nothing about a package Yoklama cannot measure.** Such a package may
  be in use without Yoklama seeing it, so neither filter lists it. The end of the report counts it
  as `no last-used date`.

## Development

```sh
python3 -B -m unittest discover -s tests
```

The tests use saved responses and a temporary git repository; they never touch the network.
Use `--db` to try a run without touching your real state. The kernel checkout is kept beside
whichever database you name.

## Uninstalling

```sh
systemctl --user disable --now sicil.timer
rm ~/.local/bin/sicil
```

Collected data stays under `~/.local/state/sicil`; delete it too if you don't want it.
