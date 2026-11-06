"""Command line entry point."""

import argparse
import os
import shutil
import sqlite3
import sys

from . import filters as filters_module
from . import report as report_module
from . import rules, show as show_module
from .report import YOKLAMA_NOT_FOUND
from .run import RunResult, execute
from .sources import SourceError, Sources
from .store import Store

DEFAULT_DB = os.path.expanduser("~/.local/state/sicil/sicil.db")
MAX_NAMES_SHOWN = 8

# How a level reads inside a sentence.
LEVEL_PHRASES = {
    rules.RED: "act on this",
    rules.YELLOW: "worth a look",
    rules.UNVERIFIED: "can't verify",
    rules.LOOKS_CLOSED: "looks closed",
    rules.NOT_FOUND: "not found in AUR",
    rules.INFO: "for information",
}
PROBLEM_LEVELS = (rules.RED, rules.YELLOW)


def _names(packages: list[str]) -> str:
    unique = sorted(set(packages))
    shown = ", ".join(unique[:MAX_NAMES_SHOWN])
    extra = len(unique) - MAX_NAMES_SHOWN
    return f"{shown} +{extra} more" if extra > 0 else shown


def _problems_sentence(result: RunResult) -> str:
    entered = [(package, level) for package, _, level in result.diff.new]
    entered += [(package, level) for package, _, _, level in result.diff.changed]
    act = [package for package, level in entered if level == rules.RED]
    look = [package for package, level in entered if level == rules.YELLOW]
    parts = []
    if act:
        parts.append(f"act on {_names(act)}")
    if look:
        parts.append(f"worth a look: {_names(look)}")
    return f"New problems: {'; '.join(parts)}." if parts else "No new problems."


def _change_sentences(result: RunResult) -> list[str]:
    # A kernel note opening or closing is what the kernel line is for.
    listed = [
        package
        for package, _, level in result.diff.new
        if level not in PROBLEM_LEVELS and level != rules.INFO
    ]
    closed = [
        package for package, _, level in result.diff.closed if level != rules.INFO
    ]
    moved: dict[str, list[str]] = {}
    for package, _, _, level in result.diff.changed:
        if level not in PROBLEM_LEVELS:
            moved.setdefault(level, []).append(package)
    sentences = []
    if listed:
        sentences.append(f"Newly listed, nothing to act on: {_names(listed)}.")
    if closed:
        sentences.append(f"No longer reported: {_names(closed)}.")
    for level, packages in moved.items():
        sentences.append(f"Now {LEVEL_PHRASES[level]}: {_names(packages)}.")
    return sentences


def _standing_sentence(result: RunResult) -> str:
    count = lambda level: result.levels.get(level, 0)
    parts = [
        f"{count(rules.RED)} to act on" if count(rules.RED) else "",
        f"{count(rules.YELLOW)} worth a look" if count(rules.YELLOW) else "",
        f"{count(rules.UNVERIFIED)} can't be verified" if count(rules.UNVERIFIED) else "",
        f"{count(rules.LOOKS_CLOSED)} look closed" if count(rules.LOOKS_CLOSED) else "",
        f"{count(rules.NOT_FOUND)} not found in AUR" if count(rules.NOT_FOUND) else "",
        f"{result.removal_suggestions} removal suggestions"
        if result.removal_suggestions
        else "",
    ]
    listed = [part for part in parts if part]
    return f"Standing: {', '.join(listed)}." if listed else "Nothing is listed."


def _kernel_sentence(package: str, detail: dict) -> str:
    return f"{package}: {'; '.join(report_module.kernel_parts(detail))}."


def format_result(result: RunResult) -> str:
    failed = [
        name
        for name, ok in (
            ("official packages", result.repo_ok),
            ("AUR", result.aur_ok),
            ("kernels", result.kernel_ok),
        )
        if not ok
    ]
    lines = [_problems_sentence(result), *_change_sentences(result)]
    lines.append(_standing_sentence(result))
    if failed:
        lines.append(f"Not checked this run: {', '.join(failed)}.")
    lines += [
        _kernel_sentence(package, detail)
        for package, detail in sorted(result.kernels.items())
    ]
    if result.notified:
        lines.append("Sent a desktop notification.")
    for warning in result.warnings:
        label = "Note" if warning == YOKLAMA_NOT_FOUND else "Warning"
        lines.append(f"{label}: {warning}")
    lines.append("Details: sicil report")
    return "\n".join(lines)


def _state_dir(db: str) -> str:
    return os.path.dirname(os.path.abspath(db))


def run(args: argparse.Namespace) -> int:
    try:
        store = Store(args.db)
        try:
            result = execute(
                store,
                Sources(kernel_dir=os.path.join(_state_dir(args.db), "kernel-vulns")),
            )
        finally:
            store.close()
    except (OSError, sqlite3.Error) as e:
        print(f"sicil: {args.db}: {e}", file=sys.stderr)
        return 1
    print(format_result(result))
    # A source being down is an expected state, reported as a warning.
    return 0


def terminal_width() -> int | None:
    """The width to fit, or None when nothing is there to wrap, as in a pipe."""
    return shutil.get_terminal_size((0, 0)).columns or None


def _print(text: str) -> None:
    try:
        print(text)
    except BrokenPipeError:
        # The reader closed the pipe, as `sicil report | head` does.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())


def _filters(args: argparse.Namespace) -> filters_module.Filters:
    return filters_module.Filters(
        package=args.package,
        cve=args.cve,
        severity=args.severity,
        min_cvss=args.min_cvss,
        unused=args.unused,
        used=args.used,
        installed_min=args.installed_min,
        installed_max=args.installed_max,
        record_min=args.record_min,
        record_max=args.record_max,
        status=args.status,
    )


def report(args: argparse.Namespace) -> int:
    filters = _filters(args)
    try:
        loaded = report_module.load(args.db, all_findings=args.all)
        if filters.needs_usage():
            # An empty list here would read as "nothing is unused".
            if not loaded.usage:
                raise report_module.ReportError(
                    "Yoklama not found, this filter can't run"
                )
            if not loaded.last_run["yoklama_ok"]:
                raise report_module.ReportError(
                    "the last run got no usage data from Yoklama, this filter can't run"
                )
        loaded = report_module.apply_filters(loaded, filters, Sources().vercmp)
    except (report_module.ReportError, SourceError) as e:
        print(f"sicil: {e}", file=sys.stderr)
        return 1
    if args.json:
        _print(report_module.format_json(loaded))
    else:
        _print(report_module.format_text(loaded, terminal_width()))
    return 0


def show(args: argparse.Namespace) -> int:
    try:
        package, cve = show_module.parse_id(args.id)
    except ValueError as e:
        print(f"sicil: {e}", file=sys.stderr)
        return 2
    if package is None and args.field:
        print(
            f"sicil: -f needs one package: {cve} may be in several, use package:{cve}",
            file=sys.stderr,
        )
        return 2
    width = terminal_width()
    sources = Sources(kernel_dir=os.path.join(_state_dir(args.db), "kernel-vulns"))
    try:
        loaded = report_module.load(args.db, all_findings=True)
        if package is None:
            _print(show_module.format_listing(loaded, args.db, sources, cve, width))
            return 0
        shown = show_module.lookup(loaded, args.db, sources, package, cve)
    except (report_module.ReportError, SourceError) as e:
        print(f"sicil: {e}", file=sys.stderr)
        return 1
    if not args.field:
        _print(show_module.format_shown(shown, width))
        return 0
    if not shown.known and args.field not in ("installed", "status", "url"):
        print(f"sicil: nothing recorded for {shown.id}", file=sys.stderr)
        return 1
    _print(show_module.field_value(shown, args.field))
    return 0


def _at_least_zero(text: str) -> int:
    value = int(text)
    if value < 0:
        raise ValueError(text)
    return value


TOP_DESCRIPTION = """\
Check whether installed packages have known security problems.
Only reads and reports: never installs, updates or removes anything.

Commands:
  run     check the sources and record what changed
  report  show the recorded findings; no network; filters narrow them down
  show    show one record, judged against the version installed now
"""

# The overview in `sicil -h`. A test keeps it in step with the flags of `sicil report`.
TOP_HELP = """\
Filters of `sicil report` (rules and examples: sicil report -h):
  -p, --package NAME                  package name; 'lib*' works
  --cve ID                            CVE ID; 'CVE-2021-*' works
  -s, --severity LEVEL                low, medium, high, critical or unknown
  -c, --min-cvss SCORE                this CVSS score and above
  --unused DAYS, --used DAYS          last use, from Yoklama
  --installed-min, --installed-max    installed version
  --record-min, --record-max          version in the record
  --status STATUS                     open, unverified or looks-closed

Examples:
  sicil run
  sicil report -s high
  sicil report -p 'lib*' -c 7
  sicil show pam:CVE-2025-6020
"""

REPORT_DESCRIPTION = """\
Show the recorded findings. Reads the database, never the network.
Each row starts with an ID, package:CVE, to use with `sicil show`.
"""

FILTERS_DESCRIPTION = """\
Different filters must all match; a repeated filter may match any value.
A record hidden only because the filtered field is empty is counted at the
end of the report. Quote wildcards, or the shell may expand them.
"""

REPORT_HELP = """\
Examples:
  sicil report -p pam -p libxml2 -c 7     pam or libxml2, with CVSS 7 or above
  sicil report -p 'lib*' -s high          packages named lib*, high or critical
  sicil report --cve 'CVE-2021-*' --json  CVEs from 2021, as JSON
  sicil report -s low -s unknown          every severity, unknown included
  sicil report --unused 60 --status open  open problems, not used for 60 days
  sicil report --installed-max 5.9        installed version 5.9 or older
"""


def _help_layout(prog: str) -> argparse.HelpFormatter:
    # Wide enough for --installed-min VERSION to keep its text on the same line.
    return argparse.RawDescriptionHelpFormatter(prog, max_help_position=28)


def _add_filters(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("filters", FILTERS_DESCRIPTION)
    many = dict(action="append", default=[])
    group.add_argument(
        "-p",
        "--package",
        metavar="NAME",
        help="package name; wildcards work: 'lib*'",
        **many,
    )
    group.add_argument(
        "--cve",
        metavar="ID",
        help="CVE ID; wildcards work: 'CVE-2021-*'. On a kernel it lists the matching IDs",
        **many,
    )
    group.add_argument(
        "-s",
        "--severity",
        metavar="LEVEL",
        type=str.lower,
        choices=filters_module.SEVERITY_CHOICES,
        help="this level and above: low, medium, high, critical."
        " `-s unknown` alone shows unknown severity",
        **many,
    )
    group.add_argument(
        "-c",
        "--min-cvss",
        metavar="SCORE",
        type=float,
        help="this CVSS score and above (CNA, or else CISA-ADP)",
        **many,
    )
    group.add_argument(
        "--unused",
        metavar="DAYS",
        type=_at_least_zero,
        help="not used for this many days; a package never used counts."
        " Needs Yoklama",
        **many,
    )
    group.add_argument(
        "--used",
        metavar="DAYS",
        type=_at_least_zero,
        help="used within this many days. Needs Yoklama",
        **many,
    )
    for name, what, bound in (
        ("--installed-min", "installed version", "this or newer"),
        ("--installed-max", "installed version", "this or older"),
        ("--record-min", "version in the record", "this or newer"),
        ("--record-max", "version in the record", "this or older"),
    ):
        group.add_argument(
            name,
            metavar="VERSION",
            help=f"{what} {bound}, compared by vercmp",
            **many,
        )
    group.add_argument(
        "--status",
        metavar="STATUS",
        choices=filters_module.STATUS_CHOICES,
        help="open: red or yellow; unverified: can't verify; looks-closed: looks closed",
        **many,
    )


def build_parser() -> tuple[argparse.ArgumentParser, argparse.ArgumentParser]:
    """The parser and its `report` part, whose flags the overview must list."""
    parser = argparse.ArgumentParser(
        prog="sicil",
        usage="sicil [-h] COMMAND ...",
        description=TOP_DESCRIPTION,
        epilog=TOP_HELP,
        formatter_class=_help_layout,
    )
    # TOP_DESCRIPTION lists the commands: argparse would add a heading row of its own.
    commands = parser.add_subparsers(
        metavar="COMMAND", dest="command", required=True, help=argparse.SUPPRESS
    )
    db_help = "database path (default: ~/.local/state/sicil/sicil.db)"

    run_parser = commands.add_parser(
        "run",
        description="Check the sources and record what changed.",
        formatter_class=_help_layout,
    )
    run_parser.add_argument("--db", metavar="PATH", default=DEFAULT_DB, help=db_help)
    run_parser.set_defaults(func=run)

    report_parser = commands.add_parser(
        "report",
        usage="sicil report [-h] [--all] [--json] [--db PATH] [filters]",
        description=REPORT_DESCRIPTION,
        epilog=REPORT_HELP,
        formatter_class=_help_layout,
    )
    report_parser.add_argument(
        "--all", action="store_true", help="also show closed findings"
    )
    report_parser.add_argument(
        "--json",
        action="store_true",
        help="print JSON, with the complete lists; filters apply to it too",
    )
    report_parser.add_argument("--db", metavar="PATH", default=DEFAULT_DB, help=db_help)
    _add_filters(report_parser)
    report_parser.set_defaults(func=report)

    show_parser = commands.add_parser(
        "show",
        description="Show one record, judged against the version installed now.",
        formatter_class=_help_layout,
    )
    show_parser.add_argument(
        "id", metavar="ID", help="package:CVE-..., or CVE-... for every package with it"
    )
    show_parser.add_argument(
        "-f",
        "--field",
        choices=show_module.FIELDS,
        metavar="FIELD",
        help="print one field bare: " + ", ".join(show_module.FIELDS),
    )
    show_parser.add_argument("--db", metavar="PATH", default=DEFAULT_DB, help=db_help)
    show_parser.set_defaults(func=show)
    return parser, report_parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser, _ = build_parser()
    # `sicil -h report` asks the same thing as `sicil report -h`.
    if len(argv) == 2 and argv[0] in ("-h", "--help") and argv[1] in ("run", "report", "show"):
        argv = [argv[1], argv[0]]
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
